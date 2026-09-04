//! Deterministic, file-only CTI export from existing Shenron run artifacts.
//!
//! The default path reads only sanitized aggregates. Raw observed IPs and URI
//! paths are read from private findings only after explicit opt-in. No export
//! path performs network I/O or identifies an actor or campaign.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader},
    net::IpAddr,
    path::Path,
};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CtiExportFormat {
    Stix,
    Misp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TlpLevel {
    Clear,
    Green,
    Amber,
    Red,
}

impl TlpLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Green => "green",
            Self::Amber => "amber",
            Self::Red => "red",
        }
    }

    /// Canonical STIX marking-definition name (e.g. `TLP:AMBER`). Without it a
    /// STIX viewer shows the marking name as empty.
    fn marking_name(self) -> &'static str {
        match self {
            Self::Clear => "TLP:CLEAR",
            Self::Green => "TLP:GREEN",
            Self::Amber => "TLP:AMBER",
            Self::Red => "TLP:RED",
        }
    }
}

#[derive(Debug, Default)]
struct PrivateObservables {
    source_ips: BTreeSet<String>,
    uri_paths: BTreeSet<String>,
    malformed_findings: u64,
    invalid_source_ips: u64,
}

/// Export one existing run directory without re-reading source logs. The
/// caller-selected output is a local file only; nothing is uploaded.
pub fn export_run(
    run_dir: &Path,
    output: &Path,
    format: CtiExportFormat,
    include_observables: bool,
    tlp: Option<TlpLevel>,
) -> Result<()> {
    let sanitized_path = run_dir.join("sanitized-research.json");
    let sanitized_bytes = fs::read(&sanitized_path).with_context(|| {
        format!(
            "reading sanitized run artifact {}",
            sanitized_path.display()
        )
    })?;
    let sanitized: Value = serde_json::from_slice(&sanitized_bytes).with_context(|| {
        format!(
            "parsing sanitized run artifact {}",
            sanitized_path.display()
        )
    })?;
    let manifest = read_optional_json(&run_dir.join("run-manifest.json"))?;
    let observables = if include_observables {
        load_private_observables(&run_dir.join("private-findings.jsonl"))?
    } else {
        PrivateObservables::default()
    };
    let effective_tlp = tlp.unwrap_or(if include_observables {
        TlpLevel::Red
    } else {
        TlpLevel::Amber
    });
    let document = match format {
        CtiExportFormat::Stix => stix_bundle(
            &sanitized,
            manifest.as_ref(),
            &sanitized_bytes,
            &observables,
            include_observables,
            effective_tlp,
        ),
        CtiExportFormat::Misp => misp_event(
            &sanitized,
            manifest.as_ref(),
            &sanitized_bytes,
            &observables,
            include_observables,
            effective_tlp,
        ),
    };
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    serde_json::to_writer_pretty(
        File::create(output).with_context(|| format!("creating {}", output.display()))?,
        &document,
    )?;
    Ok(())
}

fn read_optional_json(path: &Path) -> Result<Option<Value>> {
    if !path.is_file() {
        return Ok(None);
    }
    serde_json::from_reader(File::open(path)?)
        .with_context(|| format!("reading {}", path.display()))
        .map(Some)
}

fn load_private_observables(path: &Path) -> Result<PrivateObservables> {
    if !path.is_file() {
        bail!(
            "--include-observables requires private findings at {}",
            path.display()
        );
    }
    let mut values = PrivateObservables::default();
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let finding: Value = match serde_json::from_str(&line) {
            Ok(finding) => finding,
            Err(_) => {
                values.malformed_findings += 1;
                continue;
            }
        };
        if let Some(source_ip) = finding.get("source_ip").and_then(Value::as_str) {
            if source_ip.parse::<IpAddr>().is_ok() {
                values.source_ips.insert(source_ip.to_owned());
            } else {
                values.invalid_source_ips += 1;
            }
        }
        if let Some(uri_path) = finding.get("uri_path").and_then(Value::as_str) {
            values.uri_paths.insert(uri_path.to_owned());
        }
    }
    Ok(values)
}

fn stix_bundle(
    sanitized: &Value,
    manifest: Option<&Value>,
    sanitized_bytes: &[u8],
    observables: &PrivateObservables,
    include_observables: bool,
    tlp: TlpLevel,
) -> Value {
    let created = artifact_time(sanitized, manifest);
    let marking_id = stix_id("marking-definition", &format!("tlp:{}", tlp.label()));
    let identity_id = stix_id("identity", "shenron");
    let mut objects = vec![
        json!({
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": marking_id,
            "created": created,
            "name": tlp.marking_name(),
            "definition_type": "tlp",
            "definition": { "tlp": tlp.label() }
        }),
        json!({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": created,
            "modified": created,
            "name": "Shenron",
            "identity_class": "system",
            "object_marking_refs": [marking_id]
        }),
    ];
    let mut report_refs = vec![identity_id.clone()];
    for finding in cve_findings(sanitized) {
        let Some(cve) = finding.get("cve").and_then(Value::as_str) else {
            continue;
        };
        let vulnerability_id = stix_id("vulnerability", cve);
        let note_id = stix_id("note", &format!("{cve}:{finding}"));
        objects.push(json!({
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vulnerability_id,
            "created_by_ref": identity_id,
            "created": created,
            "modified": created,
            "name": cve,
            "external_references": [{"source_name": "cve", "external_id": cve}],
            "object_marking_refs": [marking_id]
        }));
        objects.push(json!({
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created_by_ref": identity_id,
            "created": created,
            "modified": created,
            "abstract": "Sanitized Shenron CVE-related request-match aggregate",
            "content": "Aggregate request-match volume for human review. This is not an attack, exploitation, compromise, vulnerable-product, campaign, or attacker-identity determination.",
            "object_refs": [vulnerability_id],
            "object_marking_refs": [marking_id],
            "x_shenron_request_count": finding.get("request_count").and_then(Value::as_u64).unwrap_or(0),
            "x_shenron_detectability": finding.get("detectability").cloned().unwrap_or(Value::Null),
            "x_shenron_template_ids": finding.get("template_ids").cloned().unwrap_or_else(|| json!([])),
            "x_shenron_distinctive_path_matches": finding.get("distinctive_path_matches").and_then(Value::as_u64).unwrap_or(0),
            "x_shenron_generic_path_matches": finding.get("generic_path_matches").and_then(Value::as_u64).unwrap_or(0)
        }));
        report_refs.push(vulnerability_id);
        report_refs.push(note_id);
    }

    if include_observables {
        for source_ip in &observables.source_ips {
            let object_type = if source_ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv4()) {
                "ipv4-addr"
            } else {
                "ipv6-addr"
            };
            let id = stix_id(object_type, source_ip);
            objects.push(json!({
                "type": object_type,
                "spec_version": "2.1",
                "id": id,
                "value": source_ip,
                "object_marking_refs": [marking_id]
            }));
            report_refs.push(id);
        }
        for uri_path in &observables.uri_paths {
            let id = stix_id("x-shenron-uri-path", uri_path);
            objects.push(json!({
                "type": "x-shenron-uri-path",
                "spec_version": "2.1",
                "id": id,
                "value": uri_path,
                "object_marking_refs": [marking_id]
            }));
            report_refs.push(id);
        }
    }
    let report_id = stix_id("report", &format!("{:x}", Sha256::digest(sanitized_bytes)));
    objects.push(json!({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created_by_ref": identity_id,
        "created": created,
        "modified": created,
        "published": created,
        "name": "Shenron sanitized CVE-related request-match aggregates",
        "description": "A file-only export of observed aggregate request matches. It does not identify a threat actor or campaign and does not determine attack, exploitation, compromise, or vulnerability.",
        "report_types": ["threat-report"],
        "object_refs": report_refs,
        "object_marking_refs": [marking_id],
        "x_shenron_telemetry_profile": manifest.and_then(|value| value.get("telemetry_profile")).cloned().unwrap_or(Value::Null),
        "x_shenron_nuclei_revision": manifest.and_then(|value| value.get("nuclei_revision")).cloned().unwrap_or(Value::Null),
        "x_shenron_private_observables_included": include_observables,
        "x_shenron_malformed_private_findings_excluded": observables.malformed_findings,
        "x_shenron_invalid_source_ips_excluded": observables.invalid_source_ips,
        "x_shenron_request_specific_matches": sanitized.pointer("/metrics/request_specific_matches").and_then(Value::as_u64).unwrap_or(0),
        "x_shenron_response_unverified_matches": sanitized.pointer("/metrics/response_unverified_matches").and_then(Value::as_u64).unwrap_or(0)
    }));
    objects.sort_by(|left, right| {
        left.get("type")
            .and_then(Value::as_str)
            .cmp(&right.get("type").and_then(Value::as_str))
            .then_with(|| {
                left.get("id")
                    .and_then(Value::as_str)
                    .cmp(&right.get("id").and_then(Value::as_str))
            })
    });
    json!({
        "type": "bundle",
        "id": stix_id("bundle", &format!("{}:{include_observables}:{report_id}", tlp.label())),
        "objects": objects
    })
}

fn misp_event(
    sanitized: &Value,
    manifest: Option<&Value>,
    sanitized_bytes: &[u8],
    observables: &PrivateObservables,
    include_observables: bool,
    tlp: TlpLevel,
) -> Value {
    let mut attributes = Vec::new();
    for finding in cve_findings(sanitized) {
        let Some(cve) = finding.get("cve").and_then(Value::as_str) else {
            continue;
        };
        attributes.push(json!({
            "type": "vulnerability",
            "category": "External analysis",
            "value": cve,
            "to_ids": false,
            "comment": format!("CVE-related request-match aggregate: {} requests; not an attack, exploitation, compromise, or vulnerable-product determination", finding.get("request_count").and_then(Value::as_u64).unwrap_or(0))
        }));
        for template_id in finding
            .get("template_ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            attributes.push(json!({
                "type": "text",
                "category": "External analysis",
                "value": template_id,
                "to_ids": false,
                "comment": format!("Public Nuclei template ID associated with {cve}")
            }));
        }
    }
    if include_observables {
        for source_ip in &observables.source_ips {
            attributes.push(json!({
                "type": "ip-src",
                "category": "Network activity",
                "value": source_ip,
                "to_ids": false,
                "comment": "Observed connection peer; not attacker attribution"
            }));
        }
        for uri_path in &observables.uri_paths {
            attributes.push(json!({
                "type": "uri",
                "category": "Network activity",
                "value": uri_path,
                "to_ids": false,
                "comment": "Observed URI path; not an attack or exploitation determination"
            }));
        }
    }
    attributes.sort_by(|left, right| {
        left.get("type")
            .and_then(Value::as_str)
            .cmp(&right.get("type").and_then(Value::as_str))
            .then_with(|| {
                left.get("value")
                    .and_then(Value::as_str)
                    .cmp(&right.get("value").and_then(Value::as_str))
            })
    });
    json!({
        "Event": {
            "uuid": bare_uuid(&format!("misp:{:x}", Sha256::digest(sanitized_bytes))),
            "info": "Shenron request-match aggregates for human review",
            "date": artifact_time(sanitized, manifest).get(..10).unwrap_or("1970-01-01"),
            "distribution": "0",
            "analysis": "2",
            "threat_level_id": "4",
            "published": false,
            "Tag": [{"name": format!("tlp:{}", tlp.label())}],
            "Attribute": attributes,
            "Shenron": {
                "sanitized_default": !include_observables,
                "private_observables_included": include_observables,
                "malformed_private_findings_excluded": observables.malformed_findings,
                "invalid_source_ips_excluded": observables.invalid_source_ips,
                "safety_note": "File-only observed-volume export; not an attack, exploitation, compromise, campaign, threat-actor, or attribution determination."
            }
        }
    })
}

fn cve_findings(sanitized: &Value) -> &[Value] {
    sanitized
        .get("cve_findings")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn artifact_time<'a>(sanitized: &'a Value, manifest: Option<&'a Value>) -> &'a str {
    manifest
        .and_then(|value| value.get("generated_at"))
        .and_then(Value::as_str)
        .or_else(|| {
            sanitized
                .pointer("/metrics/earliest_timestamp")
                .and_then(Value::as_str)
        })
        .unwrap_or("1970-01-01T00:00:00Z")
}

fn stix_id(object_type: &str, key: &str) -> String {
    format!(
        "{object_type}--{}",
        bare_uuid(&format!("{object_type}:{key}"))
    )
}

fn bare_uuid(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn fixture_run() -> tempfile::TempDir {
        let directory = tempdir().unwrap();
        fs::write(
            directory.path().join("sanitized-research.json"),
            serde_json::to_vec_pretty(&json!({
                "report_kind": "SANITIZED_RESEARCH_OUTPUT",
                "metrics": {"earliest_timestamp": "2026-01-01T00:00:00Z"},
                "cve_findings": [{
                    "cve": "CVE-2026-0001",
                    "request_count": 12,
                    "detectability": "HIGH",
                    "distinctive_path_matches": 10,
                    "generic_path_matches": 2,
                    "template_ids": ["template-a"]
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            directory.path().join("private-findings.jsonl"),
            "{\"source_ip\":\"198.51.100.99\",\"uri_path\":\"/private-secret\",\"host\":\"private.example.test\",\"headers\":[{\"name\":\"Authorization\",\"value\":\"secret-token\"}]}\n",
        )
        .unwrap();
        directory
    }

    #[test]
    fn stix_defaults_to_sanitized_aggregates_with_marking_and_valid_ids() {
        let run = fixture_run();
        let output = run.path().join("export.json");
        export_run(run.path(), &output, CtiExportFormat::Stix, false, None).unwrap();
        let text = fs::read_to_string(output).unwrap();
        for private in [
            "198.51.100.99",
            "/private-secret",
            "private.example.test",
            "secret-token",
        ] {
            assert!(!text.contains(private));
        }
        let bundle: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(bundle["type"], "bundle");
        assert!(valid_stix_id("bundle", bundle["id"].as_str().unwrap()));
        let objects = bundle["objects"].as_array().unwrap();
        assert!(objects.iter().any(|item| {
            item["type"] == "marking-definition"
                && item["definition"]["tlp"] == "amber"
                && item["name"] == "TLP:AMBER"
        }));
        assert!(objects.iter().all(|item| valid_stix_id(
            item["type"].as_str().unwrap(),
            item["id"].as_str().unwrap()
        )));
        assert!(objects.iter().all(|item| item["type"] != "threat-actor"));
        assert!(objects.iter().all(|item| item["type"] != "campaign"));
    }

    #[test]
    fn private_observables_require_opt_in_and_default_to_red_marking() {
        let run = fixture_run();
        let output = run.path().join("private-export.json");
        export_run(run.path(), &output, CtiExportFormat::Stix, true, None).unwrap();
        let text = fs::read_to_string(output).unwrap();
        assert!(text.contains("198.51.100.99"));
        assert!(text.contains("/private-secret"));
        assert!(!text.contains("secret-token"));
        let bundle: Value = serde_json::from_str(&text).unwrap();
        assert!(bundle["objects"].as_array().unwrap().iter().any(|item| {
            item["type"] == "marking-definition"
                && item["definition"]["tlp"] == "red"
                && item["name"] == "TLP:RED"
        }));
    }

    #[test]
    fn misp_export_is_file_only_and_sanitized_by_default() {
        let run = fixture_run();
        let output = run.path().join("misp.json");
        export_run(run.path(), &output, CtiExportFormat::Misp, false, None).unwrap();
        let text = fs::read_to_string(output).unwrap();
        assert!(text.contains("CVE-2026-0001"));
        assert!(text.contains("template-a"));
        assert!(!text.contains("198.51.100.99"));
        assert!(!text.contains("/private-secret"));
    }

    fn valid_stix_id(object_type: &str, id: &str) -> bool {
        let Some(uuid) = id.strip_prefix(&format!("{object_type}--")) else {
            return false;
        };
        let bytes = uuid.as_bytes();
        uuid.len() == 36
            && [8, 13, 18, 23]
                .into_iter()
                .all(|index| bytes.get(index) == Some(&b'-'))
            && bytes.get(14) == Some(&b'5')
            && bytes
                .get(19)
                .is_some_and(|value| matches!(value, b'8' | b'9' | b'a' | b'b'))
            && bytes
                .iter()
                .enumerate()
                .all(|(index, value)| [8, 13, 18, 23].contains(&index) || value.is_ascii_hexdigit())
    }
}
