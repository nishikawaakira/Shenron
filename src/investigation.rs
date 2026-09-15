//! Bounded private request context, independent of detection matches.
use crate::{
    event::{RawRetention, TelemetryCapabilities, TelemetryProfile},
    production::{stream_referenced_events, PathProvenance},
};
use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
};

pub const SAFETY_NOTE: &str = "PRIVATE: observed connection peers and request paths, not actor identity or a determination of attack, exploitation, or compromise. Peers may be CDN/LB/NAT/proxies. Includes non-matching requests; no detection is inferred. Do not share without review.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceReference {
    pub input_file: String,
    /// One-based physical line in decoded text (including blank/malformed lines).
    pub line_number: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextRecord {
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub method: Option<String>,
    pub uri_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_query: Option<String>,
    pub response_status: Option<u16>,
    pub response_bytes: Option<u64>,
    pub source_reference: SourceReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf_action: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub waf_labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct ContextCounts {
    pub parseable_records: u64,
    pub parse_errors: u64,
    pub nonselected_peers: u64,
    pub selected_without_timestamp: u64,
    pub selected_outside_window: u64,
    pub eligible_records: u64,
    pub retained_records: usize,
    pub records_beyond_cap: u64,
    pub maximum_records: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest_retained: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_retained: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ContextReport {
    pub report_kind: &'static str,
    pub safety_note: &'static str,
    pub retention_note: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    pub query_values_included: bool,
    /// Private selection criteria, retained even when no records match or the cap is reached.
    pub selected_source_ips: BTreeSet<IpAddr>,
    pub counts: ContextCounts,
    pub corpus: Vec<PathProvenance>,
    pub records: Vec<ContextRecord>,
    pub field_availability: TelemetryCapabilities,
}

pub struct ContextOptions {
    pub source_ips: BTreeSet<IpAddr>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub maximum_records: usize,
    pub include_query: bool,
}

/// Strict deterministic traversal: filesystem failures are errors, not skips.
pub(crate) fn sorted_input_files(input: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if input.is_file() {
        return Ok(vec![input.to_owned()]);
    }
    if !input.is_dir() {
        bail!("input must be a readable file or directory");
    }
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(input) {
        let entry = entry.context("walking input corpus")?;
        if entry.file_type().is_symlink() {
            bail!("symbolic links inside a corpus must be resolved explicitly");
        }
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    files.sort();
    Ok(files)
}

pub fn request_context(
    input: &Path,
    profile: TelemetryProfile,
    options: &ContextOptions,
) -> anyhow::Result<ContextReport> {
    if options
        .from
        .zip(options.to)
        .is_some_and(|(from, to)| from > to)
        || options.maximum_records == 0
        || options.source_ips.is_empty()
    {
        bail!("context requires ordered UTC bounds when both are specified, selected peers, and a positive finite record cap");
    }
    let mut report = ContextReport {
        report_kind: "PRIVATE_REQUEST_CONTEXT", safety_note: SAFETY_NOTE,
        retention_note: "First eligible records in sorted input-file/physical-line order are retained; retained records are then sorted by UTC time, file, and line. Not necessarily the earliest records when capped. Query values are absent unless explicitly enabled. A field absent from a record is either unavailable in this telemetry profile (see field_availability) or unrecorded for that request. Absence is not a determination that a control did not act. Retained time bounds describe only the retained records. When records were omitted beyond the cap, they are a lower bound on the observed span.",
        from: options.from, to: options.to, query_values_included: options.include_query,
        selected_source_ips: options.source_ips.clone(),
        counts: ContextCounts { maximum_records: options.maximum_records, ..Default::default() },
        corpus: Vec::new(), records: Vec::new(),
        field_availability: profile.capabilities(),
    };
    for path in sorted_input_files(input)? {
        let provenance =
            stream_referenced_events(&path, profile, RawRetention::Drop, |line_number, event| {
                let Ok(event) = event else {
                    report.counts.parse_errors += 1;
                    return Ok(());
                };
                report.counts.parseable_records += 1;
                let selected = event
                    .source_ip
                    .as_deref()
                    .and_then(|ip| ip.parse::<IpAddr>().ok())
                    .is_some_and(|ip| options.source_ips.contains(&ip));
                if !selected {
                    report.counts.nonselected_peers += 1;
                    return Ok(());
                }
                let Some(timestamp) = event.timestamp else {
                    report.counts.selected_without_timestamp += 1;
                    return Ok(());
                };
                if options.from.is_some_and(|from| timestamp < from)
                    || options.to.is_some_and(|to| timestamp > to)
                {
                    report.counts.selected_outside_window += 1;
                    return Ok(());
                }
                report.counts.eligible_records += 1;
                if report.records.len() >= options.maximum_records {
                    report.counts.records_beyond_cap += 1;
                    return Ok(());
                }
                report.records.push(ContextRecord {
                    timestamp,
                    source_ip: event.source_ip.expect("selected peer exists"),
                    method: event.method,
                    uri_path: event.uri_path,
                    uri_query: if options.include_query {
                        event.uri_query
                    } else {
                        None
                    },
                    response_status: event.status,
                    response_bytes: event.response_bytes,
                    source_reference: SourceReference {
                        input_file: path.display().to_string(),
                        line_number,
                    },
                    host: if report.field_availability.host {
                        event.host
                    } else {
                        None
                    },
                    user_agent: if report.field_availability.user_agent {
                        event.user_agent
                    } else {
                        None
                    },
                    country: if report.field_availability.country {
                        event.country
                    } else {
                        None
                    },
                    ja3: if report.field_availability.ja3 {
                        event.ja3
                    } else {
                        None
                    },
                    ja4: if report.field_availability.ja4 {
                        event.ja4
                    } else {
                        None
                    },
                    waf_action: if report.field_availability.waf_action {
                        event.waf_action
                    } else {
                        None
                    },
                    waf_labels: if report.field_availability.waf_labels {
                        event.waf_labels
                    } else {
                        Vec::new()
                    },
                    referer: if options.include_query && report.field_availability.referer {
                        event.referer
                    } else {
                        None
                    },
                });
                Ok(())
            })?;
        report.corpus.push(provenance);
    }
    report.records.sort_by(|a, b| {
        (
            a.timestamp,
            &a.source_reference.input_file,
            a.source_reference.line_number,
        )
            .cmp(&(
                b.timestamp,
                &b.source_reference.input_file,
                b.source_reference.line_number,
            ))
    });
    report.counts.retained_records = report.records.len();
    report.counts.earliest_retained = report.records.first().map(|record| record.timestamp);
    report.counts.latest_retained = report.records.last().map(|record| record.timestamp);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{fs, io::Write};

    #[test]
    fn window_missing_time_and_peer_exclusions_reconcile_and_corrupt_gzip_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("waf.jsonl");
        let event = |ip: &str, timestamp: Option<i64>| {
            serde_json::json!({"timestamp": timestamp, "httpRequest":{"clientIp":ip, "uri":"/context"}}).to_string()
        };
        let from: DateTime<Utc> = "2026-08-24T00:00:00Z".parse().unwrap();
        fs::write(
            &input,
            [
                event("198.51.100.1", Some(from.timestamp_millis())),
                event("198.51.100.1", None),
                event("198.51.100.1", Some(0)),
                event("198.51.100.2", Some(from.timestamp_millis())),
            ]
            .join("\n"),
        )
        .unwrap();
        let options = ContextOptions {
            source_ips: ["198.51.100.1".parse().unwrap()].into(),
            from: Some(from),
            to: Some(from),
            maximum_records: 10,
            include_query: false,
        };
        let result = request_context(&input, TelemetryProfile::AwsWaf, &options).unwrap();
        assert_eq!(result.counts.parseable_records, 4);
        assert_eq!(result.counts.eligible_records, 1);
        assert_eq!(result.counts.nonselected_peers, 1);
        assert_eq!(result.counts.selected_without_timestamp, 1);
        assert_eq!(result.counts.selected_outside_window, 1);
        let gzip = dir.path().join("broken.gz");
        fs::write(&gzip, b"invalid gzip").unwrap();
        assert!(request_context(&gzip, TelemetryProfile::AwsWaf, &options).is_err());
    }
    #[test]
    fn nonmatching_context_has_physical_lines_caps_and_private_only_values() {
        let dir = tempfile::tempdir().unwrap();
        let line = "198.51.100.1 - - [24/Aug/2026:11:20:30 +0000] \"GET /ordinary?token=secret HTTP/1.1\" 200 12 \"-\" \"-\"\n";
        let bytes = format!("\nbad\n{line}{line}");
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(bytes.as_bytes()).unwrap();
        let compressed = gzip.finish().unwrap();
        fs::write(dir.path().join("a.gz"), &compressed).unwrap();
        let mut options = ContextOptions {
            source_ips: ["198.51.100.1".parse().unwrap()].into(),
            from: Some("2026-08-24T00:00:00Z".parse().unwrap()),
            to: Some("2026-08-25T00:00:00Z".parse().unwrap()),
            maximum_records: 1,
            include_query: false,
        };
        let result =
            request_context(dir.path(), TelemetryProfile::ApacheCombined, &options).unwrap();
        assert_eq!(result.counts.parse_errors, 1);
        assert_eq!(result.counts.records_beyond_cap, 1);
        assert_eq!(result.records[0].source_reference.line_number, 3);
        assert_eq!(
            result.corpus[0].sha256,
            Some(format!("{:x}", Sha256::digest(&compressed)))
        );
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("token=secret"));
        let counts = serde_json::to_string(&result.counts).unwrap();
        assert!(!counts.contains("198.51.100.1") && !counts.contains("/ordinary"));
        options.include_query = true;
        assert!(serde_json::to_string(
            &request_context(dir.path(), TelemetryProfile::ApacheCombined, &options).unwrap()
        )
        .unwrap()
        .contains("token=secret"));
    }

    #[test]
    fn concatenated_gzip_context_preserves_lines_fingerprint_and_capped_selection() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("context.gz");
        let line = "198.51.100.1 - - [24/Aug/2026:11:20:30 +0000] \"GET /ordinary HTTP/1.1\" 200 12 \"-\" \"-\"\n";
        let mut stored = Vec::new();
        for member in [format!("\nbad\n{line}"), line.to_owned()] {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(member.as_bytes()).unwrap();
            stored.extend(encoder.finish().unwrap());
        }
        fs::write(&input, &stored).unwrap();
        let mut options = ContextOptions {
            source_ips: [
                "198.51.100.1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ]
            .into(),
            from: Some("2026-08-24T00:00:00Z".parse().unwrap()),
            to: Some("2026-08-25T00:00:00Z".parse().unwrap()),
            maximum_records: 10,
            include_query: false,
        };
        let report = request_context(&input, TelemetryProfile::ApacheCombined, &options).unwrap();
        assert_eq!(report.counts.parseable_records, 2);
        assert_eq!(report.counts.parse_errors, 1);
        assert_eq!(
            report
                .records
                .iter()
                .map(|r| r.source_reference.line_number)
                .collect::<Vec<_>>(),
            [3, 4]
        );
        assert_eq!(report.corpus[0].byte_length, Some(stored.len() as u64));
        assert_eq!(
            report.corpus[0].sha256,
            Some(format!("{:x}", Sha256::digest(&stored)))
        );
        options.maximum_records = 1;
        let capped = request_context(&input, TelemetryProfile::ApacheCombined, &options).unwrap();
        assert_eq!(capped.counts.records_beyond_cap, 1);
        assert_eq!(capped.selected_source_ips, options.source_ips);
    }
}
