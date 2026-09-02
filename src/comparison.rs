//! Read-only comparison of two frozen Shenron run-artifact directories.
//!
//! The output is deterministic local triage context only. First-seen entities
//! and elevated volume are not determinations of denial-of-service, attack,
//! abuse, exploitation, compromise, or attacker identity.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::Path,
};

use anyhow::Context;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    concentration::PrivateRequestConcentrationReport,
    production::{explain_private_findings, load_private_concentration, FindingExplanation},
};

pub const ELEVATED_RATIO: f64 = 3.0;
pub const MIN_BASELINE_REQUESTS: u64 = 30;

#[derive(Debug, Clone, Serialize)]
pub struct RunProvenance {
    pub shenron_version: Option<String>,
    pub telemetry_profile: Option<String>,
    pub nuclei_revision: Option<String>,
    pub filter_from: Option<String>,
    pub filter_to: Option<String>,
    pub artifacts_sha256: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonProvenance {
    pub baseline: RunProvenance,
    pub current: RunProvenance,
}

#[derive(Debug, Serialize)]
pub struct Comparability {
    pub comparable: bool,
    pub kind: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NumericDelta {
    pub baseline: u64,
    pub current: u64,
    pub delta: i64,
}
#[derive(Debug, Serialize)]
pub struct OptionalRatioDelta {
    pub baseline: Option<f64>,
    pub current: Option<f64>,
    pub delta: Option<f64>,
}
#[derive(Debug, Serialize)]
pub struct CveDelta {
    pub cve: String,
    pub request_count: NumericDelta,
    pub unique_source_clusters: NumericDelta,
    pub unique_ja4_fingerprints: NumericDelta,
    pub protection_gap_rate: OptionalRatioDelta,
}
#[derive(Debug, Serialize)]
pub struct CveDiff {
    pub available: bool,
    pub reason: Option<String>,
    pub newly_observed_cves: Vec<String>,
    pub disappeared_cves: Vec<String>,
    pub common_cve_deltas: Vec<CveDelta>,
}

#[derive(Debug, Default, Serialize)]
pub struct FirstSeenCounts {
    pub source_ips: usize,
    pub hosts: usize,
    pub uri_paths: usize,
    pub ja4_fingerprints: usize,
    pub client_ips: Option<usize>,
}
#[derive(Debug, Serialize)]
pub struct FirstSeenPrivate {
    pub source_ips: Vec<String>,
    pub hosts: Vec<String>,
    pub uri_paths: Vec<String>,
    pub ja4_fingerprints: Vec<String>,
    pub client_ips: Option<Vec<String>>,
    pub unavailable: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VolumeDetail {
    pub key: String,
    pub baseline_requests: Option<u64>,
    pub current_requests: u64,
    pub ratio: Option<f64>,
    pub label: String,
}
#[derive(Debug, Serialize)]
pub struct ConcentrationDeltaSummary {
    pub available: bool,
    pub reason: Option<String>,
    pub elevated_paths: usize,
    pub elevated_source_ips: usize,
    pub low_baseline_paths: usize,
    pub low_baseline_source_ips: usize,
    pub median_rpm_ratio: Option<f64>,
    /// `Some(true)` when the median per-minute rate ratio reached the fixed
    /// elevated threshold; `None` when the ratio could not be computed.
    pub median_rpm_elevated: Option<bool>,
    pub peak_rpm_delta: Option<i64>,
    pub top_ten_paths_share_delta: Option<f64>,
    pub top_ten_source_ips_share_delta: Option<f64>,
}
#[derive(Debug, Serialize)]
pub struct ConcentrationDeltaPrivate {
    pub paths: Vec<VolumeDetail>,
    pub source_ips: Vec<VolumeDetail>,
}

#[derive(Debug, Serialize)]
pub struct SanitizedTemporalComparison {
    pub report_kind: String,
    pub safety_note: String,
    pub provenance: ComparisonProvenance,
    pub comparability: Comparability,
    pub cve_diff: CveDiff,
    pub first_seen_counts: FirstSeenCounts,
    pub concentration_delta: ConcentrationDeltaSummary,
}
#[derive(Debug, Serialize)]
pub struct PrivateTemporalComparison {
    pub report_kind: String,
    pub safety_note: String,
    pub provenance: ComparisonProvenance,
    pub first_seen_entities: FirstSeenPrivate,
    pub concentration_delta_detail: ConcentrationDeltaPrivate,
}
pub struct TemporalComparison {
    pub sanitized: SanitizedTemporalComparison,
    pub private: PrivateTemporalComparison,
}

#[derive(Debug, Clone)]
struct CveRecord {
    request_count: u64,
    sources: u64,
    ja4: u64,
    gap: Option<f64>,
}
struct RunArtifacts {
    provenance: RunProvenance,
    triage_policy: Option<String>,
    cves: Option<BTreeMap<String, CveRecord>>,
    findings: Option<Vec<FindingExplanation>>,
    concentration: Option<PrivateRequestConcentrationReport>,
}

pub fn compare_runs(baseline_dir: &Path, current_dir: &Path) -> anyhow::Result<TemporalComparison> {
    let baseline = load_run(baseline_dir)?;
    let current = load_run(current_dir)?;
    let provenance = ComparisonProvenance {
        baseline: baseline.provenance.clone(),
        current: current.provenance.clone(),
    };
    let comparability = comparability(&baseline, &current);
    let cve_diff = cve_diff(baseline.cves.as_ref(), current.cves.as_ref());
    let (first_seen_counts, first_seen_entities) =
        first_seen(baseline.findings.as_deref(), current.findings.as_deref());
    let (concentration_delta, concentration_delta_detail) = concentration_delta(
        baseline.concentration.as_ref(),
        current.concentration.as_ref(),
    );
    let safety = safety_note().to_owned();
    Ok(TemporalComparison {
        sanitized: SanitizedTemporalComparison {
            report_kind: "SANITIZED_TEMPORAL_COMPARISON".to_owned(),
            safety_note: safety.clone(),
            provenance: provenance.clone(),
            comparability,
            cve_diff,
            first_seen_counts,
            concentration_delta,
        },
        private: PrivateTemporalComparison {
            report_kind: "TEMPORAL_COMPARISON_PRIVATE".to_owned(),
            safety_note: safety,
            provenance,
            first_seen_entities,
            concentration_delta_detail,
        },
    })
}

pub fn write_comparison(output: &Path, comparison: &TemporalComparison) -> anyhow::Result<()> {
    fs::create_dir_all(output).with_context(|| format!("creating {}", output.display()))?;
    for (name, value) in [
        (
            "comparison-summary.json",
            serde_json::to_value(&comparison.sanitized)?,
        ),
        (
            "comparison-detail.json",
            serde_json::to_value(&comparison.private)?,
        ),
    ] {
        serde_json::to_writer_pretty(File::create(output.join(name))?, &value)?;
    }
    Ok(())
}

fn load_run(dir: &Path) -> anyhow::Result<RunArtifacts> {
    let manifest_path = dir.join("run-manifest.json");
    let manifest = read_json_optional(&manifest_path)?;
    let sanitized_path = dir.join("sanitized-research.json");
    let sanitized = read_json_optional(&sanitized_path)?;
    let private_path = dir.join("private-findings.jsonl");
    let concentration_path = dir.join("request-concentration.json");
    let mut hashes = BTreeMap::new();
    for (name, path) in [
        ("run-manifest.json", &manifest_path),
        ("sanitized-research.json", &sanitized_path),
        ("private-findings.jsonl", &private_path),
        ("request-concentration.json", &concentration_path),
    ] {
        let hash = path.exists().then(|| sha256_file(path)).transpose()?;
        hashes.insert(name.to_owned(), hash);
    }
    let provenance = RunProvenance {
        shenron_version: string_at(manifest.as_ref(), &["shenron_version"]),
        telemetry_profile: string_at(manifest.as_ref(), &["telemetry_profile"])
            .or_else(|| string_at(sanitized.as_ref(), &["telemetry_profile"])),
        nuclei_revision: string_at(manifest.as_ref(), &["nuclei_revision"]),
        filter_from: string_at(manifest.as_ref(), &["hunt_parameters", "filter_from"])
            .or_else(|| string_at(sanitized.as_ref(), &["filter_from"])),
        filter_to: string_at(manifest.as_ref(), &["hunt_parameters", "filter_to"])
            .or_else(|| string_at(sanitized.as_ref(), &["filter_to"])),
        artifacts_sha256: hashes,
    };
    let triage_policy = manifest
        .as_ref()
        .and_then(|value| value.pointer("/hunt_parameters/triage_policy"))
        .map(Value::to_string);
    let cves = sanitized.as_ref().and_then(parse_cves);
    let findings = private_path
        .exists()
        .then(|| explain_private_findings(&private_path))
        .transpose()?;
    let concentration = concentration_path
        .exists()
        .then(|| load_private_concentration(&concentration_path))
        .transpose()?;
    Ok(RunArtifacts {
        provenance,
        triage_policy,
        cves,
        findings,
        concentration,
    })
}

fn read_json_optional(path: &Path) -> anyhow::Result<Option<Value>> {
    if path.exists() {
        Ok(Some(
            serde_json::from_reader(File::open(path)?)
                .with_context(|| format!("reading {}", path.display()))?,
        ))
    } else {
        Ok(None)
    }
}
fn string_at(value: Option<&Value>, path: &[&str]) -> Option<String> {
    path.iter()
        .try_fold(value?, |node, key| node.get(*key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}
fn parse_cves(value: &Value) -> Option<BTreeMap<String, CveRecord>> {
    (value.get("report_kind")?.as_str()? == "SANITIZED_RESEARCH_OUTPUT").then_some(())?;
    let mut result = BTreeMap::new();
    for item in value.get("cve_findings")?.as_array()? {
        let cve = item.get("cve")?.as_str()?.to_owned();
        result.insert(
            cve,
            CveRecord {
                request_count: item
                    .get("request_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                sources: item
                    .get("unique_source_clusters")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                ja4: item
                    .get("unique_ja4_fingerprints")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                gap: item.get("protection_gap_rate").and_then(Value::as_f64),
            },
        );
    }
    Some(result)
}
fn comparability(b: &RunArtifacts, c: &RunArtifacts) -> Comparability {
    let mut reasons = Vec::new();
    if b.provenance.telemetry_profile.is_none() || c.provenance.telemetry_profile.is_none() {
        reasons.push("telemetry_profile is unavailable for one or both runs".to_owned());
    }
    if b.provenance.telemetry_profile != c.provenance.telemetry_profile {
        reasons.push("telemetry_profile differs".to_owned());
    }
    if b.triage_policy.is_none() || c.triage_policy.is_none() {
        reasons.push("triage baseline is unavailable for one or both runs".to_owned());
    }
    if b.triage_policy != c.triage_policy {
        reasons.push("triage baseline differs or is unavailable".to_owned());
    }
    let same_filter = b.provenance.filter_from == c.provenance.filter_from
        && b.provenance.filter_to == c.provenance.filter_to;
    // The structural kind is only meaningful once the runs are comparable; if
    // they are not, the headline is `not-comparable` and `reasons` explains why,
    // so a consumer does not act on a `cti-revision` label across mismatched
    // profiles or triage baselines.
    let kind = if !reasons.is_empty() {
        "not-comparable"
    } else if same_filter && b.provenance.nuclei_revision != c.provenance.nuclei_revision {
        "cti-revision"
    } else if b.provenance.nuclei_revision == c.provenance.nuclei_revision && !same_filter {
        "calendar-window"
    } else {
        "artifact-diff"
    };
    Comparability {
        comparable: reasons.is_empty(),
        kind: kind.to_owned(),
        reasons,
    }
}
fn cve_diff(
    b: Option<&BTreeMap<String, CveRecord>>,
    c: Option<&BTreeMap<String, CveRecord>>,
) -> CveDiff {
    let (Some(b), Some(c)) = (b, c) else {
        return CveDiff {
            available: false,
            reason: Some("sanitized hunt report unavailable for one or both runs".to_owned()),
            newly_observed_cves: vec![],
            disappeared_cves: vec![],
            common_cve_deltas: vec![],
        };
    };
    let newly = c
        .keys()
        .filter(|key| !b.contains_key(*key))
        .cloned()
        .collect();
    let disappeared = b
        .keys()
        .filter(|key| !c.contains_key(*key))
        .cloned()
        .collect();
    let common_cve_deltas = b
        .iter()
        .filter_map(|(cve, left)| {
            c.get(cve).map(|right| CveDelta {
                cve: cve.clone(),
                request_count: num(left.request_count, right.request_count),
                unique_source_clusters: num(left.sources, right.sources),
                unique_ja4_fingerprints: num(left.ja4, right.ja4),
                protection_gap_rate: OptionalRatioDelta {
                    baseline: left.gap,
                    current: right.gap,
                    delta: left.gap.zip(right.gap).map(|(a, b)| b - a),
                },
            })
        })
        .collect();
    CveDiff {
        available: true,
        reason: None,
        newly_observed_cves: newly,
        disappeared_cves: disappeared,
        common_cve_deltas,
    }
}
fn num(b: u64, c: u64) -> NumericDelta {
    NumericDelta {
        baseline: b,
        current: c,
        delta: c as i64 - b as i64,
    }
}
fn values(
    findings: &[FindingExplanation],
    field: fn(&FindingExplanation) -> Option<&String>,
) -> BTreeSet<String> {
    findings.iter().filter_map(field).cloned().collect()
}
fn first_seen(
    b: Option<&[FindingExplanation]>,
    c: Option<&[FindingExplanation]>,
) -> (FirstSeenCounts, FirstSeenPrivate) {
    let Some(b) = b else {
        return unavailable_entities("baseline private-findings.jsonl is unavailable");
    };
    let Some(c) = c else {
        return unavailable_entities("current private-findings.jsonl is unavailable");
    };
    let diff = |field| {
        values(c, field)
            .difference(&values(b, field))
            .cloned()
            .collect::<Vec<_>>()
    };
    let source = diff(|f| f.source_ip.as_ref());
    let hosts = diff(|f| f.host.as_ref());
    let paths = diff(|f| f.uri_path.as_ref());
    let ja4 = diff(|f| f.ja4.as_ref());
    let b_clients = values(b, |f| f.client_ip.as_ref());
    let c_clients = values(c, |f| f.client_ip.as_ref());
    let (client_ips, client_count, unavailable) = if b_clients.is_empty() || c_clients.is_empty() {
        (None,None,vec!["client_ip comparison unavailable because one or both runs have no validated client IPs".to_owned()])
    } else {
        let items = c_clients
            .difference(&b_clients)
            .cloned()
            .collect::<Vec<_>>();
        let count = Some(items.len());
        (Some(items), count, vec![])
    };
    (
        FirstSeenCounts {
            source_ips: source.len(),
            hosts: hosts.len(),
            uri_paths: paths.len(),
            ja4_fingerprints: ja4.len(),
            client_ips: client_count,
        },
        FirstSeenPrivate {
            source_ips: source,
            hosts,
            uri_paths: paths,
            ja4_fingerprints: ja4,
            client_ips,
            unavailable,
        },
    )
}
fn unavailable_entities(reason: &str) -> (FirstSeenCounts, FirstSeenPrivate) {
    (
        FirstSeenCounts::default(),
        FirstSeenPrivate {
            source_ips: vec![],
            hosts: vec![],
            uri_paths: vec![],
            ja4_fingerprints: vec![],
            client_ips: None,
            unavailable: vec![reason.to_owned()],
        },
    )
}
fn concentration_delta(
    b: Option<&PrivateRequestConcentrationReport>,
    c: Option<&PrivateRequestConcentrationReport>,
) -> (ConcentrationDeltaSummary, ConcentrationDeltaPrivate) {
    let (Some(b), Some(c)) = (b, c) else {
        return (
            ConcentrationDeltaSummary {
                available: false,
                reason: Some(
                    "request-concentration.json is unavailable for one or both runs".to_owned(),
                ),
                elevated_paths: 0,
                elevated_source_ips: 0,
                low_baseline_paths: 0,
                low_baseline_source_ips: 0,
                median_rpm_ratio: None,
                median_rpm_elevated: None,
                peak_rpm_delta: None,
                top_ten_paths_share_delta: None,
                top_ten_source_ips_share_delta: None,
            },
            ConcentrationDeltaPrivate {
                paths: vec![],
                source_ips: vec![],
            },
        );
    };
    let paths = volume_details(
        b.paths
            .iter()
            .map(|x| (x.uri_path.clone(), x.summary.requests))
            .collect(),
        c.paths
            .iter()
            .map(|x| (x.uri_path.clone(), x.summary.requests))
            .collect(),
    );
    let sources = volume_details(
        b.source_ips
            .iter()
            .map(|x| (x.source_ip.clone(), x.requests))
            .collect(),
        c.source_ips
            .iter()
            .map(|x| (x.source_ip.clone(), x.requests))
            .collect(),
    );
    let median_rpm_ratio = b
        .summary
        .requests_per_minute
        .median_requests_per_minute
        .zip(c.summary.requests_per_minute.median_requests_per_minute)
        .and_then(|(b, c)| (b != 0.0).then(|| c / b));
    let peak_rpm_delta = b
        .summary
        .requests_per_minute
        .peak_requests_per_minute
        .zip(c.summary.requests_per_minute.peak_requests_per_minute)
        .map(|(b, c)| c as i64 - b as i64);
    (
        ConcentrationDeltaSummary {
            available: true,
            reason: None,
            elevated_paths: paths.iter().filter(|x| x.label == "elevated").count(),
            elevated_source_ips: sources.iter().filter(|x| x.label == "elevated").count(),
            low_baseline_paths: paths.iter().filter(|x| x.label == "low-baseline").count(),
            low_baseline_source_ips: sources.iter().filter(|x| x.label == "low-baseline").count(),
            median_rpm_ratio,
            median_rpm_elevated: median_rpm_ratio.map(|ratio| ratio >= ELEVATED_RATIO),
            peak_rpm_delta,
            top_ten_paths_share_delta: Some(
                c.summary.top_ten_paths_request_share - b.summary.top_ten_paths_request_share,
            ),
            top_ten_source_ips_share_delta: Some(
                c.summary.top_ten_source_ips_request_share
                    - b.summary.top_ten_source_ips_request_share,
            ),
        },
        ConcentrationDeltaPrivate {
            paths,
            source_ips: sources,
        },
    )
}
fn volume_details(b: BTreeMap<String, u64>, c: BTreeMap<String, u64>) -> Vec<VolumeDetail> {
    c.into_iter()
        .map(|(key, current)| match b.get(&key) {
            None => VolumeDetail {
                key,
                baseline_requests: None,
                current_requests: current,
                ratio: None,
                label: "new".to_owned(),
            },
            Some(&baseline) if baseline < MIN_BASELINE_REQUESTS => VolumeDetail {
                key,
                baseline_requests: Some(baseline),
                current_requests: current,
                ratio: None,
                label: "low-baseline".to_owned(),
            },
            Some(&baseline) => {
                let ratio = current as f64 / baseline as f64;
                VolumeDetail {
                    key,
                    baseline_requests: Some(baseline),
                    current_requests: current,
                    ratio: Some(ratio),
                    label: if ratio >= ELEVATED_RATIO {
                        "elevated"
                    } else {
                        "unchanged"
                    }
                    .to_owned(),
                }
            }
        })
        .collect()
}
fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("hashing artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading artifact {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
fn safety_note() -> &'static str {
    "First-seen entities and elevated volume are triage context only. They are not determinations of a denial-of-service attempt, attack, abuse, exploitation, compromise, or attacker identity; new means review, not malicious."
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concentration::{
        PathConcentrationSummary, PrivatePathConcentration, PrivateSourceConcentration,
        RequestConcentrationSummary, RequestRateSummary, StatusClassCounts,
    };
    use crate::{
        nuclei::{Detectability, RequestSpecificity},
        production::FindingSource,
    };
    fn conc(
        paths: Vec<(&str, u64)>,
        sources: Vec<(&str, u64)>,
        median: f64,
    ) -> PrivateRequestConcentrationReport {
        PrivateRequestConcentrationReport {
            report_kind: "REQUEST_CONCENTRATION_PRIVATE".into(),
            safety_note: String::new(),
            summary: RequestConcentrationSummary {
                total_requests: 100,
                distinct_uri_paths: 0,
                distinct_source_ips: 0,
                requests_without_uri_path: 0,
                requests_without_source_ip: 0,
                paths_beyond_tracking_cap: 0,
                source_ips_beyond_tracking_cap: 0,
                source_path_pairs_beyond_tracking_cap: 0,
                top_path: None,
                top_ten_paths_request_share: 0.0,
                top_ten_source_ips_request_share: 0.0,
                requests_per_minute: RequestRateSummary {
                    peak_requests_per_minute: Some(1),
                    median_requests_per_minute: Some(median),
                    peak_to_median_ratio: None,
                    observations_without_timestamp: 0,
                },
                focus: None,
            },
            paths: paths
                .into_iter()
                .map(|(p, n)| PrivatePathConcentration {
                    uri_path: p.into(),
                    summary: PathConcentrationSummary {
                        requests: n,
                        request_share: 0.,
                        distinct_source_ips: 0,
                        response_status_classes: StatusClassCounts::default(),
                        response_bytes: None,
                    },
                })
                .collect(),
            source_ips: sources
                .into_iter()
                .map(|(ip, n)| PrivateSourceConcentration {
                    source_ip: ip.into(),
                    requests: n,
                    most_requested_uri_path: None,
                })
                .collect(),
            focus: None,
        }
    }
    #[test]
    fn concentration_labels_low_baseline_elevated_and_new() {
        let (b, c) = (
            conc(vec![("/low", 10), ("/high", 30)], vec![], 10.),
            conc(vec![("/low", 60), ("/high", 90), ("/new", 2)], vec![], 30.),
        );
        let (s, p) = concentration_delta(Some(&b), Some(&c));
        assert_eq!(s.low_baseline_paths, 1);
        assert_eq!(s.elevated_paths, 1);
        assert_eq!(
            p.paths.iter().find(|x| x.key == "/new").unwrap().label,
            "new"
        );
    }

    fn finding(source_ip: &str, host: &str, path: &str, ja4: &str) -> FindingExplanation {
        FindingExplanation {
            template_id: "template".to_owned(),
            cves: vec!["CVE-2026-0001".to_owned()],
            detectability: Detectability::High,
            request_specificity: RequestSpecificity::RequestSpecific,
            timestamp: None,
            source_ip: Some(source_ip.to_owned()),
            client_ip: None,
            host: Some(host.to_owned()),
            method: None,
            uri_path: Some(path.to_owned()),
            uri_query: None,
            waf_action: None,
            waf_rule_id: None,
            waf_rule_type: None,
            waf_labels: vec![],
            waf_non_terminating_rule_ids: vec![],
            headers: vec![],
            ja3: None,
            ja4: Some(ja4.to_owned()),
            request_id: None,
            log_source: None,
            source: FindingSource::Nuclei,
            rule_title: None,
            sigma_level: None,
        }
    }

    #[test]
    fn diffs_cves_and_first_seen_private_entities() {
        let baseline = BTreeMap::from([(
            "CVE-2026-0001".to_owned(),
            CveRecord {
                request_count: 2,
                sources: 1,
                ja4: 1,
                gap: Some(0.5),
            },
        )]);
        let current = BTreeMap::from([
            (
                "CVE-2026-0001".to_owned(),
                CveRecord {
                    request_count: 5,
                    sources: 2,
                    ja4: 2,
                    gap: Some(0.75),
                },
            ),
            (
                "CVE-2026-0002".to_owned(),
                CveRecord {
                    request_count: 1,
                    sources: 1,
                    ja4: 0,
                    gap: None,
                },
            ),
        ]);
        let cves = cve_diff(Some(&baseline), Some(&current));
        assert_eq!(cves.newly_observed_cves, ["CVE-2026-0002"]);
        assert_eq!(cves.common_cve_deltas[0].request_count.delta, 3);
        let (counts, private) = first_seen(
            Some(&[finding("198.51.100.1", "old.example", "/old", "old-ja4")]),
            Some(&[
                finding("198.51.100.1", "old.example", "/old", "old-ja4"),
                finding("198.51.100.2", "new.example", "/new", "new-ja4"),
            ]),
        );
        assert_eq!(counts.source_ips, 1);
        assert_eq!(counts.hosts, 1);
        assert_eq!(counts.uri_paths, 1);
        assert_eq!(private.source_ips, ["198.51.100.2"]);
    }

    #[test]
    fn labels_cti_revision_when_comparable_and_not_comparable_on_profile_mismatch() {
        let run = |profile: &str, revision: &str| RunArtifacts {
            provenance: RunProvenance {
                shenron_version: None,
                telemetry_profile: Some(profile.to_owned()),
                nuclei_revision: Some(revision.to_owned()),
                filter_from: Some("2026-01-01T00:00:00Z".to_owned()),
                filter_to: Some("2026-01-02T00:00:00Z".to_owned()),
                artifacts_sha256: BTreeMap::new(),
            },
            triage_policy: Some("default".to_owned()),
            cves: None,
            findings: None,
            concentration: None,
        };
        // Same profile and triage baseline, same time window, different Nuclei
        // revision: comparable, and labeled as a retro-hunt (CTI-revision) diff.
        let cti = comparability(&run("aws-waf", "one"), &run("aws-waf", "two"));
        assert!(cti.comparable);
        assert_eq!(cti.kind, "cti-revision");

        // Different telemetry profiles: not comparable, so the headline is
        // `not-comparable` (never `cti-revision`) and the reason is disclosed.
        let mismatch = comparability(&run("aws-waf", "one"), &run("apache-combined", "two"));
        assert!(!mismatch.comparable);
        assert_eq!(mismatch.kind, "not-comparable");
        assert!(mismatch
            .reasons
            .iter()
            .any(|reason| reason.contains("telemetry_profile")));
    }
}
