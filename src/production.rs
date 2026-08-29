//! Read-only local production AWS WAF inspection and validated Nuclei hunts.
//!
//! Raw inputs are streamed without modification. Private findings are written
//! separately from a sanitized aggregate report and are never uploaded.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::{
    access_log::{AccessLogFormat, AccessLogLines},
    event::{HttpHeader, TelemetryProfile, TrustedProxySet, WebEvent},
    nuclei::{
        frozen_nuclei_selection, validated_detections, Detectability, RequestSpecificity,
        ValidatedNucleiDetection,
    },
    waf::{maybe_gzip_reader, WafLines},
};

#[derive(Debug, Default, Serialize)]
pub struct FieldAvailability {
    pub client_ip: usize,
    pub ja4: usize,
    pub ja3: usize,
    pub uri: usize,
    pub query: usize,
    pub headers: usize,
    pub host: usize,
    pub method: usize,
    pub waf_action: usize,
    pub waf_labels: usize,
    pub terminating_rule_id: usize,
    pub non_terminating_rules: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct InspectionReport {
    pub telemetry_profile: TelemetryProfile,
    pub telemetry_capabilities: crate::event::TelemetryCapabilities,
    pub files_found: usize,
    pub compressed_files: usize,
    pub approximate_input_bytes: u64,
    pub sampled_events: usize,
    pub malformed_events: usize,
    pub earliest_timestamp: Option<String>,
    pub latest_timestamp: Option<String>,
    pub fields_available: FieldAvailability,
}

#[derive(Debug, Deserialize)]
struct KevReportInput {
    entries: Vec<KevRecord>,
}

#[derive(Debug, Deserialize)]
struct KevRecord {
    cve: String,
}

#[derive(Debug, Default, Serialize)]
pub struct HuntMetrics {
    pub waf_outcome_available: bool,
    pub filter_from: Option<String>,
    pub filter_to: Option<String>,
    pub files_analyzed: usize,
    pub total_requests_analyzed: usize,
    pub requests_outside_time_range: usize,
    pub requests_without_timestamp_excluded: usize,
    pub parse_errors: usize,
    pub earliest_timestamp: Option<String>,
    pub latest_timestamp: Option<String>,
    pub cve_related_request_matches: usize,
    pub request_specific_matches: usize,
    pub response_unverified_matches: usize,
    pub unique_cves_observed: usize,
    pub unique_cisa_kevs_observed: usize,
    pub unique_source_clusters: usize,
    pub unique_ja4_fingerprints: usize,
    pub high_confidence_findings: usize,
    pub medium_confidence_findings: usize,
    pub low_confidence_findings: usize,
    pub blocked: usize,
    pub allowed_or_not_blocked: usize,
    pub count_related_evidence: usize,
    pub unknown_outcome: usize,
}

/// Inclusive UTC interval applied before matching. Events without a timestamp
/// cannot be placed in an explicitly requested interval and are excluded.
#[derive(Debug, Clone, Default)]
pub struct HuntTimeRange {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

impl HuntTimeRange {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.from.zip(self.to).is_some_and(|(from, to)| from > to) {
            bail!("--from must be earlier than or equal to --to");
        }
        Ok(())
    }

    fn includes(&self, timestamp: Option<DateTime<Utc>>) -> bool {
        let Some(timestamp) = timestamp else {
            return self.from.is_none() && self.to.is_none();
        };
        self.from.is_none_or(|from| timestamp >= from) && self.to.is_none_or(|to| timestamp <= to)
    }
}

/// Immutable hunt settings independent of the original log format. Forwarded
/// client resolution remains disabled unless trusted proxies are supplied.
#[derive(Debug, Clone, Default)]
pub struct HuntOptions {
    pub time_range: HuntTimeRange,
    pub trusted_proxies: TrustedProxySet,
    pub triage_policy: HuntTriagePolicy,
}

/// The fixed baseline triage policy recorded with a hunt. Triage itself runs
/// later in `production explain`; this metadata fixes the baseline used for
/// reproducibility without asserting anything about attack attribution.
#[derive(Debug, Clone, Serialize)]
pub struct HuntTriagePolicy {
    pub kind: String,
    pub breadth_observations: usize,
    pub breadth_templates: usize,
    pub depth_observations: usize,
    pub window: Option<String>,
}

impl Default for HuntTriagePolicy {
    fn default() -> Self {
        Self {
            kind: "default-fixed-baseline".to_owned(),
            breadth_observations: 3,
            breadth_templates: 2,
            depth_observations: 10,
            window: None,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct OutcomeCounts {
    pub blocked: usize,
    pub allowed_or_not_blocked: usize,
    pub count_related_evidence: usize,
    pub unknown: usize,
}

#[derive(Debug, Serialize)]
pub struct SanitizedCveFinding {
    pub cve: String,
    pub cisa_kev: bool,
    pub detectability: Detectability,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub request_count: usize,
    pub unique_source_clusters: usize,
    pub unique_ja4_fingerprints: usize,
    pub unique_hosts: usize,
    /// Response status is triage context only, never proof of compromise.
    pub response_status_counts: BTreeMap<u16, usize>,
    pub outcomes: OutcomeCounts,
    pub protection_gap_rate: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct SanitizedHuntReport {
    pub report_kind: String,
    pub safety_note: String,
    pub metrics: HuntMetrics,
    pub cve_findings: Vec<SanitizedCveFinding>,
}

/// Aggregate-only comparison of match volume for predicates derived from one
/// validated Nuclei Detection IR. These figures are not precision, ground
/// truth, or attack/exploitation/compromise determinations.
#[derive(Debug, Serialize)]
pub struct AblationReport {
    pub report_kind: String,
    pub safety_note: String,
    pub telemetry_profile: TelemetryProfile,
    pub filter_from: Option<String>,
    pub filter_to: Option<String>,
    pub files_analyzed: usize,
    pub total_events_evaluated: usize,
    pub requests_outside_time_range: usize,
    pub requests_without_timestamp_excluded: usize,
    pub parse_errors: usize,
    pub strategies: Vec<AblationStrategyVolume>,
    /// Behavior-triage volume is intentionally deferred because its current
    /// implementation is CLI-local rather than shared Detection IR logic.
    pub deferred_strategy: String,
}

/// `matched_event_volume_rate` is matched events divided by all evaluated
/// events. It is an alert-volume ratio only, never an accuracy metric.
#[derive(Debug, Serialize)]
pub struct AblationStrategyVolume {
    pub strategy: String,
    pub matched_events: usize,
    pub matched_event_volume_rate: Option<f64>,
    pub distinct_event_cve_matches: usize,
}

#[derive(Default)]
struct AblationAccumulator {
    matched_events: usize,
    distinct_event_cve_matches: usize,
}

/// Sanitized, read-only measurement of validated Nuclei matcher replay against
/// a complete local historical corpus. It is separate from candidate replay:
/// this report never creates an enforcement artifact.
#[derive(Debug, Serialize)]
pub struct HistoricalReplayReport {
    pub report_kind: String,
    pub safety_note: String,
    pub telemetry_profile: TelemetryProfile,
    pub filter_from: Option<String>,
    pub filter_to: Option<String>,
    pub files_analyzed: usize,
    pub total_events_evaluated: usize,
    pub requests_outside_time_range: usize,
    pub requests_without_timestamp_excluded: usize,
    pub parse_errors: usize,
    pub inputs: ReplayInputs,
    pub per_cve: Vec<CveCoverage>,
    pub aggregate: CoverageAggregate,
}

/// Content hashes of frozen local replay inputs. These hashes contain no
/// telemetry values and make a reviewable replay reproducible.
#[derive(Debug, Serialize)]
pub struct ReplayInputs {
    pub nuclei_report_sha256: Option<String>,
    pub kev_report_sha256: Option<String>,
    pub findings_sha256: Option<String>,
}

/// Per-CVE conservative source-finding re-observation and aggregate-only
/// historical match counts.
#[derive(Debug, Serialize)]
pub struct CveCoverage {
    pub cve: String,
    pub is_kev: bool,
    pub known_findings: u64,
    pub known_matched: u64,
    pub known_missed: u64,
    pub coverage: Option<f64>,
    pub other_matches_with_request_id: u64,
    pub other_matches_without_request_id: u64,
    pub matched_events_blocked: u64,
    pub matched_events_not_blocked: u64,
    pub matched_events_unknown_outcome: u64,
}

/// CVE-crossing replay totals. `known_findings` counts distinct source finding
/// records, even when one finding references multiple CVEs; per-CVE
/// `known_findings` instead counts findings that reference that CVE. Each
/// matched historical event contributes at most once to `matched_events_total`,
/// other-match counts, and outcomes.
#[derive(Debug, Serialize)]
pub struct CoverageAggregate {
    pub known_findings: u64,
    pub known_matched: u64,
    pub known_missed: u64,
    pub coverage: Option<f64>,
    pub matched_events_total: u64,
    pub other_matches_with_request_id: u64,
    pub other_matches_without_request_id: u64,
    pub matched_events_blocked: u64,
    pub matched_events_not_blocked: u64,
    pub matched_events_unknown_outcome: u64,
}

#[derive(Default)]
struct ReplayCveAccumulator {
    known_findings: u64,
    known_request_ids: BTreeSet<String>,
    known_matched_request_ids: BTreeSet<String>,
    other_matches_with_request_id: u64,
    other_matches_without_request_id: u64,
    outcomes: ReplayOutcomeCounts,
}

#[derive(Default)]
struct ReplayOutcomeCounts {
    blocked: u64,
    not_blocked: u64,
    unknown: u64,
}

#[derive(Serialize)]
struct RunManifest {
    report_kind: &'static str,
    safety_note: &'static str,
    shenron_version: &'static str,
    generated_at: String,
    telemetry_profile: TelemetryProfile,
    nuclei_revision: Option<String>,
    inputs: RunManifestInputs,
    hunt_parameters: RunManifestParameters,
    exclusions: RunManifestExclusions,
}

#[derive(Serialize)]
struct RunManifestInputs {
    nuclei_templates: PathProvenance,
    nuclei_report: PathProvenance,
    kev_report: PathProvenance,
    approved_validated_template_count: usize,
}

#[derive(Serialize)]
struct PathProvenance {
    path: String,
    byte_length: Option<u64>,
    sha256: Option<String>,
}

#[derive(Serialize)]
struct RunManifestParameters {
    filter_from: Option<String>,
    filter_to: Option<String>,
    trusted_proxy_networks: Vec<String>,
    triage_policy: HuntTriagePolicy,
}

#[derive(Serialize)]
struct RunManifestExclusions {
    generic_root_probe_request_evidence: &'static str,
    requests_outside_time_range: usize,
    requests_without_timestamp_excluded: usize,
    parse_errors: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct PrivateFinding {
    template_id: String,
    cves: Vec<String>,
    detectability: Detectability,
    #[serde(default)]
    request_specificity: RequestSpecificity,
    timestamp: Option<String>,
    source_ip: Option<String>,
    #[serde(default)]
    client_ip: Option<String>,
    host: Option<String>,
    method: Option<String>,
    uri_path: Option<String>,
    uri_query: Option<String>,
    headers: Vec<HttpHeader>,
    ja3: Option<String>,
    ja4: Option<String>,
    waf_action: Option<String>,
    #[serde(default)]
    waf_rule_id: Option<String>,
    #[serde(default)]
    waf_rule_type: Option<String>,
    #[serde(default)]
    waf_labels: Vec<String>,
    #[serde(default)]
    waf_non_terminating_rule_ids: Vec<String>,
    request_id: Option<String>,
}

/// A terminal-safe view of private hunt evidence. The CLI keeps private
/// attributes hidden unless the analyst explicitly opts in.
#[derive(Debug)]
pub struct FindingExplanation {
    pub template_id: String,
    pub cves: Vec<String>,
    pub detectability: Detectability,
    pub request_specificity: RequestSpecificity,
    pub timestamp: Option<String>,
    pub source_ip: Option<String>,
    pub client_ip: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub uri_path: Option<String>,
    pub uri_query: Option<String>,
    pub waf_action: Option<String>,
    pub waf_rule_id: Option<String>,
    pub waf_rule_type: Option<String>,
    pub waf_labels: Vec<String>,
    pub waf_non_terminating_rule_ids: Vec<String>,
    pub headers: Vec<HttpHeader>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub request_id: Option<String>,
}

pub fn explain_private_findings(path: &Path) -> anyhow::Result<Vec<FindingExplanation>> {
    let reader = BufReader::new(
        File::open(path).with_context(|| format!("opening private findings {}", path.display()))?,
    );
    let mut findings = Vec::new();
    for (line_number, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let finding: PrivateFinding = serde_json::from_str(&line).with_context(|| {
            format!(
                "parsing private finding {} at line {}",
                path.display(),
                line_number + 1
            )
        })?;
        findings.push(FindingExplanation {
            template_id: finding.template_id,
            cves: finding.cves,
            detectability: finding.detectability,
            request_specificity: finding.request_specificity,
            timestamp: finding.timestamp,
            source_ip: finding.source_ip,
            client_ip: finding.client_ip,
            host: finding.host,
            method: finding.method,
            uri_path: finding.uri_path,
            uri_query: finding.uri_query,
            waf_action: finding.waf_action,
            waf_rule_id: finding.waf_rule_id,
            waf_rule_type: finding.waf_rule_type,
            waf_labels: finding.waf_labels,
            waf_non_terminating_rule_ids: finding.waf_non_terminating_rule_ids,
            headers: finding.headers,
            ja3: finding.ja3,
            ja4: finding.ja4,
            request_id: finding.request_id,
        });
    }
    Ok(findings)
}

pub fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

#[derive(Debug, Default)]
struct CveAccumulator {
    kev: bool,
    detectability: Detectability,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    requests: usize,
    source_ips: BTreeSet<String>,
    ja4s: BTreeSet<String>,
    hosts: BTreeSet<String>,
    response_status_counts: BTreeMap<u16, usize>,
    outcomes: OutcomeCounts,
}

pub fn inspect(
    input: &Path,
    telemetry_profile: TelemetryProfile,
    sample_limit: usize,
) -> anyhow::Result<InspectionReport> {
    inspect_with_trusted_proxies(
        input,
        telemetry_profile,
        sample_limit,
        &TrustedProxySet::default(),
    )
}

pub fn inspect_with_trusted_proxies(
    input: &Path,
    telemetry_profile: TelemetryProfile,
    sample_limit: usize,
    trusted_proxies: &TrustedProxySet,
) -> anyhow::Result<InspectionReport> {
    let files = input_files(input, telemetry_profile)?;
    let mut report = InspectionReport {
        telemetry_profile,
        telemetry_capabilities: telemetry_profile.capabilities(),
        files_found: files.len(),
        compressed_files: files.iter().filter(|path| is_gzip(path)).count(),
        approximate_input_bytes: files
            .iter()
            .filter_map(|path| fs::metadata(path).ok().map(|metadata| metadata.len()))
            .sum(),
        ..InspectionReport::default()
    };
    for path in files {
        if report.sampled_events >= sample_limit {
            break;
        }
        stream_events_with_trusted_proxies(&path, telemetry_profile, trusted_proxies, |result| {
            if report.sampled_events >= sample_limit {
                return Ok(());
            }
            match result {
                Ok(event) => {
                    report.sampled_events += 1;
                    record_availability(&mut report.fields_available, &event);
                    update_time_range(
                        &mut report.earliest_timestamp,
                        &mut report.latest_timestamp,
                        event.timestamp,
                    );
                }
                Err(_) => report.malformed_events += 1,
            }
            Ok(())
        })?;
    }
    Ok(report)
}

pub fn hunt(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: &Path,
    output: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: HuntTimeRange,
) -> anyhow::Result<SanitizedHuntReport> {
    hunt_with_options(
        input,
        nuclei_templates,
        nuclei_report,
        kev_report,
        output,
        telemetry_profile,
        HuntOptions {
            time_range,
            trusted_proxies: TrustedProxySet::default(),
            triage_policy: HuntTriagePolicy::default(),
        },
    )
}

pub fn hunt_with_options(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: &Path,
    output: &Path,
    telemetry_profile: TelemetryProfile,
    options: HuntOptions,
) -> anyhow::Result<SanitizedHuntReport> {
    let HuntOptions {
        time_range,
        trusted_proxies,
        triage_policy,
    } = options;
    time_range.validate()?;
    ensure_separate_output(input, output)?;
    let (approved_templates, nuclei_revision) = approved_template_ids(nuclei_report)?;
    let detections = validated_detections(nuclei_templates, &approved_templates);
    if detections.is_empty() {
        bail!("no validated Nuclei detections could be rebuilt from the supplied report and template checkout");
    }
    let kev_cves = kev_cves(kev_report)?;
    let files = input_files(input, telemetry_profile)?;
    fs::create_dir_all(output)
        .with_context(|| format!("creating private output directory {}", output.display()))?;
    let private_path = output.join("private-findings.jsonl");
    let mut private = BufWriter::new(
        File::create(&private_path)
            .with_context(|| format!("creating {}", private_path.display()))?,
    );
    let mut metrics = HuntMetrics {
        files_analyzed: files.len(),
        waf_outcome_available: telemetry_profile == TelemetryProfile::AwsWaf,
        filter_from: time_range.from.map(|time| time.to_rfc3339()),
        filter_to: time_range.to.map(|time| time.to_rfc3339()),
        ..HuntMetrics::default()
    };
    let mut cves = BTreeMap::<String, CveAccumulator>::new();
    let mut all_sources = BTreeSet::new();
    let mut all_ja4s = BTreeSet::new();
    for path in files {
        stream_events_with_trusted_proxies(&path, telemetry_profile, &trusted_proxies, |result| {
            let event = match result {
                Ok(event) => event,
                Err(_) => {
                    metrics.parse_errors += 1;
                    return Ok(());
                }
            };
            if !time_range.includes(event.timestamp) {
                if event.timestamp.is_some() {
                    metrics.requests_outside_time_range += 1;
                } else {
                    metrics.requests_without_timestamp_excluded += 1;
                }
                return Ok(());
            }
            metrics.total_requests_analyzed += 1;
            update_time_range(
                &mut metrics.earliest_timestamp,
                &mut metrics.latest_timestamp,
                event.timestamp,
            );
            let matches = matching_templates(&detections, &event);
            if matches.is_empty() {
                return Ok(());
            }
            for detection in &matches {
                serde_json::to_writer(&mut private, &private_finding(detection, &event))?;
                private.write_all(b"\n")?;
            }
            let mut observed_cves = BTreeMap::<String, (Detectability, RequestSpecificity)>::new();
            for detection in &matches {
                for cve in &detection.cves {
                    observed_cves
                        .entry(cve.clone())
                        .and_modify(|current| {
                            current.0 = strongest(current.0, detection.detectability);
                            current.1 =
                                strongest_specificity(current.1, detection.request_specificity());
                        })
                        .or_insert((detection.detectability, detection.request_specificity()));
                }
            }
            for (cve, (detectability, request_specificity)) in observed_cves {
                metrics.cve_related_request_matches += 1;
                match request_specificity {
                    RequestSpecificity::RequestSpecific => metrics.request_specific_matches += 1,
                    RequestSpecificity::ResponseUnverified => {
                        metrics.response_unverified_matches += 1
                    }
                }
                match detectability {
                    Detectability::High => metrics.high_confidence_findings += 1,
                    Detectability::Medium => metrics.medium_confidence_findings += 1,
                    Detectability::Low => metrics.low_confidence_findings += 1,
                    Detectability::Undetectable | Detectability::Unknown => {}
                }
                let accumulator = cves.entry(cve.clone()).or_default();
                accumulator.kev = kev_cves.contains(&cve);
                accumulator.detectability = strongest(accumulator.detectability, detectability);
                accumulator.requests += 1;
                update_accumulator_time(accumulator, event.timestamp);
                if let Some(value) = &event.source_ip {
                    all_sources.insert(value.clone());
                    accumulator.source_ips.insert(value.clone());
                }
                if let Some(value) = &event.ja4 {
                    all_ja4s.insert(value.clone());
                    accumulator.ja4s.insert(value.clone());
                }
                if let Some(value) = &event.host {
                    accumulator.hosts.insert(value.clone());
                }
                if let Some(status) = event.status {
                    *accumulator
                        .response_status_counts
                        .entry(status)
                        .or_default() += 1;
                }
                if metrics.waf_outcome_available {
                    record_outcome(&mut accumulator.outcomes, &event);
                }
            }
            Ok(())
        })?;
    }
    private.flush()?;
    metrics.unique_cves_observed = cves.len();
    metrics.unique_cisa_kevs_observed = cves.values().filter(|item| item.kev).count();
    metrics.unique_source_clusters = all_sources.len();
    metrics.unique_ja4_fingerprints = all_ja4s.len();
    for item in cves.values() {
        metrics.blocked += item.outcomes.blocked;
        metrics.allowed_or_not_blocked += item.outcomes.allowed_or_not_blocked;
        metrics.count_related_evidence += item.outcomes.count_related_evidence;
        metrics.unknown_outcome += item.outcomes.unknown;
    }
    let cve_findings = cves
        .into_iter()
        .map(|(cve, item)| {
            let known_outcomes = item.outcomes.blocked + item.outcomes.allowed_or_not_blocked;
            let protection_gap_rate = (known_outcomes != 0)
                .then(|| item.outcomes.allowed_or_not_blocked as f64 / known_outcomes as f64);
            SanitizedCveFinding {
                cve,
                cisa_kev: item.kev,
                detectability: item.detectability,
                first_seen: item.first_seen.map(|time| time.to_rfc3339()),
                last_seen: item.last_seen.map(|time| time.to_rfc3339()),
                request_count: item.requests,
                unique_source_clusters: item.source_ips.len(),
                unique_ja4_fingerprints: item.ja4s.len(),
                unique_hosts: item.hosts.len(),
                response_status_counts: item.response_status_counts,
                outcomes: item.outcomes,
                protection_gap_rate,
            }
        })
        .collect();
    let report = SanitizedHuntReport {
        report_kind: "SANITIZED_RESEARCH_OUTPUT".to_owned(),
        safety_note: if metrics.waf_outcome_available { "A protection gap means only that a CVE-related request match was not blocked according to available AWS WAF action evidence; it does not establish exploitation success." } else { "WAF outcome is unavailable for this telemetry source, so no protection-gap rate is calculated." }.to_owned() + " No raw request values, source IPs, hostnames, JA3, JA4, or headers are included here.",
        metrics,
        cve_findings,
    };
    write_run_manifest(
        output,
        telemetry_profile,
        nuclei_templates,
        nuclei_report,
        kev_report,
        nuclei_revision,
        approved_templates.len(),
        &time_range,
        &trusted_proxies,
        triage_policy,
        &report.metrics,
    )?;
    Ok(report)
}

/// Compare aggregate match volume among predicates derived from the same
/// validated Detection IR. No private findings or raw event values are written.
pub fn ablation(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: HuntTimeRange,
) -> anyhow::Result<AblationReport> {
    time_range.validate()?;
    let (approved_templates, _) = approved_template_ids(nuclei_report)?;
    let detections = validated_detections(nuclei_templates, &approved_templates);
    if detections.is_empty() {
        bail!("no validated Nuclei detections could be rebuilt from the supplied report and template checkout");
    }
    // Keep the same frozen-report input contract as hunt even though KEV
    // membership is not a volume-comparison dimension.
    let _kev_cves = kev_cves(kev_report)?;
    let files = input_files(input, telemetry_profile)?;
    let mut total_events_evaluated = 0;
    let mut requests_outside_time_range = 0;
    let mut requests_without_timestamp_excluded = 0;
    let mut parse_errors = 0;
    let mut accumulators = std::array::from_fn::<_, 5, _>(|_| AblationAccumulator::default());
    for path in &files {
        stream_events(path, telemetry_profile, |result| {
            let event = match result {
                Ok(event) => event,
                Err(_) => {
                    parse_errors += 1;
                    return Ok(());
                }
            };
            if !time_range.includes(event.timestamp) {
                if event.timestamp.is_some() {
                    requests_outside_time_range += 1;
                } else {
                    requests_without_timestamp_excluded += 1;
                }
                return Ok(());
            }
            total_events_evaluated += 1;
            let mut event_cves = std::array::from_fn::<_, 5, _>(|_| BTreeSet::new());
            for detection in &detections {
                let matches = [
                    detection.matches_path_only(&event),
                    detection.matches_path_and_query(&event),
                    detection.matches_path_query_headers(&event),
                    detection.matches(&event),
                    detection.matches(&event)
                        && detection.request_specificity() == RequestSpecificity::RequestSpecific,
                ];
                for (index, matched) in matches.into_iter().enumerate() {
                    if matched {
                        event_cves[index].extend(detection.cves.iter().cloned());
                    }
                }
            }
            for (accumulator, cves) in accumulators.iter_mut().zip(event_cves) {
                if !cves.is_empty() {
                    accumulator.matched_events += 1;
                    accumulator.distinct_event_cve_matches += cves.len();
                }
            }
            Ok(())
        })?;
    }
    let strategy_names = [
        "path_only",
        "path_and_query",
        "path_query_headers",
        "nuclei_ir",
        "nuclei_ir_request_specific",
    ];
    let strategies = strategy_names
        .into_iter()
        .zip(accumulators)
        .map(|(strategy, accumulator)| AblationStrategyVolume {
            strategy: strategy.to_owned(),
            matched_events: accumulator.matched_events,
            matched_event_volume_rate: (total_events_evaluated != 0)
                .then(|| accumulator.matched_events as f64 / total_events_evaluated as f64),
            distinct_event_cve_matches: accumulator.distinct_event_cve_matches,
        })
        .collect();
    Ok(AblationReport {
        report_kind: "ABLATION_VOLUME_COMPARISON".to_owned(),
        safety_note: "Aggregate match-volume comparison only. A volume rate is matched events divided by total events evaluated; it is not precision, recall, accuracy, ground truth, or an attack/exploitation/compromise determination. No private findings or raw telemetry values are included.".to_owned(),
        telemetry_profile,
        filter_from: time_range.from.map(|timestamp| timestamp.to_rfc3339()),
        filter_to: time_range.to.map(|timestamp| timestamp.to_rfc3339()),
        files_analyzed: files.len(),
        total_events_evaluated,
        requests_outside_time_range,
        requests_without_timestamp_excluded,
        parse_errors,
        strategies,
        deferred_strategy: "nuclei_ir_behavior_triaged (TODO: behavior-triage volume requires shared library logic)".to_owned(),
    })
}

/// Replay all validated Nuclei request matchers over local historical telemetry
/// and return a sanitized measurement report. This performs no network access,
/// writes no private findings, and never deploys a control.
pub fn historical_replay(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: &Path,
    findings: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: HuntTimeRange,
) -> anyhow::Result<HistoricalReplayReport> {
    time_range.validate()?;
    let (approved_templates, _) = approved_template_ids(nuclei_report)?;
    let detections = validated_detections(nuclei_templates, &approved_templates);
    if detections.is_empty() {
        bail!("no validated Nuclei detections could be rebuilt from the supplied report and template checkout");
    }
    let kev_cves = kev_cves(kev_report)?;
    let source_findings = explain_private_findings(findings)?;
    let known_findings_total = source_findings.len() as u64;
    let mut per_cve = BTreeMap::<String, ReplayCveAccumulator>::new();
    let mut known_source_request_ids = BTreeSet::new();
    for finding in source_findings {
        for cve in finding.cves {
            let accumulator = per_cve.entry(cve).or_default();
            accumulator.known_findings += 1;
            if let Some(request_id) = &finding.request_id {
                accumulator.known_request_ids.insert(request_id.clone());
                known_source_request_ids.insert(request_id.clone());
            }
        }
    }

    let files = input_files(input, telemetry_profile)?;
    let mut total_events_evaluated = 0;
    let mut requests_outside_time_range = 0;
    let mut requests_without_timestamp_excluded = 0;
    let mut parse_errors = 0;
    let mut matched_events_total = 0_u64;
    let mut aggregate_other_matches_with_request_id = 0_u64;
    let mut aggregate_other_matches_without_request_id = 0_u64;
    let mut aggregate_outcomes = ReplayOutcomeCounts::default();
    let mut aggregate_known_matched_request_ids = BTreeSet::new();

    for path in &files {
        stream_events(path, telemetry_profile, |result| {
            let event = match result {
                Ok(event) => event,
                Err(_) => {
                    parse_errors += 1;
                    return Ok(());
                }
            };
            if !time_range.includes(event.timestamp) {
                if event.timestamp.is_some() {
                    requests_outside_time_range += 1;
                } else {
                    requests_without_timestamp_excluded += 1;
                }
                return Ok(());
            }
            total_events_evaluated += 1;
            let matched_cves = matching_templates(&detections, &event)
                .into_iter()
                .flat_map(|detection| detection.cves.iter().cloned())
                .collect::<BTreeSet<_>>();
            if matched_cves.is_empty() {
                return Ok(());
            }

            matched_events_total += 1;
            record_replay_outcome(&mut aggregate_outcomes, &event);
            let request_id = event.request_id.as_deref();
            let mut matched_known_for_any_cve = false;
            for cve in matched_cves {
                let accumulator = per_cve.entry(cve).or_default();
                let known_match = request_id
                    .is_some_and(|request_id| accumulator.known_request_ids.contains(request_id));
                if known_match {
                    let request_id = request_id.expect("known_match requires a request ID");
                    accumulator
                        .known_matched_request_ids
                        .insert(request_id.to_owned());
                    aggregate_known_matched_request_ids.insert(request_id.to_owned());
                    matched_known_for_any_cve = true;
                } else if request_id.is_some() {
                    accumulator.other_matches_with_request_id += 1;
                } else {
                    accumulator.other_matches_without_request_id += 1;
                }
                record_replay_outcome(&mut accumulator.outcomes, &event);
            }
            if !matched_known_for_any_cve {
                if request_id.is_some() {
                    aggregate_other_matches_with_request_id += 1;
                } else {
                    aggregate_other_matches_without_request_id += 1;
                }
            }
            Ok(())
        })?;
    }

    let mut cve_coverage = per_cve
        .into_iter()
        .map(|(cve, accumulator)| {
            let known_matched = accumulator.known_matched_request_ids.len() as u64;
            let coverage = (!accumulator.known_request_ids.is_empty())
                .then(|| known_matched as f64 / accumulator.known_findings as f64);
            CveCoverage {
                is_kev: kev_cves.contains(&cve),
                cve,
                known_findings: accumulator.known_findings,
                known_matched,
                known_missed: accumulator.known_findings.saturating_sub(known_matched),
                coverage,
                other_matches_with_request_id: accumulator.other_matches_with_request_id,
                other_matches_without_request_id: accumulator.other_matches_without_request_id,
                matched_events_blocked: accumulator.outcomes.blocked,
                matched_events_not_blocked: accumulator.outcomes.not_blocked,
                matched_events_unknown_outcome: accumulator.outcomes.unknown,
            }
        })
        .collect::<Vec<_>>();
    cve_coverage.sort_by(|left, right| {
        right
            .known_findings
            .cmp(&left.known_findings)
            .then_with(|| left.cve.cmp(&right.cve))
    });

    let known_matched = aggregate_known_matched_request_ids.len() as u64;
    let aggregate = CoverageAggregate {
        known_findings: known_findings_total,
        known_matched,
        known_missed: known_findings_total.saturating_sub(known_matched),
        coverage: (!known_source_request_ids.is_empty())
            .then(|| known_matched as f64 / known_findings_total as f64),
        matched_events_total,
        other_matches_with_request_id: aggregate_other_matches_with_request_id,
        other_matches_without_request_id: aggregate_other_matches_without_request_id,
        matched_events_blocked: aggregate_outcomes.blocked,
        matched_events_not_blocked: aggregate_outcomes.not_blocked,
        matched_events_unknown_outcome: aggregate_outcomes.unknown,
    };

    Ok(HistoricalReplayReport {
        report_kind: "HISTORICAL_REPLAY_COVERAGE".to_owned(),
        safety_note: "Coverage is a conservative lower bound based only on re-observed source-finding request IDs; it is not precision, recall, accuracy, ground truth, or an attack, exploitation, or compromise determination. Other matches may represent additional attempts or accidental matches and require human review. No raw request values, IP addresses, hostnames, headers, or request IDs are included.".to_owned(),
        telemetry_profile,
        filter_from: time_range.from.map(|timestamp| timestamp.to_rfc3339()),
        filter_to: time_range.to.map(|timestamp| timestamp.to_rfc3339()),
        files_analyzed: files.len(),
        total_events_evaluated,
        requests_outside_time_range,
        requests_without_timestamp_excluded,
        parse_errors,
        inputs: ReplayInputs {
            nuclei_report_sha256: sha256_file(nuclei_report),
            kev_report_sha256: sha256_file(kev_report),
            findings_sha256: sha256_file(findings),
        },
        per_cve: cve_coverage,
        aggregate,
    })
}

fn record_replay_outcome(outcomes: &mut ReplayOutcomeCounts, event: &WebEvent) {
    match event
        .waf_action
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("BLOCK") => outcomes.blocked += 1,
        Some("ALLOW") | Some("COUNT") => outcomes.not_blocked += 1,
        _ => outcomes.unknown += 1,
    }
}

fn approved_template_ids(path: &Path) -> anyhow::Result<(BTreeSet<String>, Option<String>)> {
    let selection = frozen_nuclei_selection(path)?;
    Ok((selection.template_ids, selection.nuclei_revision))
}

#[allow(clippy::too_many_arguments)]
fn write_run_manifest(
    output: &Path,
    telemetry_profile: TelemetryProfile,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: &Path,
    nuclei_revision: Option<String>,
    approved_validated_template_count: usize,
    time_range: &HuntTimeRange,
    trusted_proxies: &TrustedProxySet,
    triage_policy: HuntTriagePolicy,
    metrics: &HuntMetrics,
) -> anyhow::Result<()> {
    let manifest = RunManifest {
        report_kind: "RUN_MANIFEST",
        safety_note: "Contains only run configuration, provenance, and aggregate exclusion counts. SHA-256 values support frozen research-input integrity checks and do not contain raw request values, IP addresses, hostnames, JA3/JA4, queries, or headers.",
        shenron_version: env!("CARGO_PKG_VERSION"),
        generated_at: Utc::now().to_rfc3339(),
        telemetry_profile,
        nuclei_revision,
        inputs: RunManifestInputs {
            nuclei_templates: path_provenance(nuclei_templates),
            nuclei_report: path_provenance(nuclei_report),
            kev_report: path_provenance(kev_report),
            approved_validated_template_count,
        },
        hunt_parameters: RunManifestParameters {
            filter_from: time_range.from.map(|timestamp| timestamp.to_rfc3339()),
            filter_to: time_range.to.map(|timestamp| timestamp.to_rfc3339()),
            trusted_proxy_networks: trusted_proxies.configured_proxy_networks(),
            triage_policy,
        },
        exclusions: RunManifestExclusions {
            generic_root_probe_request_evidence:
                "not converted into passive request evidence",
            requests_outside_time_range: metrics.requests_outside_time_range,
            requests_without_timestamp_excluded: metrics.requests_without_timestamp_excluded,
            parse_errors: metrics.parse_errors,
        },
    };
    let path = output.join("run-manifest.json");
    serde_json::to_writer_pretty(
        File::create(&path).with_context(|| format!("creating {}", path.display()))?,
        &manifest,
    )?;
    Ok(())
}

fn path_provenance(path: &Path) -> PathProvenance {
    let metadata = fs::metadata(path).ok();
    let is_file = metadata.as_ref().is_some_and(|metadata| metadata.is_file());
    PathProvenance {
        path: path.display().to_string(),
        byte_length: metadata
            .as_ref()
            .filter(|metadata| metadata.is_file())
            .map(|metadata| metadata.len()),
        // A template checkout is a directory, so its pinned Nuclei revision is
        // recorded instead of attempting to invent a directory-wide hash.
        sha256: is_file.then(|| sha256_file(path)).flatten(),
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

fn kev_cves(path: &Path) -> anyhow::Result<BTreeSet<String>> {
    let report: KevReportInput = serde_json::from_reader(File::open(path)?)?;
    Ok(report
        .entries
        .into_iter()
        .map(|entry| entry.cve.trim().to_ascii_uppercase())
        .collect())
}

fn matching_templates<'a>(
    detections: &'a [ValidatedNucleiDetection],
    event: &WebEvent,
) -> Vec<&'a ValidatedNucleiDetection> {
    let mut template_ids = BTreeSet::new();
    detections
        .iter()
        .filter(|detection| detection.matches(event))
        .filter(|detection| template_ids.insert(detection.template_id.clone()))
        .collect()
}

fn private_finding(detection: &ValidatedNucleiDetection, event: &WebEvent) -> PrivateFinding {
    PrivateFinding {
        template_id: detection.template_id.clone(),
        cves: detection.cves.clone(),
        detectability: detection.detectability,
        request_specificity: detection.request_specificity(),
        timestamp: event.timestamp.map(|time| time.to_rfc3339()),
        source_ip: event.source_ip.clone(),
        client_ip: event.client_ip.clone(),
        host: event.host.clone(),
        method: event.method.clone(),
        uri_path: event.uri_path.clone(),
        uri_query: event.uri_query.clone(),
        headers: event.headers.clone(),
        ja3: event.ja3.clone(),
        ja4: event.ja4.clone(),
        waf_action: event.waf_action.clone(),
        waf_rule_id: event.waf_rule_id.clone(),
        waf_rule_type: event.waf_rule_type.clone(),
        waf_labels: event.waf_labels.clone(),
        waf_non_terminating_rule_ids: event.waf_non_terminating_rule_ids.clone(),
        request_id: event.request_id.clone(),
    }
}

fn record_availability(fields: &mut FieldAvailability, event: &WebEvent) {
    fields.client_ip += usize::from(event.client_ip.is_some());
    fields.ja4 += usize::from(event.ja4.is_some());
    fields.ja3 += usize::from(event.ja3.is_some());
    fields.uri += usize::from(event.uri_path.is_some());
    fields.query += usize::from(event.uri_query.is_some());
    fields.headers += usize::from(!event.headers.is_empty());
    fields.host += usize::from(event.host.is_some());
    fields.method += usize::from(event.method.is_some());
    fields.waf_action += usize::from(event.waf_action.is_some());
    fields.waf_labels += usize::from(!event.waf_labels.is_empty());
    fields.terminating_rule_id += usize::from(event.waf_rule_id.is_some());
    fields.non_terminating_rules += usize::from(!event.waf_non_terminating_rule_ids.is_empty());
}

fn record_outcome(outcomes: &mut OutcomeCounts, event: &WebEvent) {
    if !event.waf_non_terminating_rule_ids.is_empty() {
        outcomes.count_related_evidence += 1;
    }
    match event
        .waf_action
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("BLOCK") => outcomes.blocked += 1,
        Some("ALLOW") | Some("COUNT") => outcomes.allowed_or_not_blocked += 1,
        _ => outcomes.unknown += 1,
    }
}

fn strongest(left: Detectability, right: Detectability) -> Detectability {
    let rank = |value| match value {
        Detectability::High => 4,
        Detectability::Medium => 3,
        Detectability::Low => 2,
        Detectability::Undetectable => 1,
        Detectability::Unknown => 0,
    };
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}

fn strongest_specificity(
    left: RequestSpecificity,
    right: RequestSpecificity,
) -> RequestSpecificity {
    match (left, right) {
        (RequestSpecificity::RequestSpecific, _) | (_, RequestSpecificity::RequestSpecific) => {
            RequestSpecificity::RequestSpecific
        }
        _ => RequestSpecificity::ResponseUnverified,
    }
}

fn update_accumulator_time(item: &mut CveAccumulator, timestamp: Option<DateTime<Utc>>) {
    let Some(timestamp) = timestamp else {
        return;
    };
    if item
        .first_seen
        .as_ref()
        .is_none_or(|first| timestamp < *first)
    {
        item.first_seen = Some(timestamp);
    }
    if item.last_seen.as_ref().is_none_or(|last| timestamp > *last) {
        item.last_seen = Some(timestamp);
    }
}

fn update_time_range(
    earliest: &mut Option<String>,
    latest: &mut Option<String>,
    timestamp: Option<DateTime<Utc>>,
) {
    let Some(timestamp) = timestamp else {
        return;
    };
    let value = timestamp.to_rfc3339();
    if earliest.as_ref().is_none_or(|current| value < *current) {
        *earliest = Some(value.clone());
    }
    if latest.as_ref().is_none_or(|current| value > *current) {
        *latest = Some(value);
    }
}

pub(crate) fn input_files(
    input: &Path,
    telemetry_profile: TelemetryProfile,
) -> anyhow::Result<Vec<PathBuf>> {
    if input.is_file() {
        return is_input_file(input, telemetry_profile)
            .then(|| vec![input.to_owned()])
            .ok_or_else(|| anyhow::anyhow!("unsupported input file {}", input.display()));
    }
    if !input.is_dir() {
        bail!(
            "input {} is neither a file nor a directory",
            input.display()
        );
    }
    Ok(WalkDir::new(input)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file() && is_input_file(entry.path(), telemetry_profile)
        })
        .map(|entry| entry.into_path())
        .collect())
}

fn is_input_file(path: &Path, telemetry_profile: TelemetryProfile) -> bool {
    if is_gzip(path) {
        return true;
    }
    match telemetry_profile {
        TelemetryProfile::AwsWaf => matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("json" | "jsonl")
        ),
        TelemetryProfile::NginxCombined
        | TelemetryProfile::ApacheCombined
        | TelemetryProfile::ApacheVhostCombined
        | TelemetryProfile::NginxCombinedHost
        | TelemetryProfile::NginxSecurity => matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("log" | "txt")
        ),
    }
}

fn is_gzip(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
}

fn event_reader(path: &Path) -> anyhow::Result<Box<dyn Read>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    Ok(maybe_gzip_reader(file, is_gzip(path)))
}

pub(crate) fn stream_events<F>(
    path: &Path,
    telemetry_profile: TelemetryProfile,
    callback: F,
) -> anyhow::Result<()>
where
    F: FnMut(Result<WebEvent, String>) -> anyhow::Result<()>,
{
    stream_events_with_trusted_proxies(
        path,
        telemetry_profile,
        &TrustedProxySet::default(),
        callback,
    )
}

pub(crate) fn stream_events_with_trusted_proxies<F>(
    path: &Path,
    telemetry_profile: TelemetryProfile,
    trusted_proxies: &TrustedProxySet,
    mut callback: F,
) -> anyhow::Result<()>
where
    F: FnMut(Result<WebEvent, String>) -> anyhow::Result<()>,
{
    let reader = event_reader(path)?;
    match telemetry_profile {
        TelemetryProfile::AwsWaf => {
            for item in WafLines::new(reader) {
                callback(
                    item.map(|mut event| {
                        trusted_proxies.resolve_client_ip(&mut event);
                        event
                    })
                    .map_err(|error| error.to_string()),
                )?;
            }
        }
        TelemetryProfile::NginxCombined => {
            for item in AccessLogLines::new(reader, AccessLogFormat::NginxCombined) {
                callback(
                    item.map(|mut event| {
                        trusted_proxies.resolve_client_ip(&mut event);
                        event
                    })
                    .map_err(|error| error.to_string()),
                )?;
            }
        }
        TelemetryProfile::ApacheCombined => {
            for item in AccessLogLines::new(reader, AccessLogFormat::ApacheCombined) {
                callback(
                    item.map(|mut event| {
                        trusted_proxies.resolve_client_ip(&mut event);
                        event
                    })
                    .map_err(|error| error.to_string()),
                )?;
            }
        }
        TelemetryProfile::ApacheVhostCombined => {
            for item in AccessLogLines::new(reader, AccessLogFormat::ApacheVhostCombined) {
                callback(
                    item.map(|mut event| {
                        trusted_proxies.resolve_client_ip(&mut event);
                        event
                    })
                    .map_err(|error| error.to_string()),
                )?;
            }
        }
        TelemetryProfile::NginxCombinedHost | TelemetryProfile::NginxSecurity => {
            bail!("counterfactual telemetry profiles are analysis-only and cannot parse production logs")
        }
    }
    Ok(())
}

/// Refuse an output path nested in, or containing, immutable raw input.
pub fn ensure_separate_output(input: &Path, output: &Path) -> anyhow::Result<()> {
    let input =
        fs::canonicalize(input).with_context(|| format!("resolving {}", input.display()))?;
    let output = if output.is_absolute() {
        output.to_owned()
    } else {
        std::env::current_dir()?.join(output)
    };
    let output = output
        .parent()
        .and_then(|parent| {
            fs::canonicalize(parent).ok().map(|parent| {
                parent.join(
                    output
                        .file_name()
                        .unwrap_or_else(|| std::ffi::OsStr::new("output")),
                )
            })
        })
        .unwrap_or(output);
    if output.starts_with(&input) || input.starts_with(&output) {
        bail!("output directory must be separate from immutable raw input");
    }
    Ok(())
}
