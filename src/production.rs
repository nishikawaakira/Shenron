//! Read-only local production AWS WAF inspection and validated Nuclei hunts.
//!
//! Raw inputs are streamed without modification. Private findings are written
//! separately from a sanitized aggregate report and are never uploaded.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
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
    bot_ranges::{
        default_source_catalog, observe_without_range_snapshot, BotOperatorObservation,
        BotRangeAccumulator, BotRangeDatabase, PrivateBotRangeReport,
    },
    concentration::{
        add_focus_asn_groups, add_focus_prefix_groups, FocusPrefixLengths, FocusSelector,
        PrivateRequestConcentrationReport, RequestConcentration, RequestConcentrationSummary,
        DEFAULT_RATE_WINDOW_SECONDS,
    },
    consistency::{
        compare_declared_with_observed, declared_browser_family, ConsistencyAccumulator,
        ConsistencySummary, PrivateConsistencyReport,
    },
    event::{HttpHeader, LogSource, TelemetryProfile, TrustedProxySet, WebEvent},
    nuclei::{
        frozen_nuclei_selection, path_distinctiveness, validated_detections, Detectability,
        PathDistinctiveness, RequestSpecificity, ValidatedNucleiDetection,
    },
    reputation::AsnDatabase,
    waf::{maybe_gzip_reader, WafLines},
};

/// Bundled Sigma rule whose matches receive response-status review context.
/// This remains a request-pattern label, never an exploitation determination.
pub const SENSITIVE_CONFIG_PROBE_RULE_ID: &str = "shenron-secret-config-file-probe";

#[derive(Debug, Default, Serialize)]
pub struct FieldAvailability {
    pub client_ip: usize,
    pub ja4: usize,
    pub ja3: usize,
    pub tls_protocol: usize,
    pub tls_cipher: usize,
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
    /// Path-only triage labels; these counts never exclude a match or express
    /// ground truth, precision, attack, exploitation, or compromise.
    pub distinctive_path_matches: usize,
    pub generic_path_matches: usize,
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
    /// Supported Sigma rules evaluated in this hunt (0 when Sigma was disabled or
    /// no rules were found). The Sigma pass is a generic request-pattern layer,
    /// kept entirely separate from the CVE metrics above.
    pub sigma_rules_evaluated: usize,
    /// Distinct requests (events) that matched at least one Sigma rule. Use this
    /// when reporting how many requests carried a Sigma detection.
    pub sigma_matched_requests: usize,
    /// Individual Sigma rule matches across all events. One request can match
    /// several rules, so this can exceed `sigma_matched_requests`; it is a count
    /// of rule matches, not of requests.
    pub sigma_rule_matches: usize,
    /// Distinct Sigma rules that matched at least one event.
    pub distinct_sigma_rules: usize,
    /// Distinct requests matching the sensitive/config-file probe rule. These
    /// are retained regardless of response status and do not assert attack.
    pub sensitive_config_probe_matches: usize,
    /// Matching requests whose observed response status was in 200..=299.
    /// This is a review-priority signal, not evidence of content disclosure.
    pub sensitive_config_probe_success_responses: usize,
    /// Matching requests whose telemetry did not expose a response status.
    /// Missing status is never treated as a success response.
    pub sensitive_config_probe_status_unavailable: usize,
    /// Aggregate-only comparison between self-declared bot User-Agents and a
    /// frozen published-range snapshot. Operator labels are public metadata;
    /// source addresses remain in the private companion artifact.
    pub bot_range_observations: Vec<BotOperatorObservation>,
    /// False when no local snapshot was configured. In that case evaluation is
    /// skipped without changing any CVE or Sigma metric.
    pub bot_range_snapshot_loaded: bool,
    /// Aggregate-only outcomes for declared-versus-observed consistency
    /// checks. Raw declarations and observed values are private-only.
    pub declared_observed_consistency: ConsistencySummary,
    /// Aggregate request-volume distribution only. This is separate from CVE
    /// metrics and does not determine attack, abuse, or compromise.
    pub request_concentration: Option<RequestConcentrationSummary>,
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
    /// Supported Sigma rules to evaluate in the same streaming pass. `None`
    /// disables the generic Sigma detection layer; the CVE-anchored Nuclei pass
    /// is unaffected either way.
    pub sigma_ruleset: Option<crate::sigma::RuleSet>,
    /// Optional frozen local published crawler-range database. It is evaluated
    /// in the existing event stream and never performs network access.
    pub bot_range_database: Option<BotRangeDatabase>,
    /// Snapshot path recorded as additional run provenance without changing
    /// the existing Nuclei/KEV provenance fields or hash behavior.
    pub bot_range_snapshot_path: Option<PathBuf>,
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
    /// Path-only triage counts. They contain no raw paths and do not change
    /// which CVE-related request matches are retained.
    pub distinctive_path_matches: u64,
    pub generic_path_matches: u64,
    pub unique_source_clusters: usize,
    pub unique_ja4_fingerprints: usize,
    pub unique_hosts: usize,
    /// Response status is triage context only, never proof of compromise.
    pub response_status_counts: BTreeMap<u16, usize>,
    pub outcomes: OutcomeCounts,
    pub protection_gap_rate: Option<f64>,
    /// Deterministically sorted public Nuclei template identifiers which
    /// produced a request match for this CVE. These are CTI metadata, not
    /// customer telemetry values.
    pub template_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SanitizedHuntReport {
    pub report_kind: String,
    pub safety_note: String,
    pub metrics: HuntMetrics,
    pub cve_findings: Vec<SanitizedCveFinding>,
}

/// Aggregate-only request-volume distribution output for `production
/// concentration`. It intentionally contains no raw paths, IPs, hosts,
/// headers, or other request values.
#[derive(Debug, Serialize)]
pub struct SanitizedConcentrationReport {
    pub report_kind: String,
    pub safety_note: String,
    pub telemetry_profile: TelemetryProfile,
    pub filter_from: Option<String>,
    pub filter_to: Option<String>,
    pub files_analyzed: usize,
    pub total_requests_analyzed: usize,
    pub requests_outside_time_range: usize,
    pub requests_without_timestamp_excluded: usize,
    pub parse_errors: usize,
    pub request_concentration: RequestConcentrationSummary,
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
    /// Total validated detections compared across the rungs.
    pub validated_detections: usize,
    /// Detections with no query condition. The `path_and_query` rung cannot
    /// narrow these: they pass it exactly as they pass `path_only`. This is the
    /// honest reason the rung often adds almost nothing over `path_only`, rather
    /// than an independent narrowing step.
    pub path_and_query_detections_without_query_condition: usize,
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

struct KnownReplaySources {
    per_cve: BTreeMap<String, ReplayCveAccumulator>,
    known_findings_total: u64,
    known_source_request_ids: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
pub struct CountHypothesisReport {
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
    pub per_cve: Vec<CveHypothesis>,
}

/// One CVE's non-prescriptive COUNT simulation ladder.
#[derive(Debug, Serialize)]
pub struct CveHypothesis {
    pub cve: String,
    pub is_kev: bool,
    pub known_findings: u64,
    pub rungs: Vec<HypothesisRung>,
}

/// Aggregate-only result of simulating one condition width in COUNT mode.
#[derive(Debug, Serialize)]
pub struct HypothesisRung {
    pub strategy: String,
    pub matched_events: u64,
    pub known_matched: u64,
    pub known_coverage: Option<f64>,
    pub other_matches_with_request_id: u64,
    pub other_matches_without_request_id: u64,
    pub matched_events_blocked: u64,
    pub matched_events_not_blocked: u64,
    pub matched_events_unknown_outcome: u64,
}

#[derive(Default)]
struct CountHypothesisCveAccumulator {
    known_findings: u64,
    known_request_ids: BTreeSet<String>,
    rungs: [HypothesisRungAccumulator; 5],
}

#[derive(Default)]
struct HypothesisRungAccumulator {
    matched_events: u64,
    known_matched_request_ids: BTreeSet<String>,
    other_matches_with_request_id: u64,
    other_matches_without_request_id: u64,
    outcomes: ReplayOutcomeCounts,
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
    /// Supported Sigma rules evaluated in the generic detection pass (0 when it
    /// was disabled or no rules were found). Kept distinct from Nuclei inputs.
    sigma_rules_evaluated: usize,
    exclusions: RunManifestExclusions,
}

#[derive(Serialize)]
struct RunManifestInputs {
    nuclei_templates: PathProvenance,
    nuclei_report: PathProvenance,
    kev_report: Option<PathProvenance>,
    bot_range_snapshot: Option<PathProvenance>,
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

/// Which detection engine produced a finding. Nuclei is the CVE-anchored pass;
/// Sigma is the generic request-pattern pass added to `hunt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    #[default]
    Nuclei,
    Sigma,
}

#[derive(Debug, Deserialize, Serialize)]
struct PrivateFinding {
    /// Detection engine. Absent in older private findings, which are all Nuclei.
    #[serde(default)]
    source: FindingSource,
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
    /// Telemetry source that produced this finding. Absent in older private
    /// findings; the loader then falls back to a full-capability profile so a
    /// legacy file is never penalized by an unknown reachable maximum.
    #[serde(default)]
    log_source: Option<LogSource>,
    /// Sigma rule title, for `source = sigma` findings only.
    #[serde(default)]
    rule_title: Option<String>,
    /// Sigma rule level, for `source = sigma` findings only.
    #[serde(default)]
    sigma_level: Option<String>,
    /// Observed HTTP response status when the telemetry source records it.
    /// Missing status remains `None` and is never inferred.
    #[serde(default)]
    response_status: Option<u16>,
}

/// A terminal-safe view of private hunt evidence. The CLI keeps private
/// attributes hidden unless the analyst explicitly opts in.
#[derive(Debug, Clone)]
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
    /// Telemetry source that produced this finding, when recorded. Bounds the
    /// reachable behavior-score maximum for this evidence.
    pub log_source: Option<LogSource>,
    /// Detection engine that produced this finding.
    pub source: FindingSource,
    /// Sigma rule title, for `source = sigma` findings only.
    pub rule_title: Option<String>,
    /// Sigma rule level, for `source = sigma` findings only.
    pub sigma_level: Option<String>,
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
            log_source: finding.log_source,
            source: finding.source,
            rule_title: finding.rule_title,
            sigma_level: finding.sigma_level,
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
    distinctive_path_matches: u64,
    generic_path_matches: u64,
    template_ids: BTreeSet<String>,
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
        Some(kev_report),
        output,
        telemetry_profile,
        HuntOptions {
            time_range,
            trusted_proxies: TrustedProxySet::default(),
            triage_policy: HuntTriagePolicy::default(),
            sigma_ruleset: None,
            bot_range_database: None,
            bot_range_snapshot_path: None,
        },
    )
}

pub fn hunt_with_options(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: Option<&Path>,
    output: &Path,
    telemetry_profile: TelemetryProfile,
    options: HuntOptions,
) -> anyhow::Result<SanitizedHuntReport> {
    let HuntOptions {
        time_range,
        trusted_proxies,
        triage_policy,
        sigma_ruleset,
        bot_range_database,
        bot_range_snapshot_path,
    } = options;
    time_range.validate()?;
    ensure_separate_output(input, output)?;
    let (approved_templates, nuclei_revision) = approved_template_ids(nuclei_report)?;
    let detections = validated_detections(nuclei_templates, &approved_templates);
    if detections.is_empty() {
        bail!("no validated Nuclei detections could be rebuilt from the supplied report and template checkout");
    }
    let detection_index = DetectionPathIndex::new(&detections);
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
    let sigma_rules = sigma_ruleset
        .as_ref()
        .map(|ruleset| ruleset.supported.as_slice())
        .unwrap_or_default();
    metrics.sigma_rules_evaluated = sigma_rules.len();
    let mut cves = BTreeMap::<String, CveAccumulator>::new();
    let mut all_sources = BTreeSet::new();
    let mut all_ja4s = BTreeSet::new();
    let mut matched_sigma_rules = BTreeSet::new();
    let mut concentration =
        RequestConcentration::new(telemetry_profile.capabilities().response_bytes);
    let mut bot_ranges = BotRangeAccumulator::default();
    metrics.bot_range_snapshot_loaded = bot_range_database.is_some();
    let bot_catalog = if bot_range_database.is_none() {
        default_source_catalog()?
    } else {
        Vec::new()
    };
    let capabilities = telemetry_profile.capabilities();
    let mut consistency = ConsistencyAccumulator::default();
    let mut progress = ProgressReporter::new("hunt");
    for path in files {
        stream_events_with_trusted_proxies(&path, telemetry_profile, &trusted_proxies, |result| {
            progress.tick();
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
            concentration.observe(&event);
            if let Some(database) = &bot_range_database {
                database.observe_with_consistency(
                    &event,
                    capabilities,
                    &mut bot_ranges,
                    &mut consistency,
                );
            } else {
                observe_without_range_snapshot(
                    &bot_catalog,
                    &event,
                    capabilities,
                    &mut consistency,
                );
            }
            if let Some(browser_family) = declared_browser_family(event.user_agent.as_deref()) {
                let result = compare_declared_with_observed(
                    capabilities.tls_cipher,
                    event.tls_cipher.as_deref(),
                    None,
                );
                consistency.record(
                    "declared-browser-tls-cipher",
                    "user-agent-browser-family",
                    browser_family,
                    "tls-cipher-suite",
                    event.tls_cipher.as_deref(),
                    result,
                );
            }
            update_time_range(
                &mut metrics.earliest_timestamp,
                &mut metrics.latest_timestamp,
                event.timestamp,
            );
            let matches = detection_index.matching_templates(&detections, &event);
            // The Sigma pass is independent of the CVE pass: it must run even
            // when no Nuclei template matched, since its whole purpose is to
            // surface generic TTPs that no CVE template covers.
            let sigma_matcher = crate::sigma::EventMatcher::new(&event);
            let sigma_matches = sigma_rules
                .iter()
                .filter(|rule| sigma_matcher.matches(rule))
                .collect::<Vec<_>>();
            if matches.is_empty() && sigma_matches.is_empty() {
                return Ok(());
            }
            for detection in &matches {
                serde_json::to_writer(&mut private, &private_finding(detection, &event))?;
                private.write_all(b"\n")?;
            }
            if !sigma_matches.is_empty() {
                metrics.sigma_matched_requests += 1;
            }
            if sigma_matches
                .iter()
                .any(|rule| rule.id == SENSITIVE_CONFIG_PROBE_RULE_ID)
            {
                metrics.sensitive_config_probe_matches += 1;
                match event.status {
                    Some(200..=299) => metrics.sensitive_config_probe_success_responses += 1,
                    None => metrics.sensitive_config_probe_status_unavailable += 1,
                    Some(_) => {}
                }
            }
            for rule in &sigma_matches {
                serde_json::to_writer(&mut private, &sigma_finding(rule, &event))?;
                private.write_all(b"\n")?;
                metrics.sigma_rule_matches += 1;
                matched_sigma_rules.insert(rule.id.clone());
            }
            let mut observed_cves =
                BTreeMap::<String, (Detectability, RequestSpecificity, BTreeSet<String>)>::new();
            for detection in &matches {
                for cve in &detection.cves {
                    observed_cves
                        .entry(cve.clone())
                        .and_modify(|current| {
                            current.0 = strongest(current.0, detection.detectability);
                            current.1 =
                                strongest_specificity(current.1, detection.request_specificity());
                            current.2.insert(detection.template_id.clone());
                        })
                        .or_insert_with(|| {
                            (
                                detection.detectability,
                                detection.request_specificity(),
                                BTreeSet::from([detection.template_id.clone()]),
                            )
                        });
                }
            }
            let path_distinctiveness =
                path_distinctiveness(event.uri_path.as_deref().unwrap_or_default());
            for (cve, (detectability, request_specificity, template_ids)) in observed_cves {
                metrics.cve_related_request_matches += 1;
                match request_specificity {
                    RequestSpecificity::RequestSpecific => metrics.request_specific_matches += 1,
                    RequestSpecificity::ResponseUnverified => {
                        metrics.response_unverified_matches += 1
                    }
                }
                match path_distinctiveness {
                    PathDistinctiveness::Distinctive => metrics.distinctive_path_matches += 1,
                    PathDistinctiveness::Generic => metrics.generic_path_matches += 1,
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
                accumulator.template_ids.extend(template_ids);
                match path_distinctiveness {
                    PathDistinctiveness::Distinctive => accumulator.distinctive_path_matches += 1,
                    PathDistinctiveness::Generic => accumulator.generic_path_matches += 1,
                }
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
    write_private_concentration(output, &concentration.private_report())?;
    if bot_range_database.is_some() {
        let (observations, private_report) = bot_ranges.reports();
        metrics.bot_range_observations = observations;
        write_private_bot_ranges(output, &private_report)?;
    }
    let (consistency_summary, private_consistency) = consistency.reports();
    metrics.declared_observed_consistency = consistency_summary;
    write_private_consistency(output, &private_consistency)?;
    metrics.distinct_sigma_rules = matched_sigma_rules.len();
    metrics.unique_cves_observed = cves.len();
    metrics.unique_cisa_kevs_observed = cves.values().filter(|item| item.kev).count();
    metrics.unique_source_clusters = all_sources.len();
    metrics.unique_ja4_fingerprints = all_ja4s.len();
    metrics.request_concentration = Some(concentration.summary());
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
                distinctive_path_matches: item.distinctive_path_matches,
                generic_path_matches: item.generic_path_matches,
                unique_source_clusters: item.source_ips.len(),
                unique_ja4_fingerprints: item.ja4s.len(),
                unique_hosts: item.hosts.len(),
                response_status_counts: item.response_status_counts,
                outcomes: item.outcomes,
                protection_gap_rate,
                template_ids: item.template_ids.into_iter().collect(),
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
        bot_range_snapshot_path.as_deref(),
        nuclei_revision,
        approved_templates.len(),
        &time_range,
        &trusted_proxies,
        triage_policy,
        &report.metrics,
    )?;
    Ok(report)
}

/// Measure request-volume distribution without CTI inputs or detector matching.
/// It streams local logs once, writes a private detailed artifact plus a
/// sanitized aggregate artifact, and makes no network request.
pub fn concentration(
    input: &Path,
    output: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: HuntTimeRange,
    focus: Option<FocusSelector>,
    focus_prefix_lengths: FocusPrefixLengths,
) -> anyhow::Result<SanitizedConcentrationReport> {
    concentration_with_asn(
        input,
        output,
        telemetry_profile,
        time_range,
        focus,
        focus_prefix_lengths,
        None,
    )
}

/// Measure request-volume distribution and optionally enrich retained focus
/// peers through one analyst-supplied local ASN database. ASN values remain in
/// the private artifact; no lookup performs network access.
pub fn concentration_with_asn(
    input: &Path,
    output: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: HuntTimeRange,
    focus: Option<FocusSelector>,
    focus_prefix_lengths: FocusPrefixLengths,
    asn_database: Option<&AsnDatabase>,
) -> anyhow::Result<SanitizedConcentrationReport> {
    concentration_with_asn_and_rate_windows(
        input,
        output,
        telemetry_profile,
        time_range,
        focus,
        focus_prefix_lengths,
        asn_database,
        &DEFAULT_RATE_WINDOW_SECONDS,
    )
}

/// Variant of [`concentration_with_asn`] with explicit simultaneous rate
/// windows. Widths are exact seconds and affect reporting only, never matching
/// or any CVE metric.
#[allow(clippy::too_many_arguments)]
pub fn concentration_with_asn_and_rate_windows(
    input: &Path,
    output: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: HuntTimeRange,
    focus: Option<FocusSelector>,
    focus_prefix_lengths: FocusPrefixLengths,
    asn_database: Option<&AsnDatabase>,
    rate_window_seconds: &[u64],
) -> anyhow::Result<SanitizedConcentrationReport> {
    time_range.validate()?;
    ensure_separate_output(input, output)?;
    let files = input_files(input, telemetry_profile)?;
    fs::create_dir_all(output)
        .with_context(|| format!("creating private output directory {}", output.display()))?;
    let mut report = SanitizedConcentrationReport {
        report_kind: "SANITIZED_REQUEST_CONCENTRATION".to_owned(),
        safety_note: concentration_safety_note().to_owned(),
        telemetry_profile,
        filter_from: time_range.from.map(|time| time.to_rfc3339()),
        filter_to: time_range.to.map(|time| time.to_rfc3339()),
        files_analyzed: files.len(),
        total_requests_analyzed: 0,
        requests_outside_time_range: 0,
        requests_without_timestamp_excluded: 0,
        parse_errors: 0,
        request_concentration: RequestConcentration::new(
            telemetry_profile.capabilities().response_bytes,
        )
        .summary(),
    };
    let mut accumulator = RequestConcentration::with_limits_and_rate_windows(
        telemetry_profile.capabilities().response_bytes,
        crate::concentration::ConcentrationLimits::default(),
        rate_window_seconds,
    );
    if let Some(selector) = focus {
        accumulator.focus_on(selector);
    }
    let mut progress = ProgressReporter::new("concentration");
    for path in files {
        stream_events(&path, telemetry_profile, |result| {
            progress.tick();
            let event = match result {
                Ok(event) => event,
                Err(_) => {
                    report.parse_errors += 1;
                    return Ok(());
                }
            };
            if !time_range.includes(event.timestamp) {
                if event.timestamp.is_some() {
                    report.requests_outside_time_range += 1;
                } else {
                    report.requests_without_timestamp_excluded += 1;
                }
                return Ok(());
            }
            report.total_requests_analyzed += 1;
            accumulator.observe(&event);
            Ok(())
        })?;
    }
    report.request_concentration = accumulator.summary();
    let mut private_report = accumulator.private_report();
    if let Some(focus) = private_report.focus.as_mut() {
        add_focus_prefix_groups(focus, focus_prefix_lengths);
        if let Some(asn_database) = asn_database {
            add_focus_asn_groups(focus, asn_database);
        }
    }
    write_private_concentration(output, &private_report)?;
    let sanitized_path = output.join("sanitized-research.json");
    serde_json::to_writer_pretty(
        File::create(&sanitized_path)
            .with_context(|| format!("creating {}", sanitized_path.display()))?,
        &report,
    )?;
    write_concentration_run_manifest(output, telemetry_profile, &time_range)?;
    Ok(report)
}

/// Provenance manifest for a `concentration` run. It records the same
/// version, generation time, telemetry profile, and filter range that `hunt`
/// writes, so the HTML report reads provenance the same way for both. Nuclei is
/// not part of a concentration run, so `nuclei_revision` is always absent. It is
/// not a sanitized research artifact and contains no raw request values.
#[derive(Serialize)]
struct ConcentrationRunManifest {
    report_kind: &'static str,
    safety_note: &'static str,
    shenron_version: &'static str,
    generated_at: String,
    telemetry_profile: TelemetryProfile,
    nuclei_revision: Option<String>,
    hunt_parameters: ConcentrationManifestParameters,
}

#[derive(Serialize)]
struct ConcentrationManifestParameters {
    filter_from: Option<String>,
    filter_to: Option<String>,
}

fn write_concentration_run_manifest(
    output: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: &HuntTimeRange,
) -> anyhow::Result<()> {
    let manifest = ConcentrationRunManifest {
        report_kind: "RUN_MANIFEST",
        safety_note: "Contains only run configuration and provenance for a request-concentration run. No raw request values, IP addresses, hostnames, JA3/JA4, queries, or headers are included.",
        shenron_version: env!("CARGO_PKG_VERSION"),
        generated_at: Utc::now().to_rfc3339(),
        telemetry_profile,
        nuclei_revision: None,
        hunt_parameters: ConcentrationManifestParameters {
            filter_from: time_range.from.map(|time| time.to_rfc3339()),
            filter_to: time_range.to.map(|time| time.to_rfc3339()),
        },
    };
    let path = output.join("run-manifest.json");
    serde_json::to_writer_pretty(
        File::create(&path).with_context(|| format!("creating {}", path.display()))?,
        &manifest,
    )?;
    Ok(())
}

/// Read the private concentration detail written by `hunt` or `concentration`.
/// Callers must treat the contained paths and connection-peer IPs as sensitive.
pub fn load_private_concentration(
    path: &Path,
) -> anyhow::Result<PrivateRequestConcentrationReport> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("reading private concentration artifact {}", path.display()))
}

fn write_private_concentration(
    output: &Path,
    report: &PrivateRequestConcentrationReport,
) -> anyhow::Result<()> {
    let path = output.join("request-concentration.json");
    serde_json::to_writer_pretty(
        File::create(&path).with_context(|| format!("creating {}", path.display()))?,
        report,
    )?;
    Ok(())
}

fn write_private_bot_ranges(output: &Path, report: &PrivateBotRangeReport) -> anyhow::Result<()> {
    let path = output.join("bot-range-observations.json");
    serde_json::to_writer_pretty(
        File::create(&path).with_context(|| format!("creating {}", path.display()))?,
        report,
    )?;
    Ok(())
}

fn write_private_consistency(
    output: &Path,
    report: &PrivateConsistencyReport,
) -> anyhow::Result<()> {
    let path = output.join("declared-observed-observations.json");
    serde_json::to_writer_pretty(
        File::create(&path).with_context(|| format!("creating {}", path.display()))?,
        report,
    )?;
    Ok(())
}

fn concentration_safety_note() -> &'static str {
    "This is a request-volume distribution only. It is not a determination of a denial-of-service attempt, an attack, abuse, or an attacker identity. High concentration on one path can equally result from a popular or embedded resource, a misconfigured client, a crawler, a load test, or a denial-of-service attempt; distinguishing them requires human review. No raw request values, source IPs, hostnames, JA3, JA4, or headers are included here."
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
    ablation_with_optional_kev(
        input,
        nuclei_templates,
        nuclei_report,
        Some(kev_report),
        telemetry_profile,
        time_range,
    )
}

/// Same aggregate-only comparison as [`ablation`], with optional local KEV
/// context. Omitting KEV treats its set as empty.
pub fn ablation_with_optional_kev(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: Option<&Path>,
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
    let mut progress = ProgressReporter::new("ablation");
    for path in &files {
        stream_events(path, telemetry_profile, |result| {
            progress.tick();
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
        validated_detections: detections.len(),
        path_and_query_detections_without_query_condition: detections
            .iter()
            .filter(|detection| !detection.has_query_condition())
            .count(),
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
    historical_replay_with_optional_kev(
        input,
        nuclei_templates,
        nuclei_report,
        Some(kev_report),
        findings,
        telemetry_profile,
        time_range,
    )
}

/// Same sanitized replay as [`historical_replay`], with optional local KEV
/// context. Omitting KEV treats every CVE as not in KEV.
pub fn historical_replay_with_optional_kev(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: Option<&Path>,
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
    let detection_index = DetectionPathIndex::new(&detections);
    let kev_cves = kev_cves(kev_report)?;
    let known_sources = known_replay_sources(explain_private_findings(findings)?);
    let KnownReplaySources {
        mut per_cve,
        known_findings_total,
        known_source_request_ids,
    } = known_sources;

    // Fail fast on the outcome the findings alone already determine: with no
    // source request ID, conservative coverage is unreachable no matter what
    // the corpus contains. Warn before the (potentially very long) scan rather
    // than after it. nginx/Apache combined logs never carry a request ID.
    // Aggregate match volumes remain meaningful, so this is a warning, not an
    // error.
    if known_findings_total > 0 && known_source_request_ids.is_empty() {
        eprintln!(
            "warning: none of the {known_findings_total} loaded findings carries a request ID, so conservative replay coverage will be unavailable regardless of this scan (nginx/Apache combined logs do not record a request ID). Aggregate match volumes are still computed."
        );
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

    let mut progress = ProgressReporter::new("replay");
    for path in &files {
        stream_events(path, telemetry_profile, |result| {
            progress.tick();
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
            let matched_cves = detection_index
                .matching_templates(&detections, &event)
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
            kev_report_sha256: kev_report.and_then(sha256_file),
            findings_sha256: sha256_file(findings),
        },
        per_cve: cve_coverage,
        aggregate,
    })
}

/// Simulate broad-to-narrow validated Nuclei conditions as local COUNT-mode
/// hypotheses. This writes no findings, contacts no network, and makes no
/// deployment or recommendation.
pub fn count_hypotheses(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: &Path,
    findings: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: HuntTimeRange,
) -> anyhow::Result<CountHypothesisReport> {
    count_hypotheses_with_optional_kev(
        input,
        nuclei_templates,
        nuclei_report,
        Some(kev_report),
        findings,
        telemetry_profile,
        time_range,
    )
}

/// Same COUNT-hypothesis measurement as [`count_hypotheses`], with optional
/// local KEV context. Omitting KEV treats every CVE as not in KEV.
pub fn count_hypotheses_with_optional_kev(
    input: &Path,
    nuclei_templates: &Path,
    nuclei_report: &Path,
    kev_report: Option<&Path>,
    findings: &Path,
    telemetry_profile: TelemetryProfile,
    time_range: HuntTimeRange,
) -> anyhow::Result<CountHypothesisReport> {
    time_range.validate()?;
    let (approved_templates, _) = approved_template_ids(nuclei_report)?;
    let detections = validated_detections(nuclei_templates, &approved_templates);
    if detections.is_empty() {
        bail!("no validated Nuclei detections could be rebuilt from the supplied report and template checkout");
    }
    let kev_cves = kev_cves(kev_report)?;
    let known_sources = known_replay_sources(explain_private_findings(findings)?);
    let mut per_cve = known_sources
        .per_cve
        .into_iter()
        .map(|(cve, source)| {
            (
                cve,
                CountHypothesisCveAccumulator {
                    known_findings: source.known_findings,
                    known_request_ids: source.known_request_ids,
                    ..CountHypothesisCveAccumulator::default()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let files = input_files(input, telemetry_profile)?;
    let mut total_events_evaluated = 0;
    let mut requests_outside_time_range = 0;
    let mut requests_without_timestamp_excluded = 0;
    let mut parse_errors = 0;
    let mut progress = ProgressReporter::new("count-hypotheses");
    for path in &files {
        stream_events(path, telemetry_profile, |result| {
            progress.tick();
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
            let request_id = event.request_id.as_deref();
            for (index, cves) in event_cves.into_iter().enumerate() {
                for cve in cves {
                    let accumulator = per_cve.entry(cve).or_default();
                    let rung = &mut accumulator.rungs[index];
                    rung.matched_events += 1;
                    if request_id.is_some_and(|request_id| {
                        accumulator.known_request_ids.contains(request_id)
                    }) {
                        rung.known_matched_request_ids.insert(
                            request_id
                                .expect("known match requires a request ID")
                                .to_owned(),
                        );
                    } else if request_id.is_some() {
                        rung.other_matches_with_request_id += 1;
                    } else {
                        rung.other_matches_without_request_id += 1;
                    }
                    record_replay_outcome(&mut rung.outcomes, &event);
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
    let mut cve_hypotheses = per_cve
        .into_iter()
        .map(|(cve, accumulator)| {
            let rungs = strategy_names
                .iter()
                .zip(accumulator.rungs)
                .map(|(strategy, rung)| {
                    let known_matched = rung.known_matched_request_ids.len() as u64;
                    HypothesisRung {
                        strategy: (*strategy).to_owned(),
                        matched_events: rung.matched_events,
                        known_matched,
                        known_coverage: (!accumulator.known_request_ids.is_empty())
                            .then(|| known_matched as f64 / accumulator.known_findings as f64),
                        other_matches_with_request_id: rung.other_matches_with_request_id,
                        other_matches_without_request_id: rung.other_matches_without_request_id,
                        matched_events_blocked: rung.outcomes.blocked,
                        matched_events_not_blocked: rung.outcomes.not_blocked,
                        matched_events_unknown_outcome: rung.outcomes.unknown,
                    }
                })
                .collect();
            CveHypothesis {
                is_kev: kev_cves.contains(&cve),
                cve,
                known_findings: accumulator.known_findings,
                rungs,
            }
        })
        .collect::<Vec<_>>();
    cve_hypotheses.sort_by(|left, right| {
        right
            .known_findings
            .cmp(&left.known_findings)
            .then_with(|| left.cve.cmp(&right.cve))
    });

    Ok(CountHypothesisReport {
        report_kind: "COUNT_HYPOTHESIS_LADDER".to_owned(),
        safety_note: "Each rung is an offline simulation of how a COUNT-mode condition would match local historical telemetry. Coverage is a conservative lower bound, not precision, recall, accuracy, ground truth, or an attack, exploitation, or compromise determination. Other matches may be additional attempts or accidental matches and require human review. Shenron does not deploy a control; an analyst must choose a rung and apply it through a separate COUNT-only export workflow. No raw request values, IP addresses, hostnames, headers, or request IDs are included.".to_owned(),
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
            kev_report_sha256: kev_report.and_then(sha256_file),
            findings_sha256: sha256_file(findings),
        },
        per_cve: cve_hypotheses,
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

fn known_replay_sources(source_findings: Vec<FindingExplanation>) -> KnownReplaySources {
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
    KnownReplaySources {
        per_cve,
        known_findings_total,
        known_source_request_ids,
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
    kev_report: Option<&Path>,
    bot_range_snapshot: Option<&Path>,
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
            kev_report: kev_report.map(path_provenance),
            bot_range_snapshot: bot_range_snapshot.map(path_provenance),
            approved_validated_template_count,
        },
        hunt_parameters: RunManifestParameters {
            filter_from: time_range.from.map(|timestamp| timestamp.to_rfc3339()),
            filter_to: time_range.to.map(|timestamp| timestamp.to_rfc3339()),
            trusted_proxy_networks: trusted_proxies.configured_proxy_networks(),
            triage_policy,
        },
        sigma_rules_evaluated: metrics.sigma_rules_evaluated,
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

fn kev_cves(path: Option<&Path>) -> anyhow::Result<BTreeSet<String>> {
    let Some(path) = path else {
        return Ok(BTreeSet::new());
    };
    let report: KevReportInput = serde_json::from_reader(File::open(path)?)?;
    Ok(report
        .entries
        .into_iter()
        .map(|entry| entry.cve.trim().to_ascii_uppercase())
        .collect())
}

struct DetectionPathIndex {
    exact: HashMap<String, Vec<usize>>,
    unindexed: Vec<usize>,
}

impl DetectionPathIndex {
    fn new(detections: &[ValidatedNucleiDetection]) -> Self {
        let mut exact = HashMap::<String, Vec<usize>>::new();
        let mut unindexed = Vec::new();
        for (index, detection) in detections.iter().enumerate() {
            if let Some(path) = detection.exact_path_requirement() {
                // `index` increases monotonically, preserving the source
                // detection order inside every path bucket.
                exact.entry(path.to_owned()).or_default().push(index);
            } else {
                // Future non-literal matchers remain correct by falling back
                // to ordered evaluation rather than being silently skipped.
                unindexed.push(index);
            }
        }
        Self { exact, unindexed }
    }

    fn matching_templates<'a>(
        &self,
        detections: &'a [ValidatedNucleiDetection],
        event: &WebEvent,
    ) -> Vec<&'a ValidatedNucleiDetection> {
        let exact_candidates = event
            .uri_path
            .as_deref()
            .and_then(|path| self.exact.get(path))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut template_ids = BTreeSet::new();

        if self.unindexed.is_empty() {
            return exact_candidates
                .iter()
                .map(|index| &detections[*index])
                .filter(|detection| detection.matches(event))
                .filter(|detection| template_ids.insert(detection.template_id.as_str()))
                .collect();
        }

        // This path is dormant for today's literal-only IR. If a future
        // matcher cannot be indexed, merge both sorted index lists so the
        // original first-match and output ordering semantics remain exact.
        let mut candidates = Vec::with_capacity(exact_candidates.len() + self.unindexed.len());
        candidates.extend_from_slice(exact_candidates);
        candidates.extend_from_slice(&self.unindexed);
        candidates.sort_unstable();
        candidates
            .into_iter()
            .map(|index| &detections[index])
            .filter(|detection| detection.matches(event))
            .filter(|detection| template_ids.insert(detection.template_id.as_str()))
            .collect()
    }
}

fn private_finding(detection: &ValidatedNucleiDetection, event: &WebEvent) -> PrivateFinding {
    PrivateFinding {
        source: FindingSource::Nuclei,
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
        log_source: Some(event.log_source),
        rule_title: None,
        sigma_level: None,
        response_status: event.status,
    }
}

/// Build a private finding for a matched Sigma rule. Sigma is the generic
/// request-pattern pass: it carries no Nuclei detectability (recorded as
/// `Unknown`) and is conservatively `ResponseUnverified`. The rule's own CVE
/// tags are preserved but never merged into the CVE metrics.
fn sigma_finding(rule: &crate::sigma::CompiledRule, event: &WebEvent) -> PrivateFinding {
    PrivateFinding {
        source: FindingSource::Sigma,
        template_id: rule.id.clone(),
        cves: rule.cves.clone(),
        detectability: Detectability::Unknown,
        request_specificity: RequestSpecificity::ResponseUnverified,
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
        log_source: Some(event.log_source),
        rule_title: Some(rule.title.clone()),
        sigma_level: rule.level.clone(),
        response_status: event.status,
    }
}

fn record_availability(fields: &mut FieldAvailability, event: &WebEvent) {
    fields.client_ip += usize::from(event.client_ip.is_some());
    fields.ja4 += usize::from(event.ja4.is_some());
    fields.ja3 += usize::from(event.ja3.is_some());
    fields.tls_protocol += usize::from(event.tls_protocol.is_some());
    fields.tls_cipher += usize::from(event.tls_cipher.is_some());
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

/// Emit a periodic progress heartbeat to stderr during a long corpus scan. It
/// reports only a running record count and a fixed command label; it never
/// includes request values, IP addresses, hostnames, or any other telemetry.
pub(crate) struct ProgressReporter {
    label: &'static str,
    processed: u64,
    interval: u64,
}

impl ProgressReporter {
    pub(crate) fn new(label: &'static str) -> Self {
        Self {
            label,
            processed: 0,
            interval: 500_000,
        }
    }

    pub(crate) fn tick(&mut self) {
        self.processed += 1;
        if self.processed.is_multiple_of(self.interval) {
            eprintln!(
                "progress: {} scanned {} records so far...",
                self.label, self.processed
            );
        }
    }
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

#[cfg(test)]
mod matcher_index_tests {
    use super::*;

    #[test]
    fn path_index_preserves_linear_match_and_first_template_order() {
        let detections = crate::nuclei::supported_detections(Path::new("tests/fixtures/nuclei"));
        let index = DetectionPathIndex::new(&detections);
        let mut inputs = include_str!("../tests/fixtures/production/waf.jsonl")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        inputs.push(
            r#"{"timestamp":1735689600000,"action":"ALLOW","httpRequest":{"clientIp":"198.51.100.10","headers":[],"uri":"/not-indexed","httpMethod":"GET"}}"#
                .to_owned(),
        );

        for input in inputs {
            let event = crate::waf::parse_line(&input).unwrap();
            let mut seen = BTreeSet::new();
            let linear = detections
                .iter()
                .filter(|detection| detection.matches(&event))
                .filter(|detection| seen.insert(detection.template_id.clone()))
                .map(|detection| detection.template_id.as_str())
                .collect::<Vec<_>>();
            let indexed = index
                .matching_templates(&detections, &event)
                .into_iter()
                .map(|detection| detection.template_id.as_str())
                .collect::<Vec<_>>();
            assert_eq!(indexed, linear);
        }
    }
}
