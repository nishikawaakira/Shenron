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
use walkdir::WalkDir;

use crate::{
    access_log::{AccessLogFormat, AccessLogLines},
    event::{HttpHeader, TelemetryProfile, WebEvent},
    nuclei::{validated_detections, ConversionStatus, Detectability, ValidatedNucleiDetection},
    waf::{maybe_gzip_reader, WafLines},
};

#[derive(Debug, Default, Serialize)]
pub struct FieldAvailability {
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
struct NucleiReportInput {
    templates: Vec<NucleiTemplateRecord>,
}

#[derive(Debug, Deserialize)]
struct NucleiTemplateRecord {
    template_id: String,
    cves: Vec<String>,
    conversion_status: ConversionStatus,
    validation_status: String,
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
    pub files_analyzed: usize,
    pub total_requests_analyzed: usize,
    pub parse_errors: usize,
    pub earliest_timestamp: Option<String>,
    pub latest_timestamp: Option<String>,
    pub exploitation_attempt_findings: usize,
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

#[derive(Debug, Deserialize, Serialize)]
struct PrivateFinding {
    template_id: String,
    cves: Vec<String>,
    detectability: Detectability,
    timestamp: Option<String>,
    source_ip: Option<String>,
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
    pub timestamp: Option<String>,
    pub source_ip: Option<String>,
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
            timestamp: finding.timestamp,
            source_ip: finding.source_ip,
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
        stream_events(&path, telemetry_profile, |result| {
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
) -> anyhow::Result<SanitizedHuntReport> {
    ensure_separate_output(input, output)?;
    let approved_templates = approved_template_ids(nuclei_report)?;
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
        ..HuntMetrics::default()
    };
    let mut cves = BTreeMap::<String, CveAccumulator>::new();
    let mut all_sources = BTreeSet::new();
    let mut all_ja4s = BTreeSet::new();
    for path in files {
        stream_events(&path, telemetry_profile, |result| {
            let event = match result {
                Ok(event) => event,
                Err(_) => {
                    metrics.parse_errors += 1;
                    return Ok(());
                }
            };
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
            let mut observed_cves = BTreeMap::<String, Detectability>::new();
            for detection in &matches {
                for cve in &detection.cves {
                    observed_cves
                        .entry(cve.clone())
                        .and_modify(|current| {
                            *current = strongest(*current, detection.detectability)
                        })
                        .or_insert(detection.detectability);
                }
            }
            for (cve, detectability) in observed_cves {
                metrics.exploitation_attempt_findings += 1;
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
    Ok(SanitizedHuntReport {
        report_kind: "SANITIZED_RESEARCH_OUTPUT".to_owned(),
        safety_note: if metrics.waf_outcome_available { "A protection gap means only that a matched exploitation attempt was not blocked according to available AWS WAF action evidence; it does not establish exploitation success." } else { "WAF outcome is unavailable for this telemetry source, so no protection-gap rate is calculated." }.to_owned() + " No raw request values, source IPs, hostnames, JA3, JA4, or headers are included here.",
        metrics,
        cve_findings,
    })
}

fn approved_template_ids(path: &Path) -> anyhow::Result<BTreeSet<String>> {
    let report: NucleiReportInput = serde_json::from_reader(File::open(path)?)?;
    Ok(report
        .templates
        .into_iter()
        .filter(|template| {
            template.conversion_status == ConversionStatus::Supported
                && template.validation_status == "passed"
                && !template.cves.is_empty()
        })
        .map(|template| template.template_id)
        .collect())
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
        timestamp: event.timestamp.map(|time| time.to_rfc3339()),
        source_ip: event.source_ip.clone(),
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

fn input_files(input: &Path, telemetry_profile: TelemetryProfile) -> anyhow::Result<Vec<PathBuf>> {
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

fn stream_events<F>(
    path: &Path,
    telemetry_profile: TelemetryProfile,
    mut callback: F,
) -> anyhow::Result<()>
where
    F: FnMut(Result<WebEvent, String>) -> anyhow::Result<()>,
{
    let reader = event_reader(path)?;
    match telemetry_profile {
        TelemetryProfile::AwsWaf => {
            for item in WafLines::new(reader) {
                callback(item.map_err(|error| error.to_string()))?;
            }
        }
        TelemetryProfile::NginxCombined => {
            for item in AccessLogLines::new(reader, AccessLogFormat::NginxCombined) {
                callback(item.map_err(|error| error.to_string()))?;
            }
        }
        TelemetryProfile::ApacheCombined => {
            for item in AccessLogLines::new(reader, AccessLogFormat::ApacheCombined) {
                callback(item.map_err(|error| error.to_string()))?;
            }
        }
        TelemetryProfile::NginxCombinedHost | TelemetryProfile::NginxSecurity => {
            bail!("counterfactual telemetry profiles are analysis-only and cannot parse production logs")
        }
    }
    Ok(())
}

fn ensure_separate_output(input: &Path, output: &Path) -> anyhow::Result<()> {
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
