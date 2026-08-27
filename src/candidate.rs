//! Source-neutral defensive candidates and review-only control exporters.
//!
//! Exporters never deploy a control. Preventive exports require recorded
//! historical replay evidence and refuse any non-faithful translation.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::{TelemetryProfile, WebEvent};
use crate::production::FindingExplanation;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefensiveCondition {
    UriEquals { value: String },
    UriContains { value: String },
    UriStartsWith { value: String },
    QueryEquals { value: String },
    QueryContains { value: String },
    MethodEquals { value: String },
    HostEquals { value: String },
    HeaderEquals { name: String, value: String },
    HeaderContains { name: String, value: String },
    Ja3Equals { value: String },
    Ja4Equals { value: String },
    UserAgentEquals { value: String },
    UserAgentContains { value: String },
    And { conditions: Vec<DefensiveCondition> },
    Or { conditions: Vec<DefensiveCondition> },
    Not { condition: Box<DefensiveCondition> },
}

impl DefensiveCondition {
    pub fn matches(&self, event: &WebEvent) -> bool {
        match self {
            Self::UriEquals { value } => event.uri_path.as_deref() == Some(value),
            Self::UriContains { value } => {
                event.uri_path.as_deref().is_some_and(|v| v.contains(value))
            }
            Self::UriStartsWith { value } => event
                .uri_path
                .as_deref()
                .is_some_and(|v| v.starts_with(value)),
            Self::QueryEquals { value } => event.uri_query.as_deref() == Some(value),
            Self::QueryContains { value } => event
                .uri_query
                .as_deref()
                .is_some_and(|v| v.contains(value)),
            Self::MethodEquals { value } => event.method.as_deref().is_some_and(|v| v == value),
            Self::HostEquals { value } => event.host.as_deref().is_some_and(|v| v == value),
            Self::HeaderEquals { name, value } => event
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case(name) && header.value == *value),
            Self::HeaderContains { name, value } => event.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case(name) && header.value.contains(value)
            }),
            Self::Ja3Equals { value } => event.ja3.as_deref() == Some(value),
            Self::Ja4Equals { value } => event.ja4.as_deref() == Some(value),
            Self::UserAgentEquals { value } => event.user_agent.as_deref() == Some(value),
            Self::UserAgentContains { value } => event
                .user_agent
                .as_deref()
                .is_some_and(|v| v.contains(value)),
            Self::And { conditions } => {
                !conditions.is_empty() && conditions.iter().all(|c| c.matches(event))
            }
            Self::Or { conditions } => conditions.iter().any(|c| c.matches(event)),
            Self::Not { condition } => !condition.matches(event),
        }
    }
    fn values<'a>(&'a self, output: &mut Vec<&'a str>) {
        match self {
            Self::UriEquals { value }
            | Self::UriContains { value }
            | Self::UriStartsWith { value }
            | Self::QueryEquals { value }
            | Self::QueryContains { value }
            | Self::MethodEquals { value }
            | Self::HostEquals { value }
            | Self::Ja3Equals { value }
            | Self::Ja4Equals { value }
            | Self::UserAgentEquals { value }
            | Self::UserAgentContains { value } => output.push(value),
            Self::HeaderEquals { name, value } | Self::HeaderContains { name, value } => {
                output.push(name);
                output.push(value);
            }
            Self::And { conditions } | Self::Or { conditions } => {
                for c in conditions {
                    c.values(output);
                }
            }
            Self::Not { condition } => condition.values(output),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingReference {
    pub template_id: String,
    pub timestamp: Option<String>,
    pub request_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateEvidence {
    pub historical_requests_evaluated: u64,
    pub known_threat_findings: u64,
    pub known_threat_findings_matched: u64,
    pub known_threat_findings_missed: u64,
    pub other_historical_matches: u64,
    pub threat_coverage: Option<f64>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub replay_completed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    Count,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefensiveCandidate {
    pub schema_version: u8,
    pub id: String,
    pub conditions: DefensiveCondition,
    pub source_findings: Vec<FindingReference>,
    pub cves: Vec<String>,
    pub kev: bool,
    pub evidence: CandidateEvidence,
    pub recommended_action: RecommendedAction,
    pub telemetry_profile: TelemetryProfile,
    pub generation_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    AwsWafJson,
    TerraformAwsWaf,
    Ossec,
}
impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Self::AwsWafJson => "aws-waf-json",
            Self::TerraformAwsWaf => "terraform-aws-waf",
            Self::Ossec => "ossec",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompatibilityStatus {
    FullySupported,
    PartiallySupported,
    Unsupported,
}
#[derive(Debug, Clone, Serialize)]
pub struct CompatibilityReport {
    pub backend: String,
    pub telemetry_profile: TelemetryProfile,
    pub status: CompatibilityStatus,
    pub reasons: Vec<String>,
}

pub fn load(path: &Path) -> Result<DefensiveCandidate> {
    serde_json::from_reader(
        fs::File::open(path).with_context(|| format!("opening candidate {}", path.display()))?,
    )
    .context("parsing defensive candidate JSON")
}
pub fn build_from_findings(
    findings: &[FindingExplanation],
    cve: &str,
    telemetry_profile: TelemetryProfile,
    kev: bool,
) -> Result<DefensiveCandidate> {
    let cve = cve.trim().to_ascii_uppercase();
    let selected: Vec<_> = findings
        .iter()
        .filter(|finding| {
            finding
                .cves
                .iter()
                .any(|value| value.eq_ignore_ascii_case(&cve))
        })
        .collect();
    if selected.is_empty() {
        bail!("no private findings reference {cve}");
    }
    let shared = |value: fn(&FindingExplanation) -> Option<&String>| -> Option<String> {
        let first = value(selected[0])?.clone();
        selected
            .iter()
            .all(|finding| value(finding).is_some_and(|value| value == &first))
            .then_some(first)
    };
    let method = shared(|finding| finding.method.as_ref())
        .context("candidate build refused: selected findings do not share one method")?;
    let path = shared(|finding| finding.uri_path.as_ref())
        .context("candidate build refused: selected findings do not share one URI path")?;
    let mut conditions = vec![
        DefensiveCondition::MethodEquals { value: method },
        DefensiveCondition::UriEquals { value: path },
    ];
    if let Some(query) = shared(|finding| finding.uri_query.as_ref()) {
        conditions.push(DefensiveCondition::QueryEquals { value: query });
    }
    let timestamps: Vec<_> = selected
        .iter()
        .filter_map(|finding| finding.timestamp.as_deref())
        .filter_map(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|value| value.with_timezone(&Utc))
        })
        .collect();
    let known = selected.len() as u64;
    Ok(DefensiveCandidate {
        schema_version: 1,
        id: format!("shenron-{}", cve.to_ascii_lowercase()),
        conditions: DefensiveCondition::And { conditions },
        source_findings: selected
            .iter()
            .map(|finding| FindingReference {
                template_id: finding.template_id.clone(),
                timestamp: finding.timestamp.clone(),
                request_id: finding.request_id.clone(),
            })
            .collect(),
        cves: vec![cve],
        kev,
        evidence: CandidateEvidence {
            historical_requests_evaluated: 0,
            known_threat_findings: known,
            known_threat_findings_matched: known,
            known_threat_findings_missed: 0,
            other_historical_matches: 0,
            threat_coverage: Some(1.0),
            first_seen: timestamps.iter().min().cloned(),
            last_seen: timestamps.iter().max().cloned(),
            replay_completed: false,
        },
        recommended_action: RecommendedAction::Count,
        telemetry_profile,
        generation_version: "shenron-candidate-build-v1".to_owned(),
    })
}
#[derive(Debug, Clone, Copy)]
pub struct BatchBuildStats {
    pub candidates: usize,
    pub excluded_blocked_findings: usize,
    pub skipped_incomplete_findings: usize,
}
/// Builds one narrow candidate per CVE and exact request pattern. For AWS WAF,
/// terminating BLOCK findings are intentionally excluded: they are already
/// protected according to the available WAF outcome evidence.
pub fn build_batch_from_findings(
    findings: &[FindingExplanation],
    telemetry_profile: TelemetryProfile,
) -> (Vec<DefensiveCandidate>, BatchBuildStats) {
    let mut groups =
        BTreeMap::<(String, String, String, Option<String>), Vec<&FindingExplanation>>::new();
    let mut excluded_blocked_findings = 0;
    let mut skipped_incomplete_findings = 0;
    for finding in findings {
        if telemetry_profile == TelemetryProfile::AwsWaf
            && finding
                .waf_action
                .as_deref()
                .is_some_and(|action| action.eq_ignore_ascii_case("BLOCK"))
        {
            excluded_blocked_findings += 1;
            continue;
        }
        let (Some(method), Some(path)) = (&finding.method, &finding.uri_path) else {
            skipped_incomplete_findings += 1;
            continue;
        };
        for cve in &finding.cves {
            groups
                .entry((
                    cve.trim().to_ascii_uppercase(),
                    method.clone(),
                    path.clone(),
                    finding.uri_query.clone(),
                ))
                .or_default()
                .push(finding);
        }
    }
    let candidates = groups
        .into_iter()
        .enumerate()
        .map(|(index, ((cve, method, path, query), sources))| {
            let timestamps: Vec<_> = sources
                .iter()
                .filter_map(|finding| finding.timestamp.as_deref())
                .filter_map(|value| {
                    DateTime::parse_from_rfc3339(value)
                        .ok()
                        .map(|value| value.with_timezone(&Utc))
                })
                .collect();
            let mut conditions = vec![
                DefensiveCondition::MethodEquals { value: method },
                DefensiveCondition::UriEquals { value: path },
            ];
            if let Some(query) = query {
                conditions.push(DefensiveCondition::QueryEquals { value: query });
            }
            let known = sources.len() as u64;
            DefensiveCandidate {
                schema_version: 1,
                id: format!("shenron-{}-{:03}", cve.to_ascii_lowercase(), index + 1),
                conditions: DefensiveCondition::And { conditions },
                source_findings: sources
                    .iter()
                    .map(|finding| FindingReference {
                        template_id: finding.template_id.clone(),
                        timestamp: finding.timestamp.clone(),
                        request_id: finding.request_id.clone(),
                    })
                    .collect(),
                cves: vec![cve],
                kev: false,
                evidence: CandidateEvidence {
                    historical_requests_evaluated: 0,
                    known_threat_findings: known,
                    known_threat_findings_matched: 0,
                    known_threat_findings_missed: known,
                    other_historical_matches: 0,
                    threat_coverage: None,
                    first_seen: timestamps.iter().min().cloned(),
                    last_seen: timestamps.iter().max().cloned(),
                    replay_completed: false,
                },
                recommended_action: RecommendedAction::Count,
                telemetry_profile,
                generation_version: "shenron-candidate-build-batch-v1".to_owned(),
            }
        })
        .collect::<Vec<_>>();
    let stats = BatchBuildStats {
        candidates: candidates.len(),
        excluded_blocked_findings,
        skipped_incomplete_findings,
    };
    (candidates, stats)
}
pub fn save_batch(candidates: &[DefensiveCandidate], output: &Path) -> Result<()> {
    if output.exists() && !output.is_dir() {
        bail!(
            "candidate batch output must be a directory: {}",
            output.display()
        );
    }
    fs::create_dir_all(output)?;
    let paths: Vec<_> = candidates
        .iter()
        .map(|candidate| output.join(format!("{}.json", candidate.id)))
        .collect();
    if let Some(path) = paths.iter().find(|path| path.exists()) {
        bail!(
            "refusing to overwrite existing candidate: {}",
            path.display()
        );
    }
    for (candidate, path) in candidates.iter().zip(paths) {
        save(candidate, &path)?;
    }
    Ok(())
}
pub fn replay(
    mut candidate: DefensiveCandidate,
    input: &Path,
    telemetry_profile: TelemetryProfile,
) -> Result<DefensiveCandidate> {
    let mut evaluated = 0_u64;
    let known_request_ids = candidate
        .source_findings
        .iter()
        .filter_map(|finding| finding.request_id.clone())
        .collect::<BTreeSet<_>>();
    let mut matched_known_request_ids = BTreeSet::new();
    let mut other_historical_matches = 0_u64;
    for path in crate::production::input_files(input, telemetry_profile)? {
        crate::production::stream_events(&path, telemetry_profile, |event| {
            if let Ok(event) = event {
                evaluated += 1;
                if candidate.conditions.matches(&event) {
                    match event.request_id.as_ref() {
                        Some(request_id) if known_request_ids.contains(request_id) => {
                            matched_known_request_ids.insert(request_id.clone());
                        }
                        _ => other_historical_matches += 1,
                    }
                }
            }
            Ok(())
        })?;
    }
    let known = candidate.evidence.known_threat_findings;
    let matched_known = matched_known_request_ids.len() as u64;
    candidate.evidence.historical_requests_evaluated = evaluated;
    candidate.evidence.known_threat_findings_matched = matched_known;
    candidate.evidence.known_threat_findings_missed = known.saturating_sub(matched_known);
    candidate.evidence.other_historical_matches = other_historical_matches;
    candidate.evidence.threat_coverage =
        (known != 0 && !known_request_ids.is_empty()).then(|| matched_known as f64 / known as f64);
    candidate.evidence.replay_completed = true;
    candidate.telemetry_profile = telemetry_profile;
    Ok(candidate)
}
pub fn save(candidate: &DefensiveCandidate, path: &Path) -> Result<()> {
    ensure_new(path)?;
    serde_json::to_writer_pretty(fs::File::create(path)?, candidate)?;
    Ok(())
}

pub fn compatibility(
    candidate: &DefensiveCandidate,
    backend: Backend,
    telemetry: TelemetryProfile,
) -> CompatibilityReport {
    let mut reasons = Vec::new();
    compatible_condition(&candidate.conditions, backend, telemetry, &mut reasons, 0);
    let status = if reasons.is_empty() {
        CompatibilityStatus::FullySupported
    } else if reasons.len() == leaf_count(&candidate.conditions) {
        CompatibilityStatus::Unsupported
    } else {
        CompatibilityStatus::PartiallySupported
    };
    CompatibilityReport {
        backend: backend.name().to_owned(),
        telemetry_profile: telemetry,
        status,
        reasons,
    }
}
fn compatible_condition(
    c: &DefensiveCondition,
    backend: Backend,
    telemetry: TelemetryProfile,
    reasons: &mut Vec<String>,
    depth: usize,
) {
    let reasons_before = reasons.len();
    if matches!(backend, Backend::AwsWafJson | Backend::TerraformAwsWaf) && depth > 3 {
        reasons.push("AWS WAF permits at most three nested logical statement levels".to_owned());
        return;
    }
    let capabilities = telemetry.capabilities();
    let unavailable = |field: &str, available: bool, reasons: &mut Vec<String>| {
        if !available {
            reasons.push(format!(
                "{field} is unavailable in the selected telemetry profile"
            ));
        }
    };
    match c {
        DefensiveCondition::HostEquals { .. } => unavailable("host", capabilities.host, reasons),
        DefensiveCondition::Ja3Equals { .. } => unavailable("JA3", capabilities.ja3, reasons),
        DefensiveCondition::Ja4Equals { .. } => unavailable("JA4", capabilities.ja4, reasons),
        DefensiveCondition::HeaderEquals { .. } | DefensiveCondition::HeaderContains { .. } => {
            unavailable(
                "arbitrary request headers",
                matches!(
                    capabilities.headers,
                    crate::event::HeaderCapability::Arbitrary
                ),
                reasons,
            )
        }
        DefensiveCondition::UserAgentEquals { .. }
        | DefensiveCondition::UserAgentContains { .. } => {
            unavailable("User-Agent", capabilities.user_agent, reasons)
        }
        DefensiveCondition::And { conditions } | DefensiveCondition::Or { conditions } => {
            if conditions.is_empty() {
                reasons.push("empty logical condition".to_owned());
            }
            for child in conditions {
                compatible_condition(child, backend, telemetry, reasons, depth + 1);
            }
        }
        DefensiveCondition::Not { condition } => {
            compatible_condition(condition, backend, telemetry, reasons, depth + 1)
        }
        _ => {}
    }
    if backend == Backend::Ossec && reasons.len() == reasons_before && !ossec_shape_supported(c) {
        reasons.push(format!(
            "OSSEC raw combined-log exporter cannot faithfully represent {}",
            condition_name(c)
        ));
    }
}
fn ossec_shape_supported(c: &DefensiveCondition) -> bool {
    match c {
        DefensiveCondition::MethodEquals { .. }
        | DefensiveCondition::UriEquals { .. }
        | DefensiveCondition::UriContains { .. }
        | DefensiveCondition::UriStartsWith { .. }
        | DefensiveCondition::QueryEquals { .. }
        | DefensiveCondition::QueryContains { .. }
        | DefensiveCondition::UserAgentEquals { .. }
        | DefensiveCondition::UserAgentContains { .. } => true,
        DefensiveCondition::And { conditions } => {
            !conditions.is_empty() && conditions.iter().all(ossec_shape_supported)
        }
        _ => false,
    }
}
fn leaf_count(c: &DefensiveCondition) -> usize {
    match c {
        DefensiveCondition::And { conditions } | DefensiveCondition::Or { conditions } => {
            conditions.iter().map(leaf_count).sum()
        }
        DefensiveCondition::Not { condition } => leaf_count(condition),
        _ => 1,
    }
}
fn condition_name(c: &DefensiveCondition) -> &'static str {
    match c {
        DefensiveCondition::Ja4Equals { .. } => "JA4 equality",
        DefensiveCondition::Ja3Equals { .. } => "JA3 equality",
        DefensiveCondition::HostEquals { .. } => "host equality",
        DefensiveCondition::HeaderEquals { .. } => "header equality",
        DefensiveCondition::HeaderContains { .. } => "header contains",
        DefensiveCondition::Or { .. } => "OR",
        DefensiveCondition::Not { .. } => "NOT",
        _ => "condition",
    }
}

pub fn export(
    candidate: &DefensiveCandidate,
    backend: Backend,
    telemetry: TelemetryProfile,
    output: &Path,
    priority: Option<u32>,
    ossec_rule_id: u32,
) -> Result<CompatibilityReport> {
    reject_sensitive(candidate)?;
    let report = compatibility(candidate, backend, telemetry);
    if report.status != CompatibilityStatus::FullySupported {
        bail!(
            "export refused: {:?}: {}",
            report.status,
            report.reasons.join("; ")
        );
    }
    if matches!(backend, Backend::AwsWafJson | Backend::TerraformAwsWaf)
        && !candidate.evidence.replay_completed
    {
        bail!("preventive export refused: candidate has not been validated against historical traffic");
    }
    if matches!(backend, Backend::AwsWafJson | Backend::TerraformAwsWaf) && priority.is_none() {
        bail!("preventive export requires --priority; Shenron cannot infer WebACL priority");
    }
    let rendered = match backend {
        Backend::AwsWafJson => {
            serde_json::to_string_pretty(&aws_rule(candidate, priority.unwrap()))?
        }
        Backend::TerraformAwsWaf => terraform_rule(candidate, priority.unwrap()),
        Backend::Ossec => ossec_rule(candidate, ossec_rule_id)?,
    };
    ensure_new(output)?;
    fs::write(output, rendered)?;
    write_evidence(candidate, &report, output)?;
    Ok(report)
}
fn aws_rule(c: &DefensiveCandidate, priority: u32) -> serde_json::Value {
    serde_json::json!({"Name": safe_name(&c.id), "Priority": priority, "Action": {"Count": {}}, "Statement": aws_statement(&c.conditions), "VisibilityConfig": {"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": safe_name(&c.id)}})
}
fn aws_statement(c: &DefensiveCondition) -> serde_json::Value {
    match c {
        DefensiveCondition::And { conditions } => {
            serde_json::json!({"AndStatement":{"Statements": conditions.iter().map(aws_statement).collect::<Vec<_>>()}})
        }
        DefensiveCondition::Or { conditions } => {
            serde_json::json!({"OrStatement":{"Statements": conditions.iter().map(aws_statement).collect::<Vec<_>>()}})
        }
        DefensiveCondition::Not { condition } => {
            serde_json::json!({"NotStatement":{"Statement":aws_statement(condition)}})
        }
        _ => {
            let (value, constraint, field) = match c {
                DefensiveCondition::UriEquals { value } => {
                    (value, "EXACTLY", serde_json::json!({"UriPath":{}}))
                }
                DefensiveCondition::UriContains { value } => {
                    (value, "CONTAINS", serde_json::json!({"UriPath":{}}))
                }
                DefensiveCondition::UriStartsWith { value } => {
                    (value, "STARTS_WITH", serde_json::json!({"UriPath":{}}))
                }
                DefensiveCondition::QueryEquals { value } => {
                    (value, "EXACTLY", serde_json::json!({"QueryString":{}}))
                }
                DefensiveCondition::QueryContains { value } => {
                    (value, "CONTAINS", serde_json::json!({"QueryString":{}}))
                }
                DefensiveCondition::MethodEquals { value } => {
                    (value, "EXACTLY", serde_json::json!({"Method":{}}))
                }
                DefensiveCondition::HostEquals { value } => (
                    value,
                    "EXACTLY",
                    serde_json::json!({"SingleHeader":{"Name":"host"}}),
                ),
                DefensiveCondition::HeaderEquals { name, value } => (
                    value,
                    "EXACTLY",
                    serde_json::json!({"SingleHeader":{"Name":name.to_ascii_lowercase()}}),
                ),
                DefensiveCondition::HeaderContains { name, value } => (
                    value,
                    "CONTAINS",
                    serde_json::json!({"SingleHeader":{"Name":name.to_ascii_lowercase()}}),
                ),
                DefensiveCondition::Ja3Equals { value } => (
                    value,
                    "EXACTLY",
                    serde_json::json!({"JA3Fingerprint":{"FallbackBehavior":"NO_MATCH"}}),
                ),
                DefensiveCondition::Ja4Equals { value } => (
                    value,
                    "EXACTLY",
                    serde_json::json!({"JA4Fingerprint":{"FallbackBehavior":"NO_MATCH"}}),
                ),
                DefensiveCondition::UserAgentEquals { value } => (
                    value,
                    "EXACTLY",
                    serde_json::json!({"SingleHeader":{"Name":"user-agent"}}),
                ),
                DefensiveCondition::UserAgentContains { value } => (
                    value,
                    "CONTAINS",
                    serde_json::json!({"SingleHeader":{"Name":"user-agent"}}),
                ),
                _ => unreachable!(),
            };
            serde_json::json!({"ByteMatchStatement":{"SearchString":value,"FieldToMatch":field,"TextTransformations":[{"Priority":0,"Type":"NONE"}],"PositionalConstraint":constraint}})
        }
    }
}
fn terraform_rule(c: &DefensiveCandidate, priority: u32) -> String {
    format!("# Generated by Shenron. Defensive candidate only; review before deployment.\n# CVEs: {}\n# Recommended initial action: COUNT\n# Threat coverage: {:?}; other historical matches: {}\n# Integrate this rule fragment into an existing aws_wafv2_web_acl.\n\nrule {{\n  name     = {}\n  priority = {}\n\n  action {{\n    count {{}}\n  }}\n\n{}\n  visibility_config {{\n    cloudwatch_metrics_enabled = true\n    metric_name                = {}\n    sampled_requests_enabled   = true\n  }}\n}}\n", c.cves.join(", "), c.evidence.threat_coverage, c.evidence.other_historical_matches, hcl(&safe_name(&c.id)), priority, terraform_statement(&c.conditions, 2), hcl(&safe_name(&c.id)))
}
fn terraform_statement(c: &DefensiveCondition, indent: usize) -> String {
    let pad = " ".repeat(indent);
    match c {
        DefensiveCondition::And { conditions } | DefensiveCondition::Or { conditions } => {
            let operator = if matches!(c, DefensiveCondition::And { .. }) {
                "and_statement"
            } else {
                "or_statement"
            };
            let children = conditions
                .iter()
                .map(|child| terraform_statement(child, indent + 4))
                .collect::<Vec<_>>()
                .join("\n");
            format!("{pad}statement {{\n{pad}  {operator} {{\n{children}\n{pad}  }}\n{pad}}}")
        }
        DefensiveCondition::Not { condition } => format!(
            "{pad}statement {{\n{pad}  not_statement {{\n{}\n{pad}  }}\n{pad}}}",
            terraform_statement(condition, indent + 4)
        ),
        _ => {
            let (value, constraint, field) = match c {
                DefensiveCondition::UriEquals { value } => {
                    (value, "EXACTLY", "uri_path {}".to_owned())
                }
                DefensiveCondition::UriContains { value } => {
                    (value, "CONTAINS", "uri_path {}".to_owned())
                }
                DefensiveCondition::UriStartsWith { value } => {
                    (value, "STARTS_WITH", "uri_path {}".to_owned())
                }
                DefensiveCondition::QueryEquals { value } => {
                    (value, "EXACTLY", "query_string {}".to_owned())
                }
                DefensiveCondition::QueryContains { value } => {
                    (value, "CONTAINS", "query_string {}".to_owned())
                }
                DefensiveCondition::MethodEquals { value } => {
                    (value, "EXACTLY", "method {}".to_owned())
                }
                DefensiveCondition::HostEquals { value } => (
                    value,
                    "EXACTLY",
                    "single_header { name = \"host\" }".to_owned(),
                ),
                DefensiveCondition::HeaderEquals { name, value } => (
                    value,
                    "EXACTLY",
                    format!(
                        "single_header {{ name = {} }}",
                        hcl(&name.to_ascii_lowercase())
                    ),
                ),
                DefensiveCondition::HeaderContains { name, value } => (
                    value,
                    "CONTAINS",
                    format!(
                        "single_header {{ name = {} }}",
                        hcl(&name.to_ascii_lowercase())
                    ),
                ),
                DefensiveCondition::Ja3Equals { value } => (
                    value,
                    "EXACTLY",
                    "ja3_fingerprint { fallback_behavior = \"NO_MATCH\" }".to_owned(),
                ),
                DefensiveCondition::Ja4Equals { value } => (
                    value,
                    "EXACTLY",
                    "ja4_fingerprint { fallback_behavior = \"NO_MATCH\" }".to_owned(),
                ),
                DefensiveCondition::UserAgentEquals { value } => (
                    value,
                    "EXACTLY",
                    "single_header { name = \"user-agent\" }".to_owned(),
                ),
                DefensiveCondition::UserAgentContains { value } => (
                    value,
                    "CONTAINS",
                    "single_header { name = \"user-agent\" }".to_owned(),
                ),
                _ => unreachable!(),
            };
            format!("{pad}statement {{\n{pad}  byte_match_statement {{\n{pad}    search_string         = {}\n{pad}    positional_constraint = \"{constraint}\"\n{pad}    field_to_match {{\n{pad}      {field}\n{pad}    }}\n{pad}    text_transformation {{\n{pad}      priority = 0\n{pad}      type     = \"NONE\"\n{pad}    }}\n{pad}  }}\n{pad}}}", hcl(value))
        }
    }
}
fn ossec_rule(c: &DefensiveCandidate, id: u32) -> Result<String> {
    if !(100..=99_999).contains(&id) {
        bail!("OSSEC rule id must be 100 through 99999");
    }
    Ok(format!("<!-- Generated by Shenron. Detection control only: this does not block requests. -->\n<!-- Requires nginx/Apache combined logs decoded as web-log. Test with ossec-logtest. -->\n<group name=\"shenron,web,\">\n  <rule id=\"{}\" level=\"10\">\n    <category>web-log</category>\n    <pcre2>{}</pcre2>\n    <description>Shenron candidate {} detection</description>\n{}  </rule>\n</group>\n", id, xml(&ossec_pattern(&c.conditions)?), xml(&c.id), c.cves.iter().map(|v| format!("    <info type=\"cve\">{}</info>\n", xml(v))).collect::<String>()))
}
fn ossec_pattern(c: &DefensiveCondition) -> Result<String> {
    let mut leaves = Vec::new();
    flatten_and(c, &mut leaves)?;
    let mut pieces = Vec::new();
    for c in leaves {
        match c {
            DefensiveCondition::MethodEquals { value } => {
                pieces.push(format!("(?=.*\\\"{} )", regex(value)))
            }
            DefensiveCondition::UriEquals { value } => pieces.push(format!(
                "(?=.*\\\"[A-Z]+ {}(?:\\?[^ ]*)? HTTP/)",
                regex(value)
            )),
            DefensiveCondition::UriContains { value } => {
                pieces.push(format!("(?=.*\\\"[A-Z]+ [^ ]*{}[^ ]* HTTP/)", regex(value)))
            }
            DefensiveCondition::UriStartsWith { value } => {
                pieces.push(format!("(?=.*\\\"[A-Z]+ {}[^ ]* HTTP/)", regex(value)))
            }
            DefensiveCondition::QueryEquals { value } => {
                pieces.push(format!("(?=.*\\\"[A-Z]+ [^ ]*\\?{} HTTP/)", regex(value)))
            }
            DefensiveCondition::QueryContains { value } => pieces.push(format!(
                "(?=.*\\\"[A-Z]+ [^ ]*\\?[^ ]*{}[^ ]* HTTP/)",
                regex(value)
            )),
            DefensiveCondition::UserAgentEquals { value } => {
                pieces.push(format!("(?=.*\\\"[^\\\"]*\\\" \\\"{}\\\"$)", regex(value)))
            }
            DefensiveCondition::UserAgentContains { value } => pieces.push(format!(
                "(?=.*\\\"[^\\\"]*\\\" \\\"[^\\\"]*{}[^\\\"]*\\\"$)",
                regex(value)
            )),
            _ => bail!("unsupported OSSEC raw-log condition"),
        }
    }
    Ok(format!("^{}.*$", pieces.join("")))
}
fn flatten_and<'a>(
    c: &'a DefensiveCondition,
    output: &mut Vec<&'a DefensiveCondition>,
) -> Result<()> {
    match c {
        DefensiveCondition::And { conditions } => {
            for child in conditions {
                flatten_and(child, output)?;
            }
        }
        _ if ossec_shape_supported(c) => output.push(c),
        _ => bail!("OSSEC exporter requires an AND of raw combined-log conditions"),
    }
    Ok(())
}
fn write_evidence(
    c: &DefensiveCandidate,
    report: &CompatibilityReport,
    output: &Path,
) -> Result<()> {
    let sidecar = output.with_file_name(format!(
        "{}.evidence.json",
        output
            .file_stem()
            .and_then(|v| v.to_str())
            .unwrap_or("candidate")
    ));
    ensure_new(&sidecar)?;
    serde_json::to_writer_pretty(
        fs::File::create(sidecar)?,
        &serde_json::json!({"candidate_id":c.id,"cves":c.cves,"kev":c.kev,"evidence":c.evidence,"recommended_initial_action":"COUNT","backend_compatibility":report,"safety_note":"Candidate artifact only. Human review is required; no deployment was performed."}),
    )?;
    Ok(())
}
fn ensure_new(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("refusing to overwrite existing output: {}", path.display());
    }
    if path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("research") | Some("nuclei-templates")
        )
    }) {
        bail!("refusing to write exporter output into frozen research or a template checkout");
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}
fn reject_sensitive(c: &DefensiveCandidate) -> Result<()> {
    let mut values = Vec::new();
    c.conditions.values(&mut values);
    if values.iter().any(|v| {
        let v = v.to_ascii_lowercase();
        [
            "authorization",
            "cookie",
            "token",
            "secret",
            "api-key",
            "apikey",
            "bearer ",
        ]
        .iter()
        .any(|needle| v.contains(needle))
    }) {
        bail!("export refused: candidate condition appears to contain a credential, token, cookie, or personal secret");
    }
    Ok(())
}
fn safe_name(value: &str) -> String {
    let mut name: String = value
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    name.truncate(128);
    name.trim_matches('-').to_owned()
}
fn hcl(v: &str) -> String {
    serde_json::to_string(v).unwrap()
}
fn xml(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
fn regex(v: &str) -> String {
    regex::escape(v)
}
