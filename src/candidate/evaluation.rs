//! Read-only candidate evaluation on explicitly selected local corpora.
use super::{Backend, CompatibilityReport, DefensiveCandidate, DefensiveCondition};
use crate::{
    concentration::{
        PrivatePathConcentration, PrivateSourceConcentration, RequestConcentration,
        RequestConcentrationSummary,
    },
    event::{RawRetention, TelemetryProfile, WebEvent},
    investigation::sorted_input_files,
    production::{stream_referenced_events, PathProvenance},
};
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const NOTE: &str = "PRIVATE independent-corpus COUNT evaluation. Cohort roles and labels are analyst declarations, not verified ground truth. Matches are not attacks and unmatched records are not established benign traffic. This report does not set replay_completed, authorize export, measure false-positive rate, or deploy a control. Review matched paths/statuses and coverage on representative separate corpora. Do not share raw peer/path detail.";

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortRole {
    Development,
    Reference,
    Holdout,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCorpus {
    pub input: PathBuf,
    pub telemetry_profile: TelemetryProfile,
    pub role: CohortRole,
    pub label: Option<String>,
    /// Optional frozen whole-file provenance. Mismatches abort, never silently accept drift.
    pub expected_corpus: Option<Vec<PathProvenance>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationPlan {
    pub corpora: Vec<EvaluationCorpus>,
}

#[derive(Debug, Serialize)]
pub struct CorpusEvaluation {
    pub role: CohortRole,
    pub label: Option<String>,
    pub telemetry_profile: TelemetryProfile,
    pub corpus: Vec<PathProvenance>,
    pub parseable_records: u64,
    pub parse_errors: u64,
    pub source_address_unavailable: u64,
    pub source_address_invalid: u64,
    /// Any referenced leaf lacks a value; not necessarily an indeterminate whole expression (OR/NOT).
    pub records_with_absent_condition_fields: u64,
    pub matching_records: u64,
    pub match_share: Option<f64>,
    pub matches: RequestConcentrationSummary,
    pub top_paths: Vec<PrivatePathConcentration>,
    pub top_peers: Vec<PrivateSourceConcentration>,
    pub retained_paths_omitted_from_display: usize,
    pub retained_peers_omitted_from_display: usize,
    pub files_with_identical_bytes_in_another_cohort: usize,
    pub aws_compatibility: CompatibilityReport,
}

#[derive(Debug, Serialize)]
pub struct EvaluationReport {
    pub report_kind: &'static str,
    pub safety_note: &'static str,
    pub candidate_sha256: String,
    pub plan_sha256: String,
    pub maximum_displayed_paths_and_peers: usize,
    pub corpora: Vec<CorpusEvaluation>,
}

pub fn evaluate(
    candidate_path: &Path,
    plan_path: &Path,
    maximum_details: usize,
) -> anyhow::Result<EvaluationReport> {
    if maximum_details == 0 {
        bail!("candidate evaluation requires a positive finite detail limit");
    }
    let candidate_bytes = fs::read(candidate_path)?;
    let candidate: DefensiveCandidate = serde_json::from_slice(&candidate_bytes)?;
    super::validate_address_sets(&candidate.conditions)?;
    let plan_bytes = fs::read(plan_path)?;
    let plan: EvaluationPlan =
        serde_json::from_slice(&plan_bytes).context("reading private evaluation plan")?;
    if plan.corpora.len() < 2 {
        bail!("evaluation requires at least two explicitly selected corpora");
    }
    let mut report = EvaluationReport {
        report_kind: "PRIVATE_CANDIDATE_CORPUS_EVALUATION",
        safety_note: NOTE,
        candidate_sha256: digest(&candidate_bytes),
        plan_sha256: digest(&plan_bytes),
        maximum_displayed_paths_and_peers: maximum_details,
        corpora: Vec::new(),
    };
    let uses_addresses = super::uses_source_address_set(&candidate);
    for cohort in plan.corpora {
        let input = if cohort.input.is_absolute() {
            cohort.input
        } else {
            plan_path
                .parent()
                .unwrap_or(Path::new("."))
                .join(cohort.input)
        };
        let caps = cohort.telemetry_profile.capabilities();
        let mut matched = RequestConcentration::with_capabilities(caps.response_bytes, caps.status);
        let mut row = CorpusEvaluation {
            role: cohort.role,
            label: cohort.label,
            telemetry_profile: cohort.telemetry_profile,
            corpus: Vec::new(),
            parseable_records: 0,
            parse_errors: 0,
            source_address_unavailable: 0,
            source_address_invalid: 0,
            records_with_absent_condition_fields: 0,
            matching_records: 0,
            match_share: None,
            matches: matched.summary(),
            top_paths: Vec::new(),
            top_peers: Vec::new(),
            retained_paths_omitted_from_display: 0,
            retained_peers_omitted_from_display: 0,
            files_with_identical_bytes_in_another_cohort: 0,
            aws_compatibility: super::compatibility(
                &candidate,
                Backend::AwsWafJson,
                cohort.telemetry_profile,
            ),
        };
        for path in sorted_input_files(&input)? {
            row.corpus.push(stream_referenced_events(
                &path,
                cohort.telemetry_profile,
                RawRetention::Drop,
                |_, event| {
                    let Ok(event) = event else {
                        row.parse_errors += 1;
                        return Ok(());
                    };
                    row.parseable_records += 1;
                    if absent_condition_field(&candidate.conditions, &event) {
                        row.records_with_absent_condition_fields += 1;
                    }
                    // Match the established replay handling of frozen source-address sets.
                    if uses_addresses {
                        match event.source_ip.as_deref() {
                            None => {
                                row.source_address_unavailable += 1;
                                return Ok(());
                            }
                            Some(ip) if ip.parse::<std::net::IpAddr>().is_err() => {
                                row.source_address_invalid += 1;
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                    if candidate.conditions.matches(&event) {
                        row.matching_records += 1;
                        matched.observe(&event);
                    }
                    Ok(())
                },
            )?);
        }
        if let Some(mut expected) = cohort.expected_corpus {
            expected.sort_by(|a, b| a.path.cmp(&b.path));
            if expected != row.corpus {
                bail!("evaluation corpus differs from its frozen expected provenance; results were not accepted");
            }
        }
        row.match_share = (row.parseable_records > 0)
            .then(|| row.matching_records as f64 / row.parseable_records as f64);
        let private = matched.private_report();
        row.matches = private.summary;
        row.retained_paths_omitted_from_display =
            private.paths.len().saturating_sub(maximum_details);
        row.retained_peers_omitted_from_display =
            private.source_ips.len().saturating_sub(maximum_details);
        row.top_paths = private.paths.into_iter().take(maximum_details).collect();
        row.top_peers = private
            .source_ips
            .into_iter()
            .take(maximum_details)
            .collect();
        report.corpora.push(row);
    }
    let mut owners: BTreeMap<String, std::collections::BTreeSet<usize>> = BTreeMap::new();
    for (index, row) in report.corpora.iter().enumerate() {
        for file in &row.corpus {
            owners
                .entry(input_fingerprint(file)?.to_owned())
                .or_default()
                .insert(index);
        }
    }
    for row in &mut report.corpora {
        let mut shared_files = 0;
        for file in &row.corpus {
            let fingerprint = input_fingerprint(file)?;
            let cohort_owners = owners
                .get(fingerprint)
                .context("input fingerprint missing from corpus ownership index")?;
            shared_files += usize::from(cohort_owners.len() > 1);
        }
        row.files_with_identical_bytes_in_another_cohort = shared_files;
    }
    Ok(report)
}

fn input_fingerprint(file: &PathProvenance) -> anyhow::Result<&str> {
    file.sha256
        .as_deref()
        .context("input fingerprint unavailable for corpus evaluation provenance")
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn absent_condition_field(condition: &DefensiveCondition, e: &WebEvent) -> bool {
    use DefensiveCondition::*;
    match condition {
        SourceAddressSet { .. } => e.source_ip.is_none(),
        UriEquals { .. }
        | UriContains { .. }
        | UriEqualsAsciiCaseInsensitive { .. }
        | UriContainsAsciiCaseInsensitive { .. }
        | UriStartsWith { .. } => e.uri_path.is_none(),
        QueryEquals { .. } | QueryContains { .. } => e.uri_query.is_none(),
        MethodEquals { .. } => e.method.is_none(),
        HostEquals { .. } => e.host.is_none(),
        HeaderEquals { name, .. } | HeaderContains { name, .. } => {
            !e.headers.iter().any(|h| h.name.eq_ignore_ascii_case(name))
        }
        Ja3Equals { .. } => e.ja3.is_none(),
        Ja4Equals { .. } => e.ja4.is_none(),
        UserAgentEquals { .. } | UserAgentContains { .. } => e.user_agent.is_none(),
        And { conditions } | Or { conditions } => {
            conditions.iter().any(|c| absent_condition_field(c, e))
        }
        Not { condition } => absent_condition_field(condition, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_input_fingerprint_is_an_error_without_exposing_the_private_path() {
        let mut file = PathProvenance {
            path: "/private/corpus.log".into(),
            byte_length: Some(42),
            sha256: None,
        };
        assert_eq!(
            input_fingerprint(&file).unwrap_err().to_string(),
            "input fingerprint unavailable for corpus evaluation provenance"
        );
        file.sha256 = Some("frozen-fingerprint".into());
        assert_eq!(input_fingerprint(&file).unwrap(), "frozen-fingerprint");
    }
}
