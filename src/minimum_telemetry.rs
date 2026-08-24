//! Measured, conservative minimum-telemetry analysis.
//!
//! This module consumes the static Nuclei Detection IR and frozen local KEV /
//! telemetry reports. It never executes a template, sends a request, or logs
//! a template's header values.

use std::{collections::BTreeSet, fs::File, path::Path};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::nuclei::{combined_header_dependencies, Detectability, HeaderDependency};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Sensitivity {
    Safe,
    Conditional,
    Sensitive,
    HighRisk,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Recommendation {
    Recommended,
    Optional,
    Conditional,
    NotRecommended,
}

/// The only fields in the measured greedy SAFE profile. Keeping this list in
/// code lets documentation examples be checked for drift.
pub const RECOMMENDED_SAFE_HEADERS: [&str; 5] = [
    "content-type",
    "accept",
    "accept-encoding",
    "soapaction",
    "accept-language",
];

#[derive(Debug, Serialize)]
pub struct CoverageSnapshot {
    pub observable_templates: usize,
    pub unique_cves: usize,
    pub cisa_kev_cves: usize,
    pub web_relevant_kev_cves: usize,
    pub aws_waf_observable_recovered_percent: f64,
}

#[derive(Debug, Serialize)]
pub struct HeaderTemplateRecord {
    pub template_id: String,
    pub cves: Vec<String>,
    pub template_path: String,
    pub detectability: Detectability,
    pub required_headers: Vec<String>,
    pub multiple_headers_required: bool,
    pub value_matters: bool,
    pub presence_only: bool,
    pub cisa_kev_cves: Vec<String>,
    pub web_relevant_kev_cves: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HeaderRanking {
    pub header: String,
    pub sensitivity: Sensitivity,
    pub recommendation: Recommendation,
    pub risk_rationale: String,
    pub templates: usize,
    pub unique_cves: usize,
    pub cisa_kev_cves: usize,
    pub web_relevant_kev_cves: usize,
    pub single_header_templates: usize,
    pub multi_header_templates: usize,
    pub marginal: MarginalGain,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct MarginalGain {
    pub additional_templates: usize,
    pub additional_unique_cves: usize,
    pub additional_cisa_kev_cves: usize,
    pub additional_web_relevant_kev_cves: usize,
}

#[derive(Debug, Serialize)]
pub struct GreedyStep {
    pub step: usize,
    pub added_field: String,
    pub gain: MarginalGain,
    pub coverage: CoverageSnapshot,
}

#[derive(Debug, Serialize)]
pub struct MinimumTelemetryReport {
    pub nuclei_revision: String,
    pub methodology: String,
    pub baseline: CoverageSnapshot,
    pub header_dependent_templates: Vec<HeaderTemplateRecord>,
    pub header_rankings: Vec<HeaderRanking>,
    pub host_counterfactual: MarginalGain,
    pub greedy_safe_profile: Vec<GreedyStep>,
    pub greedy_stop_reason: String,
    pub all_safe_headers_counterfactual: CoverageSnapshot,
    pub all_required_headers_counterfactual: CoverageSnapshot,
    pub request_body_counterfactual: CounterfactualNote,
    pub ja4_note: String,
}

#[derive(Debug, Serialize)]
pub struct CounterfactualNote {
    pub templates_with_request_body_semantics: usize,
    pub additional_observable_templates: Option<usize>,
    pub operational_recommendation: Recommendation,
    pub note: String,
}

#[derive(Debug, Deserialize)]
struct ComparisonInput {
    reports: Vec<ComparisonSource>,
}
#[derive(Debug, Deserialize)]
struct ComparisonSource {
    telemetry: String,
    templates: Vec<ComparisonTemplate>,
}
#[derive(Debug, Deserialize)]
struct ComparisonTemplate {
    cves: Vec<String>,
    level: Detectability,
}
#[derive(Debug, Deserialize)]
struct KevInput {
    entries: Vec<KevEntry>,
}
#[derive(Debug, Deserialize)]
struct KevEntry {
    cve: String,
    web_relevance: String,
}

pub fn analyze(
    templates: &Path,
    comparison_path: &Path,
    kev_path: &Path,
    nuclei_revision: &str,
) -> anyhow::Result<MinimumTelemetryReport> {
    let comparison: ComparisonInput =
        serde_json::from_reader(File::open(comparison_path).with_context(|| {
            format!("opening comparison report {}", comparison_path.display())
        })?)?;
    let kev: KevInput = serde_json::from_reader(
        File::open(kev_path)
            .with_context(|| format!("opening KEV report {}", kev_path.display()))?,
    )?;
    let kev_cves: BTreeSet<_> = kev
        .entries
        .iter()
        .map(|entry| normalize(&entry.cve))
        .collect();
    let web_kev_cves: BTreeSet<_> = kev
        .entries
        .iter()
        .filter(|entry| entry.web_relevance == "WEB_RELEVANT")
        .map(|entry| normalize(&entry.cve))
        .collect();
    let source = comparison
        .reports
        .iter()
        .find(|source| source.telemetry == "nginx-combined")
        .context("comparison does not contain the nginx-combined baseline")?;
    let aws = comparison
        .reports
        .iter()
        .find(|source| source.telemetry == "aws-waf")
        .context("comparison does not contain the aws-waf reference")?;
    let baseline_cves = observable_cves(&source.templates);
    let aws_observable = source_count(&aws.templates);
    let dependencies = combined_header_dependencies(templates);
    let records = records(&dependencies, &kev_cves, &web_kev_cves);
    let baseline = snapshot(
        source_count(&source.templates),
        &baseline_cves,
        &kev_cves,
        &web_kev_cves,
        aws_observable,
    );
    let candidate_names: BTreeSet<_> = dependencies
        .iter()
        .flat_map(|dependency| dependency.headers.iter().map(|header| header.name.clone()))
        .collect();
    let mut rankings = candidate_names
        .iter()
        .map(|header| {
            let (sensitivity, recommendation, rationale) = classify(header);
            let gain = gain_for(
                &dependencies,
                &BTreeSet::from([header.clone()]),
                &kev_cves,
                &web_kev_cves,
            );
            let templates = dependencies_for_header(&dependencies, header);
            HeaderRanking {
                header: header.clone(),
                sensitivity,
                recommendation,
                risk_rationale: rationale.to_owned(),
                templates: templates.len(),
                unique_cves: cves(&templates).len(),
                cisa_kev_cves: cves(&templates).intersection(&kev_cves).count(),
                web_relevant_kev_cves: cves(&templates).intersection(&web_kev_cves).count(),
                single_header_templates: templates
                    .iter()
                    .filter(|item| item.headers.len() == 1)
                    .count(),
                multi_header_templates: templates
                    .iter()
                    .filter(|item| item.headers.len() > 1)
                    .count(),
                marginal: gain,
            }
        })
        .collect::<Vec<_>>();
    rankings.sort_by(|left, right| {
        right
            .marginal
            .additional_templates
            .cmp(&left.marginal.additional_templates)
            .then_with(|| {
                right
                    .marginal
                    .additional_web_relevant_kev_cves
                    .cmp(&left.marginal.additional_web_relevant_kev_cves)
            })
            .then_with(|| left.header.cmp(&right.header))
    });

    let safe: BTreeSet<_> = rankings
        .iter()
        .filter(|item| matches!(item.sensitivity, Sensitivity::Safe))
        .map(|item| item.header.clone())
        .collect();
    let mut selected = BTreeSet::new();
    let mut greedy_safe_profile = Vec::new();
    loop {
        let best = safe
            .iter()
            .filter(|header| !selected.contains(*header))
            .map(|header| {
                let mut trial = selected.clone();
                trial.insert(header.clone());
                (
                    header.clone(),
                    gain_for(&dependencies, &trial, &kev_cves, &web_kev_cves),
                )
            })
            .max_by(|left, right| {
                left.1
                    .additional_templates
                    .cmp(&right.1.additional_templates)
                    .then_with(|| {
                        left.1
                            .additional_web_relevant_kev_cves
                            .cmp(&right.1.additional_web_relevant_kev_cves)
                    })
                    .then_with(|| right.0.cmp(&left.0))
            });
        let Some((header, total_gain)) = best else {
            break;
        };
        let previous = gain_for(&dependencies, &selected, &kev_cves, &web_kev_cves);
        let marginal = subtract(total_gain.clone(), previous);
        if marginal.additional_templates == 0 {
            break;
        }
        selected.insert(header.clone());
        let recovered = gain_for(&dependencies, &selected, &kev_cves, &web_kev_cves);
        let profile_cves = union(&baseline_cves, &recovered_cves(&dependencies, &selected));
        greedy_safe_profile.push(GreedyStep {
            step: greedy_safe_profile.len() + 1,
            added_field: header,
            gain: marginal,
            coverage: snapshot(
                baseline.observable_templates + recovered.additional_templates,
                &profile_cves,
                &kev_cves,
                &web_kev_cves,
                aws_observable,
            ),
        });
    }
    let all_safe_gain = gain_for(&dependencies, &safe, &kev_cves, &web_kev_cves);
    let all_safe_cves = union(&baseline_cves, &recovered_cves(&dependencies, &safe));
    let all_gain = gain_for(&dependencies, &candidate_names, &kev_cves, &web_kev_cves);
    let all_cves = union(
        &baseline_cves,
        &recovered_cves(&dependencies, &candidate_names),
    );
    let host_counterfactual = gain_for(
        &dependencies,
        &BTreeSet::from(["host".to_owned()]),
        &kev_cves,
        &web_kev_cves,
    );
    Ok(MinimumTelemetryReport {
        nuclei_revision: nuclei_revision.to_owned(),
        methodology: "Starting from the frozen nginx/Apache combined baseline, each field is assessed only when every required non-baseline header for a template would be available. Header names are lowercase ASCII because HTTP names are case-insensitive. Exact header values are never retained in this report. Greedy selection is transparent and not mathematically optimal.".to_owned(),
        baseline,
        header_dependent_templates: records,
        header_rankings: rankings,
        host_counterfactual,
        greedy_stop_reason: "No remaining SAFE field produced a positive marginal observable-template gain under the conservative all-required-header rule.".to_owned(),
        greedy_safe_profile,
        all_safe_headers_counterfactual: snapshot(source_count(&source.templates) + all_safe_gain.additional_templates, &all_safe_cves, &kev_cves, &web_kev_cves, aws_observable),
        all_required_headers_counterfactual: snapshot(source_count(&source.templates) + all_gain.additional_templates, &all_cves, &kev_cves, &web_kev_cves, aws_observable),
        request_body_counterfactual: CounterfactualNote { templates_with_request_body_semantics: 1584, additional_observable_templates: None, operational_recommendation: Recommendation::NotRecommended, note: "The frozen inventory records 1,584 HTTP CVE templates with request-body semantics, but Shenron's passive Detection IR deliberately does not model body matching. A numeric gain would overstate evidence; complete request-body logging is not recommended by default.".to_owned() },
        ja4_note: "JA4 is enrichment for pivots and defensive-rule refinement. No Nuclei-derived CVE observability gain is assigned because this Detection IR has no JA4 requirement.".to_owned(),
    })
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}
fn observable(level: Detectability) -> bool {
    matches!(level, Detectability::High | Detectability::Medium)
}
fn source_count(templates: &[ComparisonTemplate]) -> usize {
    templates
        .iter()
        .filter(|item| observable(item.level))
        .count()
}
fn observable_cves(templates: &[ComparisonTemplate]) -> BTreeSet<String> {
    templates
        .iter()
        .filter(|item| observable(item.level))
        .flat_map(|item| item.cves.iter().map(|cve| normalize(cve)))
        .collect()
}
fn cves(items: &[&HeaderDependency]) -> BTreeSet<String> {
    items
        .iter()
        .flat_map(|item| item.cves.iter().map(|cve| normalize(cve)))
        .collect()
}
fn union(left: &BTreeSet<String>, right: &BTreeSet<String>) -> BTreeSet<String> {
    left.union(right).cloned().collect()
}
fn dependencies_for_header<'a>(
    items: &'a [HeaderDependency],
    header: &str,
) -> Vec<&'a HeaderDependency> {
    items
        .iter()
        .filter(|item| item.headers.iter().any(|required| required.name == header))
        .collect()
}
fn required_names(item: &HeaderDependency) -> BTreeSet<String> {
    item.headers
        .iter()
        .map(|header| header.name.clone())
        .collect()
}
fn recoverable(item: &HeaderDependency, fields: &BTreeSet<String>) -> bool {
    observable(item.detectability) && required_names(item).is_subset(fields)
}
fn recovered<'a>(
    items: &'a [HeaderDependency],
    fields: &BTreeSet<String>,
) -> Vec<&'a HeaderDependency> {
    items
        .iter()
        .filter(|item| recoverable(item, fields))
        .collect()
}
fn recovered_cves(items: &[HeaderDependency], fields: &BTreeSet<String>) -> BTreeSet<String> {
    cves(&recovered(items, fields))
}
fn gain_for(
    items: &[HeaderDependency],
    fields: &BTreeSet<String>,
    kev: &BTreeSet<String>,
    web_kev: &BTreeSet<String>,
) -> MarginalGain {
    let selected = recovered(items, fields);
    let values = cves(&selected);
    MarginalGain {
        additional_templates: selected.len(),
        additional_unique_cves: values.len(),
        additional_cisa_kev_cves: values.intersection(kev).count(),
        additional_web_relevant_kev_cves: values.intersection(web_kev).count(),
    }
}
fn subtract(total: MarginalGain, prior: MarginalGain) -> MarginalGain {
    MarginalGain {
        additional_templates: total.additional_templates - prior.additional_templates,
        additional_unique_cves: total
            .additional_unique_cves
            .saturating_sub(prior.additional_unique_cves),
        additional_cisa_kev_cves: total
            .additional_cisa_kev_cves
            .saturating_sub(prior.additional_cisa_kev_cves),
        additional_web_relevant_kev_cves: total
            .additional_web_relevant_kev_cves
            .saturating_sub(prior.additional_web_relevant_kev_cves),
    }
}
fn snapshot(
    templates: usize,
    cve_set: &BTreeSet<String>,
    kev: &BTreeSet<String>,
    web_kev: &BTreeSet<String>,
    aws: usize,
) -> CoverageSnapshot {
    CoverageSnapshot {
        observable_templates: templates,
        unique_cves: cve_set.len(),
        cisa_kev_cves: cve_set.intersection(kev).count(),
        web_relevant_kev_cves: cve_set.intersection(web_kev).count(),
        aws_waf_observable_recovered_percent: templates as f64 / aws as f64 * 100.0,
    }
}
fn records(
    items: &[HeaderDependency],
    kev: &BTreeSet<String>,
    web_kev: &BTreeSet<String>,
) -> Vec<HeaderTemplateRecord> {
    items
        .iter()
        .map(|item| {
            let cves = item
                .cves
                .iter()
                .map(|cve| normalize(cve))
                .collect::<Vec<_>>();
            HeaderTemplateRecord {
                template_id: item.template_id.clone(),
                cves: cves.clone(),
                template_path: item.template_path.clone(),
                detectability: item.detectability,
                required_headers: item
                    .headers
                    .iter()
                    .map(|header| header.name.clone())
                    .collect(),
                multiple_headers_required: item.multiple_headers_required,
                value_matters: item.headers.iter().any(|header| header.value_matters),
                presence_only: item.headers.iter().all(|header| header.presence_only),
                cisa_kev_cves: cves
                    .iter()
                    .filter(|cve| kev.contains(*cve))
                    .cloned()
                    .collect(),
                web_relevant_kev_cves: cves
                    .iter()
                    .filter(|cve| web_kev.contains(*cve))
                    .cloned()
                    .collect(),
            }
        })
        .collect()
}
fn classify(header: &str) -> (Sensitivity, Recommendation, &'static str) {
    match header { "content-type" | "accept" | "accept-encoding" | "accept-language" | "soapaction" => (Sensitivity::Safe, Recommendation::Recommended, "Protocol/content-negotiation metadata; normally does not contain credentials or request content."), "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" | "x-auth-token" | "x-access-token" | "token" => (Sensitivity::Sensitive, Recommendation::NotRecommended, "Commonly carries credentials, session material, or API secrets; raw values should not be logged."), "host" | "referer" | "origin" | "x-forwarded-for" | "x-requested-with" => (Sensitivity::Conditional, Recommendation::Conditional, "Useful context but may disclose tenant identity, internal topology, URL parameters, or client identifiers."), _ => (Sensitivity::Conditional, Recommendation::Conditional, "Header semantics and values are organization-specific; review before selecting for logging.") }
}
