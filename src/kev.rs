//! Offline CISA KEV-to-Nuclei coverage analysis.
//!
//! This module consumes local JSON snapshots only. It neither contacts CISA nor
//! executes Nuclei templates; downloading a catalog is an analyst action.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::nuclei::{ConversionStatus, Detectability};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WebRelevance {
    WebRelevant,
    NotWebRelevant,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KevNucleiState {
    NoNucleiTemplate,
    NonHttpNucleiTemplate,
    HttpTemplateNotObservable,
    HttpTemplateObservableUnsupported,
    HttpTemplateConverted,
    HttpTemplateValidated,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevCatalog {
    catalog_version: Option<String>,
    date_released: Option<String>,
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub known_ransomware_campaign_use: String,
    pub required_action: String,
    pub due_date: String,
    pub short_description: String,
}

#[derive(Debug, Deserialize)]
struct NucleiCoverageInput {
    nuclei_revision: String,
    templates: Vec<NucleiTemplateInput>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct NucleiTemplateInput {
    template_id: String,
    cves: Vec<String>,
    template_path: String,
    protocol: String,
    detectability: Detectability,
    conversion_status: ConversionStatus,
    validation_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KevNucleiTemplate {
    pub template_id: String,
    pub template_path: String,
    pub protocol: String,
    pub detectability: Detectability,
    pub conversion_status: ConversionStatus,
    pub validation_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KevResult {
    pub cve: String,
    pub kev: KevEntry,
    pub web_relevance: WebRelevance,
    pub web_relevance_reasons: Vec<String>,
    pub nuclei_templates: Vec<KevNucleiTemplate>,
    pub best_nuclei_state: KevNucleiState,
    pub observable: bool,
    pub convertible: bool,
    pub validated: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct KevCoverageMetrics {
    pub total_kevs: usize,
    pub web_relevant: usize,
    pub not_web_relevant: usize,
    pub unknown_web_relevance: usize,
    pub web_relevant_with_nuclei_template: usize,
    pub web_relevant_with_http_nuclei_template: usize,
    pub web_relevant_observable: usize,
    pub web_relevant_convertible: usize,
    pub web_relevant_validated: usize,
    pub web_relevant_no_nuclei_template: usize,
}

#[derive(Debug, Serialize)]
pub struct KevCoverageReport {
    pub catalog_version: Option<String>,
    pub catalog_date_released: Option<String>,
    pub nuclei_revision: String,
    pub web_relevance_methodology: String,
    pub metrics: KevCoverageMetrics,
    pub state_counts: BTreeMap<String, usize>,
    pub entries: Vec<KevResult>,
}

pub fn coverage(kev_path: &Path, nuclei_report_path: &Path) -> anyhow::Result<KevCoverageReport> {
    let catalog: KevCatalog = serde_json::from_reader(
        fs::File::open(kev_path)
            .with_context(|| format!("opening KEV catalog {}", kev_path.display()))?,
    )
    .with_context(|| format!("parsing KEV catalog {}", kev_path.display()))?;
    let nuclei: NucleiCoverageInput = serde_json::from_reader(
        fs::File::open(nuclei_report_path)
            .with_context(|| format!("opening Nuclei report {}", nuclei_report_path.display()))?,
    )
    .with_context(|| format!("parsing Nuclei report {}", nuclei_report_path.display()))?;

    let mut templates_by_cve: BTreeMap<String, Vec<NucleiTemplateInput>> = BTreeMap::new();
    for template in nuclei.templates {
        for cve in &template.cves {
            templates_by_cve
                .entry(normalize_cve(cve))
                .or_default()
                .push(template.clone());
        }
    }

    let mut metrics = KevCoverageMetrics::default();
    let mut state_counts = BTreeMap::new();
    let mut entries = Vec::with_capacity(catalog.vulnerabilities.len());
    for kev in catalog.vulnerabilities {
        metrics.total_kevs += 1;
        let cve = normalize_cve(&kev.cve_id);
        let templates = templates_by_cve.remove(&cve).unwrap_or_default();
        let (web_relevance, web_relevance_reasons) = web_relevance(&kev, &templates);
        let observable = templates.iter().any(|template| {
            matches!(
                template.detectability,
                Detectability::High | Detectability::Medium
            )
        });
        let convertible = templates
            .iter()
            .any(|template| template.conversion_status == ConversionStatus::Supported);
        let validated = templates
            .iter()
            .any(|template| template.validation_status == "passed");
        let best_nuclei_state = best_state(&templates, observable, convertible, validated);
        *state_counts
            .entry(state_label(best_nuclei_state).to_owned())
            .or_default() += 1;

        match web_relevance {
            WebRelevance::WebRelevant => {
                metrics.web_relevant += 1;
                metrics.web_relevant_with_nuclei_template += usize::from(!templates.is_empty());
                let has_http = templates.iter().any(|template| template.protocol == "http");
                metrics.web_relevant_with_http_nuclei_template += usize::from(has_http);
                metrics.web_relevant_observable += usize::from(observable);
                metrics.web_relevant_convertible += usize::from(convertible);
                metrics.web_relevant_validated += usize::from(validated);
                metrics.web_relevant_no_nuclei_template += usize::from(templates.is_empty());
            }
            WebRelevance::NotWebRelevant => metrics.not_web_relevant += 1,
            WebRelevance::Unknown => metrics.unknown_web_relevance += 1,
        }
        entries.push(KevResult {
            cve,
            kev,
            web_relevance,
            web_relevance_reasons,
            nuclei_templates: templates
                .into_iter()
                .map(|template| KevNucleiTemplate {
                    template_id: template.template_id,
                    template_path: template.template_path,
                    protocol: template.protocol,
                    detectability: template.detectability,
                    conversion_status: template.conversion_status,
                    validation_status: template.validation_status,
                })
                .collect(),
            best_nuclei_state,
            observable,
            convertible,
            validated,
        });
    }
    entries.sort_by(|left, right| left.cve.cmp(&right.cve));
    Ok(KevCoverageReport {
        catalog_version: catalog.catalog_version,
        catalog_date_released: catalog.date_released,
        nuclei_revision: nuclei.nuclei_revision,
        web_relevance_methodology: "WEB_RELEVANT requires explicit HTTP/HTTPS/web-interface evidence in CISA's short description or at least one Nuclei HTTP template. NOT_WEB_RELEVANT requires one or more Nuclei templates and no HTTP template. All other entries are UNKNOWN; absence of Nuclei evidence is never treated as not detectable.".to_owned(),
        metrics,
        state_counts,
        entries,
    })
}

fn normalize_cve(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn web_relevance(kev: &KevEntry, templates: &[NucleiTemplateInput]) -> (WebRelevance, Vec<String>) {
    if templates.iter().any(|template| template.protocol == "http") {
        return (
            WebRelevance::WebRelevant,
            vec!["nuclei_http_template".to_owned()],
        );
    }
    let description = kev.short_description.to_ascii_lowercase();
    if [
        "http",
        "https",
        "web request",
        "web interface",
        "web application",
        "web server",
    ]
    .iter()
    .any(|needle| description.contains(needle))
    {
        return (
            WebRelevance::WebRelevant,
            vec!["cisa_description_explicit_web_transport".to_owned()],
        );
    }
    if !templates.is_empty() {
        return (
            WebRelevance::NotWebRelevant,
            vec!["only_non_http_nuclei_templates".to_owned()],
        );
    }
    (
        WebRelevance::Unknown,
        vec!["insufficient_evidence".to_owned()],
    )
}

fn best_state(
    templates: &[NucleiTemplateInput],
    observable: bool,
    convertible: bool,
    validated: bool,
) -> KevNucleiState {
    if templates.is_empty() {
        KevNucleiState::NoNucleiTemplate
    } else if !templates.iter().any(|template| template.protocol == "http") {
        KevNucleiState::NonHttpNucleiTemplate
    } else if validated {
        KevNucleiState::HttpTemplateValidated
    } else if convertible {
        KevNucleiState::HttpTemplateConverted
    } else if observable {
        KevNucleiState::HttpTemplateObservableUnsupported
    } else {
        KevNucleiState::HttpTemplateNotObservable
    }
}

fn state_label(state: KevNucleiState) -> &'static str {
    match state {
        KevNucleiState::NoNucleiTemplate => "NO_NUCLEI_TEMPLATE",
        KevNucleiState::NonHttpNucleiTemplate => "NON_HTTP_NUCLEI_TEMPLATE",
        KevNucleiState::HttpTemplateNotObservable => "HTTP_TEMPLATE_NOT_OBSERVABLE",
        KevNucleiState::HttpTemplateObservableUnsupported => "HTTP_TEMPLATE_OBSERVABLE_UNSUPPORTED",
        KevNucleiState::HttpTemplateConverted => "HTTP_TEMPLATE_CONVERTED",
        KevNucleiState::HttpTemplateValidated => "HTTP_TEMPLATE_VALIDATED",
    }
}
