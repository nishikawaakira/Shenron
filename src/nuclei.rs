//! Static, passive analysis of untrusted Nuclei template YAML.
//!
//! This module never executes template code, resolves arbitrary helpers, or
//! sends requests. It extracts only a narrow literal HTTP subset for hunting.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use walkdir::WalkDir;

use crate::{
    access_log::{parse_combined_line, AccessLogFormat},
    event::{HeaderCapability, TelemetryProfile},
};
use crate::{event::WebEvent, waf::parse_line};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Detectability {
    High,
    Medium,
    Low,
    Undetectable,
    #[default]
    Unknown,
}

/// How resistant a request-side match is to an incidental URI-only match.
/// This is neither attack severity nor evidence of exploitation or compromise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequestSpecificity {
    /// The request includes a query, fragment, or explicit header requirement.
    RequestSpecific,
    /// Only method and path matched; Nuclei response confirmation is absent.
    #[default]
    ResponseUnverified,
}

impl RequestSpecificity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::RequestSpecific => "request-specific",
            Self::ResponseUnverified => {
                "response-unverified (URI match only; Nuclei response confirmation not reproducible)"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConversionStatus {
    Supported,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemplateAnalysis {
    pub template_id: String,
    pub cves: Vec<String>,
    pub template_path: String,
    pub nuclei_revision: String,
    pub protocol: String,
    pub detectability: Detectability,
    pub detectability_reasons: Vec<String>,
    pub observable_features: Vec<String>,
    pub unavailable_features: Vec<String>,
    pub conversion_status: ConversionStatus,
    pub conversion_reason: Option<String>,
    pub synthetic_generation_status: String,
    pub validation_status: String,
    pub mutation_validation_status: String,
    pub near_miss_validation_status: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct InventoryMetrics {
    pub templates_scanned: usize,
    pub cve_templates: usize,
    pub http_cve_templates: usize,
    pub structured_http: usize,
    pub raw_http: usize,
    pub multiple_requests: usize,
    pub methods: usize,
    pub paths: usize,
    pub payloads: usize,
    pub attack_modes: usize,
    pub request_bodies: usize,
    pub request_headers: usize,
    pub query_parameters: usize,
    pub response_matchers: usize,
    pub dsl: usize,
    pub interactsh_oast: usize,
    pub redirects: usize,
    pub variables: usize,
    pub helper_functions: usize,
    pub extractors: usize,
    pub unsupported_constructs: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct CoverageMetrics {
    /// Request-side capability funnel. These counts describe the template
    /// corpus and converted IR only; they do not estimate field precision,
    /// exploitation, compromise, or a vulnerable product's presence.
    pub cve_templates: usize,
    pub http_cve_templates: usize,
    pub supported_request_ir_templates: usize,
    /// One template can yield multiple literal request alternatives.
    pub supported_request_ir_detections: usize,
    pub request_specific_detections: usize,
    pub response_unverified_detections: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub undetectable: usize,
    pub unknown: usize,
    pub convertible_in_principle: usize,
    pub supported_by_shenron: usize,
    pub unsupported_by_shenron: usize,
    pub templates_tested: usize,
    pub synthetic_events_generated: usize,
    pub expected_detections: usize,
    pub correct_detections: usize,
    pub missed_detections: usize,
    pub unexpected_matches: usize,
    pub mutation_cases: usize,
    pub mutation_failures: usize,
    pub near_miss_cases: usize,
    pub near_miss_failures: usize,
}

#[derive(Debug, Serialize)]
pub struct InventoryReport {
    pub nuclei_revision: String,
    pub metrics: InventoryMetrics,
    pub templates: Vec<TemplateAnalysis>,
    pub detectability_reasons: BTreeMap<String, usize>,
    pub implementation_gaps: BTreeMap<String, usize>,
    pub feature_combinations: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct CoverageReport {
    pub nuclei_revision: String,
    pub inventory: InventoryMetrics,
    pub coverage: CoverageMetrics,
    pub templates: Vec<TemplateAnalysis>,
    pub detectability_reasons: BTreeMap<String, usize>,
    pub implementation_gaps: BTreeMap<String, usize>,
    pub feature_combinations: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Serialize)]
pub struct TelemetryCoverageMetrics {
    pub http_cve_templates: usize,
    pub observable: usize,
    pub convertible: usize,
    pub validated: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub undetectable: usize,
    pub unknown: usize,
}

#[derive(Debug, Serialize)]
pub struct TelemetryCoverageReport {
    pub nuclei_revision: String,
    pub telemetry: TelemetryProfile,
    pub metrics: TelemetryCoverageMetrics,
    pub detectability_reasons: BTreeMap<String, usize>,
    pub templates: Vec<TelemetryTemplateAssessment>,
}

/// Per-template evidence for a telemetry-specific classification.  This is
/// intentionally derived from the one Nuclei Detection IR, not a source rule.
#[derive(Debug, Serialize)]
pub struct TelemetryTemplateAssessment {
    pub template_id: String,
    pub cves: Vec<String>,
    pub template_path: String,
    pub level: Detectability,
    pub reasons: Vec<String>,
    pub convertible: bool,
    pub validated: bool,
}

#[derive(Debug, Serialize)]
pub struct TelemetryComparisonReport {
    pub nuclei_revision: String,
    pub reports: Vec<TelemetryCoverageReport>,
}

/// A static request-header dependency recovered from the same narrow Nuclei
/// Detection IR used for benchmark conversion. Header values are deliberately
/// not serialized: minimum-telemetry research needs their matching semantics,
/// not potentially sensitive upstream payloads.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderDependency {
    pub template_id: String,
    pub cves: Vec<String>,
    pub template_path: String,
    pub detectability: Detectability,
    pub headers: Vec<HeaderRequirement>,
    pub multiple_headers_required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderRequirement {
    /// Lowercase ASCII for case-insensitive aggregate comparison.
    pub name: String,
    pub value_matters: bool,
    pub presence_only: bool,
    pub match_kind: HeaderMatchKind,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderMatchKind {
    ExactValue,
}

#[derive(Debug, Clone)]
struct NucleiDetection {
    method: String,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
    headers: Vec<(String, String)>,
}

/// A validated template identity paired with the same request matcher used by
/// the synthetic Nuclei coverage run. Production hunting filters this list by
/// the frozen report's passed validation status; it does not create a second
/// matching implementation.
#[derive(Debug, Clone)]
pub struct ValidatedNucleiDetection {
    pub template_id: String,
    pub cves: Vec<String>,
    pub detectability: Detectability,
    detection: NucleiDetection,
}

/// A serializable copy of the literal request conditions used by a validated
/// Nuclei Detection IR. It is static template-derived data, not telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestMatcherView {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub headers: Vec<(String, String)>,
    pub request_specificity: RequestSpecificity,
}

/// The template IDs eligible for a production hunt according to a frozen
/// Nuclei report. The selection intentionally requires all three gates:
/// supported conversion, passed validation, and at least one CVE.
#[derive(Debug, Clone)]
pub struct FrozenNucleiSelection {
    pub template_ids: BTreeSet<String>,
    pub nuclei_revision: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FrozenNucleiReport {
    #[serde(default)]
    nuclei_revision: Option<String>,
    templates: Vec<FrozenNucleiTemplate>,
}

#[derive(Debug, Deserialize)]
struct FrozenNucleiTemplate {
    template_id: String,
    cves: Vec<String>,
    conversion_status: ConversionStatus,
    validation_status: String,
}

impl ValidatedNucleiDetection {
    pub fn matches(&self, event: &WebEvent) -> bool {
        self.detection.matches(event)
    }

    /// A deliberately weaker predicate derived from the same Detection IR for
    /// ablation volume comparisons only. It is not a precision, attack, or
    /// compromise assessment.
    pub fn matches_path_only(&self, event: &WebEvent) -> bool {
        self.detection.matches_path_only(event)
    }

    /// A deliberately weaker predicate derived from the same Detection IR for
    /// ablation volume comparisons only. It is not a precision, attack, or
    /// compromise assessment.
    pub fn matches_path_and_query(&self, event: &WebEvent) -> bool {
        self.detection.matches_path_and_query(event)
    }

    /// A deliberately weaker predicate derived from the same Detection IR for
    /// ablation volume comparisons only. It is not a precision, attack, or
    /// compromise assessment.
    pub fn matches_path_query_headers(&self, event: &WebEvent) -> bool {
        self.detection.matches_path_query_headers(event)
    }

    /// Request-side specificity only. It intentionally does not claim that an
    /// attack occurred, a product is vulnerable, or a response was verified.
    pub fn request_specificity(&self) -> RequestSpecificity {
        self.detection.request_specificity()
    }

    /// Returns a copy of the exact literal request conditions that this
    /// validated detection matches. This read-only view never executes a
    /// template or accesses telemetry.
    pub fn request_matcher_view(&self) -> RequestMatcherView {
        RequestMatcherView {
            method: self.detection.method.clone(),
            path: self.detection.path.clone(),
            query: self.detection.query.clone(),
            fragment: self.detection.fragment.clone(),
            headers: self.detection.headers.clone(),
            request_specificity: self.request_specificity(),
        }
    }
}

impl NucleiDetection {
    fn is_generic_root_probe(&self) -> bool {
        self.path == "/" && self.query.is_none() && self.headers.is_empty()
    }

    fn request_specificity(&self) -> RequestSpecificity {
        if self.query.is_some() || self.fragment.is_some() || !self.headers.is_empty() {
            RequestSpecificity::RequestSpecific
        } else {
            RequestSpecificity::ResponseUnverified
        }
    }

    fn matches(&self, event: &WebEvent) -> bool {
        event
            .method
            .as_deref()
            .is_some_and(|method| method.eq_ignore_ascii_case(&self.method))
            && event.uri_path.as_deref() == Some(self.path.as_str())
            && self.query.as_ref().is_none_or(|query| {
                event
                    .uri_query
                    .as_deref()
                    .is_some_and(|actual| actual.contains(query))
            })
            && self
                .fragment
                .as_ref()
                .is_none_or(|fragment| event.uri_fragment.as_deref() == Some(fragment))
            && self.headers.iter().all(|(name, expected)| {
                event.headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case(name)
                        && header.value.eq_ignore_ascii_case(expected)
                })
            })
    }

    fn matches_path_only(&self, event: &WebEvent) -> bool {
        event.uri_path.as_deref() == Some(self.path.as_str())
    }

    fn matches_path_and_query(&self, event: &WebEvent) -> bool {
        self.matches_path_only(event)
            && self.query.as_ref().is_none_or(|query| {
                event
                    .uri_query
                    .as_deref()
                    .is_some_and(|actual| actual.contains(query))
            })
    }

    fn matches_path_query_headers(&self, event: &WebEvent) -> bool {
        self.matches_path_and_query(event) && self.required_headers_match(event)
    }

    fn required_headers_match(&self, event: &WebEvent) -> bool {
        self.headers.iter().all(|(name, expected)| {
            event.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case(name)
                    && header.value.eq_ignore_ascii_case(expected)
            })
        })
    }

    fn synthetic_event(&self, id: &str, mutation: bool) -> anyhow::Result<WebEvent> {
        let query = self.query.as_ref().map(|query| {
            if mutation {
                format!("x=1&{query}")
            } else {
                query.clone()
            }
        });
        let mut headers = self.headers.clone();
        headers.push(("Host".to_owned(), "nuclei.synthetic.test".to_owned()));
        if !mutation {
            headers.push((
                "User-Agent".to_owned(),
                "Shenron-Nuclei-Validation/1.0".to_owned(),
            ));
        }
        if mutation {
            for (name, _) in &mut headers {
                *name = name.to_ascii_lowercase();
            }
            headers.reverse();
        }
        let header_json: Vec<_> = headers
            .iter()
            .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
            .collect();
        let mut request = serde_json::json!({"clientIp":"198.51.100.200","country":"US","headers":header_json,"uri":self.path,"httpVersion":"HTTP/2.0","httpMethod":self.method,"requestId":id});
        if let Some(query) = query {
            request["args"] = serde_json::Value::String(query);
        }
        let mut record = serde_json::json!({"timestamp":1735689600000_i64,"formatVersion":1,"webaclId":"nuclei-synthetic","terminatingRuleId":"Default_Action","terminatingRuleType":"REGULAR","action":"ALLOW","httpSourceName":"ALB","httpSourceId":"app/nuclei/0001","httpRequest":request});
        if let Some(fragment) = &self.fragment {
            record["fragment"] = serde_json::Value::String(fragment.clone());
        }
        parse_line(&record.to_string()).map_err(Into::into)
    }

    fn near_miss_event(&self, id: &str) -> anyhow::Result<WebEvent> {
        let mut altered = self.clone();
        altered.path = format!("{}-docs", altered.path.trim_end_matches('/'));
        altered.synthetic_event(id, false)
    }

    fn synthetic_combined_event(&self, format: AccessLogFormat) -> Result<WebEvent, String> {
        let mut target = self.path.clone();
        if let Some(query) = &self.query {
            target.push('?');
            target.push_str(query);
        }
        if let Some(fragment) = &self.fragment {
            target.push('#');
            target.push_str(fragment);
        }
        let referer = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("referer"))
            .map(|(_, value)| value.as_str())
            .unwrap_or("-");
        let user_agent = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.as_str())
            .unwrap_or("-");
        let escape = |value: &str| value.replace('\\', "\\\\").replace('"', "\\\"");
        let vhost_prefix = matches!(format, AccessLogFormat::ApacheVhostCombined)
            .then_some("nuclei.synthetic.test:443 ")
            .unwrap_or_default();
        let line = format!(
            "{vhost_prefix}198.51.100.200 - - [01/Jan/2025:00:00:00 +0000] \"{} {} HTTP/1.1\" 404 0 \"{}\" \"{}\"",
            self.method,
            escape(&target),
            escape(referer),
            escape(user_agent)
        );
        parse_combined_line(&line, format).map_err(|error| error.to_string())
    }

    fn requires_unavailable_combined_header(&self) -> bool {
        self.headers.iter().any(|(name, _)| {
            !name.eq_ignore_ascii_case("referer") && !name.eq_ignore_ascii_case("user-agent")
        })
    }
}

struct AnalyzedTemplate {
    analysis: TemplateAnalysis,
    detections: Vec<NucleiDetection>,
    features: TemplateFeatures,
}

#[derive(Default)]
struct TemplateFeatures {
    structured: bool,
    raw: bool,
    multiple: bool,
    method: bool,
    path: bool,
    payloads: bool,
    attack: bool,
    body: bool,
    headers: bool,
    query: bool,
    response_matchers: bool,
    dsl: bool,
    oast: bool,
    redirects: bool,
    variables: bool,
    helper_functions: bool,
    extractors: bool,
}

pub fn inventory(templates: &Path, nuclei_revision: &str) -> InventoryReport {
    let mut analyzed = analyze_directory(templates);
    let mut metrics = InventoryMetrics::default();
    let mut reasons = BTreeMap::new();
    let mut gaps = BTreeMap::new();
    let mut combinations = BTreeMap::new();
    for item in &mut analyzed {
        item.analysis.nuclei_revision = nuclei_revision.to_owned();
        metrics.templates_scanned += 1;
        if !item.analysis.cves.is_empty() {
            metrics.cve_templates += 1;
        }
        if !item.analysis.cves.is_empty() && item.analysis.protocol == "http" {
            metrics.http_cve_templates += 1;
        }
        count_features(&mut metrics, &item.features);
        if item.analysis.cves.is_empty() {
            continue;
        }
        *combinations
            .entry(feature_combination(&item.features))
            .or_default() += 1;
        count_values(&mut reasons, &item.analysis.detectability_reasons);
        if let Some(reason) = &item.analysis.conversion_reason {
            *gaps.entry(reason.clone()).or_default() += 1;
        }
        if item.analysis.conversion_status == ConversionStatus::Unsupported {
            metrics.unsupported_constructs += 1;
        }
    }
    InventoryReport {
        nuclei_revision: nuclei_revision.to_owned(),
        metrics,
        templates: analyzed.into_iter().map(|item| item.analysis).collect(),
        detectability_reasons: reasons,
        implementation_gaps: gaps,
        feature_combinations: combinations,
    }
}

pub fn coverage(templates: &Path, nuclei_revision: &str) -> CoverageReport {
    let mut analyzed = analyze_directory(templates);
    let mut inventory_metrics = InventoryMetrics::default();
    let mut coverage = CoverageMetrics::default();
    let mut reasons = BTreeMap::new();
    let mut gaps = BTreeMap::new();
    let mut combinations = BTreeMap::new();
    for item in &mut analyzed {
        item.analysis.nuclei_revision = nuclei_revision.to_owned();
        inventory_metrics.templates_scanned += 1;
        if !item.analysis.cves.is_empty() {
            inventory_metrics.cve_templates += 1;
            coverage.cve_templates += 1;
        }
        if !item.analysis.cves.is_empty() && item.analysis.protocol == "http" {
            inventory_metrics.http_cve_templates += 1;
            coverage.http_cve_templates += 1;
        }
        count_features(&mut inventory_metrics, &item.features);
        count_values(&mut reasons, &item.analysis.detectability_reasons);
        if item.analysis.cves.is_empty() {
            continue;
        }
        *combinations
            .entry(feature_combination(&item.features))
            .or_default() += 1;
        match item.analysis.detectability {
            Detectability::High => coverage.high += 1,
            Detectability::Medium => coverage.medium += 1,
            Detectability::Low => coverage.low += 1,
            Detectability::Undetectable => coverage.undetectable += 1,
            Detectability::Unknown => coverage.unknown += 1,
        }
        if matches!(
            item.analysis.detectability,
            Detectability::High | Detectability::Medium
        ) {
            coverage.convertible_in_principle += 1;
        }
        if item.analysis.conversion_status == ConversionStatus::Supported {
            coverage.supported_by_shenron += 1;
            if item.detections.is_empty() {
                coverage.unsupported_by_shenron += 1;
                coverage.supported_by_shenron -= 1;
                item.analysis.conversion_status = ConversionStatus::Unsupported;
                item.analysis.conversion_reason = Some("detection_ir_error".to_owned());
                *gaps.entry("detection_ir_error".to_owned()).or_default() += 1;
                continue;
            }
            coverage.supported_request_ir_templates += 1;
            for detection in &item.detections {
                let validated = ValidatedNucleiDetection {
                    template_id: item.analysis.template_id.clone(),
                    cves: item.analysis.cves.clone(),
                    detectability: item.analysis.detectability,
                    detection: detection.clone(),
                };
                coverage.supported_request_ir_detections += 1;
                match validated.request_specificity() {
                    RequestSpecificity::RequestSpecific => {
                        coverage.request_specific_detections += 1
                    }
                    RequestSpecificity::ResponseUnverified => {
                        coverage.response_unverified_detections += 1
                    }
                }
            }
            coverage.templates_tested += 1;
            let mut exact_passed = true;
            let mut mutation_passed = true;
            let mut near_miss_passed = true;
            for (index, detection) in item.detections.iter().enumerate() {
                coverage.synthetic_events_generated += 1;
                coverage.expected_detections += 1;
                match detection.synthetic_event(
                    &format!("nuclei-{}-{index}-exact", item.analysis.template_id),
                    false,
                ) {
                    Ok(exact) if detection.matches(&exact) => coverage.correct_detections += 1,
                    _ => {
                        coverage.missed_detections += 1;
                        exact_passed = false;
                    }
                }
                coverage.mutation_cases += 1;
                coverage.synthetic_events_generated += 1;
                match detection.synthetic_event(
                    &format!("nuclei-{}-{index}-mutation", item.analysis.template_id),
                    true,
                ) {
                    Ok(mutated) if detection.matches(&mutated) => {}
                    _ => {
                        coverage.mutation_failures += 1;
                        mutation_passed = false;
                    }
                }
                coverage.near_miss_cases += 1;
                coverage.synthetic_events_generated += 1;
                if detection
                    .near_miss_event(&format!(
                        "nuclei-{}-{index}-near-miss",
                        item.analysis.template_id
                    ))
                    .is_ok_and(|near_miss| detection.matches(&near_miss))
                {
                    coverage.unexpected_matches += 1;
                    coverage.near_miss_failures += 1;
                    near_miss_passed = false;
                }
            }
            item.analysis.validation_status = validation_status(exact_passed);
            item.analysis.mutation_validation_status = validation_status(mutation_passed);
            item.analysis.near_miss_validation_status = validation_status(near_miss_passed);
            item.analysis.synthetic_generation_status = "generated".to_owned();
        } else {
            coverage.unsupported_by_shenron += 1;
            inventory_metrics.unsupported_constructs += 1;
            if let Some(reason) = &item.analysis.conversion_reason {
                *gaps.entry(reason.clone()).or_default() += 1;
            }
        }
    }
    CoverageReport {
        nuclei_revision: nuclei_revision.to_owned(),
        inventory: inventory_metrics,
        coverage,
        templates: analyzed.into_iter().map(|item| item.analysis).collect(),
        detectability_reasons: reasons,
        implementation_gaps: gaps,
        feature_combinations: combinations,
    }
}

/// Rebuilds only the matcher IR for template IDs whose static conversion and
/// synthetic validation are already recorded as passed in a frozen report.
pub fn validated_detections(
    templates: &Path,
    validated_template_ids: &std::collections::BTreeSet<String>,
) -> Vec<ValidatedNucleiDetection> {
    analyze_directory(templates)
        .into_iter()
        .filter(|item| {
            validated_template_ids.contains(&item.analysis.template_id)
                && item.analysis.conversion_status == ConversionStatus::Supported
        })
        .flat_map(|item| {
            let template_id = item.analysis.template_id;
            let cves = item.analysis.cves;
            let detectability = item.analysis.detectability;
            item.detections
                .into_iter()
                .map(move |detection| ValidatedNucleiDetection {
                    template_id: template_id.clone(),
                    cves: cves.clone(),
                    detectability,
                    detection,
                })
        })
        .collect()
}

/// Rebuilds every supported literal Detection IR in a local checkout. This is
/// intended for static matcher inspection when no frozen report is supplied.
pub fn supported_detections(templates: &Path) -> Vec<ValidatedNucleiDetection> {
    let supported_template_ids = analyze_directory(templates)
        .into_iter()
        .filter(|item| item.analysis.conversion_status == ConversionStatus::Supported)
        .map(|item| item.analysis.template_id)
        .collect();
    validated_detections(templates, &supported_template_ids)
}

/// Reads the same frozen-report eligibility gates used by production hunt.
/// This is local JSON parsing only; it does not execute templates or access a
/// network resource.
pub fn frozen_nuclei_selection(path: &Path) -> Result<FrozenNucleiSelection> {
    let report: FrozenNucleiReport = serde_json::from_reader(fs::File::open(path)?)?;
    let template_ids = report
        .templates
        .into_iter()
        .filter(|template| {
            template.conversion_status == ConversionStatus::Supported
                && template.validation_status == "passed"
                && !template.cves.is_empty()
        })
        .map(|template| template.template_id)
        .collect();
    Ok(FrozenNucleiSelection {
        template_ids,
        nuclei_revision: report.nuclei_revision,
    })
}

/// Re-evaluates static Nuclei request requirements against each explicitly
/// documented telemetry profile. It does not change the frozen AWS WAF report.
pub fn compare_telemetry(templates: &Path, nuclei_revision: &str) -> TelemetryComparisonReport {
    let analyzed = analyze_directory(templates);
    let reports = [
        TelemetryProfile::AwsWaf,
        TelemetryProfile::NginxCombined,
        TelemetryProfile::ApacheCombined,
        TelemetryProfile::NginxCombinedHost,
        TelemetryProfile::NginxSecurity,
    ]
    .into_iter()
    .map(|telemetry| telemetry_report(&analyzed, telemetry, nuclei_revision))
    .collect();
    TelemetryComparisonReport {
        nuclei_revision: nuclei_revision.to_owned(),
        reports,
    }
}

/// Runs the telemetry-specific analysis used by comparison mode for one
/// explicitly selected profile.
pub fn coverage_for_telemetry(
    templates: &Path,
    telemetry: TelemetryProfile,
    nuclei_revision: &str,
) -> TelemetryCoverageReport {
    telemetry_report(&analyze_directory(templates), telemetry, nuclei_revision)
}

/// Returns the template dependencies that standard combined logs cannot meet
/// because they require headers other than Referer or User-Agent. This does
/// not expose raw header values and does not execute templates.
pub fn combined_header_dependencies(templates: &Path) -> Vec<HeaderDependency> {
    analyze_directory(templates)
        .into_iter()
        .filter(|item| {
            !item.analysis.cves.is_empty()
                && item.analysis.protocol == "http"
                && item
                    .detections
                    .iter()
                    .any(NucleiDetection::requires_unavailable_combined_header)
        })
        .map(|item| {
            let mut headers = item
                .detections
                .iter()
                .flat_map(|detection| detection.headers.iter())
                .filter(|(name, _)| {
                    !name.eq_ignore_ascii_case("referer")
                        && !name.eq_ignore_ascii_case("user-agent")
                })
                .map(|(name, _)| HeaderRequirement {
                    name: name.to_ascii_lowercase(),
                    value_matters: true,
                    presence_only: false,
                    match_kind: HeaderMatchKind::ExactValue,
                })
                .collect::<Vec<_>>();
            headers.sort_by(|left, right| left.name.cmp(&right.name));
            headers.dedup_by(|left, right| left.name == right.name);
            HeaderDependency {
                template_id: item.analysis.template_id,
                cves: item.analysis.cves,
                template_path: item.analysis.template_path,
                detectability: item.analysis.detectability,
                multiple_headers_required: headers.len() > 1,
                headers,
            }
        })
        .collect()
}

fn telemetry_report(
    analyzed: &[AnalyzedTemplate],
    telemetry: TelemetryProfile,
    nuclei_revision: &str,
) -> TelemetryCoverageReport {
    let capabilities = telemetry.capabilities();
    let mut metrics = TelemetryCoverageMetrics::default();
    let mut reasons = BTreeMap::new();
    let mut templates = Vec::new();
    for item in analyzed {
        if item.analysis.cves.is_empty() || item.analysis.protocol != "http" {
            continue;
        }
        metrics.http_cve_templates += 1;
        let mut level = item.analysis.detectability;
        let unavailable_headers = matches!(
            telemetry,
            TelemetryProfile::NginxCombined | TelemetryProfile::ApacheCombined
        ) && item
            .detections
            .iter()
            .any(NucleiDetection::requires_unavailable_combined_header);
        let mut template_reasons = Vec::new();
        if unavailable_headers {
            // The IR matches all required headers conjunctively, so an
            // arbitrary-header requirement is not observable in standard
            // combined telemetry. This is stronger and more honest than
            // downgrading it to a partial match.
            level = Detectability::Undetectable;
            template_reasons.push("arbitrary_header_unavailable".to_owned());
            *reasons
                .entry("arbitrary_header_unavailable".to_owned())
                .or_default() += 1;
        }
        match level {
            Detectability::High => metrics.high += 1,
            Detectability::Medium => metrics.medium += 1,
            Detectability::Low => metrics.low += 1,
            Detectability::Undetectable => metrics.undetectable += 1,
            Detectability::Unknown => metrics.unknown += 1,
        }
        if matches!(level, Detectability::High | Detectability::Medium) {
            metrics.observable += 1;
        }
        let source_compatible = item.analysis.conversion_status == ConversionStatus::Supported
            && (!matches!(capabilities.headers, HeaderCapability::RefererAndUserAgent)
                || !unavailable_headers);
        let mut validated = false;
        if source_compatible {
            metrics.convertible += 1;
            validated = match telemetry {
                TelemetryProfile::AwsWaf => true,
                TelemetryProfile::NginxCombined => item.detections.iter().all(|detection| {
                    detection
                        .synthetic_combined_event(AccessLogFormat::NginxCombined)
                        .is_ok_and(|event| detection.matches(&event))
                }),
                TelemetryProfile::ApacheCombined => item.detections.iter().all(|detection| {
                    detection
                        .synthetic_combined_event(AccessLogFormat::ApacheCombined)
                        .is_ok_and(|event| detection.matches(&event))
                }),
                TelemetryProfile::ApacheVhostCombined => item.detections.iter().all(|detection| {
                    detection
                        .synthetic_combined_event(AccessLogFormat::ApacheVhostCombined)
                        .is_ok_and(|event| detection.matches(&event))
                }),
                // These profiles model logging changes, not a currently
                // implemented parser. Their result is observability-only
                // until a matching custom parser is configured.
                TelemetryProfile::NginxCombinedHost | TelemetryProfile::NginxSecurity => false,
            };
            metrics.validated += usize::from(validated);
            if !validated
                && matches!(
                    telemetry,
                    TelemetryProfile::NginxCombined | TelemetryProfile::ApacheCombined
                )
            {
                template_reasons.push("combined_synthetic_validation_failed".to_owned());
                *reasons
                    .entry("combined_synthetic_validation_failed".to_owned())
                    .or_default() += 1;
            }
        }
        templates.push(TelemetryTemplateAssessment {
            template_id: item.analysis.template_id.clone(),
            cves: item.analysis.cves.clone(),
            template_path: item.analysis.template_path.clone(),
            level,
            reasons: template_reasons,
            convertible: source_compatible,
            validated,
        });
    }
    TelemetryCoverageReport {
        nuclei_revision: nuclei_revision.to_owned(),
        telemetry,
        metrics,
        detectability_reasons: reasons,
        templates,
    }
}

fn analyze_directory(path: &Path) -> Vec<AnalyzedTemplate> {
    WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && matches!(
                    entry
                        .path()
                        .extension()
                        .and_then(|extension| extension.to_str()),
                    Some("yml" | "yaml")
                )
        })
        .map(|entry| {
            let relative = entry
                .path()
                .strip_prefix(path)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            match fs::read_to_string(entry.path()) {
                Ok(input) if !input.to_ascii_lowercase().contains("cve") => {
                    non_cve_template(relative)
                }
                Ok(input) => match serde_yaml::from_str::<Value>(&input) {
                    Ok(value) => analyze_value(&value, relative),
                    Err(_) => unsupported_parse(relative),
                },
                Err(_) => unsupported_parse(relative),
            }
        })
        .collect()
}

/// The real benchmark's CVE coverage denominator is explicit CVE metadata.
/// Avoid parsing unrelated templates merely to discover they are unrelated;
/// this preserves the all-template count while keeping the benchmark usable on
/// a large upstream checkout.
fn non_cve_template(path: String) -> AnalyzedTemplate {
    AnalyzedTemplate {
        analysis: TemplateAnalysis {
            template_id: path.clone(),
            cves: Vec::new(),
            template_path: path,
            nuclei_revision: "unknown".to_owned(),
            protocol: "not_analyzed_non_cve".to_owned(),
            detectability: Detectability::Unknown,
            detectability_reasons: vec!["not_cve_candidate".to_owned()],
            observable_features: Vec::new(),
            unavailable_features: Vec::new(),
            conversion_status: ConversionStatus::Unsupported,
            conversion_reason: Some("not_cve_candidate".to_owned()),
            synthetic_generation_status: "not_generated".to_owned(),
            validation_status: "not_tested".to_owned(),
            mutation_validation_status: "not_tested".to_owned(),
            near_miss_validation_status: "not_tested".to_owned(),
        },
        detections: Vec::new(),
        features: TemplateFeatures::default(),
    }
}

fn unsupported_parse(path: String) -> AnalyzedTemplate {
    AnalyzedTemplate {
        analysis: TemplateAnalysis {
            template_id: path.clone(),
            cves: Vec::new(),
            template_path: path,
            nuclei_revision: "unknown".to_owned(),
            protocol: "unknown".to_owned(),
            detectability: Detectability::Unknown,
            detectability_reasons: vec!["nuclei_parse_error".to_owned()],
            observable_features: Vec::new(),
            unavailable_features: Vec::new(),
            conversion_status: ConversionStatus::Unsupported,
            conversion_reason: Some("nuclei_parse_error".to_owned()),
            synthetic_generation_status: "not_generated".to_owned(),
            validation_status: "not_tested".to_owned(),
            mutation_validation_status: "not_tested".to_owned(),
            near_miss_validation_status: "not_tested".to_owned(),
        },
        detections: Vec::new(),
        features: TemplateFeatures::default(),
    }
}

fn analyze_value(root: &Value, path: String) -> AnalyzedTemplate {
    let id = value_string(map_get(root, "id")).unwrap_or_else(|| path.clone());
    let cves = extract_cves(root);
    let requests = map_get(root, "http")
        .or_else(|| map_get(root, "requests"))
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default();
    let protocol = if requests.is_empty() {
        "non_http".to_owned()
    } else {
        "http".to_owned()
    };
    let mut features = TemplateFeatures {
        multiple: requests.len() > 1,
        ..TemplateFeatures::default()
    };
    if requests.is_empty() {
        return AnalyzedTemplate {
            analysis: TemplateAnalysis {
                template_id: id,
                cves,
                template_path: path,
                nuclei_revision: "unknown".to_owned(),
                protocol,
                detectability: Detectability::Undetectable,
                detectability_reasons: vec!["no_http_request".to_owned()],
                observable_features: Vec::new(),
                unavailable_features: vec!["protocol_not_in_webevent".to_owned()],
                conversion_status: ConversionStatus::Unsupported,
                conversion_reason: Some("non_http_template".to_owned()),
                synthetic_generation_status: "not_generated".to_owned(),
                validation_status: "not_tested".to_owned(),
                mutation_validation_status: "not_tested".to_owned(),
                near_miss_validation_status: "not_tested".to_owned(),
            },
            detections: Vec::new(),
            features,
        };
    }
    let request = &requests[0];
    features.raw = map_get(request, "raw").is_some();
    features.structured = map_get(request, "path").is_some();
    features.method = map_get(request, "method").is_some() || features.raw;
    features.path = features.structured || features.raw;
    features.payloads = map_get(request, "payloads").is_some();
    features.attack = map_get(request, "attack").is_some();
    features.body = map_get(request, "body").is_some()
        || map_get(request, "raw")
            .and_then(Value::as_sequence)
            .is_some_and(|raws| {
                raws.iter().filter_map(|raw| raw.as_str()).any(|raw| {
                    raw.replace("\r\n", "\n")
                        .split_once("\n\n")
                        .is_some_and(|(_, body)| !body.trim().is_empty())
                })
            });
    features.headers = map_get(request, "headers").is_some();
    features.response_matchers = map_get(request, "matchers").is_some();
    features.dsl = value_contains(request, "dsl");
    features.oast = value_contains(request, "interactsh");
    features.redirects =
        map_get(request, "redirects").is_some() || map_get(request, "max-redirects").is_some();
    features.extractors = map_get(request, "extractors").is_some();
    let request_text = serde_yaml::to_string(request).unwrap_or_default();
    features.variables = request_text.contains("{{");
    features.helper_functions = features.variables && request_text.contains('(');
    let parsed = if features.raw {
        parse_raw_request(request)
    } else {
        parse_structured_request(request)
    };
    // A Nuclei template commonly probes `{{BaseURL}}` to identify a product
    // from its response before it makes a meaningful CVE assertion. A passive
    // request log cannot reproduce that response-side confirmation. Do not
    // turn an otherwise ordinary root request into CVE evidence merely because
    // it is one alternative in such a template; retain any explicit request
    // alternatives from the same template.
    let (parsed, generic_response_probes_excluded) = match parsed {
        Ok(detections) if features.response_matchers => {
            let original_count = detections.len();
            let detections = detections
                .into_iter()
                .filter(|detection| !detection.is_generic_root_probe())
                .collect::<Vec<_>>();
            let excluded_count = original_count.saturating_sub(detections.len());
            (Ok(detections), excluded_count)
        }
        result => (result, 0),
    };
    let only_generic_response_probes =
        parsed.as_ref().is_ok_and(Vec::is_empty) && generic_response_probes_excluded > 0;
    if let Ok(detections) = &parsed {
        features.headers |= detections
            .iter()
            .any(|detection| !detection.headers.is_empty());
    }
    let mut reasons = Vec::new();
    let mut observable = Vec::new();
    let mut unavailable = Vec::new();
    if features.response_matchers {
        unavailable.push("response_evidence".to_owned());
    }
    if features.body {
        unavailable.push("request_body".to_owned());
    }
    if features.oast {
        unavailable.push("oast_verification".to_owned());
    }
    if generic_response_probes_excluded > 0 {
        reasons.push("response_dependent_generic_probe_excluded".to_owned());
    }
    if only_generic_response_probes {
        reasons.push("response_dependent_generic_probe".to_owned());
    } else if let Ok(detections) = &parsed {
        observable.push("method".to_owned());
        observable.push("uri_path".to_owned());
        if detections.iter().any(|detection| detection.query.is_some()) {
            observable.push("uri_query".to_owned());
            features.query = true;
            reasons.push("exploit_specific_query".to_owned());
        }
        if detections
            .first()
            .is_some_and(|detection| !detection.headers.is_empty())
        {
            observable.push("headers".to_owned());
            reasons.push("distinctive_request_header".to_owned());
        }
        if detections.iter().all(|detection| detection.path == "/") {
            reasons.push("request_too_generic".to_owned());
        } else {
            reasons.push("distinctive_request_path".to_owned());
        }
    }
    let (detectability, conversion_reason) = if features.payloads {
        (
            Detectability::Unknown,
            Some("payload_expansion_unsupported".to_owned()),
        )
    } else if features.attack {
        (
            Detectability::Unknown,
            Some("payload_attack_mode_unsupported".to_owned()),
        )
    } else if features.oast && parsed.is_err() {
        (Detectability::Unknown, Some("oast_required".to_owned()))
    } else if only_generic_response_probes {
        (
            Detectability::Low,
            Some("response_dependent_generic_probe".to_owned()),
        )
    } else if parsed.is_err() {
        (
            Detectability::Unknown,
            Some(parsed.as_ref().map_or_else(
                |reason| reason.clone(),
                |_| "unknown_parse_error".to_owned(),
            )),
        )
    } else if features.multiple {
        (
            Detectability::Medium,
            Some("multi_request_unsupported".to_owned()),
        )
    } else if features.body {
        (
            Detectability::Medium,
            Some("request_body_unavailable".to_owned()),
        )
    } else if features.oast {
        (Detectability::Medium, Some("oast_required".to_owned()))
    } else if parsed.as_ref().is_ok_and(|detections| {
        !detections.is_empty()
            && detections.iter().all(|detection| {
                detection.path == "/" && detection.query.is_none() && detection.headers.is_empty()
            })
    }) {
        (Detectability::Low, Some("request_too_generic".to_owned()))
    } else {
        (Detectability::High, None)
    };
    if features.oast {
        reasons.push("oast_verification_unavailable".to_owned());
    }
    if features.body {
        reasons.push("request_body_unavailable".to_owned());
    }
    if features.multiple {
        reasons.push("multi_request_context".to_owned());
    }
    if detectability == Detectability::Unknown && reasons.is_empty() {
        if let Some(reason) = &conversion_reason {
            reasons.push(reason.clone());
        }
    }
    let conversion_status = if conversion_reason.is_none() {
        ConversionStatus::Supported
    } else {
        ConversionStatus::Unsupported
    };
    AnalyzedTemplate {
        analysis: TemplateAnalysis {
            template_id: id,
            cves,
            template_path: path,
            nuclei_revision: "unknown".to_owned(),
            protocol,
            detectability,
            detectability_reasons: reasons,
            observable_features: observable,
            unavailable_features: unavailable,
            conversion_status,
            conversion_reason,
            synthetic_generation_status: "not_generated".to_owned(),
            validation_status: "not_tested".to_owned(),
            mutation_validation_status: "not_tested".to_owned(),
            near_miss_validation_status: "not_tested".to_owned(),
        },
        detections: parsed.unwrap_or_default(),
        features,
    }
}

fn parse_structured_request(request: &Value) -> Result<Vec<NucleiDetection>, String> {
    let method = value_string(map_get(request, "method")).unwrap_or_else(|| "GET".to_owned());
    let paths = map_get(request, "path")
        .and_then(Value::as_sequence)
        .ok_or_else(|| "missing_structured_path".to_owned())?;
    if paths.is_empty() {
        return Err("multiple_paths_unsupported".to_owned());
    }
    let headers = parse_headers(map_get(request, "headers"))?;
    paths
        .iter()
        .map(|value| {
            let path = normalize_template_path(
                &value_string(Some(value)).ok_or_else(|| "non_string_path".to_owned())?,
            )?;
            Ok(NucleiDetection {
                method: method.clone(),
                path: path.0,
                query: path.1,
                fragment: path.2,
                headers: headers.clone(),
            })
        })
        .collect()
}

fn parse_raw_request(request: &Value) -> Result<Vec<NucleiDetection>, String> {
    let raws = map_get(request, "raw")
        .and_then(Value::as_sequence)
        .ok_or_else(|| "raw_http_not_implemented".to_owned())?;
    if raws.len() != 1 {
        return Err("multiple_raw_requests_unsupported".to_owned());
    }
    let raw = value_string(Some(&raws[0])).ok_or_else(|| "non_string_raw_request".to_owned())?;
    if raw.replace("{{Hostname}}", "").contains("{{") {
        return Err("raw_http_helper_or_variable_unsupported".to_owned());
    }
    let normalized = raw.replace("\r\n", "\n");
    let mut lines = normalized.lines();
    let request_line = lines.next().ok_or_else(|| "empty_raw_request".to_owned())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "invalid_raw_request_line".to_owned())?
        .to_owned();
    let target = parts
        .next()
        .ok_or_else(|| "invalid_raw_request_line".to_owned())?;
    if !parts
        .next()
        .is_some_and(|version| version.starts_with("HTTP/"))
    {
        return Err("invalid_raw_request_line".to_owned());
    }
    let (path, query, fragment) = split_path_query(target)?;
    let mut headers = Vec::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("invalid_raw_header".to_owned());
        };
        if !name.eq_ignore_ascii_case("host") {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    Ok(vec![NucleiDetection {
        method,
        path,
        query,
        fragment,
        headers,
    }])
}

fn validation_status(passed: bool) -> String {
    if passed { "passed" } else { "failed" }.to_owned()
}

fn normalize_template_path(
    value: &str,
) -> Result<(String, Option<String>, Option<String>), String> {
    let value = value
        .trim()
        .replace("{{BaseURL}}", "")
        .replace("{{RootURL}}", "")
        .replace("{{interactsh-url}}", "oast.invalid");
    if value.contains("{{") || value.contains("}}") {
        return Err("variable_resolution_unsupported".to_owned());
    }
    split_path_query(if value.is_empty() { "/" } else { &value })
}

fn split_path_query(value: &str) -> Result<(String, Option<String>, Option<String>), String> {
    if !value.starts_with('/') {
        return Err("non_literal_request_path".to_owned());
    }
    let (without_fragment, fragment) = value
        .split_once('#')
        .map_or((value, None), |(path, fragment)| (path, Some(fragment)));
    let (path, query) = without_fragment
        .split_once('?')
        .map_or((without_fragment, None), |(path, query)| {
            (path, Some(query))
        });
    Ok((
        path.to_owned(),
        query.filter(|query| !query.is_empty()).map(str::to_owned),
        fragment
            .filter(|fragment| !fragment.is_empty())
            .map(str::to_owned),
    ))
}

fn parse_headers(value: Option<&Value>) -> Result<Vec<(String, String)>, String> {
    let Some(headers) = value else {
        return Ok(Vec::new());
    };
    let map = headers
        .as_mapping()
        .ok_or_else(|| "non_mapping_headers".to_owned())?;
    map.iter()
        .map(|(name, value)| {
            let name =
                value_string(Some(name)).ok_or_else(|| "non_string_header_name".to_owned())?;
            let value =
                value_string(Some(value)).ok_or_else(|| "non_string_header_value".to_owned())?;
            if value.contains("{{") {
                return Err("variable_resolution_unsupported".to_owned());
            }
            Ok((name, value))
        })
        .collect()
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_mapping()?.get(Value::String(key.to_owned()))
}
fn value_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}
fn value_contains(value: &Value, needle: &str) -> bool {
    serde_yaml::to_string(value)
        .map(|text| {
            text.to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        })
        .unwrap_or(false)
}

fn extract_cves(root: &Value) -> Vec<String> {
    let mut values = Vec::new();
    for key in ["id", "tags", "reference", "references", "cve-id"] {
        collect_strings(map_get(root, key), &mut values);
    }
    if let Some(info) = map_get(root, "info") {
        for key in ["tags", "reference", "references"] {
            collect_strings(map_get(info, key), &mut values);
        }
        if let Some(classification) = map_get(info, "classification") {
            collect_strings(map_get(classification, "cve-id"), &mut values);
        }
        if let Some(metadata) = map_get(info, "metadata") {
            collect_strings(
                map_get(metadata, "cve-id").or_else(|| map_get(metadata, "cve")),
                &mut values,
            );
        }
    }
    let regex = Regex::new(r"(?i)CVE[-_ ]?(\d{4})[-_ ]?(\d{4,})").expect("valid CVE regex");
    let mut cves: Vec<_> = values
        .iter()
        .flat_map(|value| {
            regex
                .captures_iter(value)
                .map(|capture| format!("CVE-{}-{}", &capture[1], &capture[2]))
        })
        .collect();
    cves.sort();
    cves.dedup();
    cves
}

fn collect_strings(value: Option<&Value>, values: &mut Vec<String>) {
    match value {
        Some(Value::String(value)) => values.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
        ),
        Some(Value::Sequence(items)) => {
            for item in items {
                collect_strings(Some(item), values);
            }
        }
        _ => {}
    }
}

fn count_features(metrics: &mut InventoryMetrics, features: &TemplateFeatures) {
    metrics.structured_http += usize::from(features.structured);
    metrics.raw_http += usize::from(features.raw);
    metrics.multiple_requests += usize::from(features.multiple);
    metrics.methods += usize::from(features.method);
    metrics.paths += usize::from(features.path);
    metrics.payloads += usize::from(features.payloads);
    metrics.attack_modes += usize::from(features.attack);
    metrics.request_bodies += usize::from(features.body);
    metrics.request_headers += usize::from(features.headers);
    metrics.query_parameters += usize::from(features.query);
    metrics.response_matchers += usize::from(features.response_matchers);
    metrics.dsl += usize::from(features.dsl);
    metrics.interactsh_oast += usize::from(features.oast);
    metrics.redirects += usize::from(features.redirects);
    metrics.variables += usize::from(features.variables);
    metrics.helper_functions += usize::from(features.helper_functions);
    metrics.extractors += usize::from(features.extractors);
}

fn feature_combination(features: &TemplateFeatures) -> String {
    let mut names = Vec::new();
    for (name, enabled) in [
        ("raw", features.raw),
        ("structured", features.structured),
        ("multi_request", features.multiple),
        ("body", features.body),
        ("payloads", features.payloads),
        ("attack", features.attack),
        ("variables", features.variables),
        ("helpers", features.helper_functions),
        ("oast", features.oast),
        ("redirects", features.redirects),
        ("extractors", features.extractors),
    ] {
        if enabled {
            names.push(name);
        }
    }
    if names.is_empty() {
        "simple".to_owned()
    } else {
        names.join("+")
    }
}
fn count_values(output: &mut BTreeMap<String, usize>, values: &[String]) {
    for value in values {
        *output.entry(value.clone()).or_default() += 1;
    }
}
