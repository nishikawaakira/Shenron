use std::{fs, path::Path};

use shenron::nuclei::{
    combined_header_dependencies, compare_telemetry, coverage, inventory, ConversionStatus,
    Detectability, RequestSpecificity,
};
use tempfile::tempdir;

#[test]
fn inventories_realistic_supported_and_unsupported_template_features() {
    let report = inventory(Path::new("tests/fixtures/nuclei"), "fixture-revision");
    assert_eq!(report.metrics.templates_scanned, 9);
    assert_eq!(report.metrics.cve_templates, 8);
    assert_eq!(report.metrics.http_cve_templates, 8);
    assert_eq!(report.metrics.structured_http, 8);
    assert_eq!(report.metrics.raw_http, 1);
    assert_eq!(report.metrics.multiple_requests, 1);
    assert_eq!(report.metrics.payloads, 1);
    assert_eq!(report.metrics.attack_modes, 1);
    assert_eq!(report.metrics.request_bodies, 1);
    assert_eq!(report.metrics.request_headers, 2);
    assert_eq!(report.metrics.query_parameters, 4);
    assert_eq!(report.metrics.response_matchers, 5);
    assert_eq!(report.metrics.interactsh_oast, 1);
    assert!(report
        .templates
        .iter()
        .all(|template| template.nuclei_revision == "fixture-revision"));
}

#[test]
fn classifies_detectability_separately_from_conversion() {
    let report = inventory(Path::new("tests/fixtures/nuclei"), "fixture-revision");
    let template = |id: &str| {
        report
            .templates
            .iter()
            .find(|item| item.template_id == id)
            .unwrap()
    };
    assert_eq!(
        template("synthetic-cve-2024-10001").detectability,
        Detectability::High
    );
    assert_eq!(
        template("synthetic-cve-2024-10001").conversion_status,
        ConversionStatus::Supported
    );
    assert_eq!(
        template("synthetic-cve-2024-10002").conversion_status,
        ConversionStatus::Supported
    );
    assert_eq!(
        template("synthetic-cve-2024-10008").conversion_status,
        ConversionStatus::Supported
    );
    assert_eq!(
        template("synthetic-cve-2024-10003").detectability,
        Detectability::Low
    );
    assert_eq!(
        template("synthetic-cve-2024-10004").detectability,
        Detectability::Medium
    );
    assert_eq!(
        template("synthetic-cve-2024-10004")
            .conversion_reason
            .as_deref(),
        Some("oast_required")
    );
    assert_eq!(
        template("synthetic-cve-2024-10005")
            .conversion_reason
            .as_deref(),
        Some("request_body_unavailable")
    );
    assert_eq!(
        template("synthetic-cve-2024-10006").detectability,
        Detectability::Unknown
    );
    assert_eq!(
        template("synthetic-cve-2024-10007")
            .conversion_reason
            .as_deref(),
        Some("multi_request_unsupported")
    );
}

#[test]
fn classifies_request_specificity_from_detection_ir_shape() {
    let approved = [
        "synthetic-cve-2024-10001",
        "synthetic-cve-2024-10002",
        "synthetic-cve-2024-10008",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let detections =
        shenron::nuclei::validated_detections(Path::new("tests/fixtures/nuclei"), &approved);
    assert!(detections
        .iter()
        .filter(|detection| detection.template_id == "synthetic-cve-2024-10001")
        .all(|detection| detection.request_specificity() == RequestSpecificity::RequestSpecific));
    assert!(detections
        .iter()
        .filter(|detection| detection.template_id == "synthetic-cve-2024-10002")
        .all(|detection| detection.request_specificity() == RequestSpecificity::RequestSpecific));
    assert_eq!(
        detections
            .iter()
            .find(|detection| {
                detection.template_id == "synthetic-cve-2024-10008"
                    && detection.request_specificity() == RequestSpecificity::ResponseUnverified
            })
            .map(|detection| detection.request_specificity()),
        Some(RequestSpecificity::ResponseUnverified)
    );
}

#[test]
fn coverage_runs_passive_exact_and_mutation_validation_for_supported_cves() {
    let report = coverage(Path::new("tests/fixtures/nuclei"), "fixture-revision");
    assert_eq!(report.coverage.high, 3);
    assert_eq!(report.coverage.medium, 3);
    assert_eq!(report.coverage.low, 1);
    assert_eq!(report.coverage.unknown, 1);
    assert_eq!(report.coverage.supported_by_shenron, 3);
    assert_eq!(report.coverage.unsupported_by_shenron, 5);
    assert_eq!(report.coverage.templates_tested, 3);
    assert_eq!(report.coverage.expected_detections, 4);
    assert_eq!(report.coverage.correct_detections, 4);
    assert_eq!(report.coverage.synthetic_events_generated, 12);
    assert_eq!(report.coverage.missed_detections, 0);
    assert_eq!(report.coverage.unexpected_matches, 0);
    assert_eq!(report.coverage.mutation_failures, 0);
    assert_eq!(report.coverage.near_miss_cases, 4);
    assert_eq!(report.coverage.near_miss_failures, 0);
    assert_eq!(report.coverage.cve_templates, 8);
    assert_eq!(report.coverage.http_cve_templates, 8);
    assert_eq!(report.coverage.supported_request_ir_templates, 3);
    assert_eq!(report.coverage.supported_request_ir_detections, 4);
    assert_eq!(report.coverage.request_specific_detections, 3);
    assert_eq!(report.coverage.response_unverified_detections, 1);
    assert_eq!(
        report.coverage.request_specific_detections
            + report.coverage.response_unverified_detections,
        report.coverage.supported_request_ir_detections
    );
}

#[test]
fn malformed_template_is_reported_as_unknown_without_stopping_inventory() {
    let directory = tempdir().unwrap();
    fs::write(
        directory.path().join("bad.yaml"),
        "id: cve-bad\ninfo: [not valid",
    )
    .unwrap();
    let report = inventory(directory.path(), "fixture-revision");
    assert_eq!(report.metrics.templates_scanned, 1);
    assert_eq!(report.templates[0].detectability, Detectability::Unknown);
    assert_eq!(
        report.templates[0].conversion_reason.as_deref(),
        Some("nuclei_parse_error")
    );
}

#[test]
fn excludes_response_dependent_root_probes_but_keeps_explicit_request_evidence() {
    let directory = tempdir().unwrap();
    fs::write(
        directory.path().join("generic-and-explicit.yaml"),
        r#"id: synthetic-cve-generic-and-explicit
info:
  name: Synthetic Generic and Explicit Endpoint
  classification:
    cve-id: CVE-2026-10001
http:
  - method: GET
    path:
      - '{{BaseURL}}'
      - '{{BaseURL}}/vulnerable/explicit?probe=1'
    matchers:
      - type: word
        part: body
        words:
          - product version
"#,
    )
    .unwrap();

    let report = coverage(directory.path(), "fixture-revision");
    let template = &report.templates[0];
    assert_eq!(template.detectability, Detectability::High);
    assert_eq!(template.conversion_status, ConversionStatus::Supported);
    assert!(template
        .detectability_reasons
        .iter()
        .any(|reason| reason == "response_dependent_generic_probe_excluded"));
    // Only the explicit URI is eligible for the shared passive Detection IR.
    assert_eq!(report.coverage.expected_detections, 1);
    assert_eq!(report.coverage.correct_detections, 1);
}

#[test]
fn refuses_a_response_dependent_generic_root_probe_as_cve_evidence() {
    let report = inventory(Path::new("tests/fixtures/nuclei"), "fixture-revision");
    let template = report
        .templates
        .iter()
        .find(|item| item.template_id == "synthetic-cve-2024-10003")
        .unwrap();
    assert_eq!(template.detectability, Detectability::Low);
    assert_eq!(template.conversion_status, ConversionStatus::Unsupported);
    assert_eq!(
        template.conversion_reason.as_deref(),
        Some("response_dependent_generic_probe")
    );
}

#[test]
fn compares_telemetry_without_source_specific_nuclei_rules() {
    let report = compare_telemetry(Path::new("tests/fixtures/nuclei"), "fixture-revision");
    let nginx = report
        .reports
        .iter()
        .find(|report| format!("{:?}", report.telemetry) == "NginxCombined")
        .unwrap();
    assert_eq!(nginx.metrics.http_cve_templates, 8);
    assert_eq!(nginx.metrics.high, 1);
    assert_eq!(nginx.metrics.medium, 3);
    assert_eq!(nginx.metrics.undetectable, 2);
    assert_eq!(nginx.metrics.convertible, 1);
    assert_eq!(nginx.metrics.validated, 1);
    assert_eq!(
        nginx
            .detectability_reasons
            .get("arbitrary_header_unavailable"),
        Some(&2)
    );
    let raw_header = nginx
        .templates
        .iter()
        .find(|template| template.template_id == "synthetic-cve-2024-10002")
        .unwrap();
    assert_eq!(raw_header.level, Detectability::Undetectable);
    assert!(!raw_header.convertible);
}

#[test]
fn exports_case_normalized_header_dependencies_without_values() {
    let dependencies = combined_header_dependencies(Path::new("tests/fixtures/nuclei"));
    let structured = dependencies
        .iter()
        .find(|item| item.template_id == "synthetic-cve-2024-10001")
        .unwrap();
    assert_eq!(structured.headers[0].name, "x-synthetic-exploit");
    assert!(structured.headers[0].value_matters);
    assert!(!structured.headers[0].presence_only);
}
