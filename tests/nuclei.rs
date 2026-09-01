use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use assert_cmd::Command;
use predicates::str::contains;
use shenron::nuclei::{
    combined_header_dependencies, compare_telemetry, coverage, inventory, path_distinctiveness,
    ConversionStatus, Detectability, PathDistinctiveness, RequestSpecificity,
};
use shenron::waf::parse_line;
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
fn classifies_path_distinctiveness_with_a_transparent_path_only_heuristic() {
    for path in ["/robots.txt", "/login", "/user/login", "/api/config", "/"] {
        assert_eq!(path_distinctiveness(path), PathDistinctiveness::Generic);
    }
    for path in [
        "/.env",
        "/remote/login",
        "/wp-json/gravitysmtp/v1/tests/mock-data",
        "/wp-content/plugins/x/y.php",
    ] {
        assert_eq!(path_distinctiveness(path), PathDistinctiveness::Distinctive);
    }
}

#[test]
fn exposes_a_template_derived_request_matcher_view() {
    let approved = ["synthetic-cve-2024-10001"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let detection =
        shenron::nuclei::validated_detections(Path::new("tests/fixtures/nuclei"), &approved)
            .into_iter()
            .next()
            .unwrap();

    let matcher = detection.request_matcher_view();
    assert_eq!(matcher.method, "GET");
    assert_eq!(matcher.path, "/vulnerable/execute");
    assert_eq!(matcher.query.as_deref(), Some("cmd=probe"));
    assert_eq!(matcher.fragment, None);
    assert_eq!(
        matcher.headers,
        [("X-Synthetic-Exploit".to_owned(), "marker-10001".to_owned())]
    );
    assert_eq!(
        matcher.request_specificity,
        RequestSpecificity::RequestSpecific
    );
    assert_eq!(
        matcher.path_distinctiveness,
        PathDistinctiveness::Distinctive
    );
}

#[test]
fn lab_matchers_lists_supported_template_literals_and_respects_frozen_report_gates() {
    let output_directory = tempdir().unwrap();
    let all_output = output_directory.path().join("all-matchers.json");
    Command::cargo_bin("shenron-lab")
        .unwrap()
        .args([
            "nuclei",
            "matchers",
            "--templates",
            "tests/fixtures/nuclei",
            "--revision",
            "fixture-revision",
            "--output",
            all_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    let all_matchers: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&all_output).unwrap()).unwrap();
    let all_records = all_matchers.as_array().unwrap();
    assert_eq!(all_records.len(), 5);
    let raw_matcher = all_records
        .iter()
        .find(|record| record["template_id"] == "synthetic-cve-2024-10002")
        .unwrap();
    assert_eq!(raw_matcher["path"], "/vulnerable/raw");
    assert_eq!(raw_matcher["query"], "mode=check");
    assert_eq!(raw_matcher["request_specificity"], "request-specific");
    assert_eq!(raw_matcher["path_distinctiveness"], "distinctive");

    let filtered_output = output_directory.path().join("filtered-matchers.json");
    Command::cargo_bin("shenron-lab")
        .unwrap()
        .args([
            "nuclei",
            "matchers",
            "--templates",
            "tests/fixtures/nuclei",
            "--revision",
            "fixture-revision",
            "--report",
            "tests/fixtures/production/nuclei-report.json",
            "--output",
            filtered_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    let filtered_matchers: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(filtered_output).unwrap()).unwrap();
    let filtered_records = filtered_matchers.as_array().unwrap();
    assert_eq!(filtered_records.len(), 1);
    assert_eq!(
        filtered_records[0]["template_id"],
        "synthetic-cve-2024-10001"
    );
}

// These tests use only file:// remotes. CI never contacts GitHub while
// exercising the clone, fetch, default-branch, and pinned-checkout paths.
#[test]
fn lab_update_checks_out_an_explicit_local_revision() {
    let directory = tempdir().unwrap();
    let (source, first_revision, _) = local_template_repo(directory.path());
    let destination = directory.path().join("checkouts/nuclei-templates");
    let repository = format!("file://{}", source.display());

    let mut command = Command::cargo_bin("shenron-lab").unwrap();
    command.env("GIT_ALLOW_PROTOCOL", "file");
    command
        .args([
            "nuclei",
            "update",
            "--templates",
            destination.to_str().unwrap(),
            "--repo",
            &repository,
            "--revision",
            &first_revision,
        ])
        .assert()
        .success()
        .stdout(contains(&first_revision))
        .stdout(contains("no customer data was transmitted"));
    assert_eq!(git_at(&destination, &["rev-parse", "HEAD"]), first_revision);
}

#[test]
fn lab_update_uses_the_local_remote_default_branch_tip_when_unpinned() {
    let directory = tempdir().unwrap();
    let (source, _, latest_revision) = local_template_repo(directory.path());
    let destination = directory.path().join("nuclei-templates");
    let repository = format!("file://{}", source.display());

    let mut command = Command::cargo_bin("shenron-lab").unwrap();
    command.env("GIT_ALLOW_PROTOCOL", "file");
    command
        .args([
            "nuclei",
            "update",
            "--templates",
            destination.to_str().unwrap(),
            "--repo",
            &repository,
        ])
        .assert()
        .success()
        .stdout(contains(&latest_revision));
    assert_eq!(
        git_at(&destination, &["rev-parse", "HEAD"]),
        latest_revision
    );
}

fn local_template_repo(root: &Path) -> (PathBuf, String, String) {
    let source = root.join("public-nuclei-templates");
    fs::create_dir_all(source.join("http/cves")).unwrap();
    git_at(&source, &["init"]);
    fs::write(source.join("http/cves/first.yaml"), "id: first\n").unwrap();
    git_at(&source, &["add", "."]);
    git_at(
        &source,
        &[
            "-c",
            "user.name=Shenron Test",
            "-c",
            "user.email=shenron-test@example.invalid",
            "commit",
            "-m",
            "first",
        ],
    );
    let first_revision = git_at(&source, &["rev-parse", "HEAD"]);
    fs::write(source.join("http/cves/second.yaml"), "id: second\n").unwrap();
    git_at(&source, &["add", "."]);
    git_at(
        &source,
        &[
            "-c",
            "user.name=Shenron Test",
            "-c",
            "user.email=shenron-test@example.invalid",
            "commit",
            "-m",
            "second",
        ],
    );
    let latest_revision = git_at(&source, &["rev-parse", "HEAD"]);
    (source, first_revision, latest_revision)
}

fn git_at(directory: &Path, args: &[&str]) -> String {
    let output = ProcessCommand::new("git")
        .current_dir(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn derived_ablation_matchers_are_monotonic_for_the_same_detection_ir() {
    let approved = ["synthetic-cve-2024-10002"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let detection =
        shenron::nuclei::validated_detections(Path::new("tests/fixtures/nuclei"), &approved)
            .into_iter()
            .next()
            .unwrap();
    let raw = r#"{"timestamp":1735689600000,"fragment":"fragment-10002","httpRequest":{"clientIp":"192.0.2.10","headers":[{"name":"Host","value":"example.test"},{"name":"X-Synthetic-Mode","value":"raw-10002"}],"uri":"/vulnerable/raw","args":"mode=check","httpMethod":"POST"}}"#;
    let event = parse_line(raw).unwrap();
    assert!(detection.matches_path_only(&event));
    assert!(detection.matches_path_and_query(&event));
    assert!(detection.matches_path_query_headers(&event));
    assert!(detection.matches(&event));

    let mut method_mismatch = event.clone();
    method_mismatch.method = Some("GET".to_owned());
    assert!(method_mismatch.uri_path.is_some());
    assert!(detection.matches_path_only(&method_mismatch));
    assert!(detection.matches_path_and_query(&method_mismatch));
    assert!(detection.matches_path_query_headers(&method_mismatch));
    assert!(!detection.matches(&method_mismatch));

    let mut fragment_mismatch = event.clone();
    fragment_mismatch.uri_fragment = Some("other-fragment".to_owned());
    assert!(detection.matches_path_only(&fragment_mismatch));
    assert!(detection.matches_path_and_query(&fragment_mismatch));
    assert!(detection.matches_path_query_headers(&fragment_mismatch));
    assert!(!detection.matches(&fragment_mismatch));

    let mut header_mismatch = event.clone();
    header_mismatch.headers.clear();
    assert!(detection.matches_path_only(&header_mismatch));
    assert!(detection.matches_path_and_query(&header_mismatch));
    assert!(!detection.matches_path_query_headers(&header_mismatch));
    assert!(!detection.matches(&header_mismatch));
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
