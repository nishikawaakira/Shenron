use std::{fs, path::Path};

use assert_cmd::Command;
use predicates::str::contains;
use shenron::event::TelemetryProfile;
use shenron::production::{explain_private_findings, hunt, inspect};
use tempfile::tempdir;

#[test]
fn inspection_reports_structure_without_request_values() {
    let report = inspect(
        Path::new("tests/fixtures/production/waf.jsonl"),
        TelemetryProfile::AwsWaf,
        10,
    )
    .unwrap();
    assert_eq!(report.files_found, 1);
    assert_eq!(report.sampled_events, 2);
    assert_eq!(report.malformed_events, 0);
    assert_eq!(report.fields_available.ja4, 2);
    assert_eq!(report.fields_available.query, 2);
    assert_eq!(report.fields_available.headers, 2);
}

#[test]
fn hunt_uses_validated_matchers_and_separates_sensitive_output() {
    let output = tempdir().unwrap();
    let report = hunt(
        Path::new("tests/fixtures/production/waf.jsonl"),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Path::new("tests/fixtures/production/kev-report.json"),
        output.path(),
        TelemetryProfile::AwsWaf,
    )
    .unwrap();
    assert_eq!(report.metrics.total_requests_analyzed, 2);
    assert_eq!(report.metrics.exploitation_attempt_findings, 2);
    assert_eq!(report.metrics.unique_cves_observed, 1);
    assert_eq!(report.metrics.unique_cisa_kevs_observed, 1);
    assert_eq!(report.metrics.blocked, 1);
    assert_eq!(report.metrics.allowed_or_not_blocked, 1);
    assert_eq!(report.cve_findings[0].outcomes.allowed_or_not_blocked, 1);
    assert_eq!(report.cve_findings[0].outcomes.blocked, 1);
    assert_eq!(report.cve_findings[0].protection_gap_rate, Some(0.5));
    assert!(report.cve_findings[0].response_status_counts.is_empty());

    let private = fs::read_to_string(output.path().join("private-findings.jsonl")).unwrap();
    assert!(private.contains("secret-token"));
    let sanitized = serde_json::to_string(&report).unwrap();
    assert!(!sanitized.contains("secret-token"));
    assert!(!sanitized.contains("internal.example.test"));
    assert!(!sanitized.contains("198.51.100.1"));
    let explanations =
        explain_private_findings(&output.path().join("private-findings.jsonl")).unwrap();
    assert_eq!(explanations.len(), 2);
    assert_eq!(explanations[0].template_id, "synthetic-cve-2024-10001");
    assert_eq!(explanations[0].cves, ["CVE-2024-10001"]);
    assert_eq!(
        explanations[0].ja4.as_deref(),
        Some("t13d1516h2_8daaf6152771_02713d6af862")
    );
    assert_eq!(
        explanations[0].waf_rule_id.as_deref(),
        Some("Default_Action")
    );
    assert!(explanations[0]
        .headers
        .iter()
        .any(|header| header.name == "X-Synthetic-Exploit"));

    let private_findings = output.path().join("private-findings.jsonl");
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            private_findings.to_str().unwrap(),
            "--waf-outcome",
            "block",
            "--show-evidence",
        ])
        .assert()
        .success()
        .stdout(contains(
            "CVE / Nuclei template mappings: 1 (WAF outcome filter: block)",
        ))
        .stdout(contains("WAF action: BLOCK"))
        .stdout(contains("AWS#KnownExploit"));

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            private_findings.to_str().unwrap(),
            "--waf-outcome",
            "not-blocked",
        ])
        .assert()
        .success()
        .stdout(contains(
            "CVE / Nuclei template mappings: 1 (WAF outcome filter: not-blocked)",
        ))
        .stdout(contains("WAF action: ALLOW"));
}

#[test]
fn hunt_rejects_an_output_nested_under_immutable_input() {
    let input = tempdir().unwrap();
    fs::copy(
        "tests/fixtures/production/waf.jsonl",
        input.path().join("waf.jsonl"),
    )
    .unwrap();
    assert!(hunt(
        input.path(),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Path::new("tests/fixtures/production/kev-report.json"),
        &input.path().join("derived"),
        TelemetryProfile::AwsWaf,
    )
    .is_err());
}

#[test]
fn nginx_hunt_preserves_status_context_without_claiming_a_waf_outcome() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("access.log");
    fs::write(
        &input,
        r#"198.51.100.9 - - [24/Aug/2026:11:20:30 +0000] "GET /first-literal-path HTTP/1.1" 404 42 "-" "example-agent""#,
    )
    .unwrap();
    let nuclei_report = directory.path().join("nuclei-report.json");
    fs::write(
        &nuclei_report,
        r#"{"templates":[{"template_id":"synthetic-cve-2024-10008","cves":["CVE-2024-10008"],"conversion_status":"SUPPORTED","validation_status":"passed"}]}"#,
    )
    .unwrap();
    let kev_report = directory.path().join("kev-report.json");
    fs::write(&kev_report, r#"{"entries":[]}"#).unwrap();
    let report = hunt(
        &input,
        Path::new("tests/fixtures/nuclei"),
        &nuclei_report,
        &kev_report,
        &directory.path().join("results"),
        TelemetryProfile::NginxCombined,
    )
    .unwrap();
    assert!(!report.metrics.waf_outcome_available);
    assert_eq!(
        report.cve_findings[0].response_status_counts.get(&404),
        Some(&1)
    );
    assert_eq!(report.cve_findings[0].protection_gap_rate, None);
}
