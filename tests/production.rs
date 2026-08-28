use std::{fs, path::Path};

use assert_cmd::Command;
use chrono::{DateTime, Utc};
use predicates::str::contains;
use shenron::event::{TelemetryProfile, TrustedProxy, TrustedProxySet};
use shenron::production::{
    explain_private_findings, hunt, inspect, inspect_with_trusted_proxies, HuntTimeRange,
};
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
        HuntTimeRange::default(),
    )
    .unwrap();
    assert_eq!(report.metrics.total_requests_analyzed, 2);
    assert_eq!(report.metrics.cve_related_request_matches, 2);
    assert_eq!(report.metrics.request_specific_matches, 2);
    assert_eq!(report.metrics.response_unverified_matches, 0);
    assert_eq!(
        report.metrics.request_specific_matches + report.metrics.response_unverified_matches,
        report.metrics.cve_related_request_matches
    );
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
    let manifest = fs::read_to_string(output.path().join("run-manifest.json")).unwrap();
    assert!(manifest.contains("\"report_kind\": \"RUN_MANIFEST\""));
    assert!(manifest.contains("\"shenron_version\": \"0.1.0\""));
    assert!(manifest.contains("\"telemetry_profile\": \"aws-waf\""));
    assert!(manifest.contains("\"nuclei_revision\": \"synthetic-fixture-revision\""));
    assert!(manifest.contains("\"filter_from\": null"));
    assert!(manifest.contains("\"kind\": \"default-fixed-baseline\""));
    let manifest_json: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(
        manifest_json["inputs"]["nuclei_report"]["sha256"],
        "93eaf2a9a1727f4b024f605f1a8ddb091888e624335c0c378742a62d9c31f9ce"
    );
    assert_eq!(
        manifest_json["inputs"]["kev_report"]["sha256"],
        "bb0739b666865abab9d7efd398c5d40b11c84a1c1159d43162ee14bf12dec127"
    );
    assert!(manifest_json["inputs"]["nuclei_templates"]["sha256"].is_null());
    assert!(!manifest.contains("secret-token"));
    assert!(!manifest.contains("internal.example.test"));
    assert!(!manifest.contains("198.51.100.1"));
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
        .stdout(contains("Observed connection source (peer; may be CDN/LB/NAT, not attacker attribution): 198.51.100.2"))
        .stdout(contains("Validated forwarded client IP: not available (no trusted-proxy configuration or unverifiable)"))
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
            "--show-request",
        ])
        .assert()
        .success()
        .stdout(contains(
            "CVE / Nuclei template mappings: 1 (WAF outcome filter: not-blocked)",
        ))
        .stdout(contains("WAF action: ALLOW"));

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            private_findings.to_str().unwrap(),
            "--show-source-ips",
            "--limit",
            "1",
        ])
        .assert()
        .success()
        .stdout(contains(
            "Connection/client IP triage (private findings only):",
        ))
        .stdout(contains("Triage policy: default fixed baseline"))
        .stdout(contains("198.51.100.1"))
        .stdout(contains("Grouping identity: observed-peer"))
        .stdout(contains("Matching request observations: 1"));
}

#[test]
fn inspection_resolves_a_forwarded_client_only_through_a_trusted_peer() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("waf.jsonl");
    let waf = fs::read_to_string("tests/fixtures/production/waf.jsonl")
        .unwrap()
        .replacen(
            r#"{"name":"Host","value":"internal.example.test"}"#,
            r#"{"name":"Host","value":"internal.example.test"},{"name":"X-Forwarded-For","value":"203.0.113.25, 198.51.100.20"}"#,
            1,
        );
    fs::write(&input, waf).unwrap();
    let trusted_proxies =
        TrustedProxySet::new(vec!["198.51.100.0/24".parse::<TrustedProxy>().unwrap()]);
    let report =
        inspect_with_trusted_proxies(&input, TelemetryProfile::AwsWaf, 10, &trusted_proxies)
            .unwrap();
    assert_eq!(report.fields_available.client_ip, 1);
}

#[test]
fn explain_triages_only_repeated_distinct_source_behavior() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"template-one","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:01+00:00","source_ip":"198.51.100.9","host":"example.test","method":"GET","uri_path":"/one","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"template-two","cves":["CVE-2024-10002"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:02+00:00","source_ip":"198.51.100.9","host":"example.test","method":"GET","uri_path":"/two","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"template-two","cves":["CVE-2024-10002"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:03+00:00","source_ip":"198.51.100.9","host":"example.test","method":"GET","uri_path":"/three","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"template-one","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:04+00:00","source_ip":"198.51.100.10","host":"example.test","method":"GET","uri_path":"/one","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n"
        ),
    )
    .unwrap();
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--show-source-ips",
            "--limit",
            "0",
        ])
        .assert()
        .success()
        .stdout(contains(
            "IP groups requiring investigation (repeated CVE-pattern behavior):",
        ))
        .stdout(contains(
            "198.51.100.9\n  Grouping identity: observed-peer\n  Triage basis: breadth\n  Matching request observations: 3",
        ))
        .stdout(contains(
            "198.51.100.10\n  Grouping identity: observed-peer\n  Triage basis: none\n  Matching request observations: 1",
        ));
}

#[test]
fn explain_allows_explicit_non_default_triage_thresholds() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"template-one","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:01+00:00","source_ip":"198.51.100.9","host":"example.test","method":"GET","uri_path":"/one","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"template-two","cves":["CVE-2024-10002"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:02+00:00","source_ip":"198.51.100.9","host":"example.test","method":"GET","uri_path":"/two","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"template-two","cves":["CVE-2024-10002"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:03+00:00","source_ip":"198.51.100.9","host":"example.test","method":"GET","uri_path":"/three","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"template-one","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:04+00:00","source_ip":"198.51.100.10","host":"example.test","method":"GET","uri_path":"/one","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n"
        ),
    )
    .unwrap();

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--show-source-ips",
            "--triage-breadth-observations",
            "4",
            "--triage-depth-observations",
            "20",
        ])
        .assert()
        .success()
        .stdout(contains(
            "Triage policy: CUSTOM (non-default; not comparable to the fixed research baseline)",
        ))
        .stdout(contains(
            "No IP group met the repeated-pattern triage threshold.",
        ));

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--show-source-ips",
            "--triage-breadth-observations",
            "1",
            "--triage-breadth-templates",
            "1",
        ])
        .assert()
        .success()
        .stdout(contains(
            "Triage policy: CUSTOM (non-default; not comparable to the fixed research baseline)",
        ))
        .stdout(contains(
            "198.51.100.10\n  Grouping identity: observed-peer\n  Triage basis: breadth",
        ));
}

#[test]
fn explain_windowed_triage_distinguishes_bursts_and_excludes_undated_records() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    let record = |source_ip: &str, timestamp: Option<&str>, template: &str, path: &str| {
        format!(
            r#"{{"template_id":"{template}","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":{},"source_ip":"{source_ip}","host":"example.test","method":"GET","uri_path":"{path}","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}}"#,
            timestamp
                .map(|value| format!("\"{value}\""))
                .unwrap_or_else(|| "null".to_owned()),
        )
    };
    let records = [
        record(
            "198.51.100.9",
            Some("2026-08-24T00:00:00+00:00"),
            "template-one",
            "/one",
        ),
        record(
            "198.51.100.9",
            Some("2026-08-24T00:01:00+00:00"),
            "template-two",
            "/two",
        ),
        record(
            "198.51.100.9",
            Some("2026-08-24T01:00:00+00:00"),
            "template-two",
            "/three",
        ),
        record("198.51.100.9", None, "template-one", "/undated"),
        record(
            "198.51.100.10",
            Some("2026-08-24T00:00:00+00:00"),
            "template-one",
            "/one",
        ),
        record(
            "198.51.100.10",
            Some("2026-08-24T00:01:00+00:00"),
            "template-two",
            "/two",
        ),
        record(
            "198.51.100.10",
            Some("2026-08-24T00:02:00+00:00"),
            "template-two",
            "/three",
        ),
    ]
    .join("\n");
    fs::write(&findings, records).unwrap();

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--show-source-ips",
            "--triage-window",
            "10m",
            "--limit",
            "0",
        ])
        .assert()
        .success()
        .stdout(contains(
            "Triage policy: CUSTOM (non-default; not comparable to the fixed research baseline)",
        ))
        .stdout(contains("Triage window: 10m sliding"))
        .stdout(contains(
            "198.51.100.10\n  Grouping identity: observed-peer\n  Triage basis: windowed breadth",
        ))
        .stdout(contains(
            "198.51.100.9\n  Grouping identity: observed-peer\n  Triage basis: none",
        ))
        .stdout(contains(
            "Undated observations excluded from windowed triage: 1",
        ));

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--show-source-ips",
            "--triage-window",
            "12x",
        ])
        .assert()
        .failure()
        .stderr(contains("invalid duration"));
}

#[test]
fn explain_triages_repeated_single_template_behavior_by_depth() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    let repeated = (0..10)
        .map(|second| {
            format!(
                r#"{{"template_id":"template-depth","cves":["CVE-2024-10003"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:{second:02}+00:00","source_ip":"198.51.100.11","host":"example.test","method":"GET","uri_path":"/same-path","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}}"#
            )
        })
        .chain((0..2).map(|second| {
            format!(
                r#"{{"template_id":"template-depth","cves":["CVE-2024-10003"],"detectability":"HIGH","timestamp":"2026-08-24T00:01:{second:02}+00:00","source_ip":"198.51.100.12","host":"example.test","method":"GET","uri_path":"/same-path","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}}"#
            )
        }))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&findings, repeated).unwrap();
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--show-source-ips",
            "--limit",
            "0",
        ])
        .assert()
        .success()
        .stdout(contains(
            "198.51.100.11\n  Grouping identity: observed-peer\n  Triage basis: depth\n  Matching request observations: 10",
        ))
        .stdout(contains(
            "198.51.100.12\n  Grouping identity: observed-peer\n  Triage basis: none\n  Matching request observations: 2",
        ));
}

#[test]
fn explain_prefers_a_validated_client_for_ip_grouping() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        r#"{"template_id":"template-one","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:01+00:00","source_ip":"198.51.100.9","client_ip":"203.0.113.9","host":"example.test","method":"GET","uri_path":"/one","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
    )
    .unwrap();
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--show-source-ips",
            "--limit",
            "0",
        ])
        .assert()
        .success()
        .stdout(contains("203.0.113.9\n  Grouping identity: validated-client"))
        .stdout(contains("Grouping identity: validated-client when a trusted forwarded chain was verified; otherwise observed-peer"));
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
        HuntTimeRange::default(),
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
        HuntTimeRange::default(),
    )
    .unwrap();
    assert!(!report.metrics.waf_outcome_available);
    assert_eq!(report.metrics.cve_related_request_matches, 1);
    assert_eq!(report.metrics.request_specific_matches, 0);
    assert_eq!(report.metrics.response_unverified_matches, 1);
    assert_eq!(
        report.cve_findings[0].response_status_counts.get(&404),
        Some(&1)
    );
    assert_eq!(report.cve_findings[0].protection_gap_rate, None);
}

#[test]
fn apache_vhost_hunt_preserves_vhost_without_claiming_a_waf_outcome() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("other_vhosts_access.log");
    fs::write(
        &input,
        r#"api.example.test:443 198.51.100.9 - - [24/Aug/2026:11:20:30 +0000] "GET /first-literal-path HTTP/1.1" 404 42 "-" "example-agent""#,
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
    let inspection = inspect(&input, TelemetryProfile::ApacheVhostCombined, 10).unwrap();
    assert_eq!(inspection.fields_available.host, 1);
    let report = hunt(
        &input,
        Path::new("tests/fixtures/nuclei"),
        &nuclei_report,
        &kev_report,
        &directory.path().join("results"),
        TelemetryProfile::ApacheVhostCombined,
        HuntTimeRange::default(),
    )
    .unwrap();
    assert!(!report.metrics.waf_outcome_available);
    assert_eq!(report.cve_findings[0].unique_hosts, 1);
    assert_eq!(
        report.cve_findings[0].response_status_counts.get(&404),
        Some(&1)
    );
}

#[test]
fn hunt_filters_an_inclusive_utc_time_range_before_matching() {
    let output = tempdir().unwrap();
    let report = hunt(
        Path::new("tests/fixtures/production/waf.jsonl"),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Path::new("tests/fixtures/production/kev-report.json"),
        output.path(),
        TelemetryProfile::AwsWaf,
        HuntTimeRange {
            from: Some(parse_utc("2025-01-01T00:00:30Z")),
            to: Some(parse_utc("2025-01-01T00:01:00Z")),
        },
    )
    .unwrap();
    assert_eq!(report.metrics.total_requests_analyzed, 1);
    assert_eq!(report.metrics.requests_outside_time_range, 1);
    assert_eq!(report.metrics.requests_without_timestamp_excluded, 0);
    assert_eq!(report.metrics.cve_related_request_matches, 1);
    assert_eq!(report.metrics.request_specific_matches, 1);
    assert_eq!(report.metrics.response_unverified_matches, 0);
    assert_eq!(
        report.metrics.request_specific_matches + report.metrics.response_unverified_matches,
        report.metrics.cve_related_request_matches
    );
    assert_eq!(report.metrics.blocked, 1);
    assert_eq!(
        report.metrics.filter_from.as_deref(),
        Some("2025-01-01T00:00:30+00:00")
    );
    assert_eq!(
        report.metrics.filter_to.as_deref(),
        Some("2025-01-01T00:01:00+00:00")
    );
}

fn parse_utc(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}
