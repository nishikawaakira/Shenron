use std::{
    fs,
    path::{Path, PathBuf},
};

use assert_cmd::Command;
use chrono::{DateTime, Utc};
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use shenron::event::{TelemetryProfile, TrustedProxy, TrustedProxySet};
use shenron::production::{
    ablation, concentration, count_hypotheses, explain_private_findings, historical_replay, hunt,
    hunt_with_options, inspect, inspect_with_trusted_proxies, HuntOptions, HuntTimeRange,
};
use tempfile::tempdir;
use walkdir::WalkDir;

#[test]
fn ablation_compares_aggregate_match_volume_without_private_values() {
    let report = ablation(
        Path::new("tests/fixtures/production/waf.jsonl"),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Path::new("tests/fixtures/production/kev-report.json"),
        TelemetryProfile::AwsWaf,
        HuntTimeRange::default(),
    )
    .unwrap();

    assert_eq!(report.report_kind, "ABLATION_VOLUME_COMPARISON");
    assert_eq!(report.total_events_evaluated, 2);
    assert_eq!(report.strategies.len(), 5);
    for window in report.strategies.windows(2) {
        assert!(window[0].matched_events >= window[1].matched_events);
        assert!(window[0].distinct_event_cve_matches >= window[1].distinct_event_cve_matches);
    }
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(serialized.contains("match-volume comparison"));
    assert!(!serialized.contains("secret-token"));
    assert!(!serialized.contains("internal.example.test"));
    assert!(!serialized.contains("198.51.100.1"));
}

#[test]
fn ablation_cli_writes_an_aggregate_only_report() {
    let output_directory = tempdir().unwrap();
    let output = output_directory.path().join("ablation.json");
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "ablation",
            "--input",
            "tests/fixtures/production/waf.jsonl",
            "--format",
            "aws-waf",
            "--nuclei-templates",
            "tests/fixtures/nuclei",
            "--nuclei-report",
            "tests/fixtures/production/nuclei-report.json",
            "--kev-report",
            "tests/fixtures/production/kev-report.json",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains("Ablation match-volume comparison only"))
        .stdout(contains("NOT precision"));

    let written = fs::read_to_string(output).unwrap();
    assert!(written.contains("ABLATION_VOLUME_COMPARISON"));
    assert!(!written.contains("secret-token"));
    assert!(!written.contains("internal.example.test"));
    assert!(!written.contains("198.51.100.1"));
}

#[test]
fn concentration_writes_private_detail_without_leaking_it_to_sanitized_or_default_stdout() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("access.log");
    fs::write(
        &input,
        concat!(
            "198.51.100.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /private-hot-path HTTP/1.1\" 403 10 \"-\" \"fixture-agent\"\n",
            "198.51.100.2 - - [01/Jan/2026:00:00:00 +0000] \"GET /private-hot-path HTTP/1.1\" 403 10 \"-\" \"fixture-agent\"\n",
            "198.51.100.3 - - [01/Jan/2026:00:01:00 +0000] \"GET /private-hot-path HTTP/1.1\" 404 10 \"-\" \"fixture-agent\"\n",
            "203.0.113.4 - - [01/Jan/2026:00:01:00 +0000] \"GET /other HTTP/1.1\" 200 5 \"-\" \"fixture-agent\"\n",
        ),
    )
    .unwrap();
    let output = directory.path().join("concentration-output");
    let report = concentration(
        &input,
        &output,
        TelemetryProfile::ApacheCombined,
        HuntTimeRange::default(),
    )
    .unwrap();
    assert_eq!(report.report_kind, "SANITIZED_REQUEST_CONCENTRATION");
    assert_eq!(report.total_requests_analyzed, 4);
    let top = report.request_concentration.top_path.as_ref().unwrap();
    assert_eq!(top.requests, 3);
    assert_eq!(top.distinct_source_ips, 3);
    assert_eq!(top.request_share, 0.75);
    assert_eq!(top.response_status_classes.client_error, 3);
    assert_eq!(top.response_bytes, Some(30));
    assert!(output.join("request-concentration.json").is_file());
    assert!(output.join("sanitized-research.json").is_file());
    let sanitized = fs::read_to_string(output.join("sanitized-research.json")).unwrap();
    assert!(!sanitized.contains("/private-hot-path"));
    assert!(!sanitized.contains("198.51.100.1"));
    let private = fs::read_to_string(output.join("request-concentration.json")).unwrap();
    assert!(private.contains("/private-hot-path"));
    assert!(private.contains("198.51.100.1"));

    let cli_output = directory.path().join("cli-concentration-output");
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "concentration",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "apache",
            "--output",
            cli_output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains("Request concentration (volume distribution only"))
        .stdout(contains("75.0% of 4 requests, from 3 distinct source IPs"))
        .stdout(contains("/private-hot-path").not())
        .stdout(contains("198.51.100.1").not());
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "concentration",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "apache",
            "--output",
            directory.path().join("cli-show-output").to_str().unwrap(),
            "--show-paths",
            "--show-source-ips",
        ])
        .assert()
        .success()
        .stdout(contains("/private-hot-path"))
        .stdout(contains("198.51.100.1"));
}

#[test]
fn historical_replay_measures_sanitized_cve_coverage_and_other_matches() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"synthetic-cve-2024-10001","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2025-01-01T00:00:00Z","source_ip":"198.51.100.1","host":"internal.example.test","method":"GET","uri_path":"/vulnerable/execute","uri_query":"cmd=probe","headers":[],"ja3":null,"ja4":null,"waf_action":"ALLOW","request_id":"production-allow"}"#,
            "\n"
        ),
    )
    .unwrap();
    let report = historical_replay(
        Path::new("tests/fixtures/production/waf.jsonl"),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Path::new("tests/fixtures/production/kev-report.json"),
        &findings,
        TelemetryProfile::AwsWaf,
        HuntTimeRange::default(),
    )
    .unwrap();
    assert_eq!(report.report_kind, "HISTORICAL_REPLAY_COVERAGE");
    assert_eq!(report.total_events_evaluated, 2);
    assert_eq!(report.per_cve.len(), 1);
    let coverage = &report.per_cve[0];
    assert_eq!(coverage.cve, "CVE-2024-10001");
    assert!(coverage.is_kev);
    assert_eq!(coverage.known_findings, 1);
    assert_eq!(coverage.known_matched, 1);
    assert_eq!(coverage.known_missed, 0);
    assert_eq!(coverage.coverage, Some(1.0));
    assert_eq!(coverage.other_matches_with_request_id, 1);
    assert_eq!(coverage.other_matches_without_request_id, 0);
    assert_eq!(coverage.matched_events_blocked, 1);
    assert_eq!(coverage.matched_events_not_blocked, 1);
    assert_eq!(coverage.matched_events_unknown_outcome, 0);
    assert_eq!(report.aggregate.known_findings, 1);
    assert_eq!(report.aggregate.known_matched, 1);
    assert_eq!(report.aggregate.matched_events_total, 2);
    assert_eq!(report.aggregate.other_matches_with_request_id, 1);
    assert_eq!(report.aggregate.other_matches_without_request_id, 0);
    assert_eq!(report.aggregate.matched_events_blocked, 1);
    assert_eq!(report.aggregate.matched_events_not_blocked, 1);

    let missed_findings = directory.path().join("missed-private-findings.jsonl");
    fs::write(
        &missed_findings,
        fs::read_to_string(&findings)
            .unwrap()
            .replace("production-allow", "source-request-not-in-corpus"),
    )
    .unwrap();
    let missed = historical_replay(
        Path::new("tests/fixtures/production/waf.jsonl"),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Path::new("tests/fixtures/production/kev-report.json"),
        &missed_findings,
        TelemetryProfile::AwsWaf,
        HuntTimeRange::default(),
    )
    .unwrap();
    assert_eq!(missed.per_cve[0].coverage, Some(0.0));
    assert_eq!(missed.aggregate.coverage, Some(0.0));

    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains("secret-token"));
    assert!(!serialized.contains("internal.example.test"));
    assert!(!serialized.contains("198.51.100.1"));

    let output = directory.path().join("historical-replay.json");
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "replay",
            "--input",
            "tests/fixtures/production/waf.jsonl",
            "--format",
            "aws-waf",
            "--nuclei-templates",
            "tests/fixtures/nuclei",
            "--nuclei-report",
            "tests/fixtures/production/nuclei-report.json",
            "--kev-report",
            "tests/fixtures/production/kev-report.json",
            "--findings",
            findings.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains(
            "Historical replay coverage is a conservative lower bound",
        ))
        .stdout(contains("Conservative coverage:"));
    let written = fs::read_to_string(output).unwrap();
    assert!(written.contains("HISTORICAL_REPLAY_COVERAGE"));
    assert!(!written.contains("secret-token"));
    assert!(!written.contains("internal.example.test"));
    assert!(!written.contains("198.51.100.1"));
}

#[test]
fn historical_replay_aggregate_counts_a_multi_cve_source_once() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("multi-cve-private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"synthetic-cve-2024-10001","cves":["CVE-2024-10001","CVE-2024-10002"],"detectability":"HIGH","timestamp":"2025-01-01T00:00:00Z","source_ip":"198.51.100.1","host":"internal.example.test","method":"GET","uri_path":"/vulnerable/execute","uri_query":"cmd=probe","headers":[],"ja3":null,"ja4":null,"waf_action":"ALLOW","request_id":"production-allow"}"#,
            "\n"
        ),
    )
    .unwrap();
    let report = historical_replay(
        Path::new("tests/fixtures/production/waf.jsonl"),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Path::new("tests/fixtures/production/kev-report.json"),
        &findings,
        TelemetryProfile::AwsWaf,
        HuntTimeRange::default(),
    )
    .unwrap();

    assert_eq!(report.aggregate.known_findings, 1);
    assert_eq!(report.aggregate.known_matched, 1);
    assert_eq!(report.aggregate.known_missed, 0);
    assert_eq!(report.aggregate.coverage, Some(1.0));
    assert_eq!(report.per_cve.len(), 2);
    assert!(report
        .per_cve
        .iter()
        .all(|coverage| coverage.known_findings == 1));
}

#[test]
fn count_hypotheses_reports_a_sanitized_monotonic_per_cve_ladder() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"synthetic-cve-2024-10001","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2025-01-01T00:00:00Z","source_ip":"198.51.100.1","host":"internal.example.test","method":"GET","uri_path":"/vulnerable/execute","uri_query":"cmd=probe","headers":[],"ja3":null,"ja4":null,"waf_action":"ALLOW","request_id":"production-allow"}"#,
            "\n"
        ),
    )
    .unwrap();
    let report = count_hypotheses(
        Path::new("tests/fixtures/production/waf.jsonl"),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Path::new("tests/fixtures/production/kev-report.json"),
        &findings,
        TelemetryProfile::AwsWaf,
        HuntTimeRange::default(),
    )
    .unwrap();
    assert_eq!(report.report_kind, "COUNT_HYPOTHESIS_LADDER");
    assert_eq!(report.total_events_evaluated, 2);
    assert_eq!(report.per_cve.len(), 1);
    let hypothesis = &report.per_cve[0];
    assert_eq!(hypothesis.cve, "CVE-2024-10001");
    assert!(hypothesis.is_kev);
    assert_eq!(hypothesis.known_findings, 1);
    assert_eq!(hypothesis.rungs.len(), 5);
    assert_eq!(
        hypothesis
            .rungs
            .iter()
            .map(|rung| rung.strategy.as_str())
            .collect::<Vec<_>>(),
        vec![
            "path_only",
            "path_and_query",
            "path_query_headers",
            "nuclei_ir",
            "nuclei_ir_request_specific",
        ]
    );
    for pair in hypothesis.rungs.windows(2) {
        assert!(pair[0].matched_events >= pair[1].matched_events);
        assert!(pair[0].known_matched >= pair[1].known_matched);
    }
    let full_ir = &hypothesis.rungs[3];
    assert_eq!(full_ir.matched_events, 2);
    assert_eq!(full_ir.known_matched, 1);
    assert_eq!(full_ir.known_coverage, Some(1.0));
    assert_eq!(full_ir.other_matches_with_request_id, 1);
    assert_eq!(full_ir.other_matches_without_request_id, 0);
    assert_eq!(full_ir.matched_events_blocked, 1);
    assert_eq!(full_ir.matched_events_not_blocked, 1);
    assert_eq!(full_ir.matched_events_unknown_outcome, 0);

    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains("secret-token"));
    assert!(!serialized.contains("internal.example.test"));
    assert!(!serialized.contains("198.51.100.1"));

    let output = directory.path().join("count-hypotheses.json");
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "count-hypotheses",
            "--input",
            "tests/fixtures/production/waf.jsonl",
            "--format",
            "aws-waf",
            "--nuclei-templates",
            "tests/fixtures/nuclei",
            "--nuclei-report",
            "tests/fixtures/production/nuclei-report.json",
            "--kev-report",
            "tests/fixtures/production/kev-report.json",
            "--findings",
            findings.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains("COUNT hypothesis ladder is an offline"))
        .stdout(contains("nuclei_ir_request_specific"));
    let written = fs::read_to_string(output).unwrap();
    assert!(written.contains("COUNT_HYPOTHESIS_LADDER"));
    assert!(!written.contains("secret-token"));
    assert!(!written.contains("internal.example.test"));
    assert!(!written.contains("198.51.100.1"));
}

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
    assert_eq!(report.metrics.distinctive_path_matches, 2);
    assert_eq!(report.metrics.generic_path_matches, 0);
    assert_eq!(
        report.metrics.request_specific_matches + report.metrics.response_unverified_matches,
        report.metrics.cve_related_request_matches
    );
    assert_eq!(report.metrics.unique_cves_observed, 1);
    let concentration = report.metrics.request_concentration.as_ref().unwrap();
    assert_eq!(concentration.total_requests, 2);
    assert_eq!(
        concentration.top_path.as_ref().unwrap().response_bytes,
        None
    );
    assert!(output.path().join("request-concentration.json").is_file());
    assert_eq!(report.metrics.unique_cisa_kevs_observed, 1);
    assert_eq!(report.metrics.blocked, 1);
    assert_eq!(report.metrics.allowed_or_not_blocked, 1);
    assert_eq!(report.cve_findings[0].outcomes.allowed_or_not_blocked, 1);
    assert_eq!(report.cve_findings[0].outcomes.blocked, 1);
    assert_eq!(report.cve_findings[0].protection_gap_rate, Some(0.5));
    assert_eq!(report.cve_findings[0].distinctive_path_matches, 2);
    assert_eq!(report.cve_findings[0].generic_path_matches, 0);
    assert!(report.cve_findings[0].response_status_counts.is_empty());

    let private = fs::read_to_string(output.path().join("private-findings.jsonl")).unwrap();
    assert!(private.contains("secret-token"));
    let sanitized = serde_json::to_string(&report).unwrap();
    assert!(!sanitized.contains("secret-token"));
    assert!(!sanitized.contains("internal.example.test"));
    assert!(!sanitized.contains("198.51.100.1"));
    assert!(!sanitized.contains("/vulnerable/execute"));
    assert!(sanitized.contains("\"distinctive_path_matches\":2"));
    assert!(sanitized.contains("\"generic_path_matches\":0"));
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
fn hunt_uses_prepared_default_inputs_and_output_without_kev() {
    let directory = tempdir().unwrap();
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let data_dir = directory.path().join("shenron-data");
    let templates = data_dir.join("nuclei-templates");
    copy_tree(&project.join("tests/fixtures/nuclei"), &templates);
    let nuclei_report = data_dir.join("nuclei-report.json");
    fs::create_dir_all(&data_dir).unwrap();
    fs::copy(
        project.join("tests/fixtures/production/nuclei-report.json"),
        &nuclei_report,
    )
    .unwrap();
    let input = project.join("tests/fixtures/production/waf.jsonl");

    let mut command = Command::cargo_bin("shenron").unwrap();
    command
        .current_dir(directory.path())
        .env("SHENRON_DATA_DIR", &data_dir)
        .args([
            "production",
            "hunt",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "aws-waf",
        ])
        .assert()
        .success();

    let default_outputs = fs::read_dir(directory.path().join("private-results"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(default_outputs.len(), 1);
    let default_output = &default_outputs[0];
    assert!(default_output.join("private-findings.jsonl").is_file());
    assert!(default_output.join("sanitized-research.json").is_file());
    let default_report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(default_output.join("sanitized-research.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(default_report["metrics"]["unique_cisa_kevs_observed"], 0);
    assert_eq!(default_report["cve_findings"][0]["cisa_kev"], false);

    let explicit_output = directory.path().join("explicit-output");
    let mut explicit = Command::cargo_bin("shenron").unwrap();
    explicit
        .current_dir(directory.path())
        .env("SHENRON_DATA_DIR", &data_dir)
        .args([
            "production",
            "hunt",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "aws-waf",
            "--nuclei-templates",
            templates.to_str().unwrap(),
            "--nuclei-report",
            nuclei_report.to_str().unwrap(),
            "--output",
            explicit_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    let explicit_report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(explicit_output.join("sanitized-research.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(default_report, explicit_report);
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in WalkDir::new(source) {
        let entry = entry.unwrap();
        let relative = entry.path().strip_prefix(source).unwrap();
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target).unwrap();
        } else {
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn explain_labels_generic_and_distinctive_paths_without_excluding_either() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"path-review","cves":["CVE-2024-20001"],"detectability":"LOW","timestamp":null,"source_ip":"198.51.100.9","host":"example.test","method":"GET","uri_path":"/login","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"path-review","cves":["CVE-2024-20001"],"detectability":"LOW","timestamp":null,"source_ip":"198.51.100.9","host":"example.test","method":"GET","uri_path":"/.env","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
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
            "--include-generic",
            "--show-request",
        ])
        .assert()
        .success()
        .stdout(contains("Top request paths (CVEs bundled per path):"))
        .stdout(contains("GET /login\n  Matches: 1  |  CVEs (1): CVE-2024-20001\n  Templates: 1  |  Path: generic"))
        .stdout(contains("GET /.env\n  Matches: 1  |  CVEs (1): CVE-2024-20001\n  Templates: 1  |  Path: distinctive"))
        .stdout(contains("Path distinctiveness: generic"))
        .stdout(contains("Path distinctiveness: distinctive"));
}

#[test]
fn explain_bundles_multiple_cves_and_templates_by_request_path() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"gitlab-a","cves":["CVE-2024-41001"],"detectability":"HIGH","request_specificity":"request-specific","timestamp":null,"source_ip":"198.51.100.41","host":null,"method":"GET","uri_path":"/users/sign_in","uri_query":"next=/admin","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"gitlab-b","cves":["CVE-2024-41002"],"detectability":"HIGH","request_specificity":"request-specific","timestamp":null,"source_ip":"198.51.100.42","host":null,"method":"GET","uri_path":"/users/sign_in","uri_query":"next=/admin","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"gitlab-c","cves":["CVE-2024-41003"],"detectability":"HIGH","request_specificity":"request-specific","timestamp":null,"source_ip":"198.51.100.43","host":null,"method":"GET","uri_path":"/users/sign_in","uri_query":"next=/admin","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"other-path","cves":["CVE-2024-41004"],"detectability":"HIGH","request_specificity":"request-specific","timestamp":null,"source_ip":"198.51.100.44","host":null,"method":"GET","uri_path":"/different","uri_query":"next=/admin","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n"
        ),
    )
    .unwrap();

    let output = Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--limit",
            "0",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("GET /users/sign_in").count(), 1);
    assert!(stdout.contains(
        "GET /users/sign_in\n  Matches: 3  |  CVEs (3): CVE-2024-41001, CVE-2024-41002, CVE-2024-41003\n  Templates: 3  |  Path: distinctive"
    ));
    assert_eq!(stdout.matches("GET /different").count(), 1);
    assert!(stdout.contains(
        "GET /different\n  Matches: 1  |  CVEs (1): CVE-2024-41004\n  Templates: 1  |  Path: distinctive"
    ));
}

#[test]
fn explain_uses_prepared_default_reputation_and_asn_datasets_when_available() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    let data_dir = directory.path().join("shenron-data");
    fs::create_dir_all(&data_dir).unwrap();
    fs::write(
        &findings,
        r#"{"template_id":"default-enrichment","cves":["CVE-2024-42001"],"detectability":"HIGH","request_specificity":"request-specific","timestamp":null,"source_ip":"198.51.100.9","host":null,"method":"GET","uri_path":"/distinctive","uri_query":"q=1","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}
"#,
    )
    .unwrap();
    fs::write(
        data_dir.join("asn-ranges.tsv"),
        "198.51.100.0\t198.51.100.255\t64510\tPREPARED-ASN\n",
    )
    .unwrap();
    fs::write(
        data_dir.join("reputation.jsonl"),
        r#"{"scope":"cidr","value":"198.51.100.0/24","score":90,"source":"prepared-public-list","categories":["example"]}
"#,
    )
    .unwrap();

    Command::cargo_bin("shenron")
        .unwrap()
        .env("SHENRON_DATA_DIR", &data_dir)
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--show-source-ips",
            "--show-asn",
        ])
        .assert()
        .success()
        .stdout(contains("ASN dataset provenance:"))
        .stdout(contains("Reputation dataset provenance:"))
        .stdout(contains("Resolved ASN: 64510 (PREPARED-ASN)"))
        .stdout(contains("Reputation: 90/100 (high) via cidr"));
}

#[test]
fn explain_hides_only_response_unverified_generic_paths_by_default() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"generic-noise","cves":["CVE-2024-30001"],"detectability":"LOW","request_specificity":"response-unverified","timestamp":null,"source_ip":"198.51.100.30","host":null,"method":"GET","uri_path":"/robots.txt","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"distinctive-uri","cves":["CVE-2024-30002"],"detectability":"LOW","request_specificity":"response-unverified","timestamp":null,"source_ip":"198.51.100.31","host":null,"method":"GET","uri_path":"/.env","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"specific-generic","cves":["CVE-2024-30003"],"detectability":"HIGH","request_specificity":"request-specific","timestamp":null,"source_ip":"198.51.100.32","host":null,"method":"GET","uri_path":"/login","uri_query":"next=/admin","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
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
            "--show-request",
            "--show-source-ips",
            "--limit",
            "0",
        ])
        .assert()
        .success()
        .stdout(contains(
            "Hidden 1 low-confidence matches (response-unverified on generic paths such as /robots.txt), spanning 1 CVEs. Pass --include-generic to show them.",
        ))
        // The generic match is hidden from the per-finding listing and the path
        // summary: its CVE is not listed (its path only appears in the hidden
        // disclosure line's own example text).
        .stdout(contains("CVE-2024-30001").not())
        .stdout(contains("CVE-2024-30002"))
        .stdout(contains("CVE-2024-30003"))
        .stdout(contains("198.51.100.31"))
        .stdout(contains("198.51.100.32"))
        // ...but triage grouping still sees it, so its IP appears in the IP
        // triage section, and the disclosure line explains the group counts.
        .stdout(contains("198.51.100.30"))
        .stdout(contains(
            "Triage groups are computed from all matching findings, including the low-confidence generic matches hidden from the listing",
        ));

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings.to_str().unwrap(),
            "--include-generic",
            "--show-request",
            "--limit",
            "0",
        ])
        .assert()
        .success()
        .stdout(contains("CVE-2024-30001"))
        .stdout(contains("Request: GET /robots.txt"))
        .stdout(contains("Hidden 1 low-confidence matches").not());
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
fn explain_enriches_private_ip_groups_from_offline_asn_and_reputation_datasets() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"template-one","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:01+00:00","source_ip":"203.0.113.7","host":"example.test","method":"GET","uri_path":"/one","uri_query":"probe=1","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
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
            "--asn-dataset",
            "tests/fixtures/reputation/asn.csv",
            "--reputation-dataset",
            "tests/fixtures/reputation/reputation.jsonl",
        ])
        .assert()
        .success()
        .stdout(contains("ASN dataset provenance: path="))
        .stdout(contains("Reputation dataset provenance: path="))
        .stdout(contains("Resolved ASN: 64501 (EXAMPLE-NARROW)"))
        .stdout(contains("Reputation: 90/100 (high) via ip"))
        .stdout(contains("- ip 203.0.113.7 score 90 [scanner, bruteforce]"))
        .stdout(contains("- cidr 203.0.113.0/24 score 80 [network-abuse]"))
        .stdout(contains("- asn 64501 score 70 [hosting-abuse]"))
        .stdout(contains("third-party opinion"))
        .stdout(contains("No IP is sent outside this local process."));
}

#[test]
fn explain_groups_private_findings_by_resolved_asn() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("private-findings.jsonl");
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"template-one","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:01+00:00","source_ip":"203.0.113.7","host":"example.test","method":"GET","uri_path":"/one","uri_query":"probe=1","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
            "\n",
            r#"{"template_id":"template-two","cves":["CVE-2024-10002"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:02+00:00","source_ip":"203.0.113.8","host":"example.test","method":"GET","uri_path":"/two","uri_query":"probe=2","headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null}"#,
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
            "--show-asn",
            "--asn-dataset",
            "tests/fixtures/reputation/asn.csv",
            "--reputation-dataset",
            "tests/fixtures/reputation/reputation.jsonl",
        ])
        .assert()
        .success()
        .stdout(contains("ASN 64501 (EXAMPLE-NARROW)"))
        .stdout(contains("Distinct member IPs: 2"))
        .stdout(contains("Behavior priority score:"))
        .stdout(contains("Reputation: 70/100 (medium) via asn"))
        .stdout(contains("- asn 64501 score 70 [hosting-abuse]"))
        .stdout(contains("Findings excluded because ASN was unresolved: 0"));
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

#[test]
fn explain_scores_behavior_and_groups_shared_ja4_fingerprints() {
    let directory = tempdir().unwrap();
    let findings_path = directory.path().join("private-findings.jsonl");
    let record = |template: &str,
                  cve: &str,
                  ip: &str,
                  host: &str,
                  path: &str,
                  waf: &str,
                  id: &str| {
        format!(
            r#"{{"template_id":"{template}","cves":["{cve}"],"detectability":"HIGH","timestamp":"2026-08-24T00:00:01+00:00","source_ip":"{ip}","client_ip":null,"host":"{host}","method":"GET","uri_path":"{path}","uri_query":null,"headers":[],"ja3":null,"ja4":"t13d1516h2_shared","waf_action":"{waf}","request_id":"{id}"}}"#
        )
    };
    let lines = [
        record(
            "tpl-a",
            "CVE-2024-0001",
            "203.0.113.7",
            "a.example",
            "/a",
            "ALLOW",
            "r1",
        ),
        record(
            "tpl-b",
            "CVE-2024-0002",
            "203.0.113.7",
            "b.example",
            "/b",
            "ALLOW",
            "r2",
        ),
        record(
            "tpl-c",
            "CVE-2024-0003",
            "203.0.113.7",
            "c.example",
            "/c",
            "BLOCK",
            "r3",
        ),
        record(
            "tpl-a",
            "CVE-2024-0001",
            "198.51.100.20",
            "a.example",
            "/a",
            "ALLOW",
            "r4",
        ),
    ];
    fs::write(&findings_path, lines.join("\n")).unwrap();

    let assertion = Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings_path.to_str().unwrap(),
            "--show-source-ips",
            "--show-fingerprints",
        ])
        .assert()
        .success();

    // 203.0.113.7: 3 templates (9) + 3 CVEs (6) + 3 distinctive observations (3)
    // + 3 distinctive-path points + 3 hosts (6) + 2/3 unblocked (10) = 37.
    assertion
        .stdout(contains(
            "203.0.113.7\n  Grouping identity: observed-peer\n  Triage basis: breadth\n  Matching request observations: 3\n  Distinct Nuclei template patterns: 3\n  Unique CVEs: 3\n  Matched template records: 3\n  Behavior priority score: 37/100 (low)",
        ))
        // The single-observation peer is retained as evidence but not triaged.
        .stdout(contains(
            "198.51.100.20\n  Grouping identity: observed-peer\n  Triage basis: none\n  Matching request observations: 1\n  Distinct Nuclei template patterns: 1\n  Unique CVEs: 1\n  Matched template records: 1\n  Behavior priority score: 24/100 (info)",
        ))
        // One JA4 fingerprint spans both peers: a shared-tooling signal.
        .stdout(contains("JA4 fingerprint triage (private findings only):"))
        .stdout(contains(
            "t13d1516h2_shared\n  Triage basis: breadth\n  Distinct validated clients sharing this fingerprint: 0\n  Distinct observed peers sharing this fingerprint: 2\n  Identity spread used for behavior score: 2\n  Matching request observations: 4\n  Distinct Nuclei template patterns: 3\n  Unique CVEs: 3\n  Matched template records: 4\n  Behavior priority score: 38/100 (low)",
        ));
}

#[test]
fn hunt_runs_the_sigma_pass_and_keeps_it_distinct_from_cve_findings() {
    let directory = tempdir().unwrap();
    let rules_dir = directory.path().join("rules");
    fs::create_dir(&rules_dir).unwrap();
    // Two rules with the same selection: every matching request hits both, so
    // rule matches are exactly twice the matched-request count.
    for (name, id) in [("vuln-a.yml", "test-vuln-a"), ("vuln-b.yml", "test-vuln-b")] {
        fs::write(
            rules_dir.join(name),
            format!(
                concat!(
                    "title: Vulnerable Path Probe {id}\n",
                    "id: {id}\n",
                    "logsource:\n  category: webserver\n  product: aws\n  service: waf\n",
                    "detection:\n  selection:\n    uri_path|contains: 'vulnerable'\n  condition: selection\n",
                    "level: medium\n",
                ),
                id = id
            ),
        )
        .unwrap();
    }
    let ruleset = shenron::sigma::load_rules(&rules_dir);
    assert_eq!(ruleset.supported.len(), 2);

    let output = directory.path().join("out");
    let report = hunt_with_options(
        Path::new("tests/fixtures/production/waf.jsonl"),
        Path::new("tests/fixtures/nuclei"),
        Path::new("tests/fixtures/production/nuclei-report.json"),
        Some(Path::new("tests/fixtures/production/kev-report.json")),
        &output,
        TelemetryProfile::AwsWaf,
        HuntOptions {
            sigma_ruleset: Some(ruleset),
            ..Default::default()
        },
    )
    .unwrap();

    // The Sigma pass ran and is reported separately from the CVE metrics.
    assert_eq!(report.metrics.sigma_rules_evaluated, 2);
    assert_eq!(report.metrics.distinct_sigma_rules, 2);
    // Matched requests are distinct events; rule matches count each rule hit, so
    // with two rules over the same requests, matches are twice the requests.
    assert!(report.metrics.sigma_matched_requests >= 1);
    assert_eq!(
        report.metrics.sigma_rule_matches,
        2 * report.metrics.sigma_matched_requests
    );

    // Both sources are present and distinguishable in the private findings.
    let private = fs::read_to_string(output.join("private-findings.jsonl")).unwrap();
    assert!(private.contains(r#""source":"sigma""#));
    assert!(private.contains(r#""source":"nuclei""#));

    // A Sigma finding never feeds candidate build.
    let findings = explain_private_findings(&output.join("private-findings.jsonl")).unwrap();
    let (_candidates, stats) =
        shenron::candidate::build_batch_from_findings(&findings, TelemetryProfile::AwsWaf, true);
    assert_eq!(
        stats.excluded_sigma_findings,
        report.metrics.sigma_rule_matches
    );
}

#[test]
fn replay_warns_up_front_when_findings_carry_no_request_id() {
    let directory = tempdir().unwrap();
    let findings = directory.path().join("no-id-private-findings.jsonl");
    // A finding with no request ID, as every nginx/Apache combined-log finding
    // is: conservative coverage is unreachable before the scan even starts.
    fs::write(
        &findings,
        concat!(
            r#"{"template_id":"synthetic-cve-2024-10001","cves":["CVE-2024-10001"],"detectability":"HIGH","timestamp":"2025-01-01T00:00:00Z","source_ip":"198.51.100.1","host":"internal.example.test","method":"GET","uri_path":"/vulnerable/execute","uri_query":"cmd=probe","headers":[],"ja3":null,"ja4":null,"waf_action":"ALLOW","request_id":null}"#,
            "\n"
        ),
    )
    .unwrap();
    let output = directory.path().join("replay.json");
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "replay",
            "--input",
            "tests/fixtures/production/waf.jsonl",
            "--format",
            "aws-waf",
            "--nuclei-templates",
            "tests/fixtures/nuclei",
            "--nuclei-report",
            "tests/fixtures/production/nuclei-report.json",
            "--kev-report",
            "tests/fixtures/production/kev-report.json",
            "--findings",
            findings.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        // The run still completes and produces the aggregate report.
        .success()
        .stderr(contains("none of the").and(contains("request ID")));
    // Aggregate volumes are still written.
    let written = fs::read_to_string(output).unwrap();
    assert!(written.contains("HISTORICAL_REPLAY_COVERAGE"));
}

#[test]
fn explain_json_omits_private_evidence_without_show_flags() {
    let directory = tempdir().unwrap();
    let findings_path = directory.path().join("private-findings.jsonl");
    let line = r#"{"template_id":"tpl-a","cves":["CVE-2024-0001"],"detectability":"HIGH","request_specificity":"request-specific","timestamp":"2026-08-24T00:00:01+00:00","source_ip":"203.0.113.7","client_ip":null,"host":"secret.example","method":"GET","uri_path":"/.env","uri_query":"token=abc","headers":[{"name":"User-Agent","value":"scanner-secret/1"}],"ja3":null,"ja4":"t13d1516h2_secret","waf_action":"ALLOW","request_id":"req-secret-1","log_source":"aws_waf"}"#;
    fs::write(&findings_path, line).unwrap();

    let stdout = Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings_path.to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(json["report_kind"], "EXPLAIN_PRIVATE_TRIAGE");
    // Sections gated behind --show-* flags are absent without them.
    assert!(json.get("individual_findings").is_none());
    assert!(json.get("connection_ip_groups").is_none());
    assert!(json.get("asn_groups").is_none());
    assert!(json.get("ja4_groups").is_none());
    // No private request value, IP, host, header, JA3/JA4, or request ID leaks
    // into the default JSON. (Aggregate request paths are the intended summary.)
    let text = String::from_utf8(stdout).unwrap();
    for secret in [
        "203.0.113.7",
        "secret.example",
        "t13d1516h2_secret",
        "req-secret-1",
        "token=abc",
        "scanner-secret",
    ] {
        assert!(
            !text.contains(secret),
            "private value leaked into JSON: {secret}"
        );
    }
}

#[test]
fn generic_filter_is_display_only_and_does_not_change_triage_grouping() {
    let directory = tempdir().unwrap();
    let findings_path = directory.path().join("private-findings.jsonl");
    // One source: one distinctive + two generic response-unverified matches on
    // three distinct templates. Two of the three are hidden from the listing by
    // default, but all three must reach triage grouping.
    let record = |template: &str, path: &str, second: u8| {
        format!(
            r#"{{"template_id":"{template}","cves":["CVE-2024-{template}"],"detectability":"HIGH","request_specificity":"response-unverified","timestamp":"2026-08-24T00:00:0{second}+00:00","source_ip":"203.0.113.50","client_ip":null,"host":"h.example","method":"GET","uri_path":"{path}","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":null,"request_id":null,"log_source":"apache_vhost_combined"}}"#
        )
    };
    let lines = [
        record("aaa", "/.env", 1),
        record("bbb", "/robots.txt", 2),
        record("ccc", "/sitemap.xml", 3),
    ];
    fs::write(&findings_path, lines.join("\n")).unwrap();

    let run = |include_generic: bool| -> serde_json::Value {
        let mut args = vec![
            "production",
            "explain",
            "--findings",
            findings_path.to_str().unwrap(),
            "--show-source-ips",
            "--output-format",
            "json",
            "--limit",
            "0",
        ];
        if include_generic {
            args.push("--include-generic");
        }
        let stdout = Command::cargo_bin("shenron")
            .unwrap()
            .args(&args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice(&stdout).unwrap()
    };
    let group = |report: &serde_json::Value| -> serde_json::Value {
        report["connection_ip_groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["key"] == "203.0.113.50")
            .expect("the source group is present")
            .clone()
    };

    let default = run(false);
    let with_generic = run(true);
    let group_default = group(&default);
    let group_generic = group(&with_generic);

    // Grouping sees every finding regardless of the display filter, so breadth
    // is met from all three distinct templates.
    assert_eq!(group_default["distinct_observations"], 3);
    assert_eq!(group_default["distinct_templates"], 3);
    assert_eq!(group_default["triage_basis"], "breadth");
    assert_eq!(group_default["requires_investigation"], true);

    // The group's score, observation count, and triage basis are identical
    // between the two modes; --include-generic changes only what is listed.
    assert_eq!(
        group_default["distinct_observations"],
        group_generic["distinct_observations"]
    );
    assert_eq!(group_default["triage_basis"], group_generic["triage_basis"]);
    assert_eq!(group_default["score"], group_generic["score"]);

    // The listing differs: only the distinctive path by default, all three with
    // --include-generic; total_mappings follows the listing.
    assert_eq!(default["request_paths"].as_array().unwrap().len(), 1);
    assert_eq!(with_generic["request_paths"].as_array().unwrap().len(), 3);
    assert_eq!(default["total_mappings"], 1);
    assert_eq!(with_generic["total_mappings"], 3);

    // The low-confidence disclosure count is unchanged by this refactor: the two
    // generic response-unverified matches by default, nothing with the flag.
    assert_eq!(default["hidden_low_confidence"]["count"], 2);
    assert!(with_generic.get("hidden_low_confidence").is_none());

    // The triage-scope note is present exactly when grouping exceeds the listing.
    assert!(default.get("triage_note").is_some());
    assert!(with_generic.get("triage_note").is_none());
}

#[test]
fn explain_json_round_trips_score_components() {
    let directory = tempdir().unwrap();
    let findings_path = directory.path().join("private-findings.jsonl");
    let record = |template: &str, cve: &str, path: &str| {
        format!(
            r#"{{"template_id":"{template}","cves":["{cve}"],"detectability":"HIGH","request_specificity":"request-specific","timestamp":"2026-08-24T00:00:01+00:00","source_ip":"203.0.113.7","client_ip":null,"host":"h.example","method":"GET","uri_path":"{path}","uri_query":null,"headers":[],"ja3":null,"ja4":null,"waf_action":"ALLOW","request_id":"{template}-1","log_source":"aws_waf"}}"#
        )
    };
    let lines = [
        record("tpl-a", "CVE-2024-0001", "/.env"),
        record("tpl-b", "CVE-2024-0002", "/.git/config"),
        record("tpl-c", "CVE-2024-0003", "/admin-console.php"),
    ];
    fs::write(&findings_path, lines.join("\n")).unwrap();

    let stdout = Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "production",
            "explain",
            "--findings",
            findings_path.to_str().unwrap(),
            "--show-source-ips",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    let group = json["connection_ip_groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["key"] == "203.0.113.7")
        .expect("the scored IP group is present");
    let components = group["score"]["components"].as_array().unwrap();
    // Every component survives with its name, points, and detail.
    let names = components
        .iter()
        .map(|component| {
            assert!(
                component["points"].is_number(),
                "missing points: {component}"
            );
            assert!(
                component["detail"].as_str().is_some_and(|d| !d.is_empty()),
                "missing detail: {component}"
            );
            component["name"].as_str().unwrap().to_owned()
        })
        .collect::<Vec<_>>();
    assert!(names.contains(&"template-breadth".to_owned()));
    assert!(names.contains(&"path-distinctiveness".to_owned()));
    assert!(group["score"]["total"].is_number());
    assert!(group["score"]["reachable_max"].is_number());

    // Round-trip: re-serialize the parsed group and confirm the components are
    // stable across a serialize/parse cycle.
    let reparsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(group).unwrap()).unwrap();
    assert_eq!(
        reparsed["score"]["components"],
        group["score"]["components"]
    );
}

fn parse_utc(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}
