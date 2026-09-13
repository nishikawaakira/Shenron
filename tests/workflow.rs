use assert_cmd::Command;
use serde_json::Value;

#[test]
fn hunt_and_explain_apply_scoped_review_context_without_changing_findings_or_cve_metrics() {
    use sha2::{Digest, Sha256};
    use shenron::disposition::{
        record_disposition_with_review, AnalystDisposition, DispositionKey, DispositionReview,
    };
    let temp = tempfile::tempdir().unwrap();
    let baseline = temp.path().join("baseline");
    let run = |output: &std::path::Path, flags: &[&str]| {
        Command::cargo_bin("shenron")
            .unwrap()
            .env_remove("SHENRON_SLACK_WEBHOOK")
            .args([
                "hunt",
                "--input",
                "tests/fixtures/production/waf.jsonl",
                "--format",
                "aws-waf",
                "--nuclei-templates",
                "tests/fixtures/nuclei",
                "--nuclei-report",
                "tests/fixtures/production/nuclei-report.json",
                "--no-sigma",
                "--uncompressed-findings",
                "--output",
                output.to_str().unwrap(),
            ])
            .args(flags)
            .assert()
            .success();
    };
    run(&baseline, &[]);
    let finding_bytes = fs::read(baseline.join("private-findings.jsonl")).unwrap();
    let first: Value =
        serde_json::from_slice(finding_bytes.split(|b| *b == b'\n').next().unwrap()).unwrap();
    let mut key = DispositionKey::new(
        "nuclei",
        first["template_id"].as_str().unwrap(),
        first["method"].as_str().unwrap(),
        first["uri_path"].as_str().unwrap(),
        first["uri_query"].as_str(),
    );
    key.corpus_scope = Some("private-scope-a".into());
    let store = temp.path().join("opinions.jsonl");
    record_disposition_with_review(
        &store,
        key,
        AnalystDisposition::Expected,
        Some("private review reason: checked against local evidence".into()),
        Some(DispositionReview {
            reviewer: Some("private-reviewer".into()),
            evidence_run: Some("private-evidence".into()),
            nuclei_revision: Some("private-review-nuclei-revision".into()),
            review_after: Some("2026-09-01T00:00:00Z".parse().unwrap()),
        }),
    )
    .unwrap();
    let baseline_report: Value =
        serde_json::from_slice(&fs::read(baseline.join("sanitized-research.json")).unwrap())
            .unwrap();
    for scope in ["private-scope-a", "private-scope-b"] {
        let output = temp.path().join(scope);
        run(
            &output,
            &[
                "--disposition-store",
                store.to_str().unwrap(),
                "--disposition-scope",
                scope,
                "--disposition-as-of",
                "2026-09-02T00:00:00Z",
            ],
        );
        assert_eq!(
            finding_bytes,
            fs::read(output.join("private-findings.jsonl")).unwrap()
        );
        let text = fs::read_to_string(output.join("sanitized-research.json")).unwrap();
        for private in [
            "private-scope-a",
            "private-scope-b",
            "private-reviewer",
            "private-evidence",
            "private-review-nuclei-revision",
            "private review reason: checked against local evidence",
            "\"corpus_scope\"",
            "\"reviewer\"",
            "\"evidence_run\"",
            "\"nuclei_revision\"",
            "\"disposition_context\"",
            "\"comment\"",
        ] {
            assert!(
                !text.contains(private),
                "leaked disposition metadata: {private}"
            );
        }
        let mut result: Value = serde_json::from_str(&text).unwrap();
        let counts = result["metrics"]["analyst_dispositions"].clone();
        assert_eq!(
            result["metrics"]["cve_related_request_matches"],
            baseline_report["metrics"]["cve_related_request_matches"]
        );
        assert_eq!(counts["expected"], counts["review_due_matching_findings"]);
        if scope.ends_with('a') {
            assert!(counts["expected"].as_u64().unwrap() > 0);
        } else {
            assert_eq!(counts["expected"], 0);
        }
        result["metrics"]
            .as_object_mut()
            .unwrap()
            .remove("analyst_dispositions");
        let mut expected = baseline_report.clone();
        expected["metrics"]
            .as_object_mut()
            .unwrap()
            .remove("analyst_dispositions");
        assert_eq!(result, expected);
        let manifest: Value =
            serde_json::from_slice(&fs::read(output.join("run-manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["disposition_context"]["corpus_scope"], scope);
        assert_eq!(
            manifest["disposition_context"]["store_sha256"],
            format!("{:x}", Sha256::digest(fs::read(&store).unwrap()))
        );
        let explained = Command::cargo_bin("shenron")
            .unwrap()
            .args([
                "explain",
                "--findings",
                output.join("private-findings.jsonl").to_str().unwrap(),
                "--include-generic",
                "--output-format",
                "json",
                "--disposition-store",
                store.to_str().unwrap(),
                "--disposition-scope",
                scope,
                "--disposition-as-of",
                "2026-09-02T00:00:00Z",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let explained: Value = serde_json::from_slice(&explained).unwrap();
        assert_eq!(explained["analyst_dispositions"], counts);
    }
}
use std::fs;

#[test]
fn compare_discloses_conditions_and_explicit_reference_distributions_opt_in_only() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let private_proxy_config = serde_json::json!(["198.51.100.254"]);
    let private_filter = serde_json::json!({"allowlist": {"path": "/private/filter.json", "sha256": "frozen-filter-snapshot"}});
    let mut runs = Vec::new();
    for (name, count, status) in [("a", 2, 200), ("b", 6, 500), ("current", 10, 200)] {
        let input = temp.path().join(format!("{name}.log"));
        let line = format!("198.51.100.9 - - [24/Aug/2026:11:20:30 +0000] \"GET /private-only?token=secret HTTP/1.1\" {status} 12 \"-\" \"-\"\n");
        fs::write(&input, line.repeat(count)).unwrap();
        let output = temp.path().join(name);
        Command::cargo_bin("shenron")
            .unwrap()
            .args([
                "daily",
                "--input",
                input.to_str().unwrap(),
                "--format",
                "apache",
                "--output",
                output.to_str().unwrap(),
                "--corpus-label",
                "private-label",
                "--max-paths",
                "5",
                "--from",
                "2026-08-24T00:00:00Z",
                "--to",
                "2026-08-25T00:00:00Z",
            ])
            .assert()
            .success();
        // Populate private recorded settings to verify that only signatures
        // reach the aggregate comparison, never their source values.
        let manifest_path = output.join("run-manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["hunt_parameters"]["trusted_proxy_networks"] = private_proxy_config.clone();
        manifest["inputs"] = serde_json::json!({"template_filter": private_filter});
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        runs.push(output);
        // Completed-artifact comparison must not reopen the raw corpus.
        fs::remove_file(input).unwrap();
    }
    for extra in [false, true] {
        let output = temp.path().join(if extra { "extended" } else { "legacy" });
        let mut command = Command::cargo_bin("shenron").unwrap();
        command.args([
            "compare",
            "--baseline",
            runs[0].to_str().unwrap(),
            "--current",
            runs[2].to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
        if extra {
            command.args([
                "--compare-conditions",
                "--reference-run",
                runs[1].to_str().unwrap(),
                "--reference-run",
                runs[0].to_str().unwrap(),
            ]);
        }
        let stdout = command.assert().success().get_output().stdout.clone();
        let result: Value =
            serde_json::from_slice(&fs::read(output.join("comparison-summary.json")).unwrap())
                .unwrap();
        if extra {
            let references = &result["reference_distribution"];
            let total = &references["metrics"]["total_requests"];
            assert_eq!(total["minimum"], 2.0);
            assert_eq!(total["median"], 4.0);
            assert_eq!(total["maximum"], 6.0);
            assert_eq!(total["ratio_to_median"], 2.5);
            assert_eq!(references["duplicate_directory_references_excluded"], 1);
            let conditions = &result["measurement_conditions"];
            for side in ["baseline", "current"] {
                for (label, value) in [
                    ("trusted_proxy_configuration", &private_proxy_config),
                    ("template_selection", &private_filter),
                    (
                        "corpus_scope_annotation",
                        &serde_json::json!("private-label"),
                    ),
                ] {
                    assert_eq!(
                        conditions[side]["signatures"][label],
                        format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
                    );
                }
            }
            assert_eq!(
                conditions["baseline"]["numeric"]["recorded_status_share"],
                1.0
            );
            assert_eq!(conditions["baseline"]["numeric"]["window_seconds"], 86400.0);
            assert_eq!(
                conditions["baseline"]["numeric"]["minute_cap_omissions"],
                0.0
            );
            for json in [
                references.to_string(),
                conditions.to_string(),
                String::from_utf8(stdout).unwrap(),
            ] {
                for private in [
                    "198.51.100.9",
                    "/private-only",
                    "token=secret",
                    "private-label",
                    "198.51.100.254",
                    "/private/filter.json",
                    "frozen-filter-snapshot",
                    "\"corpus_label\"",
                    "\"trusted_proxy_networks\"",
                ] {
                    assert!(!json.contains(private), "leaked {private}");
                }
            }
        } else {
            assert!(result.get("measurement_conditions").is_none());
            assert!(result.get("reference_distribution").is_none());
        }
    }
}

#[test]
fn scoped_opinions_are_private_idempotent_and_deadline_review_does_not_change_them() {
    let temp = tempfile::tempdir().unwrap();
    let store = temp.path().join("store.jsonl");
    for _ in 0..2 {
        Command::cargo_bin("shenron")
            .unwrap()
            .args([
                "disposition",
                "set",
                "--store",
                store.to_str().unwrap(),
                "--source",
                "sigma",
                "--template-id",
                "ordinary",
                "--method",
                "GET",
                "--path",
                "/private-path",
                "--disposition",
                "expected",
                "--corpus-scope",
                "site-a",
                "--review-after",
                "2026-09-01T00:00:00Z",
                "--evidence-run",
                "private-evidence",
            ])
            .assert()
            .success();
    }
    assert_eq!(fs::read_to_string(&store).unwrap().lines().count(), 1);
    let output = Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "disposition",
            "read",
            "--store",
            store.to_str().unwrap(),
            "--disposition-scope",
            "site-a",
            "--disposition-as-of",
            "2026-09-01T00:00:00Z",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let entries: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(entries[0]["disposition"], "expected");
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("\"entries_due_for_review\":1"));
    let output = Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "disposition",
            "read",
            "--store",
            store.to_str().unwrap(),
            "--disposition-scope",
            "site-b",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("\"entries_excluded_by_scope\":1"));
}
