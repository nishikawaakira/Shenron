use assert_cmd::Command;
use serde_json::Value;
use std::{fs, io::Write};

fn context_command(input: &std::path::Path, format: &str) -> Command {
    let mut command = Command::cargo_bin("shenron").unwrap();
    command.args([
        "context",
        "--input",
        input.to_str().unwrap(),
        "--format",
        format,
        "--source-ip",
        "198.51.100.1",
    ]);
    command
}

#[test]
fn context_details_follow_capabilities_and_query_gate_without_changing_counts_stdout() {
    use shenron::event::TelemetryProfile;

    let dir = tempfile::tempdir().unwrap();
    let vhost = "private.example:443 198.51.100.1 - - [24/Aug/2026:11:20:30 +0000] \"GET /ordinary?token=secret HTTP/1.1\" 200 12 \"https://referrer.example/?patient_id=private\" \"Declared-Agent\"\n";
    let waf = serde_json::json!({
        "timestamp": 1787570430000_i64, "action": "RECORDED_ACTION",
        "ja3Fingerprint": "private-ja3", "ja4Fingerprint": "private-ja4",
        "labels": [{"name": "recorded-label"}],
        "httpRequest": {"clientIp": "198.51.100.1", "country": "JP",
            "uri": "/ordinary", "args": "token=secret", "httpMethod": "GET",
            "headers": [
                {"name":"Host", "value":"private.example"},
                {"name":"User-Agent", "value":"Declared-Agent"},
                {"name":"Referer", "value":"https://referrer.example/?patient_id=private"}
            ]}
    })
    .to_string();
    for (format, profile, data) in [
        ("apache-vhost", TelemetryProfile::ApacheVhostCombined, vhost),
        ("aws-waf", TelemetryProfile::AwsWaf, waf.as_str()),
    ] {
        let input = dir.path().join(format);
        fs::write(&input, data).unwrap();
        let run = |flags: &[&str]| {
            context_command(&input, format)
                .args([
                    "--from",
                    "2026-08-24T00:00:00Z",
                    "--to",
                    "2026-08-25T00:00:00Z",
                ])
                .args(flags)
                .assert()
                .success()
                .get_output()
                .stdout
                .clone()
        };
        // Exact pre-extension counts-only serialization, including order and newline.
        assert_eq!(
            String::from_utf8(run(&[])).unwrap(),
            concat!(
                "{\n  \"parseable_records\": 1,\n  \"parse_errors\": 0,\n",
                "  \"nonselected_peers\": 0,\n  \"selected_without_timestamp\": 0,\n",
                "  \"selected_outside_window\": 0,\n  \"eligible_records\": 1,\n",
                "  \"retained_records\": 1,\n  \"records_beyond_cap\": 0,\n",
                "  \"maximum_records\": 10000\n}\n"
            )
        );
        let bytes = run(&["--show-request"]);
        assert_eq!(bytes, run(&["--show-request"]));
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            report["field_availability"],
            serde_json::to_value(profile.capabilities()).unwrap()
        );
        let record = &report["records"][0];
        assert_eq!(record["host"], "private.example");
        assert_eq!(record["user_agent"], "Declared-Agent");
        assert!(record.get("referer").is_none());
        assert!(record.get("uri_query").is_none());
        if profile == TelemetryProfile::AwsWaf {
            assert_eq!(record["waf_action"], "RECORDED_ACTION");
            assert_eq!(record["waf_labels"], serde_json::json!(["recorded-label"]));
            assert_eq!(record["country"], "JP");
            assert_eq!(record["ja3"], "private-ja3");
            assert_eq!(record["ja4"], "private-ja4");
            assert!(record["response_status"].is_null());
        } else {
            for field in ["waf_action", "waf_labels", "country", "ja3", "ja4"] {
                assert!(record.get(field).is_none(), "{field}");
            }
        }
        let query: Value =
            serde_json::from_slice(&run(&["--show-request", "--show-query"])).unwrap();
        assert_eq!(
            query["records"][0]["referer"],
            "https://referrer.example/?patient_id=private"
        );
        assert_eq!(query["records"][0]["uri_query"], "token=secret");
        assert!(report["retention_note"]
            .as_str()
            .unwrap()
            .contains("Absence is not a determination that a control did not act."));
    }
}

#[test]
fn optional_context_bounds_reconcile_counts_and_disclose_retained_span_and_caps() {
    use chrono::{DateTime, Utc};
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let at = |hour| format!("2026-08-24T{hour}:00:00Z");
    let event = |ip, timestamp: Option<&str>| {
        serde_json::json!({"timestamp": timestamp.map(|s| s.parse::<DateTime<Utc>>().unwrap().timestamp_millis()),
            "httpRequest": {"clientIp": ip, "uri": "/context"}}).to_string()
    };
    // Input order deliberately differs from timestamp order: a cap is not an earliest-N query.
    fs::write(
        &input,
        [
            event("198.51.100.1", Some(&at("12"))),
            event("198.51.100.1", Some(&at("11"))),
            event("198.51.100.1", Some(&at("10"))),
            event("198.51.100.1", None),
            event("198.51.100.2", Some(&at("11"))),
            "malformed".to_owned(),
        ]
        .join("\n"),
    )
    .unwrap();
    let run = |flags: &[&str]| {
        context_command(&input, "aws-waf")
            .arg("--show-request")
            .args(flags)
            .assert()
            .success()
            .get_output()
            .clone()
    };
    let full = run(&[]);
    assert_eq!(full.stdout, run(&[]).stdout);
    let full_report: Value = serde_json::from_slice(&full.stdout).unwrap();
    assert!(full_report.get("from").is_none());
    assert!(full_report.get("to").is_none());
    for (flags, eligible, from_present, to_present) in [
        (vec![], 3, false, false),
        (vec!["--from", "2026-08-24T11:00:00Z"], 2, true, false),
        (vec!["--to", "2026-08-24T11:00:00Z"], 2, false, true),
        (
            vec![
                "--from",
                "2026-08-24T10:00:00Z",
                "--to",
                "2026-08-24T12:00:00Z",
            ],
            3,
            true,
            true,
        ),
        (
            vec![
                "--from",
                "2026-08-24T11:00:00Z",
                "--to",
                "2026-08-24T11:00:00Z",
            ],
            1,
            true,
            true,
        ),
        (vec!["--from", "2026-08-25T00:00:00Z"], 0, true, false),
    ] {
        let result = run(&flags);
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report.get("from").is_some(), from_present);
        assert_eq!(report.get("to").is_some(), to_present);
        let counts = &report["counts"];
        assert_eq!(counts["parseable_records"], 5);
        assert_eq!(counts["parse_errors"], 1);
        assert_eq!(counts["nonselected_peers"], 1);
        assert_eq!(counts["selected_without_timestamp"], 1);
        assert_eq!(counts["eligible_records"], eligible);
        assert_eq!(counts["selected_outside_window"], 3 - eligible);
        assert_eq!(counts["retained_records"], eligible);
        assert_eq!(counts["records_beyond_cap"], 0);
        let n = |key: &str| counts[key].as_u64().unwrap();
        assert_eq!(
            n("parseable_records"),
            n("nonselected_peers")
                + n("selected_without_timestamp")
                + n("selected_outside_window")
                + n("eligible_records")
        );
        assert_eq!(
            n("eligible_records"),
            n("retained_records") + n("records_beyond_cap")
        );
        assert!(!String::from_utf8(result.stderr)
            .unwrap()
            .contains("record(s) beyond the cap were omitted;"));
        if eligible == 3 {
            assert_eq!(report["records"], full_report["records"]);
            assert_eq!(counts, &full_report["counts"]);
        }
        if eligible == 0 {
            assert!(counts["earliest_retained"].is_null());
            assert!(counts["latest_retained"].is_null());
        }
    }
    let capped = run(&["--max-records", "2"]);
    let report: Value = serde_json::from_slice(&capped.stdout).unwrap();
    assert_eq!(report["counts"]["records_beyond_cap"], 1);
    assert_eq!(report["counts"]["retained_records"], 2);
    assert_eq!(report["counts"]["eligible_records"], 3);
    assert_eq!(
        report["counts"]["earliest_retained"],
        "2026-08-24T11:00:00Z"
    );
    assert_eq!(report["counts"]["latest_retained"], "2026-08-24T12:00:00Z");
    assert_eq!(
        full_report["counts"]["earliest_retained"],
        "2026-08-24T10:00:00Z"
    );
    assert!(report["retention_note"]
        .as_str()
        .unwrap()
        .contains("they are a lower bound on the observed span"));
    assert!(String::from_utf8(capped.stderr).unwrap().contains(
        "1 record(s) beyond the cap were omitted; narrow the window or raise --max-records."
    ));
    context_command(&input, "aws-waf")
        .args([
            "--from",
            "2026-08-24T12:00:00Z",
            "--to",
            "2026-08-24T10:00:00Z",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "ordered UTC bounds when both are specified",
        ));
}

#[test]
fn context_is_aggregate_by_default_and_request_values_are_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.log");
    fs::write(&input, "198.51.100.1 - - [24/Aug/2026:11:20:30 +0000] \"GET /ordinary?token=secret HTTP/1.1\" 200 12 \"-\" \"-\"\n").unwrap();
    let run = |flags: &[&str]| {
        Command::cargo_bin("shenron")
            .unwrap()
            .args([
                "context",
                "--input",
                input.to_str().unwrap(),
                "--format",
                "apache",
                "--source-ip",
                "198.51.100.1",
                "--from",
                "2026-08-24T00:00:00Z",
                "--to",
                "2026-08-25T00:00:00Z",
            ])
            .args(flags)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    let counts = run(&[]);
    assert_eq!(
        serde_json::from_slice::<Value>(&counts).unwrap()["eligible_records"],
        1
    );
    assert!(!String::from_utf8(counts).unwrap().contains("198.51.100.1"));
    let private = String::from_utf8(run(&["--show-request"])).unwrap();
    assert!(private.contains("/ordinary") && !private.contains("token=secret"));
    assert!(String::from_utf8(run(&["--show-request", "--show-query"]))
        .unwrap()
        .contains("token=secret"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn source_references_preserve_hunt_matches_and_all_other_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("rule.yml"), "title: Ordinary\nid: ordinary\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    uri_path|contains: ordinary\n  condition: selection\nlevel: low\n").unwrap();
    let input = dir.path().join("input.log.gz");
    let mut stored = Vec::new();
    // The matching request is in the second member. Both streaming routes must read it.
    for member in ["\nbad\n", "198.51.100.1 - - [24/Aug/2026:11:20:30 +0000] \"GET /ordinary HTTP/1.1\" 200 12 \"-\" \"-\"\n"] {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(member.as_bytes()).unwrap();
        stored.extend(encoder.finish().unwrap());
    }
    fs::write(&input, stored).unwrap();
    let plain = dir.path().join("plain");
    let referenced = dir.path().join("referenced");
    for (out, references) in [(&plain, false), (&referenced, true)] {
        let mut command = Command::cargo_bin("shenron").unwrap();
        command.env_remove("SHENRON_SLACK_WEBHOOK").args([
            "hunt",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "apache",
            "--no-nuclei",
            "--rules",
            rules.to_str().unwrap(),
            "--uncompressed-findings",
            "--output",
            out.to_str().unwrap(),
        ]);
        if references {
            command.arg("--include-source-references");
        }
        command.assert().success();
    }
    let plain_finding: Value = serde_json::from_str(
        fs::read_to_string(plain.join("private-findings.jsonl"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let mut referenced_finding: Value = serde_json::from_str(
        fs::read_to_string(referenced.join("private-findings.jsonl"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(referenced_finding["source_reference"]["line_number"], 3);
    referenced_finding
        .as_object_mut()
        .unwrap()
        .remove("source_reference");
    assert_eq!(plain_finding, referenced_finding);
    for name in [
        "sanitized-research.json",
        "request-concentration.json",
        "triage-view.json",
        "triage-summary.json",
    ] {
        assert_eq!(
            fs::read(plain.join(name)).unwrap(),
            fs::read(referenced.join(name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn empty_context_keeps_sorted_selection_only_in_private_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("empty.log");
    fs::write(&input, "").unwrap();
    let output = dir.path().join("private-context.json");
    let result = Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "context",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "apache",
            "--source-ip",
            "2001:db8::1,198.51.100.2,198.51.100.1,198.51.100.2",
            "--from",
            "2026-08-24T00:00:00Z",
            "--to",
            "2026-08-25T00:00:00Z",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let private: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(
        private["selected_source_ips"],
        serde_json::json!(["198.51.100.1", "198.51.100.2", "2001:db8::1"])
    );
    assert_eq!(private["records"], serde_json::json!([]));
    let public = String::from_utf8(result.stdout).unwrap();
    let counts: Value = serde_json::from_str(&public).unwrap();
    assert_eq!(counts["eligible_records"], 0);
    for value in [
        "selected_source_ips",
        "198.51.100.1",
        "198.51.100.2",
        "2001:db8::1",
    ] {
        assert!(!public.contains(value));
    }
}
