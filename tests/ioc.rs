use assert_cmd::Command;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};

fn command(root: &Path) -> Command {
    let mut command = Command::cargo_bin("shenron").unwrap();
    command
        .env("SHENRON_DATA_DIR", root.join("empty-data"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("SHENRON_SLACK_WEBHOOK");
    command
}

fn event(ip: &str, second: i64, forwarded: Option<&str>) -> String {
    let mut headers = vec![
        json!({"name":"Host","value":"example.test"}),
        json!({"name":"User-Agent","value":"synthetic-ioc-agent"}),
    ];
    if let Some(client) = forwarded {
        headers.push(json!({"name":"X-Forwarded-For","value":client}));
    }
    json!({"timestamp":1767225600000_i64 + second*1000,"action":"ALLOW", "responseCodeSent":200,
        "ja3Fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ja4Fingerprint":"t13d1516h2_fixture_fixture",
        "httpRequest":{"clientIp":ip,"httpMethod":"GET","uri":"/review/items","args":"x=one","headers":headers}}).to_string()+"\n"
}

fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn run(
    root: &Path,
    input: &Path,
    indicators: &Path,
    name: &str,
    args: &[&str],
) -> (Value, Vec<u8>) {
    let output = root.join(name);
    let stdout = command(root)
        .args(["ioc", "--input"])
        .arg(input)
        .args(["--format", "aws-waf", "--indicators"])
        .arg(indicators)
        .arg("--output")
        .arg(&output)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    (read(output.join("ioc-matches.json")), stdout)
}

#[test]
fn tsv_types_match_canonical_peers_with_private_evidence_and_numeric_only_sanitized_output() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    let indicators = root.path().join("indicators.tsv");
    fs::write(
        &input,
        event("::ffff:192.0.2.1", 0, None) + &event("203.0.113.1", 10, None),
    )
    .unwrap();
    let values = [
        "192.0.2.1",
        "192.0.2.0/24",
        "/review/items",
        "/review/",
        "synthetic-ioc-agent",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "t13d1516h2_fixture_fixture",
        "EXAMPLE.TEST",
    ];
    let kinds = [
        "ip",
        "cidr",
        "path",
        "path-prefix",
        "user-agent",
        "ja3",
        "ja4",
        "host",
    ];
    let mut tsv = "# synthetic indicators\n\n".to_owned();
    for (kind, value) in kinds.iter().zip(values) {
        tsv += &format!("{kind}\t{value}\tprivate-cti-label\n");
    }
    tsv += "ip\t::ffff:192.0.2.1\tduplicate-label\nip\tnot-an-address\nprivate-unknown-type\tprivate-value\n";
    fs::write(&indicators, tsv).unwrap();
    let (report, stdout) = run(root.path(), &input, &indicators, "first", &[]);
    let summary = &report["summary"];
    assert_eq!(summary["loaded_indicators"], 8);
    assert_eq!(summary["matched_indicators"], 8);
    assert_eq!(summary["matched_requests"], 2);
    assert_eq!(summary["indicator_matches"], 14);
    assert_eq!(summary["source_ip_matches"], 2);
    assert_eq!(summary["client_ip_matches"], 0);
    assert_eq!(summary["duplicate_records"], 1);
    assert_eq!(summary["comment_or_empty_records"], 2);
    assert_eq!(summary["rejected_by_reason"]["invalid-value"], 1);
    assert_eq!(summary["rejected_by_reason"]["unsupported-object-type"], 1);
    for (index, row) in report["indicators"].as_array().unwrap().iter().enumerate() {
        let expected = if index < 2 { 1 } else { 2 };
        assert_eq!(row["matches"], expected);
        assert_eq!(row["distinct_source_ips"], expected);
        assert_eq!(row["input_file"], indicators.to_str().unwrap());
        assert_eq!(row["records"][0]["input_file"], input.to_str().unwrap());
        assert_eq!(row["records"][0]["line_number"], 1);
        assert_eq!(row["records"][0]["method"], "GET");
        assert_eq!(row["records"][0]["path"], "/review/items");
        assert_eq!(row["records"][0]["status"], 200);
        assert_eq!(row["first_seen"], "2026-01-01T00:00:00Z");
        assert_eq!(
            row["last_seen"],
            if index < 2 {
                "2026-01-01T00:00:00Z"
            } else {
                "2026-01-01T00:00:10Z"
            }
        );
    }
    let text = String::from_utf8(stdout.clone()).unwrap();
    let sanitized = fs::read_to_string(root.path().join("first/sanitized-ioc.json")).unwrap();
    for value in values.into_iter().chain([
        "private-cti-label",
        "duplicate-label",
        "private-unknown-type",
        "private-value",
    ]) {
        assert!(!text.contains(value), "stdout contains {value}");
        assert!(!sanitized.contains(value), "sanitized contains {value}");
    }
    let (_, repeat) = run(root.path(), &input, &indicators, "repeat", &[]);
    assert_eq!(stdout, repeat);
    for name in [
        "ioc-matches.json",
        "sanitized-ioc.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("first").join(name)).unwrap(),
            fs::read(root.path().join("repeat").join(name)).unwrap()
        );
    }
    let (_, shown) = run(
        root.path(),
        &input,
        &indicators,
        "shown",
        &["--show-matches", "--limit", "1"],
    );
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.contains("192.0.2.1"));
    assert!(shown.contains("private-cti-label"));
    assert!(shown.contains("Retained match records not displayed: 13"));
}

fn stix(pattern: &str) -> Value {
    json!({"type":"indicator","spec_version":"2.1","id":"indicator--private-identifier",
        "name":"private-stix-name","pattern_type":"stix","pattern":pattern})
}

#[test]
fn stix_supported_or_patterns_preserve_validity_and_reject_nonfaithful_patterns_whole() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    let indicators = root.path().join("bundle.json");
    fs::write(
        &input,
        event("192.0.2.1", 0, None)
            + &event("192.0.2.2", 10, None)
            + &event("2001:db8::1", 20, None)
            + &event("::ffff:192.0.2.1", 20, None),
    )
    .unwrap();
    let mut valid = stix("[ipv4-addr:value = '192.0.2.1' OR ipv4-addr:value = '192.0.2.0/24']");
    valid["valid_from"] = json!("2026-01-01T00:00:10Z");
    valid["valid_until"] = json!("2026-01-01T00:00:20Z");
    let mut objects = vec![
        valid,
        stix("[ipv6-addr:value = '2001:db8::/32']"),
        stix("[domain-name:value = 'EXAMPLE.TEST']"),
        stix("[url:value = 'https://example.test/review/items']"),
    ];
    for pattern in [
        "[ipv4-addr:value = '192.0.2.1' AND ipv4-addr:value = '192.0.2.2']",
        "[ipv4-addr:value = '192.0.2.1'] AND [ipv4-addr:value = '192.0.2.2']",
        "[ipv4-addr:value = '192.0.2.1'] FOLLOWEDBY [ipv4-addr:value = '192.0.2.2']",
        "[ipv4-addr:value = '192.0.2.1'] WITHIN 10 SECONDS",
        "[domain-name:value MATCHES 'example.*']",
        "[domain-name:value LIKE 'example%']",
        "[file:hashes.'SHA-256' = 'private-hash']",
        "[ipv4-addr:value = '192.0.2.1' OR domain-name:value = 'example.test']",
        "[url:value = 'https://example.test/review/items?private=query']",
        "[ipv4-addr:value = '192.0.2.1' OR file:value = 'private-file']",
    ] {
        objects.push(stix(pattern));
    }
    objects.push(json!({"type":"identity","name":"private-identity"}));
    objects.push(json!({"type":"indicator","pattern_type":"private-pattern-language","pattern":"private-pattern"}));
    fs::write(
        &indicators,
        json!({"type":"bundle","objects":objects}).to_string(),
    )
    .unwrap();
    let (report, stdout) = run(root.path(), &input, &indicators, "out", &[]);
    assert_eq!(report["summary"]["loaded_indicators"], 4);
    let rejected = &report["summary"]["rejected_by_reason"];
    assert_eq!(rejected["unsupported-operator"], 4);
    assert_eq!(rejected["compound-observation"], 2);
    assert_eq!(rejected["unsupported-object-type"], 2);
    assert_eq!(rejected["mixed-observation-types"], 1);
    assert_eq!(rejected["url-query-unsupported"], 1);
    assert_eq!(rejected["unsupported-pattern-type"], 1);
    assert_eq!(report["summary"]["ignored_stix_objects"], 1);
    let rows = report["indicators"].as_array().unwrap();
    assert_eq!(rows[0]["matches"], 3); // OR overlap on the first event counts once.
    assert_eq!(rows[0]["records"][0]["outside_validity"], true);
    assert_eq!(rows[0]["records"][1]["outside_validity"], false);
    assert_eq!(rows[0]["records"][2]["outside_validity"], true); // valid_until is exclusive.
    assert_eq!(rows[0]["outside_validity_matches"], 2);
    assert_eq!(rows[1]["matches"], 1);
    assert_eq!(rows[2]["matches"], 4);
    assert_eq!(rows[3]["matches"], 4); // URL queries are absent in the indicator, event queries do not change the path.
    assert_eq!(report["summary"]["matched_requests"], 4);
    assert_eq!(report["summary"]["outside_validity_requests"], 2);
    let sanitized = fs::read_to_string(root.path().join("out/sanitized-ioc.json")).unwrap();
    for private in [
        "192.0.2.1",
        "example.test",
        "/review/items",
        "private-stix-name",
        "private-identifier",
        "private-pattern",
        "private-identity",
        "private-hash",
    ] {
        assert!(!sanitized.contains(private));
        assert!(!String::from_utf8_lossy(&stdout).contains(private));
    }
}

#[test]
fn ioc_caps_count_omissions_and_keep_distinct_sources_as_disclosed_lower_bounds() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    let indicators = root.path().join("indicators.tsv");
    fs::write(
        &input,
        [
            "192.0.2.1",
            "192.0.2.2",
            "192.0.2.2",
            "192.0.2.3",
            "192.0.2.1",
        ]
        .iter()
        .map(|ip| event(ip, 0, None))
        .collect::<String>(),
    )
    .unwrap();
    let mut tsv = "\n".repeat(9000); // Sniffing must preserve blank lines beyond one read buffer.
    tsv+="# comment\npath\t/review/items\npath\t/review/items\npath-prefix\t/review/\nip\t192.0.2.1\nip\t192.0.2.2\n";
    fs::write(&indicators, tsv).unwrap();
    let (report, _) = run(
        root.path(),
        &input,
        &indicators,
        "out",
        &[
            "--max-indicators",
            "2",
            "--max-records-per-indicator",
            "2",
            "--max-sources-per-indicator",
            "1",
        ],
    );
    let summary = &report["summary"];
    assert_eq!(summary["loaded_indicators"], 2);
    assert_eq!(summary["duplicate_records"], 1);
    assert_eq!(summary["comment_or_empty_records"], 9001);
    assert_eq!(summary["records_beyond_indicator_cap"], 2);
    assert_eq!(summary["matched_requests"], 5);
    assert_eq!(summary["indicator_matches"], 10);
    assert_eq!(summary["records_beyond_retention_cap"], 6);
    assert_eq!(summary["source_observations_beyond_cap"], 6);
    for row in report["indicators"].as_array().unwrap() {
        assert!(row["distinct_source_ips"].is_null());
        assert_eq!(row["distinct_source_ips_at_least"], 1);
        assert_eq!(row["records_omitted"], 3);
        assert_eq!(row["records"].as_array().unwrap().len(), 2);
    }
    let manifest = read(root.path().join("out/run-manifest.json"));
    assert_eq!(manifest["options"]["max_indicators"], 2);
    assert_eq!(manifest["indicators"][0]["beyond_cap"], 2);
    assert_eq!(manifest["indicators"][0]["comments_or_empty"], 9001);
}

#[test]
fn ioc_time_bounds_and_trusted_proxy_matches_keep_peer_and_validated_client_counts_separate() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    let indicators = root.path().join("indicators.tsv");
    fs::write(
        &input,
        event("192.0.2.10", 0, Some("198.51.100.7"))
            + &event("192.0.2.10", 10, Some("198.51.100.7"))
            + &event("192.0.2.10", 20, Some("198.51.100.7")),
    )
    .unwrap();
    fs::write(&indicators, "ip\t192.0.2.10\nip\t198.51.100.7\n").unwrap();
    let bounds = [
        "--from",
        "2026-01-01T00:00:10Z",
        "--to",
        "2026-01-01T00:00:20Z",
    ];
    let (untrusted, _) = run(root.path(), &input, &indicators, "untrusted", &bounds);
    assert_eq!(untrusted["summary"]["client_ip_matches"], 0);
    let mut args = bounds.to_vec();
    args.extend(["--trusted-proxy", "192.0.2.10"]);
    let (trusted, _) = run(root.path(), &input, &indicators, "trusted", &args);
    assert_eq!(trusted["summary"]["parseable_records"], 3);
    assert_eq!(trusted["summary"]["records_outside_time_range"], 1);
    assert_eq!(trusted["summary"]["analyzed_requests"], 2);
    assert_eq!(trusted["summary"]["matched_requests"], 2);
    assert_eq!(trusted["summary"]["source_ip_matches"], 2);
    assert_eq!(trusted["summary"]["client_ip_matches"], 2);
    assert_eq!(
        trusted["indicators"][0]["records"][0]["matched_on"],
        json!(["source_ip"])
    );
    assert_eq!(
        trusted["indicators"][1]["records"][0]["matched_on"],
        json!(["client_ip"])
    );
    assert_eq!(
        trusted["indicators"][1]["records"][0]["source_ip"],
        "192.0.2.10"
    );
    assert_eq!(
        trusted["indicators"][1]["records"][0]["client_ip"],
        "198.51.100.7"
    );
}

#[test]
fn ioc_gzip_provenance_discovery_and_line_references_use_the_common_stream() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs");
    fs::create_dir(&input).unwrap();
    let tsv = b"path\t/review/items\tprivate-label\x1b[31m\n";
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(tsv).unwrap();
    let indicators_bytes = gzip.finish().unwrap();
    let indicators = root.path().join("indicators.tsv.gz");
    fs::write(&indicators, &indicators_bytes).unwrap();
    let log = event("192.0.2.1", 0, None)
        + "malformed synthetic record\n\n"
        + &event("192.0.2.2", 10, None);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(log.as_bytes()).unwrap();
    let corpus_bytes = gzip.finish().unwrap();
    fs::write(input.join("access_log"), &corpus_bytes).unwrap();
    fs::write(input.join("notes.md"), "private-note").unwrap();
    let (report, stdout) = run(
        root.path(),
        &input,
        &indicators,
        "out",
        &["--show-matches", "--limit", "0"],
    );
    assert_eq!(report["summary"]["parse_errors"], 1);
    assert_eq!(report["summary"]["files_skipped"], 1);
    assert_eq!(report["indicators"][0]["records"][0]["line_number"], 1);
    assert_eq!(report["indicators"][0]["records"][1]["line_number"], 4);
    assert!(!stdout.contains(&0x1b));
    let manifest = read(root.path().join("out/run-manifest.json"));
    assert_eq!(
        manifest["indicators"][0]["sha256"],
        format!("{:x}", Sha256::digest(&indicators_bytes))
    );
    assert_eq!(
        manifest["indicators"][0]["byte_length"],
        indicators_bytes.len()
    );
    assert_eq!(manifest["indicators"][0]["records"], 1);
    assert_eq!(
        manifest["corpus"][0]["sha256"],
        format!("{:x}", Sha256::digest(&corpus_bytes))
    );
    let before = fs::read(root.path().join("out/ioc-matches.json")).unwrap();
    command(root.path())
        .args(["ioc", "--format", "aws-waf", "--input"])
        .arg(&input)
        .arg("--indicators")
        .arg(&indicators)
        .arg("--output")
        .arg(root.path().join("out"))
        .assert()
        .failure();
    assert_eq!(
        before,
        fs::read(root.path().join("out/ioc-matches.json")).unwrap()
    );
}

#[test]
fn ioc_multiple_indicator_files_keep_missing_times_unknown_and_reject_invalid_inputs() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    let tsv = root.path().join("a.tsv");
    let bundle = root.path().join("b.json");
    let mut undated: Value = serde_json::from_str(&event("192.0.2.1", 0, None)).unwrap();
    undated.as_object_mut().unwrap().remove("timestamp");
    fs::write(&input, undated.to_string() + "\n").unwrap();
    fs::write(&tsv, "host\texample.test\tprivate-label\n").unwrap();
    let mut valid = stix("[ipv4-addr:value = '192.0.2.1']");
    valid["valid_from"] = json!("2026-01-01T00:00:00Z");
    let mut invalid = valid.clone();
    invalid["valid_until"] = json!("2025-12-31T00:00:00Z");
    let family = stix("[ipv4-addr:value = '2001:db8::1']");
    fs::write(
        &bundle,
        json!({"type":"bundle","objects":[valid,invalid,family]}).to_string(),
    )
    .unwrap();
    let execute = |name: &str, extras: &[&str]| {
        command(root.path())
            .args(["ioc", "--format", "aws-waf", "--input"])
            .arg(&input)
            .arg("--indicators")
            .arg(&bundle)
            .arg("--indicators")
            .arg(&tsv)
            .arg("--output")
            .arg(root.path().join(name))
            .args(extras)
            .assert()
            .success();
        read(root.path().join(name).join("ioc-matches.json"))
    };
    let report = execute("out", &[]);
    assert_eq!(report["summary"]["indicator_files"], 2);
    assert_eq!(report["summary"]["loaded_indicators"], 2);
    assert_eq!(report["summary"]["matched_requests"], 1);
    assert_eq!(report["summary"]["indicator_matches"], 2);
    assert_eq!(report["summary"]["validity_unavailable_matches"], 1);
    assert_eq!(report["summary"]["outside_validity_requests"], 0);
    assert_eq!(
        report["summary"]["rejected_by_reason"]["invalid-validity"],
        1
    );
    assert_eq!(
        report["summary"]["rejected_by_reason"]["address-family-mismatch"],
        1
    );
    assert!(report["indicators"][1]["records"][0]["outside_validity"].is_null());
    assert!(report["indicators"][1]["first_seen"].is_null());
    let manifest = read(root.path().join("out/run-manifest.json"));
    assert_eq!(manifest["indicators"][0]["path"], tsv.to_str().unwrap());
    assert_eq!(manifest["indicators"][1]["path"], bundle.to_str().unwrap());
    let filtered = execute("filtered", &["--from", "2026-01-01T00:00:00Z"]);
    assert_eq!(
        filtered["summary"]["undated_records_excluded_by_time_range"],
        1
    );
    assert_eq!(filtered["summary"]["matched_requests"], 0);
    command(root.path())
        .args(["ioc", "--format", "aws-waf", "--input"])
        .arg(&input)
        .arg("--indicators")
        .arg(&tsv)
        .args(["--max-indicators", "0"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("positive finite counts"));
    let result = command(root.path())
        .args(["ioc", "--format", "aws-waf", "--input"])
        .arg(&input)
        .arg("--indicators")
        .arg(&tsv)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(!String::from_utf8_lossy(&result).contains("example.test"));
    fs::write(&bundle, "{\"type\":\"bundle\",\"objects\":[").unwrap();
    let out = root.path().join("malformed");
    command(root.path())
        .args(["ioc", "--format", "aws-waf", "--input"])
        .arg(&input)
        .arg("--indicators")
        .arg(&bundle)
        .arg("--output")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicates::str::contains("reading indicator file"));
    assert!(!out.exists());
}

#[test]
fn ioc_standard_combined_matches_query_free_paths_without_inventing_host_or_fingerprints() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log.1");
    let indicators = root.path().join("indicators.tsv");
    fs::write(&input, "::ffff:192.0.2.7 - - [01/Jan/2026:00:00:00 +0000] \"GET /review/items?private=query HTTP/1.1\" 404 12 \"-\" \"synthetic-ioc-agent\"\r\n").unwrap();
    fs::write(&indicators, "ip\t192.0.2.7\ncidr\t192.0.2.0/24\npath\t/review/items\nuser-agent\tsynthetic-ioc-agent\nhost\texample.test\nja3\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nja4\tt13d1516h2_fixture_fixture\n").unwrap();
    let output = root.path().join("out");
    let stdout = command(root.path())
        .args(["ioc", "--format", "nginx", "--input"])
        .arg(&input)
        .arg("--indicators")
        .arg(&indicators)
        .arg("--output")
        .arg(&output)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report = read(output.join("ioc-matches.json"));
    assert_eq!(report["summary"]["matched_requests"], 1);
    assert_eq!(report["summary"]["matched_indicators"], 4);
    assert_eq!(report["summary"]["indicator_matches"], 4);
    assert_eq!(report["summary"]["observations_without_field"]["host"], 1);
    assert_eq!(report["summary"]["observations_without_field"]["ja3"], 1);
    assert_eq!(report["summary"]["observations_without_field"]["ja4"], 1);
    for row in &report["indicators"].as_array().unwrap()[..4] {
        assert_eq!(row["matches"], 1);
        assert_eq!(row["records"][0]["source_ip"], "::ffff:192.0.2.7");
        assert_eq!(row["records"][0]["path"], "/review/items");
        assert_eq!(row["records"][0]["status"], 404);
    }
    for row in &report["indicators"].as_array().unwrap()[4..] {
        assert_eq!(row["matches"], 0);
    }
    for private in [
        "192.0.2.7",
        "example.test",
        "/review/items",
        "private=query",
        "synthetic-ioc-agent",
    ] {
        assert!(!String::from_utf8_lossy(&stdout).contains(private));
    }
    assert!(!fs::read_to_string(output.join("ioc-matches.json"))
        .unwrap()
        .contains("private=query"));
}

#[test]
fn ioc_stix_revoked_and_invalid_revoked_are_rejected_before_matching() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    let indicators = root.path().join("bundle.json");
    fs::write(&input, event("192.0.2.1", 0, None)).unwrap();
    let mut objects = Vec::new();
    for revoked in [json!(true), json!(false), json!("private-revoked-value")] {
        let mut indicator = stix("[ipv4-addr:value = '192.0.2.1']");
        indicator["revoked"] = revoked;
        objects.push(indicator);
    }
    fs::write(
        &indicators,
        json!({"type":"bundle", "objects":objects}).to_string(),
    )
    .unwrap();
    let (report, stdout) = run(root.path(), &input, &indicators, "out", &[]);
    assert_eq!(report["summary"]["loaded_indicators"], 1);
    assert_eq!(report["summary"]["indicator_matches"], 1);
    assert_eq!(report["summary"]["rejected_by_reason"]["revoked"], 1);
    assert_eq!(
        report["summary"]["rejected_by_reason"]["invalid-revoked"],
        1
    );
    assert_eq!(report["summary"]["duplicate_records"], 0);
    let sanitized = fs::read_to_string(root.path().join("out/sanitized-ioc.json")).unwrap();
    for private in [
        "private-revoked-value",
        "private-stix-name",
        "192.0.2.1",
        "bundle.json",
    ] {
        assert!(!sanitized.contains(private));
        assert!(!String::from_utf8_lossy(&stdout).contains(private));
    }
}

#[test]
fn ioc_initial_utf8_bom_is_skipped_once_preserving_rows_and_stored_byte_provenance() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    fs::write(&input, event("192.0.2.1", 0, None)).unwrap();
    let tsv = "ip\t192.0.2.1\tprivate-bom-label\n\u{feff}ip\t192.0.2.2\n"
        .as_bytes()
        .to_vec();
    let bundle = json!({"type":"bundle", "objects":[stix("[ipv4-addr:value = '192.0.2.1']")]})
        .to_string()
        .into_bytes();
    for (index, content) in [tsv, bundle].into_iter().enumerate() {
        for bom in [false, true] {
            let indicators = root.path().join(format!("indicators-{index}-{bom}.data"));
            let mut bytes = if bom {
                vec![0xef, 0xbb, 0xbf]
            } else {
                Vec::new()
            };
            bytes.extend_from_slice(&content);
            fs::write(&indicators, &bytes).unwrap();
            let output = format!("out-{index}-{bom}");
            let (report, stdout) = run(root.path(), &input, &indicators, &output, &[]);
            assert_eq!(report["summary"]["loaded_indicators"], 1);
            assert_eq!(report["summary"]["matched_requests"], 1);
            assert_eq!(report["indicators"][0]["record_number"], 1);
            if index == 0 {
                // A BOM anywhere after the first three bytes is not stripped.
                assert_eq!(
                    report["summary"]["rejected_by_reason"]["unsupported-object-type"],
                    1
                );
            }
            let manifest = read(root.path().join(&output).join("run-manifest.json"));
            assert_eq!(manifest["indicators"][0]["utf8_bom"], bom);
            assert_eq!(
                manifest["indicators"][0]["sha256"],
                format!("{:x}", Sha256::digest(&bytes))
            );
            assert_eq!(manifest["indicators"][0]["byte_length"], bytes.len());
            let sanitized =
                fs::read_to_string(root.path().join(&output).join("sanitized-ioc.json")).unwrap();
            assert!(!sanitized.contains("utf8_bom"));
            assert!(!String::from_utf8_lossy(&stdout).contains("utf8_bom"));
            let repeat_name = format!("repeat-{index}-{bom}");
            let (_, repeat) = run(root.path(), &input, &indicators, &repeat_name, &[]);
            assert_eq!(stdout, repeat);
            for file in [
                "ioc-matches.json",
                "sanitized-ioc.json",
                "run-manifest.json",
            ] {
                assert_eq!(
                    fs::read(root.path().join(&output).join(file)).unwrap(),
                    fs::read(root.path().join(&repeat_name).join(file)).unwrap()
                );
            }
        }
    }
}

#[test]
fn ioc_host_and_url_normalization_preserves_values_and_requires_explicit_nondefault_ports() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    let tsv = root.path().join("a.tsv");
    let bundle = root.path().join("b.json");
    let hosts = [
        "Example.TEST:8443",
        "example.test.",
        "EXAMPLE.TEST:443",
        "example.test",
        "example.test.:80",
        "[2001:DB8::1]:8443",
        "[2001:db8::1]",
    ];
    let mut log = String::new();
    for host in hosts {
        let mut record: Value = serde_json::from_str(&event("192.0.2.1", 0, None)).unwrap();
        record["httpRequest"]["headers"][0]["value"] = json!(host);
        log += &(record.to_string() + "\n");
    }
    fs::write(&input, log).unwrap();
    fs::write(
        &tsv,
        "host\tEXAMPLE.TEST.:9443\tprivate-host-label\nhost\t[2001:DB8::1]:9443\n",
    )
    .unwrap();
    let mut objects = Vec::new();
    for url in [
        "https://example.test:443/review/items",
        "https://example.test/review/items",
        "http://example.test:80/review/items",
        "https://EXAMPLE.TEST.:8443/review/items",
        "https://example.test:9443/review/items",
        "https://[2001:db8::1]:443/review/items",
        "https://[2001:DB8::1]:8443/review/items",
    ] {
        objects.push(stix(&format!("[url:value = '{url}']")));
    }
    let mut domain = stix("[domain-name:value = 'EXAMPLE.TEST.:9443']");
    domain["valid_from"] = json!("2025-01-01T00:00:00Z");
    objects.push(domain);
    fs::write(
        &bundle,
        json!({"type":"bundle", "objects":objects}).to_string(),
    )
    .unwrap();
    let output = root.path().join("out");
    let stdout = command(root.path())
        .args(["ioc", "--format", "aws-waf", "--input"])
        .arg(&input)
        .arg("--indicators")
        .arg(&tsv)
        .arg("--indicators")
        .arg(&bundle)
        .arg("--output")
        .arg(&output)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report = read(output.join("ioc-matches.json"));
    assert_eq!(report["summary"]["duplicate_records"], 2);
    let rows = report["indicators"].as_array().unwrap();
    assert_eq!(rows[0]["values"], json!(["EXAMPLE.TEST.:9443"]));
    assert_eq!(rows[0]["matches"], 5);
    assert_eq!(rows[1]["values"], json!(["[2001:DB8::1]:9443"]));
    assert_eq!(rows[1]["matches"], 2);
    let find_url = |value: &str| {
        rows.iter()
            .find(|row| row["values"] == json!([value]))
            .unwrap()
    };
    assert_eq!(
        find_url("https://example.test:443/review/items")["matches"],
        4
    );
    let nondefault = find_url("https://EXAMPLE.TEST.:8443/review/items");
    assert_eq!(nondefault["matches"], 1);
    assert_eq!(nondefault["records"][0]["line_number"], 1);
    assert_eq!(
        find_url("https://example.test:9443/review/items")["matches"],
        0
    );
    assert_eq!(
        find_url("https://[2001:db8::1]:443/review/items")["matches"],
        1
    );
    let ipv6 = find_url("https://[2001:DB8::1]:8443/review/items");
    assert_eq!(ipv6["matches"], 1);
    assert_eq!(ipv6["records"][0]["line_number"], 6);
    assert_eq!(rows.last().unwrap()["indicator_type"], "domain-name");
    assert_eq!(rows.last().unwrap()["matches"], 5);
    let sanitized = fs::read_to_string(output.join("sanitized-ioc.json")).unwrap();
    for value in [
        "example.test",
        "EXAMPLE.TEST",
        "2001:db8",
        "private-host-label",
        "a.tsv",
        "b.json",
        "8443",
    ] {
        assert!(!sanitized.contains(value));
        assert!(!String::from_utf8_lossy(&stdout).contains(value));
    }
}

#[test]
fn ioc_url_authority_lookup_obeys_the_recorded_port_matrix_without_changing_host_matches() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.jsonl");
    let indicators = root.path().join("bundle.json");
    let hosts = [
        "Example.TEST:8443",
        "example.test.",
        "example.test:443",
        "example.test",
        "[2001:db8::1]:8443",
        "example.test:80",
        "example.test:8080",
    ];
    let mut log = String::new();
    for host in hosts {
        let mut record: Value = serde_json::from_str(&event("192.0.2.1", 0, None)).unwrap();
        record["httpRequest"]["headers"][0]["value"] = json!(host);
        log += &(record.to_string() + "\n");
    }
    fs::write(&input, log).unwrap();
    let cases = [
        ("https://example.test/review/items", vec![2, 3, 4, 6]),
        ("https://example.test:443/review/items", vec![2, 3, 4, 6]),
        ("https://example.test:8443/review/items", vec![1]),
        ("https://[2001:db8::1]:8443/review/items", vec![5]),
        ("http://example.test/review/items", vec![2, 3, 4, 6]),
        ("http://example.test:8080/review/items", vec![7]),
    ];
    let mut objects = vec![stix("[domain-name:value = 'example.test']")];
    for (i, (url, _)) in cases.iter().enumerate() {
        let mut indicator = stix(&format!("[url:value = '{url}']"));
        // Distinct validity bounds keep equivalent default-port spellings as separate test rows.
        indicator["valid_from"] = json!(format!("2025-01-{:02}T00:00:00Z", i + 1));
        objects.push(indicator);
    }
    fs::write(
        &indicators,
        json!({"type":"bundle", "objects":objects}).to_string(),
    )
    .unwrap();
    let (report, stdout) = run(root.path(), &input, &indicators, "out", &[]);
    let rows = report["indicators"].as_array().unwrap();
    assert_eq!(rows[0]["matches"], 6);
    for (row, (url, expected)) in rows[1..].iter().zip(cases) {
        assert_eq!(row["values"], json!([url]));
        let actual: Vec<_> = row["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["line_number"].as_u64().unwrap())
            .collect();
        assert_eq!(actual, expected, "{url}");
    }
    let sanitized = fs::read_to_string(root.path().join("out/sanitized-ioc.json")).unwrap();
    for private in [
        "example.test",
        "2001:db8",
        "/review/items",
        "bundle.json",
        "private-stix-name",
    ] {
        assert!(!sanitized.contains(private));
        assert!(!String::from_utf8_lossy(&stdout).contains(private));
    }
}
