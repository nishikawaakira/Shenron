use assert_cmd::Command;
use serde_json::{json, Value};
use std::{fs, path::Path};

fn command(root: &Path) -> Command {
    let mut command = Command::cargo_bin("shenron").unwrap();
    command
        .env("SHENRON_DATA_DIR", root.join("empty-data"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("SHENRON_SLACK_WEBHOOK");
    command
}
fn line(ip: &str, method: &str, uri: &str, status: u16, bytes: u64, second: u8) -> String {
    format!("example.test:443 {ip} - - [01/Jan/2026:00:00:{second:02} +0000] \"{method} {uri} HTTP/1.1\" {status} {bytes} \"-\" \"fixture-agent\"\n")
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn run(root: &Path, input: &Path, output: &str, args: &[&str]) -> (Value, Vec<u8>) {
    let path = root.join(output);
    let result = command(root)
        .args(["identifier-access", "--input"])
        .arg(input)
        .args(["--format", "auto", "--output"])
        .arg(&path)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    (read(path.join("identifier-access.json")), result)
}
fn sweep() -> String {
    (1000..1200)
        .map(|id| {
            line(
                "192.0.2.10",
                "GET",
                &format!("/users/me/notifications/{id}"),
                200,
                if id % 2 == 0 { 1000 + id } else { 800 },
                2,
            )
        })
        .collect()
}
fn own_data() -> String {
    let mut log = line(
        "192.0.2.20",
        "PUT",
        "/api/v1/receipts/5001.json",
        200,
        40,
        0,
    );
    log += &line(
        "192.0.2.20",
        "GET",
        "/api/v1/receipts/5001/images",
        200,
        1166,
        2,
    );
    for id in 6000..6300 {
        log += &line(
            "192.0.2.20",
            "GET",
            &format!("/api/v1/receipts/{id}/images"),
            400,
            730,
            3,
        );
    }
    log
}

#[test]
fn identifier_sweep_prior_writes_order_privacy_and_bytes_are_reproducible() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log.1");
    fs::write(&input, sweep() + &own_data()).unwrap();
    let (report, stdout) = run(
        root.path(),
        &input,
        "first",
        &["--corpus-label", "example.test private annotation"],
    );
    let (repeat, again) = run(
        root.path(),
        &input,
        "repeat",
        &["--corpus-label", "example.test private annotation"],
    );
    assert_eq!(report, repeat);
    assert_eq!(stdout, again);
    let entries = report["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .all(|row| row["distinct_ids_at_least"].is_null()));
    assert_eq!(report["summary"]["requests_excluded_by_method"], 0);
    let own = &entries[0];
    assert_eq!(own["distinct_ids"], 301);
    assert_eq!(own["content_ids"], 1);
    assert_eq!(own["rejected_ids"], 300);
    assert!(own["dominant_2xx_response_bytes"].is_null());
    assert_eq!(own["ids_written_by_same_peer"], 1);
    assert_eq!(own["ids_written_before_first_content"], 1);
    assert_eq!(own["content_id_values"], json!(["5001"]));
    let sweep = &entries[1];
    for (key, expected) in [
        ("requests", 200),
        ("distinct_ids", 200),
        ("dominant_2xx_response_bytes", 800),
        ("content_ids", 100),
        ("rejected_ids", 100),
    ] {
        assert_eq!(sweep[key], expected);
    }
    assert_eq!(sweep["rejected_id_share"], 0.5);
    assert_eq!(sweep["adjacent_step_share"], 1.0);
    assert_eq!(sweep["self_reference_segment"], "me");
    assert_eq!(sweep["template"], "/users/me/notifications/{num}");
    let sanitized = fs::read(root.path().join("first/sanitized-identifier-access.json")).unwrap();
    for bytes in [&stdout, &sanitized] {
        let text = String::from_utf8_lossy(bytes);
        for private in [
            "192.0.2.10",
            "192.0.2.20",
            "example.test",
            "/users/",
            "/api/",
            "{num}",
            "5001",
            "fixture-agent",
            "private annotation",
        ] {
            assert!(!text.contains(private), "leaked {private}");
        }
    }
    for file in [
        "identifier-access.json",
        "sanitized-identifier-access.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("first").join(file)).unwrap(),
            fs::read(root.path().join("repeat").join(file)).unwrap()
        );
    }
    let manifest = read(root.path().join("first/run-manifest.json"));
    assert_eq!(manifest["corpus_label"], "example.test private annotation");
    assert_eq!(manifest["options"]["min_distinct_ids"], 20);
    assert_eq!(
        manifest["corpus"][0]["byte_length"],
        fs::metadata(&input).unwrap().len()
    );
    assert!(manifest["corpus"][0]["sha256"].as_str().unwrap().len() == 64);
    command(root.path())
        .args(["identifier-access", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(root.path().join("first"))
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "refusing to overwrite existing output:",
        ));
}

#[test]
fn identifier_method_filter_preserves_writes_without_consuming_entry_capacity() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for id in 7000..7300 {
        log += &line(
            "192.0.2.20",
            "PUT",
            &format!("/api/v1/receipts/{id}.json"),
            200,
            800,
            0,
        );
    }
    log += &own_data();
    fs::write(&input, log).unwrap();
    let (all, _) = run(root.path(), &input, "all", &[]);
    assert_eq!(all["entries"].as_array().unwrap().len(), 2);
    assert_eq!(all["entries"][0]["method"], "GET");
    assert_eq!(all["entries"][1]["method"], "PUT");
    assert_eq!(all["entries"][1]["rejected_ids"], 300);
    assert_eq!(all["summary"]["requests_excluded_by_method"], 0);
    let args = ["--method", "GET", "--method", "HEAD", "--max-entries", "1"];
    let (filtered, stdout) = run(root.path(), &input, "reads", &args);
    let (get_only, _) = run(root.path(), &input, "get-only", &["--method", "GET"]);
    assert_eq!(get_only, filtered);
    assert_eq!(filtered["entries"], json!([all["entries"][0]]));
    assert_eq!(filtered["entries"][0]["ids_written_by_same_peer"], 1);
    assert_eq!(
        filtered["entries"][0]["ids_written_before_first_content"],
        1
    );
    let summary = &filtered["summary"];
    assert_eq!(summary["requests_excluded_by_method"], 301);
    assert_eq!(summary["total_entries"], 1);
    assert_eq!(summary["entries_at_or_above_minimum"], 1);
    assert_eq!(summary["rejected_share_at_least_08"], 1);
    assert_eq!(summary["omissions"]["entry_observations_beyond_cap"], 0);
    assert_eq!(
        read(root.path().join("reads/run-manifest.json"))["options"]["method"],
        json!(["GET", "HEAD"])
    );
    let sanitized =
        fs::read_to_string(root.path().join("reads/sanitized-identifier-access.json")).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&sanitized).unwrap()["requests_excluded_by_method"],
        301
    );
    assert!(!sanitized.contains("GET"));
    assert!(!sanitized.contains("HEAD"));
    let (_, repeat) = run(root.path(), &input, "repeat", &args);
    assert_eq!(stdout, repeat);
    for name in [
        "identifier-access.json",
        "sanitized-identifier-access.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("reads").join(name)).unwrap(),
            fs::read(root.path().join("repeat").join(name)).unwrap()
        );
    }
    let (lowercase, _) = run(root.path(), &input, "lowercase", &["--method", "get"]);
    assert_eq!(lowercase["entries"], json!([]));
    assert_eq!(lowercase["summary"]["requests_excluded_by_method"], 602);
    assert_eq!(lowercase["summary"]["total_entries"], 0);
    // Exclusions count requests once, even when several ID positions are extracted.
    fs::write(
        &input,
        line("192.0.2.20", "PUT", "/items/1/parts/2", 200, 10, 0),
    )
    .unwrap();
    let (multiple, _) = run(root.path(), &input, "multiple", &["--method", "GET"]);
    assert_eq!(multiple["summary"]["requests_excluded_by_method"], 1);
}

#[test]
fn identifier_table_has_one_row_per_entry_nulls_and_gated_columns() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    fs::write(&input, sweep() + &own_data()).unwrap();
    for (name, args, suffix) in [
        ("plain", vec![], ""),
        ("paths", vec!["--show-paths"], " method position template"),
        ("sources", vec!["--show-source-ips"], " source"),
        (
            "both",
            vec!["--show-source-ips", "--show-paths"],
            " source method position template",
        ),
    ] {
        let mut args = args;
        args.extend(["--limit", "1"]);
        let (report, stdout) = run(root.path(), &input, name, &args);
        assert_eq!(report["entries"][0]["distinct_ids_at_least"], Value::Null);
        if name != "plain" {
            for artifact in [
                "identifier-access.json",
                "sanitized-identifier-access.json",
                "run-manifest.json",
            ] {
                assert_eq!(
                    fs::read(root.path().join("plain").join(artifact)).unwrap(),
                    fs::read(root.path().join(name).join(artifact)).unwrap()
                );
            }
        }
        let text = String::from_utf8(stdout).unwrap();
        let lines: Vec<_> = text.lines().collect();
        let header = lines
            .iter()
            .position(|line| line.trim_start().starts_with("# "))
            .unwrap();
        assert_eq!(lines[header].split_whitespace().collect::<Vec<_>>().join(" "),
            format!("# requests ids content rejected share dom_bytes adjacent prefix timestamp written_before{suffix}"));
        let row: Vec<_> = lines[header + 1].split_whitespace().collect();
        assert_eq!(
            &row[..11],
            &["1", "301", "301", "1", "300", "1.00", "-", "1.00", "0.00", "0.00", "1"]
        );
        assert_eq!(lines[header + 2], "Entries not displayed: 1");
        assert_eq!(header + 3, lines.len());
        assert!(lines[header - 1].contains("not a judgment or score"));
        assert!(text.contains("  Requests excluded by method: 0"));
        assert!(!text.contains("example.test"));
        assert!(!text.contains("5001"));
        if !args.contains(&"--show-source-ips") {
            assert!(!text.contains("192.0.2."));
        }
        if !args.contains(&"--show-paths") {
            assert!(!text.contains("/api/"));
        }
    }
    let (_, stdout) = run(
        root.path(),
        &input,
        "capped",
        &["--max-ids-per-entry", "10"],
    );
    let text = String::from_utf8(stdout).unwrap();
    assert!(text.contains(">=10"));
    let row = text
        .lines()
        .find(|line| line.split_whitespace().next() == Some("1"))
        .unwrap();
    assert_eq!(
        &row.split_whitespace().collect::<Vec<_>>()[2..6],
        &[">=10", "-", "-", "-"]
    );
    let (_, stdout) = run(root.path(), &input, "entry-cap", &["--max-entries", "1"]);
    assert!(String::from_utf8(stdout)
        .unwrap()
        .contains("  Total entries: unknown"));
}

#[test]
fn identifier_unfiltered_artifact_bytes_change_only_for_method_count_and_optional_lower_bound() {
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for (source, id, status, size) in [
        ("192.0.2.10", 1, 200, 100),
        ("::ffff:192.0.2.10", 2, 200, 800),
        ("192.0.2.10", 3, 499, 10),
        ("::ffff:192.0.2.10", 1, 200, 101),
        ("192.0.2.10", 2, 200, 800),
        ("192.0.2.10", 4, 503, 10),
    ] {
        log += &line(source, "GET", &format!("/items/{id}"), status, size, 0);
    }
    fs::write(&input, log).unwrap();
    run(root.path(), &input, "report", &["--min-distinct-ids", "1"]);
    // Pre-filter/table-change bytes from the synthetic fixture, excluding only intended changes.
    for (file, expected) in [
        (
            "identifier-access.json",
            "935d29ae8560220ab7a06838ce9c7d66cffaf5aa8b863a4d4ebea080e3bc9cf4",
        ),
        (
            "sanitized-identifier-access.json",
            "a79ecbbcbcca061b1f0b8a621e9afa9ba0d5f8cf2876a1e5b0e1f30c9b35f38b",
        ),
    ] {
        let bytes = fs::read_to_string(root.path().join("report").join(file)).unwrap();
        let previous = bytes
            .lines()
            .filter(|line| !line.contains("\"requests_excluded_by_method\": "))
            .collect::<Vec<_>>()
            .join("\n")
            .replace(
                "\"distinct_ids_at_least\": null",
                "\"distinct_ids_at_least\": 4",
            );
        assert_eq!(
            format!("{:x}", Sha256::digest(previous.as_bytes())),
            expected,
            "{file}"
        );
    }
}

#[test]
fn identifier_members_timestamp_prefix_queries_and_exclusions_are_descriptive() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    let mut member_requests = 0;
    for source in 1..=50 {
        for id in 1..=(source % 6 + 1) {
            log += &line(
                &format!("198.51.100.{source}"),
                "GET",
                &format!("/member?member_code={id}"),
                200,
                100,
                0,
            );
            member_requests += 1;
        }
    }
    for i in 0..30 {
        log += &line(
            "203.0.113.1",
            "GET",
            &format!("/cache?_={}", 1767225600000_u64 + i),
            200,
            100,
            0,
        );
    }
    // Two growing branches with a return to their common prefix: 25 distinct
    // values, each at most 13 digits, and every transition is a prefix relation.
    for value in (1..=13)
        .map(|n| "0".repeat(n))
        .chain(std::iter::once("0".into()))
        .chain((1..=12).map(|n| format!("0{}", "3".repeat(n))))
    {
        log += &line(
            "203.0.113.2",
            "GET",
            &format!("/search?tel={value}"),
            200,
            100,
            0,
        );
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(root.path(), &input, "first", &[]);
    assert_eq!(report["entries"].as_array().unwrap().len(), 2);
    assert_eq!(
        report["summary"]["requests_with_identifiers"],
        member_requests + 56
    );
    let rows = report["entries"].as_array().unwrap();
    assert_eq!(
        rows.iter().find(|r| r["position"] == "query:_").unwrap()["timestamp_like_share"],
        1.0
    );
    assert_eq!(
        rows.iter().find(|r| r["position"] == "query:tel").unwrap()["prefix_extension_share"],
        1.0
    );
    let (excluded, _) = run(
        root.path(),
        &input,
        "excluded",
        &["--exclude-query-param", "_"],
    );
    assert_eq!(
        excluded["summary"]["excluded_query_identifier_observations"],
        30
    );
    assert_eq!(excluded["entries"].as_array().unwrap().len(), 1);
    let (members, _) = run(root.path(), &input, "members", &["--min-distinct-ids", "1"]);
    assert_eq!(members["entries"].as_array().unwrap().len(), 52);
}

#[test]
fn identifier_caps_retain_incomplete_entries_disclose_lower_bounds_and_nulls() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    fs::write(&input, sweep()).unwrap();
    let (report, _) = run(root.path(), &input, "ids", &["--max-ids-per-entry", "10"]);
    let row = &report["entries"][0];
    assert!(row["distinct_ids"].is_null());
    assert_eq!(row["distinct_ids_at_least"], 10);
    assert_eq!(row["id_observations_beyond_cap"], 190);
    assert!(row["rejected_id_share"].is_null());
    assert_eq!(report["summary"]["entries_with_id_cap_omissions"], 1);
    assert_eq!(report["summary"]["entries_below_minimum_unproven"], 1);
    assert_eq!(report["summary"]["sources_at_or_above_minimum"], 0);
    assert_eq!(report["summary"]["entries_at_or_above_minimum"], 0);
    assert_eq!(report["summary"]["reported_entries"], 1);
    assert!(row["redirect_only_ids"].is_null());
    let (sizes, _) = run(
        root.path(),
        &input,
        "sizes",
        &["--max-response-size-pairs-per-entry", "1"],
    );
    assert!(sizes["entries"][0]["content_ids"].is_null());
    assert_eq!(
        sizes["entries"][0]["response_size_observations_beyond_cap"],
        199
    );
    let (values, _) = run(
        root.path(),
        &input,
        "values",
        &["--max-reported-ids-per-entry", "3"],
    );
    assert_eq!(
        values["entries"][0]["content_id_values"],
        json!(["1000", "1002", "1004"])
    );
    assert_eq!(values["entries"][0]["content_id_values_not_reported"], 97);
    fs::write(&input, own_data()).unwrap();
    let (limited, _) = run(root.path(), &input, "entries", &["--max-entries", "1"]);
    assert!(limited["summary"]["total_entries"].is_null());
    assert_eq!(
        limited["summary"]["omissions"]["entry_observations_beyond_cap"],
        301
    );
    command(root.path())
        .args(["identifier-access", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(root.path().join("bad"))
        .args(["--max-entries", "0"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("positive finite counts"));
}

#[test]
fn identifier_waf_missing_status_canonical_peers_and_trust_stay_separate() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("events.json");
    let mut log = String::new();
    for i in 0..24 {
        for peer in [
            if i % 2 == 0 {
                "192.0.2.10"
            } else {
                "::ffff:192.0.2.10"
            },
            "198.51.100.1",
        ] {
            log += &format!(
                "{}\n",
                json!({"timestamp":1767225600000_i64,"action":"ALLOW",
                "httpRequest":{"clientIp":peer,"httpMethod":"GET","uri":format!("/items/{i}"),
                "args":"","headers":[{"name":"host","value":"example.test"},
                    {"name":"x-forwarded-for","value":"192.0.2.10"}]}})
            );
        }
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(
        root.path(),
        &input,
        "waf",
        &["--trusted-proxy", "198.51.100.1"],
    );
    assert_eq!(report["entries"].as_array().unwrap().len(), 2);
    for row in report["entries"].as_array().unwrap() {
        assert_eq!(row["distinct_ids"], 24);
        assert_eq!(row["source"], "192.0.2.10");
        assert!(row["rejected_id_share"].is_null());
        assert!(row["content_ids"].is_null());
        assert!(row["ids_written_before_first_content"].is_null());
        assert_eq!(row["status_classes"]["unavailable"], 24);
    }
    assert_ne!(
        report["entries"][0]["identity"],
        report["entries"][1]["identity"]
    );
}

#[test]
fn identifier_time_filters_display_gates_limit_and_discovery_are_explicit() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("access.log.1"), sweep()).unwrap();
    fs::write(input.join("access_log"), own_data()).unwrap();
    fs::write(input.join("notes.md"), "not a log").unwrap();
    let (report, stdout) = run(
        root.path(),
        &input,
        "shown",
        &["--show-paths", "--limit", "1"],
    );
    let text = String::from_utf8(stdout).unwrap();
    assert!(text.contains("Files skipped: 1 (unsupported-extension: 1)"));
    assert!(text.contains("/api/v1/receipts/{num}/images"));
    assert!(!text.contains("192.0.2."));
    assert!(text.contains("Entries not displayed: 1"));
    assert_eq!(report["summary"]["files_analyzed"], 2);
    let (_, source) = run(
        root.path(),
        &input,
        "sources",
        &["--show-source-ips", "--limit", "0"],
    );
    let text = String::from_utf8(source).unwrap();
    assert!(text.contains("192.0.2.20"));
    assert!(!text.contains("/api/"));
    assert!(text.contains("Entries not displayed: 0"));
    let (filtered, _) = run(
        root.path(),
        &input,
        "filtered",
        &["--from", "2026-01-01T00:00:03Z"],
    );
    assert_eq!(filtered["entries"][0]["distinct_ids"], 300);
    assert_eq!(filtered["summary"]["records_outside_time_range"], 202);
}

#[test]
fn identifier_write_methods_are_exact_allowlisted_tokens() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let methods = [
        "POST", "PUT", "PATCH", "DELETE", "PROPFIND", "TRACE", "get", "GARBAGE", "HEAD", "OPTIONS",
    ];
    let mut log = String::new();
    for (index, method) in methods.iter().enumerate() {
        let id = index + 1;
        log += &line(
            "192.0.2.10",
            method,
            &format!("/write/{id}.json"),
            200,
            10,
            0,
        );
        log += &line(
            "192.0.2.10",
            "GET",
            &format!("/read/{id}"),
            200,
            100 + id as u64,
            2,
        );
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(root.path(), &input, "report", &["--min-distinct-ids", "1"]);
    let entries = report["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 11);
    let read = entries.iter().find(|row| row["method"] == "GET").unwrap();
    assert_eq!(read["ids_written_by_same_peer"], 4);
    assert_eq!(read["ids_written_before_first_content"], 4);
    for row in entries.iter().filter(|row| row["method"] != "GET") {
        assert_eq!(row["ids_written_by_same_peer"], 0);
        assert_eq!(row["ids_written_before_first_content"], 0);
    }
}

#[test]
fn identifier_write_origins_exclude_self_and_keep_two_earliest_distinct_keys() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for id in [1, 2] {
        log += &line("192.0.2.10", "PUT", &format!("/items/{id}"), 200, 800, 0);
        log += &line(
            "192.0.2.10",
            "PUT",
            &format!("/items/{id}"),
            200,
            100 + id,
            4,
        );
    }
    fs::write(&input, &log).unwrap();
    let (report, _) = run(root.path(), &input, "self", &["--min-distinct-ids", "1"]);
    assert_eq!(report["entries"][0]["ids_written_by_same_peer"], 0);
    assert_eq!(report["entries"][0]["ids_written_before_first_content"], 0);
    // Arrive out of timestamp order, with more than two origins. DELETE
    // displaces PATCH as the earliest alternative to the PUT entry.
    for (method, time) in [("POST", 10), ("PATCH", 5), ("DELETE", 1), ("POST", 12)] {
        log += &line("192.0.2.10", method, "/other/1.json", 200, 200, time);
    }
    fs::write(&input, &log).unwrap();
    for (name, args) in [
        ("all", vec!["--min-distinct-ids", "1"]),
        (
            "capped",
            vec![
                "--min-distinct-ids",
                "1",
                "--max-entries",
                "1",
                "--max-written-ids-per-peer",
                "2",
            ],
        ),
    ] {
        let (report, _) = run(root.path(), &input, name, &args);
        let put = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["method"] == "PUT")
            .unwrap();
        assert_eq!(put["ids_written_by_same_peer"], 1);
        assert_eq!(put["ids_written_before_first_content"], 1);
        assert_eq!(put["write_history_incomplete"], false);
        assert_eq!(
            report["summary"]["omissions"]["write_observations_beyond_id_cap"],
            0
        );
        if name == "capped" {
            assert_eq!(
                report["summary"]["omissions"]["entry_observations_beyond_cap"],
                4
            );
        }
    }
}

#[test]
fn identifier_redirect_and_informational_only_ids_are_outside_rejected_denominator() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for (id, status, size) in [
        (1, 100, 0),
        (2, 304, 0),
        (2, 302, 0),
        (3, 404, 1),
        (4, 503, 1),
        (5, 200, 800),
        (6, 200, 800),
        (7, 200, 100),
        (8, 600, 1),
    ] {
        log += &line(
            "192.0.2.10",
            "GET",
            &format!("/items/{id}"),
            status,
            size,
            0,
        );
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(root.path(), &input, "mixed", &["--min-distinct-ids", "1"]);
    let row = &report["entries"][0];
    assert_eq!(row["content_ids"], 1);
    assert_eq!(row["rejected_ids"], 4);
    assert_eq!(row["redirect_only_ids"], 2);
    assert_eq!(row["rejected_id_share"], 0.8);
    assert_eq!(row["status_classes"]["other"], 1);
    fs::write(&input, line("192.0.2.10", "GET", "/items/1", 304, 0, 0)).unwrap();
    let (report, _) = run(
        root.path(),
        &input,
        "redirect",
        &["--min-distinct-ids", "1"],
    );
    assert_eq!(report["entries"][0]["redirect_only_ids"], 1);
    assert_eq!(report["entries"][0]["rejected_ids"], 0);
    assert!(report["entries"][0]["rejected_id_share"].is_null());
    let missing = line("192.0.2.10", "GET", "/items/1", 200, 9876, 0).replace("200 9876", "200 -");
    fs::write(&input, missing).unwrap();
    let (report, _) = run(root.path(), &input, "missing", &["--min-distinct-ids", "1"]);
    assert!(report["entries"][0]["redirect_only_ids"].is_null());
    assert!(report["entries"][0]["rejected_id_share"].is_null());
}

#[test]
fn identifier_reported_entry_counts_partition_proven_and_unproven_minima() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for (path, count) in [("proven", 2), ("incomplete", 4), ("below", 1)] {
        for id in 0..count {
            log += &line("192.0.2.10", "GET", &format!("/{path}/{id}"), 404, 1, 0);
        }
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(
        root.path(),
        &input,
        "report",
        &["--min-distinct-ids", "3", "--max-ids-per-entry", "2"],
    );
    let summary = &report["summary"];
    assert_eq!(summary["entries_below_minimum"], 2);
    assert_eq!(summary["entries_below_minimum_unproven"], 1);
    assert_eq!(summary["entries_at_or_above_minimum"], 0);
    assert_eq!(summary["reported_entries"], 1);
    let (report, _) = run(
        root.path(),
        &input,
        "lower",
        &["--min-distinct-ids", "2", "--max-ids-per-entry", "2"],
    );
    let summary = &report["summary"];
    assert_eq!(summary["entries_below_minimum_unproven"], 0);
    assert_eq!(summary["entries_at_or_above_minimum"], 2);
    assert_eq!(summary["reported_entries"], 2);
    assert_eq!(summary["sources_at_or_above_minimum"], 1);
}

struct BatchValue<'a> {
    action: Option<&'a dyn Fn()>,
    fail: bool,
}
impl serde::Serialize for BatchValue<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Fixture", 1)?;
        state.serialize_field("source", "192.0.2.10")?;
        if let Some(action) = self.action {
            action();
        }
        if self.fail {
            return Err(serde::ser::Error::custom(
                "injected batch serialization failure",
            ));
        }
        state.end()
    }
}

#[test]
fn identifier_artifact_batch_removes_completed_files_and_allows_retry() {
    use shenron::output::write_json_pretty_new_batch;
    for failing in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        let paths = [
            "identifier-access.json",
            "sanitized-identifier-access.json",
            "run-manifest.json",
        ]
        .map(|name| root.path().join(name));
        let values: Vec<_> = paths
            .iter()
            .enumerate()
            .map(|(i, path)| {
                (
                    path.as_path(),
                    BatchValue {
                        action: None,
                        fail: i == failing,
                    },
                )
            })
            .collect();
        let error = write_json_pretty_new_batch(&values).unwrap_err();
        assert!(format!("{error:#}").contains("injected batch serialization failure"));
        assert!(
            format!("{error:#}").contains(&format!("writing JSON to {}", paths[failing].display()))
        );
        assert!(paths.iter().all(|path| !path.exists()));
        write_json_pretty_new_batch(
            &paths
                .iter()
                .map(|path| (path.as_path(), json!({"ok":true})))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(paths.iter().all(|path| path.is_file()));
    }
}

#[test]
fn identifier_artifact_batch_preserves_files_created_after_preflight() {
    use shenron::output::write_json_pretty_new_batch;
    for blocked in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        let paths = [
            "identifier-access.json",
            "sanitized-identifier-access.json",
            "run-manifest.json",
        ]
        .map(|name| root.path().join(name));
        assert!(paths.iter().all(|path| !path.exists()));
        // The first output is already open when serialization creates the
        // competing output, after any run preflight could have succeeded.
        let race = || fs::write(&paths[blocked], "external file").unwrap();
        let values: Vec<_> = paths
            .iter()
            .enumerate()
            .map(|(i, path)| {
                (
                    path.as_path(),
                    BatchValue {
                        action: if i == 0 {
                            Some(&race as &dyn Fn())
                        } else {
                            None
                        },
                        fail: false,
                    },
                )
            })
            .collect();
        let error = write_json_pretty_new_batch(&values).unwrap_err();
        assert!(error
            .to_string()
            .contains("refusing to overwrite existing output:"));
        assert_eq!(
            fs::read_to_string(&paths[blocked]).unwrap(),
            "external file"
        );
        assert!(paths
            .iter()
            .enumerate()
            .all(|(i, path)| i == blocked || !path.exists()));
    }
}

#[test]
fn identifier_artifact_batch_cleanup_not_found_preserves_original_error() {
    use shenron::output::write_json_pretty_new_batch;
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("identifier-access.json");
    let second = root.path().join("sanitized-identifier-access.json");
    let gone = || fs::remove_file(&first).unwrap();
    let error = write_json_pretty_new_batch(&[
        (
            first.as_path(),
            BatchValue {
                action: None,
                fail: false,
            },
        ),
        (
            second.as_path(),
            BatchValue {
                action: Some(&gone),
                fail: true,
            },
        ),
    ])
    .unwrap_err();
    assert!(format!("{error:#}").contains("injected batch serialization failure"));
    assert!(!format!("{error:#}").contains("could not remove incomplete output"));
    assert!(!first.exists() && !second.exists());
}

#[cfg(unix)]
#[test]
fn identifier_artifact_batch_cleanup_failure_keeps_error_chain_and_other_outputs_are_removed() {
    use shenron::output::write_json_pretty_new_batch;
    let root = tempfile::tempdir().unwrap();
    let paths = [
        "identifier-access.json",
        "sanitized-identifier-access.json",
        "run-manifest.json",
    ]
    .map(|name| root.path().join(name));
    let replace = || {
        fs::remove_file(&paths[0]).unwrap();
        fs::create_dir(&paths[0]).unwrap();
        fs::write(paths[0].join("external.txt"), "external file").unwrap();
    };
    let error = write_json_pretty_new_batch(&[
        (
            paths[0].as_path(),
            BatchValue {
                action: None,
                fail: false,
            },
        ),
        (
            paths[1].as_path(),
            BatchValue {
                action: None,
                fail: false,
            },
        ),
        (
            paths[2].as_path(),
            BatchValue {
                action: Some(&replace),
                fail: true,
            },
        ),
    ])
    .unwrap_err();
    assert!(format!("{error:#}").contains("could not remove incomplete output"));
    assert!(format!("{error:#}").contains("injected batch serialization failure"));
    assert!(error.downcast_ref::<serde_json::Error>().is_some());
    assert_eq!(
        fs::read_to_string(paths[0].join("external.txt")).unwrap(),
        "external file"
    );
    assert!(!paths[1].exists() && !paths[2].exists());
}
