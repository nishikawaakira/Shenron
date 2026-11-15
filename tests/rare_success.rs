use std::{fs, io::Write, path::Path};

use assert_cmd::Command;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn command(root: &Path) -> Command {
    let mut command = Command::cargo_bin("shenron").unwrap();
    command
        .env("SHENRON_DATA_DIR", root.join("empty-data"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("SHENRON_SLACK_WEBHOOK");
    command
}

fn line(ip: &str, path: &str, method: &str, status: u16, second: u8, bytes: u64) -> String {
    format!("{ip} - - [01/Jan/2026:00:00:{second:02} +0000] \"{method} {path} HTTP/1.1\" {status} {bytes} \"-\" \"synthetic-agent\"\n")
}

fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn run(root: &Path, input: &Path, name: &str, format: &str, args: &[&str]) -> (Value, Vec<u8>) {
    let output = root.join(name);
    let stdout = command(root)
        .args(["rare-success", "--input"])
        .arg(input)
        .args(["--format", format, "--output"])
        .arg(&output)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    (read(output.join("rare-success.json")), stdout)
}

fn waf(path: &str, status: Option<u16>, millis: Option<i64>, source: Option<&str>) -> Value {
    let mut value = json!({"httpRequest":{"uri":path,"httpMethod":"GET","headers":[{"name":"Host","value":"example.test"}]}});
    if let Some(status) = status {
        value["responseCodeSent"] = json!(status);
    }
    if let Some(millis) = millis {
        value["timestamp"] = json!(millis);
    }
    if let Some(source) = source {
        value["httpRequest"]["clientIp"] = json!(source);
    }
    value
}

#[test]
fn rare_source_boundaries_count_all_requesters_and_observed_path_metrics() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    let mut log = String::new();
    for (i, status, method, bytes) in [
        (1, 200, "GET", 10),
        (2, 204, "POST", 30),
        (3, 404, "GET", 0),
        (4, 404, "GET", 5),
        (5, 500, "GET", 7),
    ] {
        log += &line(
            &format!("192.0.2.{i}"),
            "/boundary",
            method,
            status,
            i,
            bytes,
        );
    }
    for i in 1..=3 {
        log += &line(
            &format!("198.51.100.{i}"),
            "/too-many-successes",
            "GET",
            200,
            0,
            1,
        );
    }
    for i in 1..=6 {
        log += &line(
            &format!("203.0.113.{i}"),
            "/too-many-requesters",
            "GET",
            if i <= 2 { 200 } else { 404 },
            0,
            1,
        );
    }
    log += &line("192.0.2.1", "/no-success", "GET", 404, 0, 1);
    fs::write(&input, log).unwrap();
    let (report, _) = run(dir.path(), &input, "default", "nginx", &[]);
    let paths = report["paths"].as_array().unwrap();
    assert_eq!(paths.len(), 1);
    let path = &paths[0];
    assert_eq!(path["path"], "/boundary");
    assert_eq!(path["distinct_successful_sources"], 2);
    assert_eq!(path["distinct_requesting_sources"], 5);
    assert_eq!(path["successful_requests"], 2);
    assert_eq!(path["requests"], 5);
    assert_eq!(path["methods"], json!({"GET":4,"POST":1}));
    assert_eq!(path["response_bytes_min"], 0);
    assert_eq!(path["response_bytes_max"], 30);
    assert_eq!(path["first_seen"], "2026-01-01T00:00:01Z");
    assert_eq!(path["last_seen"], "2026-01-01T00:00:05Z");
    assert_eq!(path["examples"].as_array().unwrap().len(), 5);
    assert_eq!(report["summary"]["methods"], json!({"GET":4,"POST":1}));
    let (strict, _) = run(
        dir.path(),
        &input,
        "strict",
        "nginx",
        &["--max-sources", "1"],
    );
    assert_eq!(strict["summary"]["reported_paths"], 0);
    let (requesters, _) = run(
        dir.path(),
        &input,
        "requesters",
        "nginx",
        &["--max-requesting-sources", "4"],
    );
    assert_eq!(requesters["paths"].as_array().unwrap().len(), 0);
    let (method, _) = run(dir.path(), &input, "method", "nginx", &["--method", "POST"]);
    assert_eq!(method["paths"][0]["requests"], 1);
    assert_eq!(method["summary"]["requests_excluded_by_method"], 14);
}

#[test]
fn identifier_access_templates_are_shared_and_can_be_disabled() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    let ids = ["5001", "5002", "5003"];
    let uuids = [
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000003",
    ];
    let mut log = String::new();
    for (i, id) in ids.iter().enumerate() {
        log += &line(
            &format!("192.0.2.{}", i + 1),
            &format!("/items/{id}.json/images?view=one"),
            "GET",
            200,
            0,
            1,
        );
        log += &line(
            &format!("192.0.2.{}", i + 1),
            &format!("/items/{}/images", uuids[i]),
            "GET",
            200,
            0,
            1,
        );
    }
    fs::write(&input, log).unwrap();
    let (collapsed, _) = run(dir.path(), &input, "collapsed", "nginx", &[]);
    assert_eq!(collapsed["summary"]["reported_paths"], 0);
    let (visible, _) = run(
        dir.path(),
        &input,
        "templates",
        "nginx",
        &["--max-sources", "3"],
    );
    assert_eq!(visible["paths"][0]["path"], "/items/{num}.json/images");
    assert_eq!(visible["paths"][1]["path"], "/items/{uuid}/images");
    let (literal, _) = run(
        dir.path(),
        &input,
        "literal",
        "nginx",
        &["--no-collapse-identifiers"],
    );
    assert_eq!(literal["summary"]["reported_paths"], 6);
    for path in literal["paths"].as_array().unwrap() {
        assert!(!path["path"].as_str().unwrap().contains('?'));
    }
}

#[test]
fn static_extension_exclusions_and_status_overrides_are_recorded_and_optional() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    fs::write(
        &input,
        [
            line("192.0.2.1", "/asset.CSS?q=1", "GET", 200, 0, 1),
            line("192.0.2.1", "/app.js", "GET", 200, 0, 1),
            line("192.0.2.1", "/page.cssx", "GET", 200, 0, 1),
            line("192.0.2.1", "/redirect", "GET", 302, 0, 1),
        ]
        .concat(),
    )
    .unwrap();
    let (default, _) = run(dir.path(), &input, "default", "nginx", &[]);
    assert_eq!(default["summary"]["requests_excluded_by_extension"], 2);
    assert_eq!(default["summary"]["reported_paths"], 1);
    let (all, _) = run(
        dir.path(),
        &input,
        "all",
        "nginx",
        &["--exclude-extension", "", "--success-status", "2xx,3xx"],
    );
    assert_eq!(all["summary"]["requests_excluded_by_extension"], 0);
    assert_eq!(all["summary"]["reported_paths"], 4);
    let manifest = read(dir.path().join("all/run-manifest.json"));
    assert_eq!(manifest["excluded_extensions"], json!([]));
    assert_eq!(manifest["options"]["success_status"], json!(["2xx", "3xx"]));
    assert_eq!(manifest["options"]["max_path_source_pairs"], 2_000_000);
    assert_eq!(manifest["options"]["max_paths"], 1_000_000);
    assert_eq!(manifest["options"]["probe"]["min_distinct_paths"], 20);
    assert_eq!(manifest["options"]["probe"]["min_client_error_share"], 80.0);
    assert_eq!(manifest["options"]["probe"]["min_catalog_paths"], 5);
    assert_eq!(
        manifest["options"]["probe"]["min_unserved_path_share"],
        90.0
    );
}

#[test]
fn missing_status_time_and_source_do_not_invent_success_or_temporal_evidence() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let records = [
        waf("/unknown", None, Some(1767225600000), Some("192.0.2.1")),
        waf("/mixed", None, Some(1767225600000), Some("192.0.2.1")),
        waf("/mixed", Some(200), None, Some("192.0.2.1")),
        waf("/source-unknown", Some(200), Some(1767225600000), None),
        waf(
            "/missing/alfa3.php",
            Some(404),
            Some(1767225600000),
            Some("192.0.2.1"),
        ),
    ];
    fs::write(
        &input,
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let args = [
        "--min-distinct-paths",
        "1",
        "--min-catalog-paths",
        "1",
        "--min-client-error-share",
        "0",
    ];
    let (report, _) = run(dir.path(), &input, "report", "aws-waf", &args);
    assert_eq!(report["summary"]["requests_without_status"], 2);
    assert_eq!(report["summary"]["requests_without_timestamp"], 1);
    assert_eq!(report["summary"]["probe_classified_requests"], 4);
    assert_eq!(report["summary"]["paths_with_unavailable_sources"], 1);
    assert_eq!(report["summary"]["probe_shaped_sources"], 1);
    assert_eq!(report["paths"].as_array().unwrap().len(), 1);
    assert_eq!(report["paths"][0]["path"], "/mixed");
    assert_eq!(report["paths"][0]["successful_requests"], 1);
    assert_eq!(report["paths"][0]["response_bytes_min"], Value::Null);
    assert_eq!(report["paths"][0]["response_bytes_unavailable"], 2);
    assert_eq!(report["paths"][0]["preceded_by_probe_shape"], false);
    assert_eq!(
        report["paths"][0]["successful_sources"][0]["first_seen"],
        Value::Null
    );
}

fn temporal_fixture(success_second: u8) -> String {
    // Put the success first physically, to test timestamp order rather than input order.
    let mut log = line(
        "::ffff:192.0.2.7",
        "/private-operation",
        "GET",
        200,
        success_second,
        100,
    );
    for i in 0..20 {
        log += &line(
            "192.0.2.7",
            &format!("/scan-{i}/alfa3.php"),
            "GET",
            404,
            10,
            1,
        );
    }
    log
}

#[test]
fn temporal_join_uses_shared_probe_labels_and_strict_timestamp_order() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    for (name, second, expected) in [
        ("after", 30, true),
        ("before", 0, false),
        ("equal", 10, false),
    ] {
        fs::write(&input, temporal_fixture(second)).unwrap();
        let (report, _) = run(dir.path(), &input, name, "nginx", &[]);
        assert_eq!(report["summary"]["probe_shaped_sources"], 1);
        assert_eq!(
            report["summary"]["preceded_by_probe_shape"],
            usize::from(expected)
        );
        assert_eq!(report["paths"][0]["preceded_by_probe_shape"], expected);
        assert_eq!(
            report["paths"][0]["successful_sources"][0]["preceded_by_probe_shape"],
            expected
        );
        assert_eq!(report["paths"][0]["distinct_successful_sources"], 1);
        assert_eq!(
            report["paths"][0]["successful_sources"][0]["source"],
            "::ffff:192.0.2.7"
        );
    }
    fs::write(&input, temporal_fixture(30)).unwrap();
    let probe_output = dir.path().join("probe");
    command(dir.path())
        .args(["probe-sources", "--input"])
        .arg(&input)
        .args(["--format", "nginx", "--output"])
        .arg(&probe_output)
        .assert()
        .success();
    let probe = read(probe_output.join("probe-sources.json"));
    assert_eq!(probe["sources"][0]["label"], "probe-shaped");
    assert_eq!(probe["sources"][0]["source"], "192.0.2.7");
    let (raised, _) = run(
        dir.path(),
        &input,
        "raised",
        "nginx",
        &["--min-distinct-paths", "22"],
    );
    assert_eq!(raised["summary"]["probe_shaped_sources"], 0);
    assert_eq!(raised["paths"][0]["preceded_by_probe_shape"], false);
    assert_eq!(
        read(dir.path().join("raised/run-manifest.json"))["options"]["probe"]["min_distinct_paths"],
        22
    );
}

#[test]
fn path_and_pair_caps_disclose_rejections_without_claiming_incomplete_paths_are_rare() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    let rows = [
        line("192.0.2.1", "/complete", "GET", 200, 0, 1),
        line("192.0.2.1", "/complete", "GET", 200, 0, 2),
        line("192.0.2.2", "/incomplete", "GET", 200, 0, 3),
        line("192.0.2.3", "/incomplete", "GET", 200, 0, 4),
        line("192.0.2.3", "/incomplete", "GET", 200, 0, 5),
        line("192.0.2.1", "/complete", "POST", 201, 0, 6),
        line("192.0.2.1", "/later", "GET", 200, 0, 7),
    ];
    fs::write(&input, rows.concat()).unwrap();
    let (pairs, _) = run(
        dir.path(),
        &input,
        "pairs",
        "nginx",
        &[
            "--max-path-source-pairs",
            "2",
            "--max-examples",
            "1",
            "--max-auxiliary-values",
            "1",
        ],
    );
    assert_eq!(pairs["summary"]["retained_path_source_pairs"], 2);
    assert_eq!(pairs["summary"]["requests_beyond_path_source_pair_cap"], 3);
    assert_eq!(pairs["summary"]["paths_with_incomplete_source_tracking"], 2);
    assert_eq!(pairs["summary"]["reported_paths"], 1);
    assert_eq!(pairs["paths"][0]["path"], "/complete");
    assert_eq!(pairs["paths"][0]["requests"], 3);
    assert_eq!(pairs["paths"][0]["successful_requests"], 3);
    assert_eq!(pairs["paths"][0]["successful_sources"][0]["requests"], 3);
    assert_eq!(pairs["paths"][0]["examples_omitted"], 2);
    assert_eq!(pairs["paths"][0]["method_observations_beyond_cap"], 1);
    let (paths, _) = run(dir.path(), &input, "paths", "nginx", &["--max-paths", "1"]);
    assert_eq!(paths["summary"]["retained_paths"], 1);
    assert_eq!(paths["summary"]["requests_beyond_path_cap"], 4);
    assert_eq!(paths["paths"][0]["requests"], 3);
}

#[test]
fn private_display_flags_are_independent_and_sanitized_artifacts_are_byte_reproducible() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("private-input.txt");
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(line("192.0.2.19", "/private-operation", "POST", 200, 0, 100).as_bytes())
        .unwrap();
    let bytes = gzip.finish().unwrap();
    fs::write(&input, &bytes).unwrap();
    let (report, stdout) = run(dir.path(), &input, "first", "nginx", &[]);
    let (_, repeat) = run(dir.path(), &input, "repeat", "nginx", &[]);
    assert_eq!(stdout, repeat);
    for artifact in [
        "rare-success.json",
        "sanitized-rare-success.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(dir.path().join("first").join(artifact)).unwrap(),
            fs::read(dir.path().join("repeat").join(artifact)).unwrap()
        );
    }
    let manifest = read(dir.path().join("first/run-manifest.json"));
    assert_eq!(
        manifest["corpus"][0]["sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    assert_eq!(report["paths"][0]["examples"][0]["line_number"], 1);
    let sanitized =
        fs::read_to_string(dir.path().join("first/sanitized-rare-success.json")).unwrap();
    for private in [
        "192.0.2.19",
        "/private-operation",
        "private-input.txt",
        input.to_str().unwrap(),
    ] {
        assert!(!sanitized.contains(private));
        assert!(!String::from_utf8_lossy(&stdout).contains(private));
    }
    for (show, path_visible, source_visible) in [
        (vec![], false, false),
        (vec!["--show-paths"], true, false),
        (vec!["--show-source-ips"], false, true),
        (vec!["--show-paths", "--show-source-ips"], true, true),
    ] {
        for format in ["text", "json"] {
            let output = command(dir.path())
                .args(["rare-success", "--input"])
                .arg(&input)
                .args(["--format", "nginx", "--output-format", format])
                .args(&show)
                .assert()
                .success()
                .get_output()
                .stdout
                .clone();
            let text = String::from_utf8(output).unwrap();
            assert_eq!(text.contains("/private-operation"), path_visible);
            assert_eq!(text.contains("private-input.txt"), path_visible);
            assert_eq!(text.contains("192.0.2.19"), source_visible);
        }
    }
}

#[test]
fn time_filters_discovery_and_read_errors_use_shared_input_machinery() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("logs");
    fs::create_dir(&input).unwrap();
    fs::write(
        input.join("b.log.1"),
        line("192.0.2.1", "/b", "GET", 200, 20, 1),
    )
    .unwrap();
    fs::write(
        input.join("access_log"),
        line("192.0.2.1", "/a", "GET", 200, 10, 1),
    )
    .unwrap();
    fs::write(input.join("notes.md"), "not a log").unwrap();
    let (report, stdout) = run(
        dir.path(),
        &input,
        "filtered",
        "nginx",
        &[
            "--from",
            "2026-01-01T00:00:20Z",
            "--to",
            "2026-01-01T00:00:20Z",
        ],
    );
    assert_eq!(report["summary"]["files_analyzed"], 2);
    assert_eq!(report["summary"]["files_skipped"], 1);
    assert_eq!(report["summary"]["records_outside_time_range"], 1);
    assert_eq!(report["paths"][0]["path"], "/b");
    assert!(String::from_utf8(stdout)
        .unwrap()
        .contains("unsupported-extension"));
    let manifest = read(dir.path().join("filtered/run-manifest.json"));
    assert!(manifest["corpus"][0]["path"]
        .as_str()
        .unwrap()
        .ends_with("access_log"));
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(line("192.0.2.1", "/a", "GET", 200, 0, 1).as_bytes())
        .unwrap();
    let mut bytes = gzip.finish().unwrap();
    bytes.truncate(bytes.len() - 7);
    let broken = dir.path().join("broken.gz");
    fs::write(&broken, bytes).unwrap();
    let output = dir.path().join("broken-output");
    command(dir.path())
        .args(["rare-success", "--input"])
        .arg(&broken)
        .args(["--format", "nginx", "--output"])
        .arg(&output)
        .assert()
        .failure();
    assert!(!output.join("rare-success.json").exists());
}

#[test]
fn validated_clients_and_observed_peers_remain_distinct_with_raw_display_values() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let mut proxied = waf("/shared", Some(200), Some(1767225600000), Some("192.0.2.1"));
    proxied["httpRequest"]["headers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"X-Forwarded-For","value":"203.0.113.7"}));
    let direct = waf(
        "/shared",
        Some(200),
        Some(1767225600000),
        Some("::ffff:203.0.113.7"),
    );
    fs::write(&input, format!("{}\n{}\n", proxied, direct)).unwrap();
    let (report, _) = run(
        dir.path(),
        &input,
        "identities",
        "aws-waf",
        &["--trusted-proxy", "192.0.2.0/24"],
    );
    let path = &report["paths"][0];
    assert_eq!(path["distinct_successful_sources"], 2);
    let sources = path["successful_sources"].as_array().unwrap();
    assert!(sources
        .iter()
        .any(|s| s["identity"] == "validated-client" && s["source"] == "203.0.113.7"));
    assert!(sources
        .iter()
        .any(|s| s["identity"] == "observed-peer" && s["source"] == "::ffff:203.0.113.7"));
    let (strict, _) = run(
        dir.path(),
        &input,
        "strict",
        "aws-waf",
        &["--trusted-proxy", "192.0.2.0/24", "--max-sources", "1"],
    );
    assert_eq!(strict["summary"]["reported_paths"], 0);
}

#[test]
fn invalid_thresholds_and_limits_fail_without_creating_artifacts() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    fs::write(&input, line("192.0.2.1", "/a", "GET", 200, 0, 1)).unwrap();
    for args in [
        vec!["--max-paths", "0"],
        vec!["--max-path-source-pairs", "0"],
        vec!["--max-sources", "0"],
        vec!["--max-requesting-sources", "0"],
        vec!["--success-status", "200"],
        vec!["--min-client-error-share", "101"],
    ] {
        let output = dir.path().join("never-created");
        command(dir.path())
            .args(["rare-success", "--input"])
            .arg(&input)
            .args(["--format", "nginx", "--output"])
            .arg(&output)
            .args(&args)
            .assert()
            .failure();
        assert!(!output.exists());
    }
}

#[test]
fn method_filter_keeps_all_dated_methods_for_probe_classification_and_first_failure() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    let path = "/uploads/synthetic.php";
    let mut log = String::new();
    for i in 0..30 {
        let target = if i == 0 {
            path.to_owned()
        } else {
            format!("/scan-{i}/alfa3.php")
        };
        log += &line("192.0.2.7", &target, "GET", 404, 10, 1);
    }
    log += &line("192.0.2.7", path, "POST", 200, 30, 10);
    fs::write(&input, log).unwrap();
    for (name, args, selected, excluded, reported) in [
        ("all", vec![], 31, 0, 1),
        ("post", vec!["--method", "POST"], 1, 30, 1),
        ("get", vec!["--method", "GET"], 30, 1, 0),
    ] {
        let (report, stdout) = run(dir.path(), &input, name, "nginx", &args);
        assert_eq!(report["summary"]["probe_classified_requests"], 31);
        assert_eq!(report["summary"]["probe_shaped_sources"], 1);
        assert_eq!(report["summary"]["selected_requests"], selected);
        assert_eq!(report["summary"]["requests_excluded_by_method"], excluded);
        assert_eq!(report["summary"]["reported_paths"], reported);
        assert!(String::from_utf8(stdout)
            .unwrap()
            .contains("Probe-classified requests: 31"));
        if reported == 1 {
            assert_eq!(report["paths"][0]["path"], path);
            assert_eq!(report["paths"][0]["preceded_by_probe_shape"], true);
            assert_eq!(
                report["paths"][0]["successful_sources"][0]["preceded_by_probe_shape"],
                true
            );
        }
        if name == "post" {
            assert_eq!(report["paths"][0]["requests"], 1);
            assert_eq!(report["paths"][0]["methods"], json!({"POST":1}));
        }
        let sanitized = read(dir.path().join(name).join("sanitized-rare-success.json"));
        assert_eq!(sanitized["probe_classified_requests"], 31);
    }
    let (bounded, _) = run(
        dir.path(),
        &input,
        "bounded",
        "nginx",
        &["--method", "POST", "--from", "2026-01-01T00:00:20Z"],
    );
    assert_eq!(bounded["summary"]["probe_classified_requests"], 1);
    assert_eq!(bounded["summary"]["records_outside_time_range"], 30);
    assert_eq!(bounded["summary"]["probe_shaped_sources"], 0);
    assert_eq!(bounded["paths"][0]["preceded_by_probe_shape"], false);
}

#[test]
fn sanitized_methods_use_only_fixed_keys_while_private_paths_preserve_raw_tokens() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    let allowed = [
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "OPTIONS",
        "TRACE",
        "CONNECT",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
    ];
    let log = allowed
        .iter()
        .copied()
        .chain(["<SCRIPT>"])
        .map(|method| line("192.0.2.1", "/private-operation", method, 200, 0, 1))
        .collect::<String>();
    fs::write(&input, log).unwrap();
    let (private, stdout) = run(dir.path(), &input, "report", "nginx", &[]);
    assert_eq!(private["paths"][0]["methods"]["<SCRIPT>"], 1);
    let sanitized_text =
        fs::read_to_string(dir.path().join("report/sanitized-rare-success.json")).unwrap();
    assert!(!sanitized_text.contains("<SCRIPT>"));
    let sanitized: Value = serde_json::from_str(&sanitized_text).unwrap();
    let methods = sanitized["methods"].as_object().unwrap();
    assert_eq!(methods.len(), allowed.len() + 1);
    assert_eq!(methods["(other)"], 1);
    for method in allowed {
        assert_eq!(methods[method], 1);
    }
    let text = String::from_utf8(stdout).unwrap();
    assert!(!text.contains("<SCRIPT>"));
    assert!(text.contains("Method (other): 1"));
    let json_stdout = command(dir.path())
        .args(["rare-success", "--input"])
        .arg(&input)
        .args(["--format", "nginx", "--output-format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(!String::from_utf8_lossy(&json_stdout).contains("<SCRIPT>"));
    let json_stdout: Value = serde_json::from_slice(&json_stdout).unwrap();
    assert_eq!(json_stdout["summary"]["methods"], sanitized["methods"]);
}

#[test]
fn review_order_prioritizes_temporal_flags_source_counts_recency_and_path_ties() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let base = 1767225600000_i64;
    let mut records = Vec::new();
    for (path, source, status, seconds) in [
        ("/a-two-successes", "192.0.2.20", 200, Some(50)),
        ("/a-two-successes", "192.0.2.21", 200, Some(50)),
        ("/d-requesters", "192.0.2.22", 200, Some(50)),
        ("/d-requesters", "192.0.2.23", 404, Some(50)),
        ("/f-undated", "192.0.2.24", 200, None),
        ("/b-tie", "192.0.2.25", 200, Some(40)),
        ("/a-tie", "192.0.2.26", 200, Some(40)),
        ("/old", "192.0.2.27", 200, Some(30)),
        ("/z-probe", "192.0.2.7", 200, Some(30)),
        ("/z-probe", "192.0.2.28", 200, Some(30)),
    ] {
        records.push(waf(
            path,
            Some(status),
            seconds.map(|s| base + s * 1000),
            Some(source),
        ));
    }
    for i in 0..30 {
        records.push(waf(
            &format!("/scan-{i}/alfa3.php"),
            Some(404),
            Some(base + 10000),
            Some("192.0.2.7"),
        ));
    }
    fs::write(
        &input,
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let (private, _) = run(dir.path(), &input, "first", "aws-waf", &[]);
    let (repeat, _) = run(dir.path(), &input, "repeat", "aws-waf", &[]);
    assert_eq!(private, repeat);
    assert_eq!(
        fs::read(dir.path().join("first/rare-success.json")).unwrap(),
        fs::read(dir.path().join("repeat/rare-success.json")).unwrap()
    );
    let expected = [
        "/z-probe",
        "/a-tie",
        "/b-tie",
        "/old",
        "/f-undated",
        "/d-requesters",
        "/a-two-successes",
    ];
    assert_eq!(
        private["paths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        expected
    );
    let stdout = command(dir.path())
        .args(["rare-success", "--input"])
        .arg(&input)
        .args([
            "--format",
            "aws-waf",
            "--output-format",
            "json",
            "--show-paths",
            "--limit",
            "2",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let view: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(view["paths"][0]["path"], expected[0]);
    assert_eq!(view["paths"][1]["path"], expected[1]);
    assert_eq!(view["paths_not_displayed"], 5);
    let text = command(dir.path())
        .args(["rare-success", "--input"])
        .arg(&input)
        .args(["--format", "aws-waf", "--show-paths", "--limit", "2"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(text).unwrap();
    assert!(text.find("Path: /z-probe").unwrap() < text.find("Path: /a-tie").unwrap());
    assert!(!text.contains("Path: /b-tie"));
}
