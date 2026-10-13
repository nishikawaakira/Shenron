use assert_cmd::Command;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn command(root: &Path) -> Command {
    let mut command = Command::cargo_bin("shenron").unwrap();
    command
        .env("SHENRON_DATA_DIR", root.join("empty-data"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("SHENRON_SLACK_WEBHOOK");
    command
}
fn line(ip: &str, path: &str, status: u16, agent: &str) -> String {
    format!("{ip} - - [01/Jan/2026:00:00:00 +0000] \"GET {path} HTTP/1.1\" {status} 10 \"-\" \"{agent}\"\n")
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn run(root: &Path, input: &Path, name: &str, args: &[&str]) -> (Value, Vec<u8>) {
    let output = root.join(name);
    let result = command(root)
        .args(["probe-sources", "--format", "nginx", "--input"])
        .arg(input)
        .arg("--output")
        .arg(&output)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    (read(output.join("probe-sources.json")), result)
}
fn fixture() -> String {
    let mut log = String::new();
    for index in 0..24 {
        let ip = if index % 2 == 0 {
            "192.0.2.1"
        } else {
            "::ffff:192.0.2.1"
        };
        log += &line(
            ip,
            &format!("/synthetic-{index}/alfa3.php"),
            404,
            "synthetic-review-agent",
        );
        log += &line(
            "198.51.100.1",
            &format!("/article/{index}"),
            if index % 2 == 0 { 200 } else { 301 },
            "Googlebot",
        );
    }
    log += &line("192.0.2.1", "/", 200, "synthetic-review-agent");
    for status in [200, 200, 404] {
        log += &line("203.0.113.1", "/home", status, "synthetic-browser");
    }
    for index in 0..3 {
        log += &line(
            "203.0.113.2",
            &format!("/missing/{index}"),
            404,
            "synthetic-browser",
        );
    }
    log
}

#[test]
fn probe_shapes_are_auditable_private_canonical_and_byte_reproducible() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let log = fixture();
    fs::write(&input, &log).unwrap();
    let (report, stdout) = run(root.path(), &input, "first", &[]);
    let (repeat, stdout_again) = run(root.path(), &input, "repeat", &[]);
    assert_eq!(report, repeat);
    assert_eq!(stdout, stdout_again);
    for name in [
        "probe-sources.json",
        "probe-source-ips.txt",
        "run-manifest.json",
        "sanitized-research.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("first").join(name)).unwrap(),
            fs::read(root.path().join("repeat").join(name)).unwrap()
        );
    }
    assert_eq!(report["summary"]["evaluated_sources"], 4);
    assert_eq!(report["summary"]["probe_shaped_sources"], 1);
    let source = &report["sources"][0];
    assert_eq!(source["source"], "192.0.2.1");
    assert_eq!(source["requests"], 25);
    assert_eq!(source["distinct_paths"], 25);
    assert_eq!(source["catalog_distinct_paths"], 24);
    assert_eq!(source["client_error_share"], 96.0);
    assert_eq!(source["unserved_path_share"], 96.0);
    assert_eq!(source["peak_requests_per_minute"], 25);
    assert_eq!(source["active_days"], 1);
    assert_eq!(source["example_paths_omitted"], 5);
    assert!(report["sources"].as_array().unwrap()[1..]
        .iter()
        .all(|s| s["label"].is_null()));
    let sanitized = fs::read_to_string(root.path().join("first/sanitized-research.json")).unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    for raw in [
        "192.0.2.1",
        "::ffff:",
        "198.51.100.1",
        "/synthetic-",
        "Googlebot",
        "synthetic-review-agent",
    ] {
        assert!(!sanitized.contains(raw));
        assert!(!stdout.contains(raw));
    }
    let manifest = read(root.path().join("first/run-manifest.json"));
    assert_eq!(
        manifest["corpus"][0]["sha256"],
        format!("{:x}", Sha256::digest(log.as_bytes()))
    );
    assert_eq!(manifest["catalog_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(manifest["catalog_version"], 2);
    assert_eq!(
        manifest["catalog_sha256"],
        format!(
            "{:x}",
            Sha256::digest(include_bytes!("../probe-paths/probe-paths.yaml"))
        )
    );
    let (_, shown) = run(
        root.path(),
        &input,
        "shown",
        &[
            "--show-source-ips",
            "--show-paths",
            "--limit",
            "1",
            "--output-format",
            "json",
        ],
    );
    let view: Value = serde_json::from_slice(&shown).unwrap();
    assert_eq!(view["sources_not_displayed"], 3);
    assert_eq!(view["sources"][0]["paths_not_displayed"], 5);
    assert!(!String::from_utf8(shown)
        .unwrap()
        .contains("synthetic-review-agent"));
}

#[test]
fn probe_thresholds_are_validated_recorded_and_change_only_new_command_labels() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("log");
    fs::write(&input, fixture()).unwrap();
    let (report, _) = run(
        root.path(),
        &input,
        "higher",
        &[
            "--min-distinct-paths",
            "26",
            "--min-client-error-share",
            "97",
            "--min-catalog-paths",
            "30",
            "--min-unserved-path-share",
            "99",
        ],
    );
    assert_eq!(report["summary"]["probe_shaped_sources"], 0);
    let options = &read(root.path().join("higher/run-manifest.json"))["thresholds_and_limits"];
    assert_eq!(options["min_distinct_paths"], 26);
    assert_eq!(options["min_client_error_share"], 97.0);
    assert_eq!(options["min_catalog_paths"], 30);
    assert_eq!(options["min_unserved_path_share"], 99.0);
    for args in [
        ["--max-source-ips", "0"],
        ["--min-client-error-share", "101"],
        ["--min-unserved-path-share", "NaN"],
    ] {
        command(root.path())
            .args(["probe-sources", "--format", "nginx", "--input"])
            .arg(&input)
            .args(args)
            .assert()
            .failure();
    }
}

#[test]
fn probe_caps_disclose_omissions_and_do_not_infer_missing_measurements() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("log");
    fs::write(&input, fixture()).unwrap();
    let (report, _) = run(
        root.path(),
        &input,
        "capped",
        &[
            "--max-source-ips",
            "2",
            "--max-paths-per-source",
            "2",
            "--max-source-path-pairs",
            "3",
            "--max-success-paths",
            "1",
        ],
    );
    let omitted = &report["summary"]["omissions"];
    for field in [
        "requests_beyond_source_cap",
        "requests_beyond_source_path_cap",
        "requests_beyond_global_path_pair_cap",
        "successful_path_observations_beyond_cap",
    ] {
        assert!(omitted[field].as_u64().unwrap() > 0, "{field}");
    }
    for source in report["sources"].as_array().unwrap() {
        assert!(source["unserved_path_share"].is_null());
        assert!(source["criteria"]["distinct_paths"]["met"].is_null());
        assert!(source["label"].is_null());
    }
}

fn waf(ip: &str, path: &str, forwarded: Option<&str>) -> String {
    let mut headers = vec![json!({"name":"User-Agent", "value":"synthetic-private-agent"})];
    if let Some(client) = forwarded {
        headers.push(json!({"name":"X-Forwarded-For", "value":client}));
    }
    format!(
        "{}\n",
        json!({"timestamp":1767225600000_i64,"action":"ALLOW","httpRequest":{"clientIp":ip,"httpMethod":"GET","uri":path,"args":"","headers":headers}})
    )
}
#[test]
fn probe_waf_missing_status_skips_status_gate_and_separates_trusted_clients() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs.json");
    let mut log = String::new();
    for index in 0..20 {
        let path = format!("/synthetic-{index}/alfa3.php");
        log += &waf("192.0.2.10", &path, Some("203.0.113.7"));
        log += &waf("203.0.113.7", &path, None);
    }
    fs::write(&input, log).unwrap();
    let output = root.path().join("result");
    let bytes = command(root.path())
        .args(["probe-sources", "--format", "aws-waf", "--input"])
        .arg(&input)
        .args([
            "--trusted-proxy",
            "192.0.2.10",
            "--output-format",
            "json",
            "--output",
        ])
        .arg(&output)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report = read(output.join("probe-sources.json"));
    assert_eq!(report["summary"]["evaluated_sources"], 2);
    assert_eq!(report["summary"]["probe_shaped_sources"], 2);
    let rows = report["sources"].as_array().unwrap();
    assert_ne!(rows[0]["identity"], rows[1]["identity"]);
    for source in rows {
        assert_eq!(source["source"], "203.0.113.7");
        assert!(source["client_error_share"].is_null());
        assert!(source["unserved_path_share"].is_null());
        assert!(source["criteria"]["client_error_share"]["met"].is_null());
        assert_eq!(source["status_unavailable"], 20);
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("203.0.113.7"));
    assert!(!text.contains("synthetic-private-agent"));
}

#[test]
fn probe_discovery_gzip_time_filters_and_skips_are_disclosed_without_raw_stdout() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("logs");
    fs::create_dir(&logs).unwrap();
    let data = line("192.0.2.1", "/home", 200, "fixture-agent");
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(data.as_bytes()).unwrap();
    let compressed = gzip.finish().unwrap();
    fs::write(logs.join("access_log"), &compressed).unwrap();
    fs::write(
        logs.join("access.log.1"),
        format!("{data}invalid synthetic record\n"),
    )
    .unwrap();
    fs::write(logs.join("notes.md"), "not a log").unwrap();
    let (report, stdout) = run(
        root.path(),
        &logs,
        "filtered",
        &["--from", "2026-01-02T00:00:00Z"],
    );
    assert_eq!(report["summary"]["files_analyzed"], 2);
    assert_eq!(report["summary"]["files_skipped"], 1);
    assert_eq!(report["summary"]["parse_errors"], 1);
    assert_eq!(report["summary"]["records_outside_time_range"], 2);
    let stdout = String::from_utf8(stdout).unwrap();
    assert!(stdout.contains("Files skipped: 1 (unsupported-extension: 1)"));
    assert!(!stdout.contains("notes.md"));
    let manifest = read(root.path().join("filtered/run-manifest.json"));
    assert_eq!(
        manifest["corpus"][1]["sha256"],
        format!("{:x}", Sha256::digest(&compressed))
    );
    assert_eq!(
        manifest["skipped_inputs"][0]["reason"],
        "unsupported-extension"
    );
}

#[test]
fn probe_queries_do_not_add_paths_and_source_only_display_does_not_reveal_paths() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("log");
    fs::write(
        &input,
        format!(
            "{}{}",
            line(
                "192.0.2.1",
                "/alfa3.php?token=private-one",
                404,
                "private-agent"
            ),
            line(
                "192.0.2.1",
                "/alfa3.php?token=private-two",
                404,
                "private-agent"
            )
        ),
    )
    .unwrap();
    let (report, stdout) = run(
        root.path(),
        &input,
        "query",
        &["--show-source-ips", "--output-format", "json"],
    );
    let source = &report["sources"][0];
    assert_eq!(source["distinct_paths"], 1);
    assert_eq!(source["catalog_distinct_paths"], 1);
    assert_eq!(source["catalog_requests"], 2);
    assert_eq!(source["query_share"], 100.0);
    let text = String::from_utf8(stdout).unwrap();
    assert!(text.contains("192.0.2.1"));
    for value in ["/alfa3.php", "private-one", "private-two", "private-agent"] {
        assert!(!text.contains(value));
    }
    assert!(!report.to_string().contains("private-one"));
    assert!(!report.to_string().contains("private-two"));
    let bytes = command(root.path())
        .args(["probe-sources", "--input"])
        .arg(&input)
        .args(["--format", "nginx", "--output-format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(!String::from_utf8(bytes).unwrap().contains("192.0.2.1"));
}

#[test]
fn probe_text_is_multiline_value_safe_and_reports_met_failed_unavailable_and_caps() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("log");
    fs::write(&input, fixture()).unwrap();
    let (_, stdout) = run(
        root.path(),
        &input,
        "text",
        &["--show-source-ips", "--show-paths", "--limit", "1"],
    );
    let text = String::from_utf8(stdout).unwrap();
    assert!(!text.contains('�'));
    assert!(!text.contains('{'));
    assert!(text.contains("  Parseable records: 55\n  Parse errors: 0\n"));
    assert!(text.contains("  192.0.2.1 (observed-peer): probe-shaped / requests 25 / distinct paths 25 / 4xx 96.0% / catalog paths 24 / unserved 96.0% / 2026-01-01T00:00:00Z..2026-01-01T00:00:00Z\n    Conditions:"));
    assert!(text.contains("\n      /\n"));
    assert!(text.contains("retained paths not displayed: 5"));
    assert!(text.ends_with("Sources not displayed: 3\n"));
    assert!(text.contains("Condition distinct_paths: 2 met / 2 not met / 0 unavailable"));
    let (_, capped) = run(
        root.path(),
        &input,
        "cap-text",
        &[
            "--max-source-ips",
            "1",
            "--max-paths-per-source",
            "1",
            "--show-source-ips",
        ],
    );
    let capped = String::from_utf8(capped).unwrap();
    assert!(capped.contains("Tracking-cap omissions (source cap):"));
    assert!(capped.contains("Tracking-cap omissions (source path cap):"));
    assert!(capped.contains("unavailable: path_tracking_incomplete"));

    let mut event: Value = serde_json::from_str(&waf("192.0.2.1", "/path", None)).unwrap();
    event["httpRequest"]["uri"] = json!("/safe\u{1b}[31m\npath");
    event["httpRequest"]["headers"][0]["value"] = json!("private-agent\u{1b}[2J\n");
    let waf_input = root.path().join("control.json");
    fs::write(&waf_input, format!("{event}\n")).unwrap();
    let stdout = command(root.path())
        .args(["probe-sources", "--input"])
        .arg(&waf_input)
        .args(["--format", "aws-waf", "--show-source-ips", "--show-paths"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(stdout).unwrap();
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("private-agent")); // UAs remain private-artifact-only.
    assert!(text.contains("\n      /safe�[31m�path\n"));
    assert!(text.contains("unavailable: no_recorded_status"));
    assert!(text.contains("4xx gate not applied"));
}

#[test]
fn probe_hostname_peers_are_canonical_private_separate_and_never_trusted_clients() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("apache.log");
    let mut log = String::new();
    for index in 0..20 {
        let hostname = if index % 2 == 0 {
            "Crawl-203-0-113-7.Example.NET."
        } else {
            "crawl-203-0-113-7.example.net"
        };
        log += &line(
            hostname,
            &format!("/synthetic-{index}/r57shell.php"),
            404,
            "fixture-agent",
        );
        log += &line(
            "203.0.113.7",
            &format!("/synthetic-{index}/r57shell.php"),
            404,
            "fixture-agent",
        );
    }
    fs::write(&input, log).unwrap();
    let output = root.path().join("hostnames");
    let stdout = command(root.path())
        .args(["probe-sources", "--input"])
        .arg(&input)
        .args([
            "--format",
            "apache",
            "--trusted-proxy",
            "203.0.113.0/24",
            "--output",
        ])
        .arg(&output)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report = read(output.join("probe-sources.json"));
    assert_eq!(report["summary"]["evaluated_sources"], 2);
    assert_eq!(report["summary"]["probe_shaped_sources"], 2);
    assert_eq!(report["summary"]["requests_with_invalid_source_ip"], 0);
    assert_eq!(
        report["summary"]["evaluated_sources_by_identity"],
        json!({"hostname-peer":1,"observed-peer":1})
    );
    assert_eq!(
        report["summary"]["probe_shaped_sources_by_identity"],
        json!({"hostname-peer":1,"observed-peer":1})
    );
    let hostname = report["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["identity"] == "hostname-peer")
        .unwrap();
    assert_eq!(hostname["source"], "Crawl-203-0-113-7.Example.NET.");
    assert_eq!(hostname["requests"], 20);
    assert_eq!(hostname["label"], "probe-shaped");
    assert_eq!(
        fs::read_to_string(output.join("probe-source-ips.txt")).unwrap(),
        "203.0.113.7\n"
    );
    assert!(
        fs::read(output.join("probe-source-validated-client-ips.txt"))
            .unwrap()
            .is_empty()
    );
    for data in [
        stdout,
        fs::read(output.join("sanitized-research.json")).unwrap(),
    ] {
        let text = String::from_utf8(data).unwrap();
        for private in [
            "Example.NET",
            "example.net",
            "203.0.113.7",
            "r57shell.php",
            "fixture-agent",
        ] {
            assert!(!text.contains(private));
        }
    }
    let waf_input = root.path().join("hostname.json");
    fs::write(
        &waf_input,
        waf("peer.example", "/r57shell.php", Some("192.0.2.1")),
    )
    .unwrap();
    let bytes = command(root.path())
        .args(["probe-sources", "--input"])
        .arg(&waf_input)
        .args([
            "--format",
            "aws-waf",
            "--trusted-proxy",
            "192.0.2.0/24",
            "--show-source-ips",
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let view: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(view["sources"][0]["identity"], "hostname-peer");
    assert_eq!(view["sources"][0]["source"], "peer.example");
}

#[test]
fn probe_source_json_schema_distinguishes_ips_and_hostnames_and_is_reproducible() {
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.json");
    let log = waf("::ffff:192.0.2.1", "/r57shell.php", None)
        + &waf("2001:DB8::1", "/r57shell.php", None)
        + &waf("Peer.Example.NET.", "/r57shell.php", None)
        + &waf("198.51.100.1", "/r57shell.php", Some("203.0.113.7"));
    fs::write(&input, log).unwrap();
    let mut previous_stdout = None;
    for name in ["first", "repeat"] {
        let output = root.path().join(name);
        let stdout = command(root.path())
            .args(["probe-sources", "--format", "aws-waf", "--input"])
            .arg(&input)
            .args([
                "--trusted-proxy",
                "198.51.100.1",
                "--output-format",
                "json",
                "--show-source-ips",
                "--output",
            ])
            .arg(&output)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let view: Value = serde_json::from_slice(&stdout).unwrap();
        let private = read(output.join("probe-sources.json"));
        for report in [&private, &view] {
            let sources = report["sources"].as_array().unwrap();
            assert_eq!(sources.len(), 4);
            let mut identities = BTreeSet::new();
            let mut values = BTreeSet::new();
            for source in sources {
                assert!(source.get("source_ip").is_none());
                let value = source["source"].as_str().unwrap();
                let identity = source["identity"].as_str().unwrap();
                let is_hostname = identity == "hostname-peer";
                assert_eq!(
                    source["source_kind"],
                    if is_hostname { "hostname" } else { "ip" }
                );
                assert_eq!(value.parse::<IpAddr>().is_ok(), !is_hostname);
                identities.insert(identity);
                values.insert(value);
            }
            assert_eq!(
                identities,
                BTreeSet::from(["observed-peer", "validated-client", "hostname-peer"])
            );
            assert_eq!(
                values,
                BTreeSet::from([
                    "::ffff:192.0.2.1",
                    "2001:DB8::1",
                    "Peer.Example.NET.",
                    "203.0.113.7"
                ])
            );
        }
        if let Some(previous) = previous_stdout.replace(stdout.clone()) {
            assert_eq!(previous, stdout);
        }
    }
    for file in [
        "probe-sources.json",
        "sanitized-research.json",
        "run-manifest.json",
        "probe-source-ips.txt",
        "probe-source-validated-client-ips.txt",
    ] {
        assert_eq!(
            fs::read(root.path().join("first").join(file)).unwrap(),
            fs::read(root.path().join("repeat").join(file)).unwrap()
        );
    }
}

#[test]
fn probe_ip_lists_are_plain_canonical_sorted_identity_separated_and_empty_when_unmatched() {
    use std::net::IpAddr;
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.json");
    let mut log = String::new();
    for ip in [
        "192.0.2.10",
        "::ffff:192.0.2.1",
        "192.0.2.2",
        "192.0.2.1",
        "2001:DB8::1",
        "peer.example",
    ] {
        log += &waf(ip, "/r57shell.php", None);
    }
    log += &waf("198.51.100.1", "/r57shell.php", Some("::ffff:203.0.113.7"));
    fs::write(&input, log).unwrap();
    for name in ["first", "repeat", "empty"] {
        let output = root.path().join(name);
        command(root.path())
            .args(["probe-sources", "--format", "aws-waf", "--input"])
            .arg(&input)
            .args([
                "--trusted-proxy",
                "198.51.100.1",
                "--min-distinct-paths",
                if name == "empty" { "20" } else { "1" },
                "--min-catalog-paths",
                "1",
                "--output",
            ])
            .arg(&output)
            .assert()
            .success();
        for file in [
            "probe-source-ips.txt",
            "probe-source-validated-client-ips.txt",
        ] {
            let content = fs::read_to_string(output.join(file)).unwrap();
            assert!(!content.contains('#'));
            assert!(!content.contains("example"));
            let addresses = content
                .lines()
                .map(|line| line.parse::<IpAddr>().unwrap())
                .collect::<Vec<_>>();
            assert!(addresses.windows(2).all(|pair| pair[0] < pair[1]));
            if name == "empty" {
                assert!(content.is_empty());
            } else if file == "probe-source-ips.txt" {
                assert_eq!(content, "192.0.2.1\n192.0.2.2\n192.0.2.10\n2001:db8::1\n");
            } else {
                assert_eq!(content, "203.0.113.7\n");
            }
        }
        let report = read(output.join("probe-sources.json"));
        let manifest = read(output.join("run-manifest.json"));
        assert_eq!(report["safety_note"], manifest["request_shape_safety_note"]);
        assert_eq!(
            report["thresholds_and_limits"],
            manifest["thresholds_and_limits"]
        );
    }
    for file in [
        "probe-source-ips.txt",
        "probe-source-validated-client-ips.txt",
    ] {
        assert_eq!(
            fs::read(root.path().join("first").join(file)).unwrap(),
            fs::read(root.path().join("repeat").join(file)).unwrap()
        );
    }
    let plain = root.path().join("plain.log");
    fs::write(&plain, line("192.0.2.1", "/home", 200, "fixture-agent")).unwrap();
    run(root.path(), &plain, "without-proxy", &[]);
    assert!(
        fs::read(root.path().join("without-proxy/probe-source-ips.txt"))
            .unwrap()
            .is_empty()
    );
    assert!(!root
        .path()
        .join("without-proxy/probe-source-validated-client-ips.txt")
        .exists());
}
