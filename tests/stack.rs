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
fn line(ip: &str, path: &str, agent: &str) -> String {
    format!(
        "{ip} - - [01/Jan/2026:00:00:00 +0000] \"GET {path} HTTP/1.1\" 200 10 \"-\" \"{agent}\"\n"
    )
}
fn waf(source: &str, target: &str) -> Value {
    json!({"timestamp":1767225600000_i64,"responseCodeSent":200,
        "ja3Fingerprint":"synthetic-ja3","ja4Fingerprint":"synthetic-ja4",
        "httpRequest":{"clientIp":source,"country":"ZZ","httpMethod":"GET","httpVersion":"HTTP/2",
            "uri":target,"args":"alpha=private-query&alpha=again&beta=hidden&flag&&=ignored",
            "headers":[{"name":"Host","value":"example.test"},
                {"name":"User-Agent","value":"StackSynthetic/1.0"},
                {"name":"Content-Type","value":"application/synthetic; charset=utf-8"},
                {"name":"X-Synthetic","value":"never-retain-header-value"},
                {"name":"x-synthetic","value":"another-private-value"}]}})
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn run(root: &Path, input: &Path, name: &str, format: &str, args: &[&str]) -> (Value, Vec<u8>) {
    let output = root.join(name);
    let stdout = command(root)
        .args(["stack", "--input"])
        .arg(input)
        .args(["--format", format, "--output"])
        .arg(&output)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    (read(output.join("stack.json")), stdout)
}
fn metric<'a>(report: &'a Value, field: &str, value: &str) -> &'a Value {
    report["fields"][field]["values"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["value"] == value)
        .unwrap()
}
fn write_waf(path: &Path, records: &[Value]) {
    fs::write(
        path,
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
}

#[test]
fn stack_extracts_all_fields_with_profile_gating_and_canonical_peer_counts() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let a = waf("192.0.2.1", "/deep/tree/FILE.JS");
    let mut b = waf("::ffff:192.0.2.1", "/deep/tree/FILE.JS");
    b["timestamp"] = json!(1767225601000_i64);
    b["responseCodeSent"] = json!(404);
    write_waf(&input, &[a, b]);
    let all = "method,user-agent,path-extension,path-depth,query-key,header-name,content-type,status,protocol,host,ja3,ja4,tls-cipher,tls-protocol,country";
    let (report, _) = run(dir.path(), &input, "all", "aws-waf", &["--field", all]);
    for (field, value) in [
        ("method", "GET"),
        ("user-agent", "StackSynthetic/1.0"),
        ("path-extension", "js"),
        ("path-depth", "3"),
        ("query-key", "alpha"),
        ("header-name", "x-synthetic"),
        ("content-type", "application/synthetic; charset=utf-8"),
        ("protocol", "HTTP/2"),
        ("host", "example.test"),
        ("ja3", "synthetic-ja3"),
        ("ja4", "synthetic-ja4"),
        ("country", "ZZ"),
    ] {
        let row = metric(&report, field, value);
        assert_eq!(row["requests"], 2, "{field}");
        assert_eq!(row["distinct_sources"], 1, "{field}");
        assert_eq!(row["first_seen"], "2026-01-01T00:00:00Z");
        assert_eq!(row["last_seen"], "2026-01-01T00:00:01Z");
        assert_eq!(row["response_status_classes"]["success"], 1);
        assert_eq!(row["response_status_classes"]["client_error"], 1);
        assert!(row.get("client_sources").is_none());
    }
    assert_eq!(metric(&report, "status", "200")["requests"], 1);
    assert_eq!(metric(&report, "status", "404")["requests"], 1);
    assert_eq!(
        report["summary"]["fields"]["query-key"]["distinct_values"],
        3
    );
    assert_eq!(
        report["summary"]["fields"]["header-name"]["distinct_values"],
        4
    );
    for field in ["tls-cipher", "tls-protocol"] {
        assert_eq!(
            report["summary"]["fields"][field]["availability"],
            "unavailable"
        );
        assert_eq!(
            report["summary"]["fields"][field]["distinct_values"],
            Value::Null
        );
    }
    let postdata = dir.path().join("postdata.txt");
    let extended = format!(
        "{} \"application/synthetic\" \"TLSv1.3\" \"TLS_SYNTHETIC\" 0.1 postdata[]\n",
        line("192.0.2.1", "/a", "Synthetic").trim_end()
    );
    fs::write(&postdata, extended).unwrap();
    let (report, _) = run(
        dir.path(),
        &postdata,
        "postdata",
        "nginx-postdata",
        &[
            "--field",
            "content-type,tls-cipher,tls-protocol,header-name",
        ],
    );
    for (field, value) in [
        ("content-type", "application/synthetic"),
        ("tls-cipher", "TLS_SYNTHETIC"),
        ("tls-protocol", "TLSv1.3"),
    ] {
        assert_eq!(metric(&report, field, value)["requests"], 1);
    }
    assert_eq!(
        report["summary"]["fields"]["header-name"]["availability"],
        "unavailable"
    );
}

#[test]
fn unsupported_fields_and_unrecorded_values_are_distinct_from_observed_zero() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    fs::write(&input, line("192.0.2.1", "/one", "-")).unwrap();
    let (report, stdout) = run(dir.path(), &input, "missing", "nginx", &["--field", "header-name,host,country,ja3,ja4,content-type,tls-cipher,tls-protocol,user-agent,query-key"]);
    for field in [
        "header-name",
        "host",
        "country",
        "ja3",
        "ja4",
        "content-type",
        "tls-cipher",
        "tls-protocol",
    ] {
        let summary = &report["summary"]["fields"][field];
        assert_eq!(summary["availability"], "unavailable");
        assert_eq!(summary["unavailable_requests"], 1);
        for key in [
            "distinct_values",
            "distinct_values_at_least",
            "histogram",
            "requests_without_value",
        ] {
            assert_eq!(summary[key], Value::Null);
        }
        assert!(report["fields"][field]["values"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    for field in ["user-agent", "query-key"] {
        assert_eq!(
            report["summary"]["fields"][field]["availability"],
            "available"
        );
        assert_eq!(report["summary"]["fields"][field]["distinct_values"], 0);
        assert_eq!(
            report["summary"]["fields"][field]["requests_without_value"],
            1
        );
    }
    assert!(String::from_utf8(stdout)
        .unwrap()
        .contains("host: unavailable"));
    let empty = dir.path().join("empty.log");
    fs::write(&empty, "").unwrap();
    let (empty, _) = run(
        dir.path(),
        &empty,
        "empty",
        "nginx",
        &["--field", "method,ja3"],
    );
    assert_eq!(empty["summary"]["fields"]["method"]["distinct_values"], 0);
    assert_eq!(
        empty["summary"]["fields"]["ja3"]["availability"],
        "unavailable"
    );
}

#[test]
fn path_fields_use_raw_last_segments_and_query_keys_never_retain_values() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    let targets = [
        "/",
        "/archive/file.TAR.GZ",
        "/dir/.env",
        "/dir/file.",
        "/a//b/",
        "/dir/FILE.Ä",
    ];
    fs::write(
        &input,
        targets
            .iter()
            .map(|path| line("192.0.2.1", path, "Synthetic"))
            .collect::<String>(),
    )
    .unwrap();
    let (report, _) = run(
        dir.path(),
        &input,
        "paths",
        "nginx",
        &["--field", "path-extension,path-depth"],
    );
    assert_eq!(metric(&report, "path-extension", "(none)")["requests"], 4);
    assert_eq!(metric(&report, "path-extension", "gz")["requests"], 1);
    assert_eq!(metric(&report, "path-extension", "ä")["requests"], 1);
    assert_eq!(metric(&report, "path-depth", "0")["requests"], 1);
    assert_eq!(metric(&report, "path-depth", "2")["requests"], 5);
    let waf_input = dir.path().join("keys.jsonl");
    let mut event = waf("192.0.2.1", "/one");
    event["httpRequest"]["args"] =
        json!("a=private-query&a=another&%61=secret&flag&=ignored&&plus+key=x");
    write_waf(&waf_input, &[event]);
    let (report, _) = run(
        dir.path(),
        &waf_input,
        "keys",
        "aws-waf",
        &["--field", "query-key,header-name"],
    );
    assert_eq!(
        report["summary"]["fields"]["query-key"]["distinct_values"],
        4
    );
    for key in ["a", "%61", "flag", "plus+key"] {
        assert_eq!(metric(&report, "query-key", key)["requests"], 1);
    }
    let private = fs::read_to_string(dir.path().join("keys/stack.json")).unwrap();
    for value in [
        "private-query",
        "another-private-value",
        "never-retain-header-value",
        "ignored",
    ] {
        assert!(!private.contains(value));
    }
}

#[test]
fn histogram_buckets_include_exact_frequency_boundaries() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    let frequencies = [1, 2, 9, 10, 99, 100, 999, 1000];
    let mut log = String::new();
    for (i, requests) in frequencies.into_iter().enumerate() {
        for _ in 0..requests {
            log += &line("192.0.2.1", "/one", &format!("HistogramSynthetic-{i}"));
        }
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(
        dir.path(),
        &input,
        "histogram",
        "nginx",
        &["--field", "user-agent", "--rarest", "8", "--top", "8"],
    );
    assert_eq!(
        report["summary"]["fields"]["user-agent"]["histogram"],
        json!({"requests_1":1,"requests_2_to_9":2,"requests_10_to_99":2,"requests_100_to_999":2,"requests_1000_or_more":1})
    );
    assert_eq!(
        report["fields"]["user-agent"]["rarest"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["requests"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        frequencies
    );
    assert_eq!(report["fields"]["user-agent"]["top"][0]["requests"], 1000);
}

#[test]
fn rare_and_top_ties_use_source_counts_then_values_with_unknown_counts_last() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    let mut log = String::new();
    for (agent, sources) in [
        ("A", vec!["192.0.2.1", "192.0.2.1"]),
        ("B", vec!["192.0.2.1", "192.0.2.2"]),
        ("C", vec!["192.0.2.1", "192.0.2.1"]),
        ("D", vec!["peer.example.test", "peer.example.test"]),
        ("E", vec!["192.0.2.1", "192.0.2.2", "192.0.2.2"]),
    ] {
        for source in sources {
            log += &line(source, "/one", agent);
        }
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(
        dir.path(),
        &input,
        "order",
        "nginx",
        &["--field", "user-agent"],
    );
    let list = |key| {
        report["fields"]["user-agent"][key]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["value"].as_str().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(list("rarest"), ["A", "C", "B", "D", "E"]);
    assert_eq!(list("top"), ["E", "B", "A", "C", "D"]);
    assert_eq!(
        metric(&report, "user-agent", "D")["distinct_sources"],
        Value::Null
    );
    assert_eq!(report["summary"]["requests_with_invalid_peer_ip"], 2);
}

#[test]
fn value_caps_count_rejected_requests_and_observations_without_estimating_unique_values() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let mut records = Vec::new();
    for query in ["a=1&a=2&b=3", "a=4&c=5&d=6&c=7", "c=8&c=9"] {
        let mut record = waf("192.0.2.1", "/one");
        record["httpRequest"]["args"] = json!(query);
        records.push(record);
    }
    write_waf(&input, &records);
    let (report, stdout) = run(
        dir.path(),
        &input,
        "caps",
        "aws-waf",
        &["--field", "query-key", "--max-values-per-field", "2"],
    );
    let summary = &report["summary"]["fields"]["query-key"];
    assert_eq!(summary["distinct_values"], Value::Null);
    assert_eq!(summary["distinct_values_at_least"], 2);
    assert_eq!(summary["requests_beyond_value_cap"], 2);
    assert_eq!(summary["value_observations_beyond_cap"], 3);
    assert_eq!(metric(&report, "query-key", "a")["requests"], 2);
    assert_eq!(metric(&report, "query-key", "b")["requests"], 1);
    assert!(String::from_utf8(stdout)
        .unwrap()
        .contains("2 requests / 3 value observations"));
}

#[test]
fn source_pair_caps_preserve_known_members_and_expose_lower_bounds() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    fs::write(
        &input,
        [
            line("192.0.2.1", "/one", "Synthetic"),
            line("192.0.2.2", "/one", "Synthetic"),
            line("::ffff:192.0.2.1", "/one", "Synthetic"),
        ]
        .concat(),
    )
    .unwrap();
    let (report, _) = run(
        dir.path(),
        &input,
        "pairs",
        "nginx",
        &["--field", "method", "--max-source-pairs-per-field", "1"],
    );
    let row = metric(&report, "method", "GET");
    assert_eq!(row["requests"], 3);
    assert_eq!(row["distinct_sources"], Value::Null);
    assert_eq!(row["distinct_sources_at_least"], 1);
    assert_eq!(row["source_observations_beyond_cap"], 1);
    assert_eq!(
        report["summary"]["fields"]["method"]["retained_source_pairs"],
        1
    );
}

#[test]
fn trusted_clients_are_separate_optional_counts_instead_of_replacing_peers() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let mut records = Vec::new();
    for client in ["203.0.113.7", "203.0.113.8"] {
        let mut record = waf("192.0.2.1", "/one");
        record["httpRequest"]["headers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"X-Forwarded-For","value":client}));
        records.push(record);
    }
    write_waf(&input, &records);
    let (plain, _) = run(
        dir.path(),
        &input,
        "plain",
        "aws-waf",
        &["--field", "method"],
    );
    assert!(metric(&plain, "method", "GET")
        .get("client_sources")
        .is_none());
    let (trusted, _) = run(
        dir.path(),
        &input,
        "trusted",
        "aws-waf",
        &["--field", "method", "--trusted-proxy", "192.0.2.0/24"],
    );
    let row = metric(&trusted, "method", "GET");
    assert_eq!(row["distinct_sources"], 1);
    assert_eq!(row["client_sources"]["distinct_sources"], 2);
    let (capped, _) = run(
        dir.path(),
        &input,
        "capped",
        "aws-waf",
        &[
            "--field",
            "method",
            "--trusted-proxy",
            "192.0.2.0/24",
            "--max-source-pairs-per-field",
            "2",
        ],
    );
    let row = metric(&capped, "method", "GET");
    assert_eq!(row["distinct_sources"], 1);
    assert_eq!(row["client_sources"]["distinct_sources"], Value::Null);
    assert_eq!(row["client_sources"]["distinct_sources_at_least"], 1);
    assert_eq!(row["client_sources"]["source_observations_beyond_cap"], 1);
}

#[test]
fn private_values_stay_full_while_display_is_truncated_and_sanitized_is_value_free() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let agent = format!("PrivateStackUA-{}\u{1b}[31m", "あ".repeat(180));
    let mut event = waf("192.0.2.1", "/one");
    event["httpRequest"]["headers"][1]["value"] = json!(agent);
    write_waf(&input, &[event]);
    let (private, stdout) = run(dir.path(), &input, "private", "aws-waf", &[]);
    assert_eq!(metric(&private, "user-agent", &agent)["value"], agent);
    let sanitized = fs::read_to_string(dir.path().join("private/sanitized-stack.json")).unwrap();
    for sensitive in [
        "PrivateStackUA",
        "GET",
        "example.test",
        "private-query",
        "never-retain-header-value",
        "192.0.2.1",
    ] {
        assert!(!sanitized.contains(sensitive));
        assert!(!String::from_utf8_lossy(&stdout).contains(sensitive));
    }
    let summary = read(dir.path().join("private/sanitized-stack.json"));
    assert_eq!(summary["fields"].as_object().unwrap().len(), 5);
    for field in summary["fields"].as_object().unwrap().values() {
        assert!(field.get("values").is_none());
    }
    for format in ["text", "json"] {
        let output = command(dir.path())
            .args(["stack", "--input"])
            .arg(&input)
            .args([
                "--format",
                "aws-waf",
                "--field",
                "user-agent",
                "--show-values",
                "--max-display-length",
                "20",
                "--output-format",
                format,
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains(&agent));
        if format == "text" {
            assert!(text.contains("[truncated]"));
        } else {
            let view: Value = serde_json::from_str(&text).unwrap();
            let row = &view["fields"]["user-agent"]["rarest"][0];
            assert_eq!(row["value_truncated"], true);
            assert_eq!(row["value"].as_str().unwrap().chars().count(), 20);
        }
    }
}

#[test]
fn gzip_results_and_stdout_are_byte_reproducible_with_stored_byte_provenance() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("extensionless");
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(line("192.0.2.1", "/one?q=private", "Synthetic").as_bytes())
        .unwrap();
    let bytes = gzip.finish().unwrap();
    fs::write(&input, &bytes).unwrap();
    let (_, a) = run(dir.path(), &input, "a", "nginx", &[]);
    let (_, b) = run(dir.path(), &input, "b", "nginx", &[]);
    assert_eq!(a, b);
    for artifact in ["stack.json", "sanitized-stack.json", "run-manifest.json"] {
        assert_eq!(
            fs::read(dir.path().join("a").join(artifact)).unwrap(),
            fs::read(dir.path().join("b").join(artifact)).unwrap()
        );
    }
    let manifest = read(dir.path().join("a/run-manifest.json"));
    assert_eq!(
        manifest["corpus"][0]["sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    assert_eq!(manifest["options"]["max_values_per_field"], 200_000);
    assert_eq!(manifest["options"]["rarest"], 25);
    assert_eq!(manifest["options"]["top"], 10);
    assert_eq!(manifest["options"]["max_display_length"], 160);
    let (single, _) = run(
        dir.path(),
        &input,
        "single",
        "nginx",
        &["--field", "method", "--field", "method"],
    );
    assert_eq!(single["fields"].as_object().unwrap().len(), 1);
    assert_eq!(metric(&single, "method", "GET")["requests"], 1);
}

#[test]
fn shared_quality_time_filters_missing_status_and_read_errors_are_disclosed() {
    let dir = tempdir().unwrap();
    let logs = dir.path().join("logs");
    fs::create_dir(&logs).unwrap();
    let mut a = waf("192.0.2.1", "/one");
    a["timestamp"] = json!(1767225600000_i64);
    let mut b = waf("192.0.2.1", "/one");
    b["timestamp"] = json!(1767225601000_i64);
    b.as_object_mut().unwrap().remove("responseCodeSent");
    let mut undated = waf("192.0.2.1", "/one");
    undated.as_object_mut().unwrap().remove("timestamp");
    write_waf(&logs.join("a.jsonl"), &[a, b, undated]);
    fs::write(logs.join("broken.jsonl"), "not json\n").unwrap();
    fs::write(logs.join("notes.md"), "not a log").unwrap();
    let (report, _) = run(
        dir.path(),
        &logs,
        "filtered",
        "aws-waf",
        &[
            "--field",
            "status,method",
            "--from",
            "2026-01-01T00:00:01Z",
            "--to",
            "2026-01-01T00:00:01Z",
        ],
    );
    assert_eq!(report["summary"]["analyzed_requests"], 1);
    assert_eq!(report["summary"]["parse_errors"], 1);
    assert_eq!(report["summary"]["files_skipped"], 1);
    assert_eq!(report["summary"]["requests_outside_time_range"], 2);
    assert_eq!(
        report["summary"]["undated_records_excluded_by_time_range"],
        1
    );
    assert_eq!(
        report["summary"]["fields"]["status"]["requests_without_value"],
        1
    );
    assert_eq!(
        metric(&report, "method", "GET")["response_status_classes"]["unavailable"],
        1
    );
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(line("192.0.2.1", "/one", "Synthetic").as_bytes())
        .unwrap();
    let mut bytes = gzip.finish().unwrap();
    bytes.truncate(bytes.len() - 7);
    let broken = dir.path().join("broken.gz");
    fs::write(&broken, bytes).unwrap();
    let output = dir.path().join("never-written");
    command(dir.path())
        .args(["stack", "--input"])
        .arg(&broken)
        .args(["--format", "nginx", "--output"])
        .arg(&output)
        .assert()
        .failure();
    assert!(!output.join("stack.json").exists());
    for args in [
        vec!["--max-values-per-field", "0"],
        vec!["--max-source-pairs-per-field", "0"],
        vec!["--max-display-length", "0"],
        vec!["--field", "unknown"],
    ] {
        command(dir.path())
            .args(["stack", "--input"])
            .arg(logs.join("a.jsonl"))
            .args(["--format", "aws-waf", "--output"])
            .arg(&output)
            .args(args)
            .assert()
            .failure();
        assert!(!output.exists());
    }
}
