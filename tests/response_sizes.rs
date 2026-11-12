use std::{fs, path::Path};

use assert_cmd::Command;
use serde_json::Value;
use shenron::{
    access_log::{parse_combined_line, AccessLogFormat},
    event::{RawRetention, TelemetryProfile},
};

fn nginx_escape(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b == b'"' || b == b'\\' || !(32..127).contains(&b) {
                format!("\\x{b:02X}")
            } else {
                char::from(b).to_string()
            }
        })
        .collect()
}

fn body(expression: &str, inner_path: &str, hex: bool) -> String {
    let cast = format!("CAST(({expression})AS CHAR)");
    let cast = if hex { format!("HEX({cast})") } else { cast };
    format!(r#"{{"requests":[{{"path":"{inner_path}","query":"{cast}"}}]}}"#)
}

fn line(source: &str, target: &str, body: &str, bytes: u64, second: u8, prefix: bool) -> String {
    let prefix = if prefix {
        "2026 Jan 01 00:00:00 (fixture) 192.0.2.1->/var/log/nginx/example.test_access_443.log "
    } else {
        ""
    };
    format!("{prefix}{source} - - [01/Jan/2026:00:00:{second:02} +0000] \"POST {target} HTTP/1.1\" 207 {bytes} \"-\" \"fixture-agent\" \"application/json\" \"TLSv1.3\" \"fixture-cipher\" 0.125 postdata[{}]\n", nginx_escape(body))
}

fn command(root: &Path) -> Command {
    let mut c = Command::cargo_bin("shenron").unwrap();
    c.env("SHENRON_DATA_DIR", root.join("empty-data"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("SHENRON_SLACK_WEBHOOK");
    c
}

#[test]
fn nginx_postdata_header_coverage_matches_combined_profiles() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("header.yaml"),
        r#"id: synthetic-header-dependency
info:
  name: Synthetic header dependency
  severity: high
  classification:
    cve-id: CVE-2024-10001
http:
  - method: GET
    path:
      - '{{BaseURL}}/synthetic/execute'
    headers:
      X-Synthetic-Header: fixture
    matchers:
      - type: word
        part: body
        words:
          - fixture
"#,
    )
    .unwrap();
    let reports: Vec<_> = [
        TelemetryProfile::NginxCombined,
        TelemetryProfile::NginxPostdata,
        TelemetryProfile::ApacheCombined,
    ]
    .into_iter()
    .map(|profile| {
        let report = shenron::nuclei::coverage_for_telemetry(tmp.path(), profile, "fixture");
        assert_eq!(report.metrics.undetectable, 1);
        assert_eq!(report.metrics.convertible, 0);
        assert_eq!(report.metrics.validated, 0);
        assert_eq!(
            report.detectability_reasons["arbitrary_header_unavailable"],
            1
        );
        let mut value = serde_json::to_value(report).unwrap();
        value.as_object_mut().unwrap().remove("telemetry");
        value
    })
    .collect();
    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[0], reports[2]);
}

fn run(root: &Path, input: &Path, name: &str, args: &[&str]) -> (Value, Vec<u8>) {
    let out = root.join(name);
    let stdout = command(root)
        .args(["production", "response-sizes", "--input"])
        .arg(input)
        .args(["--format", "nginx-postdata", "--output"])
        .arg(&out)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    (
        serde_json::from_slice(&fs::read(out.join("response-sizes.json")).unwrap()).unwrap(),
        stdout,
    )
}

#[test]
fn nginx_postdata_preserves_escaped_body_optional_prefix_and_legacy_combined_bytes() {
    let combined = r#"198.51.100.7 - - [01/Jan/2026:00:00:00 +0000] "POST /?route=/batch HTTP/1.1" 207 1000 "-" "fixture-agent""#;
    let old = parse_combined_line(combined, AccessLogFormat::NginxCombined).unwrap();
    let bytes = serde_json::to_vec(&old).unwrap();
    let value = serde_json::to_value(&old).unwrap();
    for key in ["request_body", "request_time_seconds", "content_type"] {
        assert!(value.get(key).is_none());
    }
    for prefix in [
        "",
        "2026 Jan 01 00:00:01 (fixture) 192.0.2.1->/var/log/nginx/example.test_access.log ",
    ] {
        let raw = format!(
            r#"{prefix}{combined} "application/json" "TLSv1.3" "fixture-cipher" 0.25 postdata[{{\x22x\x22:[1,2],\x22s\x22:\x22a\x5Cb\x0D\x0A\xC3\xA9\x22}}]"#
        );
        let event = parse_combined_line(&raw, AccessLogFormat::NginxPostdata).unwrap();
        assert_eq!(
            event.host.as_deref(),
            (!prefix.is_empty()).then_some("example.test")
        );
        assert_eq!(
            event.request_body.as_deref(),
            Some(r#"{\x22x\x22:[1,2],\x22s\x22:\x22a\x5Cb\x0D\x0A\xC3\xA9\x22}"#)
        );
        assert_eq!(event.request_time_seconds, Some(0.25));
        assert_eq!(event.content_type.as_deref(), Some("application/json"));
        assert_eq!(event.response_bytes, Some(1000));
        assert_eq!(event.uri, old.uri);
        let dropped = shenron::access_log::parse_combined_line_with_raw_retention(
            &raw,
            AccessLogFormat::NginxPostdata,
            RawRetention::Drop,
        )
        .unwrap();
        assert!(dropped.raw.is_empty());
        assert_eq!(dropped.request_body, event.request_body);
        assert!(parse_combined_line(&raw, AccessLogFormat::NginxCombined).is_err());
    }
    let empty = parse_combined_line(
        &format!("{combined} \"-\" \"-\" \"-\" - postdata[]"),
        AccessLogFormat::NginxPostdata,
    )
    .unwrap();
    assert!(empty.request_body.is_none());
    assert!(empty.request_time_seconds.is_none());
    assert!(empty.content_type.is_none());
    assert_eq!(
        bytes,
        serde_json::to_vec(&parse_combined_line(combined, AccessLogFormat::NginxCombined).unwrap())
            .unwrap()
    );
    let capabilities = TelemetryProfile::NginxPostdata.capabilities();
    assert!(!capabilities.host && !capabilities.request_body);
    assert!(capabilities.response_bytes && capabilities.tls_protocol && capabilities.tls_cipher);
    for invalid in ["NaN", "inf", "-1", "invalid"] {
        assert!(parse_combined_line(
            &format!("{combined} \"-\" \"-\" \"-\" {invalid} postdata[]"),
            AccessLogFormat::NginxPostdata
        )
        .is_err());
    }
}

#[test]
fn response_sizes_adjust_request_bytes_instead_of_reporting_naive_deltas() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let control = body("SELECT 1", "/items", true);
    let count = body(
        &format!("{:<228}", "SELECT COUNT(*) FROM items"),
        "/items",
        true,
    );
    let setting = body(
        &format!("{:<172}", "SELECT value FROM settings"),
        "/items",
        true,
    );
    assert_eq!(count.len() - control.len(), 220);
    assert_eq!(setting.len() - control.len(), 164);
    let log = line("198.51.100.7", "/batch", &control, 2000, 0, true)
        + &line("198.51.100.7", "/batch", &count, 2220, 1, true)
        + &line("198.51.100.7", "/batch", &setting, 2220, 2, true);
    fs::write(&input, log).unwrap();
    let (report, stdout) = run(root.path(), &input, "first", &[]);
    let entries = report["paired_expressions"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["estimated_lengths"], serde_json::json!([1]));
    assert_eq!(entries[1]["estimated_lengths"], serde_json::json!([29]));
    for (row, request_delta, adjusted) in [(&entries[0], 220, 0), (&entries[1], 164, 56)] {
        assert_eq!(row["estimates"][0]["response_byte_delta"], 220);
        assert_eq!(row["estimates"][0]["request_byte_delta"], request_delta);
        assert_eq!(row["estimates"][0]["adjusted_delta"], adjusted);
    }
    assert_eq!(report["host_fit_rates"][0]["fit_rate"], 1.0);
    let sanitized = fs::read(root.path().join("first/sanitized-response-sizes.json")).unwrap();
    for bytes in [&stdout, &sanitized] {
        let text = String::from_utf8_lossy(bytes);
        for private in [
            "198.51.100.7",
            "example.test",
            "select",
            "/items",
            "/batch",
            "settings",
        ] {
            assert!(!text.contains(private), "{private}");
        }
    }
    let (_, again) = run(root.path(), &input, "again", &[]);
    assert_eq!(stdout, again);
    for file in [
        "response-sizes.json",
        "sanitized-response-sizes.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("first").join(file)).unwrap(),
            fs::read(root.path().join("again").join(file)).unwrap()
        );
    }
    let (_, shown) = run(
        root.path(),
        &input,
        "shown",
        &["--show-source-ips", "--show-expressions", "--limit", "1"],
    );
    let shown = String::from_utf8(shown).unwrap();
    assert!(shown.contains("198.51.100.7"));
    assert!(shown.contains("select count(*) from items"));
    assert!(shown.contains("Expressions not displayed: 1"));
}

#[test]
fn response_sizes_controls_nested_expressions_fit_and_group_boundaries_are_exact() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let control = body("SELECT 0x4f4b", "/items", true);
    let expressions = [
        ("SELECT value FROM site_settings", 38),
        ("SELECT missing FROM items", -8),
        ("SELECT blank FROM items", -4),
        ("SELECT variable FROM items", 11),
        (
            "SELECT (SELECT u.ID FROM t u JOIN m ON (m.a=u.b) WHERE u.id=1)",
            16,
        ),
    ];
    // The earlier timestamp controls even when encountered after a later control.
    let mut log = line("198.51.100.7", "/batch", &control, 9999, 50, true);
    log += &line("198.51.100.7", "/batch", &control, 2000, 0, true);
    for (i, (expression, delta)) in expressions.iter().enumerate() {
        let request = body(expression, "/items", true);
        let bytes = (2000 + request.len() as i64 - control.len() as i64 + delta) as u64;
        log += &line("198.51.100.7", "/batch", &request, bytes, i as u8 + 1, true);
    }
    // No control exists for a different inner path, peer, method, status or host.
    let other = body("SELECT other FROM items", "/different", true);
    log += &line("198.51.100.7", "/batch", &other, 2200, 10, true);
    log += &line(
        "203.0.113.9",
        "/batch",
        &body("SELECT x FROM items", "/items", true),
        2200,
        11,
        true,
    );
    log += &line(
        "198.51.100.7",
        "/batch",
        &body("SELECT x FROM items", "/items", true),
        2200,
        12,
        false,
    );
    log += &line(
        "198.51.100.7",
        "/batch",
        &body("SELECT x FROM items", "/items", true),
        2200,
        13,
        true,
    )
    .replace("\"POST ", "\"GET ");
    log += &line(
        "198.51.100.7",
        "/batch",
        &body("SELECT x FROM items", "/items", true),
        2200,
        14,
        true,
    )
    .replace(" 207 ", " 403 ");
    fs::write(&input, log).unwrap();
    let (report, _) = run(root.path(), &input, "out", &[]);
    let rows = report["paired_expressions"].as_array().unwrap();
    let find = |name: &str| rows.iter().find(|r| r["expression"] == name).unwrap();
    assert_eq!(
        find("select value from site_settings")["estimated_lengths"],
        serde_json::json!([21])
    );
    assert_eq!(find("select missing from items")["negative_estimate"], 1);
    assert!(find("select missing from items")["estimates"][0]["estimated_length"].is_null());
    assert_eq!(find("select blank from items")["empty_or_null"], 1);
    assert_eq!(
        find("select blank from items")["estimated_lengths"],
        serde_json::json!([])
    );
    assert_eq!(find("select variable from items")["not_fitting"], 1);
    assert!(find("select variable from items")["estimates"][0]["estimated_length"].is_null());
    assert_eq!(
        find("select (select u.id from t u join m on (m.a=u.b) where u.id=1)")["estimated_lengths"],
        serde_json::json!([10])
    );
    assert_eq!(report["summary"]["groups_without_control"], 5);
    // The later constant is also compared: odd size delta, hence another non-fit.
    assert_eq!(report["host_fit_rates"][0]["fitting"], 4);
    assert_eq!(report["host_fit_rates"][0]["not_fitting"], 2);
    assert_eq!(report["host_fit_rates"][0]["fit_rate"], 4.0 / 6.0);
}

#[test]
fn response_sizes_character_positions_are_not_lengths_and_sizes_have_stable_ties() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for i in 0..61 {
        let position = i % 9 + 1;
        let expression = "SELECT name FROM items";
        let argument = match i % 3 {
            0 => format!("({expression})"),
            1 => format!("COALESCE(({expression}), 0x20)"),
            _ => format!("IFNULL(CAST(({expression}) AS NCHAR), 0x20)"),
        };
        let function = ["SUBSTRING", "SUBSTR", "MID"][i % 3];
        let code = if i % 2 == 0 { "ASCII" } else { "ORD" };
        let body = format!("{code}({function}({argument}, {position}, 1)) > 64");
        log += &line(
            if i % 2 == 0 {
                "192.0.2.7"
            } else {
                "::ffff:192.0.2.7"
            },
            "/batch",
            &body,
            700 + (i % 4) as u64,
            (i % 60) as u8,
            true,
        );
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(root.path(), &input, "out", &[]);
    let row = &report["character_expressions"][0];
    assert_eq!(row["requests"], 61);
    assert_eq!(row["distinct_sources"], 1);
    assert_eq!(row["positions_probed"], 9);
    assert_eq!(row["max_position"], 9);
    assert_eq!(row["expression"], "select name from items");
    assert_eq!(
        row["response_sizes_by_status"]["207"],
        serde_json::json!([
            {"response_bytes":700,"requests":16}, {"response_bytes":701,"requests":15}, {"response_bytes":702,"requests":15}
        ])
    );
    assert!(row.get("estimated_length").is_none());
    assert_eq!(
        row["response_size_requests_not_displayed_by_status"]["207"],
        15
    );
}

#[test]
fn response_sizes_nested_character_select_and_private_display_are_safe_and_bounded() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let expression = format!(
        "SELECT concat('\u{1b}[31m', '{}é)') FROM items",
        "x".repeat(350)
    );
    let control = body("SELECT 'OK'", "/items", true);
    let read = body(&expression, "/items", true);
    let mut log = line("192.0.2.8", "/batch", &control, 1000, 0, true);
    log += &line(
        "192.0.2.8",
        "/batch",
        &read,
        (1000 + read.len() - control.len() + 10) as u64,
        1,
        true,
    );
    log += &line(
        "192.0.2.8",
        "/batch",
        "ORD(MID((SELECT (SELECT name FROM items)), 3, 1))",
        900,
        2,
        true,
    );
    log += &line(
        "192.0.2.8",
        "/batch",
        "ASCII(SUBSTR(COALESCE((SELECT\tname FROM items), 'x,y)'), 4, 1))",
        901,
        3,
        true,
    );
    let (report, expressions) = {
        fs::write(&input, &log).unwrap();
        run(
            root.path(),
            &input,
            "expressions",
            &["--show-expressions", "--limit", "1"],
        )
    };
    let text = String::from_utf8(expressions).unwrap();
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("192.0.2.8"));
    assert!(!text.contains("example.test"));
    let displayed = text
        .lines()
        .find_map(|line| line.split_once(" / expression ").map(|(_, expr)| expr))
        .unwrap();
    assert_eq!(displayed.chars().count(), 300);
    assert_eq!(
        report["paired_expressions"][0]["estimated_lengths"],
        serde_json::json!([7])
    );
    assert_eq!(report["character_expressions"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["character_expressions"][0]["expression"],
        "select name from items"
    );
    assert_eq!(report["character_expressions"][0]["positions_probed"], 2);
    let (_, sources) = run(
        root.path(),
        &input,
        "sources",
        &["--show-source-ips", "--limit", "0"],
    );
    let text = String::from_utf8(sources).unwrap();
    assert!(text.contains("192.0.2.8"));
    assert!(!text.contains("concat"));
    assert!(!text.contains("select name"));
    for file in [
        "response-sizes.json",
        "sanitized-response-sizes.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("expressions").join(file)).unwrap(),
            fs::read(root.path().join("sources").join(file)).unwrap()
        );
    }
}

#[test]
fn response_sizes_stream_gzip_fingerprint_and_discovery_are_private_and_explicit() {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("logs");
    fs::create_dir(&input).unwrap();
    let control = body("SELECT 1", "/items", true);
    let read = body("SELECT value FROM items", "/items", true);
    let mut log = line("192.0.2.9", "/batch", &control, 1000, 0, true);
    log += &line(
        "192.0.2.9",
        "/batch",
        &read,
        (1000 + read.len() - control.len() + 4) as u64,
        1,
        true,
    );
    log += "malformed synthetic record\n";
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(log.as_bytes()).unwrap();
    let gzip = gzip.finish().unwrap();
    fs::write(input.join("access_log"), &gzip).unwrap();
    fs::write(input.join("notes.md"), "synthetic fixture").unwrap();
    let (report, stdout) = run(root.path(), &input, "out", &[]);
    assert_eq!(report["summary"]["files_analyzed"], 1);
    assert_eq!(report["summary"]["parse_errors"], 1);
    assert_eq!(report["summary"]["files_skipped"], 1);
    assert!(String::from_utf8(stdout)
        .unwrap()
        .contains("Files skipped: 1 (unsupported-extension: 1)"));
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.path().join("out/run-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest["corpus"][0]["sha256"],
        format!("{:x}", Sha256::digest(&gzip))
    );
    assert_eq!(manifest["corpus"][0]["byte_length"], gzip.len());
    assert_eq!(manifest["options"]["max_observations"], 1_000_000);
    assert_eq!(
        manifest["skipped_inputs"][0]["reason"],
        "unsupported-extension"
    );
    let sanitized =
        fs::read_to_string(root.path().join("out/sanitized-response-sizes.json")).unwrap();
    assert!(!sanitized.contains("notes.md"));
    assert!(!sanitized.contains("access_log"));
    let before = fs::read(root.path().join("out/response-sizes.json")).unwrap();
    command(root.path())
        .args(["response-sizes", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(root.path().join("out"))
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "refusing to overwrite existing output",
        ));
    assert_eq!(
        before,
        fs::read(root.path().join("out/response-sizes.json")).unwrap()
    );
}

#[test]
fn response_sizes_decode_twice_measure_wire_bytes_and_disclose_unsupported_rows() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let control = "/?q=HEX%2528CAST%2528%2528SELECT%25201%2529AS%2520CHAR%2529%2529";
    let read = control.replace("SELECT%25201", "SELECT%2520value%2520FROM%2520items");
    let mut log = line("192.0.2.8", control, "", 1000, 0, false);
    log += &line(
        "192.0.2.8",
        &read,
        "",
        (1000 + read.len() - control.len() + 12) as u64,
        1,
        false,
    );
    let plain_control = body("SeLeCt 'OK'", "/items", false);
    let plain_read = body("SELECT name FROM items", "/items", false);
    log += &line("192.0.2.8", "/batch", &plain_control, 1000, 0, false);
    log += &line(
        "192.0.2.8",
        "/batch",
        &plain_read,
        (1000 + plain_read.len() - plain_control.len() + 7) as u64,
        1,
        false,
    );
    log += &line(
        "192.0.2.8",
        "/batch",
        "HEX(CAST((SELECT 1) AS CHAR)) HEX(CAST((SELECT 2) AS CHAR))",
        1000,
        2,
        false,
    );
    log += &line("192.0.2.8", "/batch", "ordinary", 1000, 3, false);
    log += &line(
        "192.0.2.8",
        "/batch",
        "CAST((SELECT 1) AS CHAR)",
        1000,
        4,
        false,
    )
    .replace("207 1000", "207 -");
    log += &line("192.0.2.8", "/batch", "ordinary", 1000, 5, false)
        .replace("postdata[ordinary]", "postdata[\\xFF]");
    fs::write(&input, log).unwrap();
    let (report, _) = run(root.path(), &input, "out", &[]);
    let rows = report["paired_expressions"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .find(|r| r["expression"] == "select value from items")
            .unwrap()["estimated_lengths"],
        serde_json::json!([7])
    );
    assert_eq!(
        rows.iter()
            .find(|r| r["expression"] == "select name from items")
            .unwrap()["estimated_lengths"],
        serde_json::json!([9])
    );
    assert_eq!(report["summary"]["requests_with_multiple_shapes"], 1);
    assert_eq!(report["summary"]["requests_without_shape"], 1);
    assert_eq!(report["summary"]["requests_without_required_fields"], 1);
    assert_eq!(report["summary"]["requests_with_unsupported_decoding"], 1);
    let (capped, _) = run(root.path(), &input, "capped", &["--max-observations", "1"]);
    assert_eq!(capped["summary"]["retained_observations"], 1);
    assert_eq!(capped["summary"]["observations_beyond_cap"], 3);
    let (filtered, _) = run(
        root.path(),
        &input,
        "filtered",
        &["--from", "2026-01-01T00:00:01Z"],
    );
    assert_eq!(filtered["summary"]["records_outside_time_range"], 2);
    assert_eq!(filtered["summary"]["groups_without_control"], 2);
    command(root.path())
        .args(["response-sizes", "--input"])
        .arg(&input)
        .args(["--format", "auto", "--output"])
        .arg(root.path().join("auto"))
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Could not determine the input format safely",
        ));
}

#[test]
fn response_sizes_zero_and_negative_candidates_do_not_assert_empty_values_or_null_rows() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let control = body("SELECT 'abc'", "/items", true);
    let mut log = line("192.0.2.8", "/batch", &control, 1000, 0, true);
    for (expression, delta) in [
        ("SELECT zero FROM items", -6),
        ("SELECT shorter FROM items", -8),
    ] {
        let read = body(expression, "/items", true);
        let bytes = (1000 + read.len() as i64 - control.len() as i64 + delta) as u64;
        log += &line("192.0.2.8", "/batch", &read, bytes, 1, true);
    }
    fs::write(&input, log).unwrap();
    let (report, _) = run(root.path(), &input, "out", &[]);
    assert_eq!(report["summary"]["empty_or_null"], 1);
    assert_eq!(report["summary"]["negative_estimate"], 1);
    for (expression, outcome) in [
        ("select zero from items", "empty_or_null"),
        ("select shorter from items", "negative_estimate"),
    ] {
        let row = report["paired_expressions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["expression"] == expression)
            .unwrap();
        assert_eq!(row[outcome], 1);
        assert_eq!(row["estimated_lengths"], serde_json::json!([]));
        assert_eq!(row["estimates"][0]["baseline_length"], 3);
        assert_eq!(row["estimates"][0]["outcome"], outcome);
        assert!(row["estimates"][0]["estimated_length"].is_null());
    }
    assert_eq!(report["host_fit_rates"][0]["fitting"], 2);
    for name in ["response-sizes.json", "sanitized-response-sizes.json"] {
        let bytes = fs::read_to_string(root.path().join("out").join(name)).unwrap();
        assert!(!bytes.contains("\"empty\""));
        assert!(!bytes.contains("null_or_no_row"));
    }
}

#[test]
fn response_sizes_fit_rate_checks_only_hex_parity_in_cast_only_and_mixed_hosts() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for hex in [false, true] {
        let control = body("SELECT 1", "/items", hex);
        log += &line("192.0.2.8", "/batch", &control, 1000, 0, true);
        for (i, delta) in [2, 3].into_iter().enumerate() {
            let read = body(&format!("SELECT value{i} FROM items"), "/items", hex);
            log += &line(
                "192.0.2.8",
                "/batch",
                &read,
                (1000 + read.len() - control.len() + delta) as u64,
                1,
                true,
            );
        }
        fs::write(&input, &log).unwrap();
        let (report, _) = run(root.path(), &input, if hex { "mixed" } else { "cast" }, &[]);
        let host = &report["host_fit_rates"][0];
        assert_eq!(host["parity_unchecked_reads"], 2);
        assert_eq!(host["fitting"], u64::from(hex));
        assert_eq!(host["not_fitting"], u64::from(hex));
        assert_eq!(report["summary"]["not_fitting"], u64::from(hex));
        if hex {
            assert_eq!(host["fit_rate"], 0.5);
        } else {
            assert!(host["fit_rate"].is_null());
        }
    }
}

#[test]
fn response_sizes_controls_reject_leading_zero_and_non_ascii_strings_but_accept_zero() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for (expression, path) in [
        ("SELECT 007", "/padded"),
        ("SELECT 'é'", "/unicode"),
        ("SELECT 0", "/zero"),
    ] {
        let control = body(expression, path, true);
        log += &line("192.0.2.8", "/batch", &control, 1000, 0, true);
        if path == "/zero" {
            let read = body("SELECT value FROM items", path, true);
            log += &line(
                "192.0.2.8",
                "/batch",
                &read,
                (1000 + read.len() - control.len() + 4) as u64,
                1,
                true,
            );
        }
    }
    fs::write(&input, log).unwrap();
    let (report, stdout) = run(root.path(), &input, "out", &[]);
    assert_eq!(report["summary"]["groups_without_control"], 2);
    assert_eq!(report["summary"]["requests_without_control"], 2);
    assert_eq!(report["summary"]["control_requests"], 1);
    assert_eq!(
        report["paired_expressions"][0]["estimates"][0]["baseline_length"],
        1
    );
    assert_eq!(
        report["paired_expressions"][0]["estimated_lengths"],
        serde_json::json!([3])
    );
    assert!(String::from_utf8(stdout)
        .unwrap()
        .contains("  Groups without control: 2"));
}

#[test]
fn response_sizes_nested_casts_belong_to_the_outer_shape_but_independent_shapes_are_excluded() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let control = body("SELECT 1", "/items", true);
    let read = body("SELECT CAST((x) AS CHAR) FROM t", "/items", true);
    let mut log = line("192.0.2.8", "/batch", &control, 1000, 0, true);
    log += &line(
        "192.0.2.8",
        "/batch",
        &read,
        (1000 + read.len() - control.len() + 8) as u64,
        1,
        true,
    );
    // An invalid outer CAST does not hide the inner accepted wrapper.
    let invalid_control = "CAST((SELECT CAST((SELECT 1) AS CHAR) FROM t) AS NCHAR)";
    let invalid_read = invalid_control.replace("SELECT 1", "SELECT value FROM items");
    log += &line("192.0.2.8", "/batch", invalid_control, 1000, 0, true);
    log += &line(
        "192.0.2.8",
        "/batch",
        &invalid_read,
        (1000 + invalid_read.len() - invalid_control.len() + 2) as u64,
        1,
        true,
    );
    log += &line(
        "192.0.2.8",
        "/batch",
        "CAST((SELECT 1) AS CHAR) CAST((SELECT 2) AS CHAR)",
        1000,
        2,
        true,
    );
    log += &line(
        "192.0.2.8",
        "/batch",
        "CAST((SELECT 1) AS CHAR) ASCII(SUBSTR((SELECT name FROM items), 1, 1))",
        1000,
        2,
        true,
    );
    fs::write(&input, log).unwrap();
    let (report, _) = run(root.path(), &input, "out", &[]);
    assert_eq!(report["summary"]["requests_with_multiple_shapes"], 2);
    assert_eq!(report["summary"]["paired_requests"], 2);
    let rows = report["paired_expressions"].as_array().unwrap();
    let nested = rows
        .iter()
        .find(|r| r["expression"] == "select cast((x) as char) from t")
        .unwrap();
    assert_eq!(nested["estimated_lengths"], serde_json::json!([5]));
    let inner = rows
        .iter()
        .find(|r| r["expression"] == "select value from items")
        .unwrap();
    assert_eq!(inner["estimated_lengths"], serde_json::json!([3]));
}

#[test]
fn response_sizes_text_summarizes_counts_numbers_both_modes_and_truncates_lengths_only_on_screen() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let control = body("SELECT 1", "/items", true);
    let read = body("SELECT value FROM items", "/items", true);
    let mut log = line("192.0.2.8", "/batch", &control, 1000, 0, true);
    for length in 1..=12 {
        log += &line(
            "192.0.2.8",
            "/batch",
            &read,
            (1000 + read.len() - control.len() + 2 * (length - 1)) as u64,
            1,
            true,
        );
    }
    log += &line(
        "192.0.2.8",
        "/batch",
        "ASCII(SUBSTR((SELECT name FROM items), 1, 1))",
        900,
        2,
        true,
    );
    fs::write(&input, log).unwrap();
    let (report, stdout) = run(root.path(), &input, "default", &[]);
    let text = String::from_utf8(stdout).unwrap();
    assert!(text.contains("  Analyzed requests: 14\n"));
    assert!(text.contains("  Paired requests: 12\n"));
    assert!(!text.contains("Parse errors:"));
    assert!(!text.contains("Invalid UTF-8 lines:"));
    assert!(!text.contains("Observations beyond cap:"));
    assert!(!text.contains("Requests without required fields:"));
    for private in [
        "192.0.2.8",
        "select value",
        "select name",
        "/items",
        "example.test",
    ] {
        assert!(!text.contains(private));
    }
    let (_, stdout) = run(
        root.path(),
        &input,
        "shown",
        &["--show-expressions", "--limit", "0"],
    );
    let text = String::from_utf8(stdout).unwrap();
    assert!(
        text.contains("  1: paired requests 12 / estimated_lengths 1,2,3,4,5,6,7,8,9,10,... (+2)")
    );
    assert!(text.contains("  2: Character requests 1 / positions_probed 1 / max_position 1"));
    assert_eq!(
        report["paired_expressions"][0]["estimated_lengths"]
            .as_array()
            .unwrap()
            .len(),
        12
    );
    for name in [
        "response-sizes.json",
        "sanitized-response-sizes.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("default").join(name)).unwrap(),
            fs::read(root.path().join("shown").join(name)).unwrap()
        );
    }
    let (_, repeat) = run(
        root.path(),
        &input,
        "repeat-shown",
        &["--show-expressions", "--limit", "0"],
    );
    assert_eq!(text.as_bytes(), repeat);
    for name in [
        "response-sizes.json",
        "sanitized-response-sizes.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("shown").join(name)).unwrap(),
            fs::read(root.path().join("repeat-shown").join(name)).unwrap()
        );
    }
}

#[test]
fn response_sizes_query_and_form_plus_spaces_match_percent_spaces_without_changing_wire_counts() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    for location in ["target", "json-path", "form"] {
        for (encoding, control_space, read_space) in [
            ("plus", "+", "+"),
            ("percent", "%20", "%20"),
            ("mixed", "+", "%20"),
        ] {
            let request = |expression: &str, space: &str| {
                let query = format!("q=HEX(CAST(({expression})AS CHAR))").replace(' ', space);
                match location {
                    "target" => (format!("/items?{query}"), String::new()),
                    "json-path" => (
                        "/batch".into(),
                        format!(r#"{{"path":"/items?{query}","note":"literal+plus"}}"#),
                    ),
                    _ => ("/batch".into(), query),
                }
            };
            let (control_target, control_body) = request("SELECT 0x4f4b", control_space);
            let (read_target, read_body) = request("SELECT value FROM items", read_space);
            let request_delta = (read_target.len() + read_body.len()) as i64
                - (control_target.len() + control_body.len()) as i64;
            let mut log = line("192.0.2.8", &control_target, &control_body, 1000, 0, true);
            log += &line(
                "192.0.2.8",
                &read_target,
                &read_body,
                (1000 + request_delta + 12) as u64,
                1,
                true,
            );
            if location == "form" {
                log = log.replace(
                    "\"application/json\"",
                    "\"Application/X-WWW-Form-Urlencoded; charset=UTF-8\"",
                );
            }
            fs::write(&input, log).unwrap();
            let (report, _) = run(root.path(), &input, &format!("{location}-{encoding}"), &[]);
            assert_eq!(
                report["summary"]["control_requests"], 1,
                "{location}/{encoding}"
            );
            assert_eq!(report["summary"]["paired_requests"], 1);
            let row = &report["paired_expressions"][0];
            assert_eq!(row["expression"], "select value from items");
            assert_eq!(row["estimated_lengths"], serde_json::json!([8]));
            assert_eq!(row["estimates"][0]["baseline_length"], 2);
            assert_eq!(row["estimates"][0]["request_byte_delta"], request_delta);
            assert_eq!(row["estimates"][0]["adjusted_delta"], 12);
        }
    }
}

#[test]
fn response_sizes_encoded_and_non_query_pluses_stay_literal() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    for (index, (prefix, suffix, control, read)) in [
        (
            "/?q=",
            "",
            "HEX(CAST((SELECT+1)AS+CHAR))",
            "HEX(CAST((SELECT+1%2B1)AS+CHAR))",
        ),
        (
            "/?q=",
            "",
            "HEX(CAST((SELECT+1)AS+CHAR))",
            "HEX(CAST((SELECT+1%252B1)AS+CHAR))",
        ),
        (
            r#"{"path":"/items?q=x","query":""#,
            r#""}"#,
            "HEX(CAST((SELECT 1)AS CHAR))",
            "HEX(CAST((SELECT 1+1)AS CHAR))",
        ),
        (
            "/items?q=x ",
            "",
            "HEX(CAST((SELECT 1)AS CHAR))",
            "HEX(CAST((SELECT 1+1)AS CHAR))",
        ),
        (
            "--boundary\r\nContent-Disposition: form-data; name=value\r\n\r\n",
            "\r\n--boundary--",
            "HEX(CAST((SELECT 1)AS CHAR))",
            "HEX(CAST((SELECT 1+1)AS CHAR))",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let control = format!("{prefix}{control}{suffix}");
        let read = format!("{prefix}{read}{suffix}");
        let target_case = index < 2;
        let (control_target, control_body, read_target, read_body) = if target_case {
            (control.as_str(), "", read.as_str(), "")
        } else {
            ("/batch", control.as_str(), "/batch", read.as_str())
        };
        let delta = read.len() as i64 - control.len() as i64;
        let mut log = line("192.0.2.8", control_target, control_body, 1000, 0, false);
        log += &line(
            "192.0.2.8",
            read_target,
            read_body,
            (1000 + delta + 4) as u64,
            1,
            false,
        );
        if index == 4 {
            log = log.replace(
                "\"application/json\"",
                "\"multipart/form-data; boundary=boundary\"",
            );
        }
        fs::write(&input, log).unwrap();
        let (report, _) = run(root.path(), &input, &format!("literal-{index}"), &[]);
        assert_eq!(report["summary"]["paired_requests"], 1, "case {index}");
        assert_eq!(report["paired_expressions"][0]["expression"], "select 1+1");
        assert_eq!(
            report["paired_expressions"][0]["estimated_lengths"],
            serde_json::json!([3])
        );
    }
}

#[test]
fn response_sizes_negative_candidates_are_counted_sorted_private_and_reproducible() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let control = "CONCAT(0x7c7c,HEX(CAST((SELECT 0x4f4b)AS CHAR)),0x7c7c)";
    let read = "CONCAT(0x7c7c,HEX(CAST((SELECT value FROM items)AS CHAR)),0x7c7c)";
    let mut log = line("192.0.2.8", "/batch", control, 1000, 0, true);
    for second in 1..=3 {
        log += &line(
            "192.0.2.8",
            "/batch",
            read,
            (1000 + read.len() as i64 - control.len() as i64 - 8) as u64,
            second,
            true,
        );
    }
    fs::write(&input, &log).unwrap();
    let (report, stdout) = run(root.path(), &input, "default", &[]);
    let row = &report["paired_expressions"][0];
    assert_eq!(
        row["negative_candidates"],
        serde_json::json!([{"value":-2,"requests":3}])
    );
    assert_eq!(row["estimated_lengths"], serde_json::json!([]));
    assert_eq!(row["negative_estimate"], 3);
    assert_eq!(row["empty_or_null"], 0);
    assert!(row["estimates"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["adjusted_delta"] == -8 && e["estimated_length"].is_null()));
    let default_text = String::from_utf8(stdout).unwrap();
    let sanitized =
        fs::read_to_string(root.path().join("default/sanitized-response-sizes.json")).unwrap();
    for private in [
        "192.0.2.8",
        "example.test",
        "select value",
        "/batch",
        "negative_candidates",
        "negative: -2",
    ] {
        assert!(!default_text.contains(private));
        assert!(!sanitized.contains(private));
    }
    let (_, shown) = run(root.path(), &input, "shown", &["--show-expressions"]);
    assert!(String::from_utf8_lossy(&shown).contains("negative: -2 x3"));
    let (_, repeat) = run(root.path(), &input, "repeat", &["--show-expressions"]);
    assert_eq!(shown, repeat);
    for name in [
        "response-sizes.json",
        "sanitized-response-sizes.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(root.path().join("shown").join(name)).unwrap(),
            fs::read(root.path().join("repeat").join(name)).unwrap()
        );
    }
    log += &line(
        "192.0.2.8",
        "/batch",
        read,
        (1000 + read.len() as i64 - control.len() as i64 - 10) as u64,
        4,
        true,
    );
    fs::write(&input, log).unwrap();
    let (sorted, _) = run(root.path(), &input, "sorted", &[]);
    assert_eq!(
        sorted["paired_expressions"][0]["negative_candidates"],
        serde_json::json!([{"value":-3,"requests":1},{"value":-2,"requests":3}])
    );
}

#[test]
fn response_sizes_hostless_prefixes_and_parse_error_subsets_do_not_change_other_parsers() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for file in ["access.log", "access_443.log"] {
        let raw = line("192.0.2.8", "/batch", "ordinary", 1000, 0, true)
            .replace("example.test_access_443.log", file);
        // The expanded prefix acceptance is deliberately limited to response-sizes.
        assert!(parse_combined_line(raw.trim_end(), AccessLogFormat::NginxPostdata).is_err());
        log += &raw;
    }
    let control = body("SELECT 1", "/items", true);
    let read = body("SELECT value FROM items", "/items", true);
    log += &line("192.0.2.8", "/batch", &control, 1000, 0, true)
        .replace("example.test_access_443.log", "access.log");
    log += &line(
        "192.0.2.8",
        "/batch",
        &read,
        (1000 + read.len() - control.len() + 4) as u64,
        1,
        true,
    )
    .replace("example.test_access_443.log", "access_443.log");
    let truncated = line("192.0.2.8", "/batch", "cut", 1000, 2, false);
    log += truncated.strip_suffix("]\n").unwrap();
    log += "\n2026/01/01 00:00:03 [error] synthetic error mentioning postdata[\nnot a record\n";
    let oversized = line("192.0.2.8", "/batch", &"x".repeat(65_536), 1000, 3, false);
    log += &oversized;
    log += oversized.strip_suffix("]\n").unwrap();
    log += "\n";
    fs::write(&input, log).unwrap();
    let (report, stdout) = run(root.path(), &input, "out", &[]);
    assert_eq!(report["summary"]["parseable_records"], 4);
    assert_eq!(report["summary"]["parse_errors"], 5);
    assert_eq!(report["summary"]["truncated_body"], 2);
    assert_eq!(report["summary"]["error_log_lines"], 1);
    assert!(report["paired_expressions"][0]["host"].is_null());
    assert_eq!(
        report["paired_expressions"][0]["estimated_lengths"],
        serde_json::json!([3])
    );
    let text = String::from_utf8(stdout).unwrap();
    assert!(text.contains("  Truncated body: 2"));
    assert!(text.contains("  Error log lines: 1"));
    let sanitized: Value = serde_json::from_slice(
        &fs::read(root.path().join("out/sanitized-response-sizes.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sanitized["parse_errors"], 5);
    assert_eq!(sanitized["truncated_body"], 2);
    assert_eq!(sanitized["error_log_lines"], 1);
}

fn postdata_with_invalid_utf8_between_valid_records() -> Vec<u8> {
    let control = body("SELECT 1", "/items", true);
    let read = body("SELECT value FROM items", "/items", true);
    let mut log = line("192.0.2.8", "/batch", &control, 1000, 0, true).into_bytes();
    let mut invalid = line("192.0.2.8", "/batch", "ordinary", 1000, 1, true).into_bytes();
    let agent = b"fixture-agent";
    let offset = invalid
        .windows(agent.len())
        .position(|v| v == agent)
        .unwrap();
    invalid.splice(offset..offset + agent.len(), [0xff, 0xfe]);
    log.extend(invalid);
    log.extend(
        line(
            "192.0.2.8",
            "/batch",
            &read,
            (1000 + read.len() - control.len() + 4) as u64,
            2,
            true,
        )
        .bytes(),
    );
    log
}

#[test]
fn response_sizes_invalid_utf8_is_counted_and_reading_continues_in_plain_and_gzip_inputs() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let log = postdata_with_invalid_utf8_between_valid_records();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&log).unwrap();
    let gzip = gzip.finish().unwrap();
    for (name, bytes) in [
        ("plain.log", log.as_slice()),
        ("compressed.gz", gzip.as_slice()),
    ] {
        let input = root.path().join(name);
        fs::write(&input, bytes).unwrap();
        let output = format!("{name}-out");
        let repeat_output = format!("{name}-repeat");
        let (report, stdout) = run(root.path(), &input, &output, &[]);
        assert_eq!(report["summary"]["parse_errors"], 1);
        assert_eq!(report["summary"]["invalid_utf8_lines"], 1);
        assert_eq!(report["summary"]["truncated_body"], 0);
        assert_eq!(report["summary"]["error_log_lines"], 0);
        assert_eq!(report["summary"]["parseable_records"], 2);
        assert_eq!(report["summary"]["analyzed_requests"], 2);
        assert_eq!(report["summary"]["paired_requests"], 1);
        assert_eq!(
            report["paired_expressions"][0]["estimated_lengths"],
            serde_json::json!([3])
        );
        assert!(String::from_utf8_lossy(&stdout).contains("  Invalid UTF-8 lines: 1\n"));
        let sanitized: Value = serde_json::from_slice(
            &fs::read(
                root.path()
                    .join(&output)
                    .join("sanitized-response-sizes.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(sanitized["parse_errors"], 1);
        assert_eq!(sanitized["invalid_utf8_lines"], 1);
        let (_, repeat) = run(root.path(), &input, &repeat_output, &[]);
        assert_eq!(stdout, repeat);
        for artifact in [
            "response-sizes.json",
            "sanitized-response-sizes.json",
            "run-manifest.json",
        ] {
            assert_eq!(
                fs::read(root.path().join(&output).join(artifact)).unwrap(),
                fs::read(root.path().join(&repeat_output).join(artifact)).unwrap()
            );
        }
    }
}

#[test]
fn response_sizes_truncated_gzip_remains_a_fatal_read_error_without_artifacts() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("truncated.gz");
    let output = root.path().join("out");
    let log = line(
        "192.0.2.8",
        "/batch",
        &body("SELECT 1", "/items", true),
        1000,
        0,
        true,
    )
    .repeat(3);
    // Stored DEFLATE blocks make a midpoint cut land inside the body, not the trailer.
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    gzip.write_all(log.as_bytes()).unwrap();
    let mut gzip = gzip.finish().unwrap();
    gzip.truncate(gzip.len() / 2);
    assert_eq!(&gzip[..3], &[0x1f, 0x8b, 0x08]);
    fs::write(&input, gzip).unwrap();
    command(root.path())
        .args(["response-sizes", "--format", "nginx-postdata", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .assert()
        .failure()
        .stderr(predicates::str::contains("reading decoded input:"));
    for artifact in [
        "response-sizes.json",
        "sanitized-response-sizes.json",
        "run-manifest.json",
    ] {
        assert!(!output.join(artifact).exists());
    }
}

#[test]
fn legacy_postdata_reader_keeps_its_invalid_utf8_handling() {
    use shenron::access_log::AccessLogLines;
    let log = postdata_with_invalid_utf8_between_valid_records();
    let mut lines = AccessLogLines::with_raw_retention(
        std::io::Cursor::new(log),
        AccessLogFormat::NginxPostdata,
        RawRetention::Drop,
    );
    assert!(lines.next().unwrap().is_ok());
    assert!(lines.next().unwrap().is_err());
    // The legacy read_line path still records this as an I/O error and continues.
    assert!(lines.io_error().is_some());
    assert!(lines.next().unwrap().is_ok());
    assert!(lines.next().is_none());
}

#[test]
fn response_sizes_counts_prefixed_error_records_by_content_not_filename() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    let mut log = String::new();
    for filename in [
        "error.log",
        "example.test_error_443.log",
        "misc.log",
        "example.test_access.log",
    ] {
        log += &format!("2026 Jan 01 00:00:00 (fixture) 192.0.2.1->/var/log/nginx/{filename} 2026/01/01 00:00:00 [error] synthetic message\n");
    }
    // A prefix without a .log suffix remains an ordinary parse error.
    log += "2026 Jan 01 00:00:00 (fixture) 192.0.2.1->/var/log/nginx/error.txt 2026/01/01 00:00:00 [error] synthetic message\n";
    fs::write(&input, log).unwrap();
    let (report, stdout) = run(root.path(), &input, "out", &[]);
    assert_eq!(report["summary"]["parse_errors"], 5);
    assert_eq!(report["summary"]["error_log_lines"], 4);
    assert_eq!(report["summary"]["analyzed_requests"], 0);
    assert!(String::from_utf8(stdout)
        .unwrap()
        .contains("  Error log lines: 4\n"));
    let sanitized: Value = serde_json::from_slice(
        &fs::read(root.path().join("out/sanitized-response-sizes.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sanitized["error_log_lines"], 4);
}

#[test]
fn response_sizes_reads_access_records_under_any_log_prefix_and_only_extracts_access_hosts() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("access.log");
    for (index, (filename, host)) in [
        ("error.log", None),
        ("example.test_error_443.log", None),
        ("misc.log", None),
        (".log", None),
        ("access.log", None),
        ("access_443.log", None),
        ("example.test_access.log", Some("example.test")),
        ("example.test_access_443.log", Some("example.test")),
    ]
    .into_iter()
    .enumerate()
    {
        let control = body("SELECT 1", "/items", true);
        let read = body("SELECT value FROM items", "/items", true);
        let first = line("192.0.2.8", "/batch", &control, 1000, 0, true)
            .replace("example.test_access_443.log", filename);
        // The normal nginx-postdata parser keeps its original prefix rules.
        let legacy = parse_combined_line(first.trim_end(), AccessLogFormat::NginxPostdata);
        assert_eq!(legacy.is_ok(), host.is_some());
        let log = first
            + &line(
                "192.0.2.8",
                "/batch",
                &read,
                (1000 + read.len() - control.len() + 4) as u64,
                1,
                true,
            )
            .replace("example.test_access_443.log", filename);
        fs::write(&input, log).unwrap();
        let (report, _) = run(root.path(), &input, &format!("out-{index}"), &[]);
        assert_eq!(report["summary"]["parseable_records"], 2);
        assert_eq!(report["summary"]["parse_errors"], 0);
        assert_eq!(report["summary"]["error_log_lines"], 0);
        assert_eq!(report["summary"]["paired_requests"], 1);
        assert_eq!(
            report["paired_expressions"][0]["host"],
            serde_json::json!(host)
        );
        assert_eq!(
            report["paired_expressions"][0]["estimated_lengths"],
            serde_json::json!([3])
        );
    }
}
