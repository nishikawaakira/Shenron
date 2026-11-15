use std::{fs, io::Write, path::Path};

use assert_cmd::Command;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use shenron::{
    access_log::{parse_combined_line, AccessLogFormat},
    event::TelemetryProfile,
    production::HuntTimeRange,
    request_anomalies::{run, Feature, Options, Report},
};
use tempfile::tempdir;

fn command(root: &Path) -> Command {
    let mut command = Command::cargo_bin("shenron").unwrap();
    command
        .env("SHENRON_DATA_DIR", root.join("empty-data"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("SHENRON_SLACK_WEBHOOK");
    command
}

fn waf(uri: &str, args: Option<&str>, source: &str, millis: i64) -> Value {
    let mut record = json!({"timestamp":millis,"responseCodeSent":200,
        "httpRequest":{"clientIp":source,"httpMethod":"GET","uri":uri,
            "headers":[{"name":"Host","value":"example.test"}]}});
    if let Some(args) = args {
        record["httpRequest"]["args"] = json!(args);
    }
    record
}

fn waf_report(target: &str, options: &Options) -> Report {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    fs::write(
        &input,
        waf(target, None, "192.0.2.1", 1767225600000).to_string(),
    )
    .unwrap();
    run(
        &input,
        TelemetryProfile::AwsWaf,
        &HuntTimeRange::default(),
        options,
        None,
    )
    .unwrap()
}

fn combined(request: &str, source: &str, status: &str) -> String {
    format!(
        r#"{source} - - [01/Jan/2026:00:00:00 +0000] "{request}" {status} 10 "-" "synthetic-agent""#
    )
}

fn read_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn byte_and_path_features_have_positive_and_negative_controls() {
    let options = Options {
        max_target_length: 32,
        ..Options::default()
    };
    let cases = [
        (Feature::DoubleEncoding, "/%252e", "/%2e"),
        (Feature::OverlongUtf8, "/%c0%ae", "/%c2%ae"),
        (Feature::NulByte, "/%00", "/%30%30"),
        (Feature::Crlf, "/%0d%0a", "/%20"),
        (Feature::ControlChar, "/%7f", "/%20"),
        (Feature::Traversal, "/a/../b", "/a/.../b"),
        (Feature::TraversalEncoded, "/a/%252e%252e%252f", "/a/%2e/b"),
        (Feature::BackslashPath, "/a%5c..%5cb", "/a%2fb"),
        (Feature::IisUnicode, "/%u002e", "/%u02e"),
        (Feature::InvalidPercentEscape, "/%zz", "/%2f"),
        (Feature::InvalidUtf8, "/%ff", "/%e3%81%82"),
        (
            Feature::LongTarget,
            "/abcdefghijklmnopqrstuvwxyz123456",
            "/abcdefghijklmnopqrstuvwxyz12345",
        ),
    ];
    for (feature, positive, negative) in cases {
        let report = waf_report(positive, &options);
        assert_eq!(
            report.summary.features[&feature].requests,
            1,
            "{} {positive}",
            feature.label()
        );
        let report = waf_report(negative, &options);
        assert_eq!(
            report.summary.features[&feature].requests,
            0,
            "{} {negative}",
            feature.label()
        );
    }
}

#[test]
fn decoding_is_limited_to_two_passes_and_traversal_uses_only_actual_path_segments() {
    let options = Options::default();
    for path in ["/%c1%9c", "/%e0%80%af", "/%f0%80%80%af"] {
        let report = waf_report(path, &options);
        assert_eq!(report.summary.features[&Feature::OverlongUtf8].requests, 1);
        assert_eq!(report.summary.features[&Feature::InvalidUtf8].requests, 1);
    }
    for path in ["/%e0%a0%80", "/%f0%90%80%80"] {
        assert_eq!(
            waf_report(path, &options).summary.features[&Feature::OverlongUtf8].requests,
            0
        );
    }
    for path in ["/..%2fsecret", "/%2e%2e/secret", "/%255c..%255csecret"] {
        let report = waf_report(path, &options);
        assert_eq!(
            report.summary.features[&Feature::TraversalEncoded].requests,
            1,
            "{path}"
        );
    }
    let report = waf_report("/../normal%20", &options);
    assert_eq!(report.summary.features[&Feature::Traversal].requests, 1);
    assert_eq!(
        report.summary.features[&Feature::TraversalEncoded].requests,
        0
    );
    let report = waf_report("/../%2e%2e/", &options);
    assert_eq!(report.summary.features[&Feature::Traversal].requests, 1);
    assert_eq!(
        report.summary.features[&Feature::TraversalEncoded].requests,
        1
    );
    let report = waf_report("/%25252e%25252e/", &options);
    assert_eq!(
        report.summary.features[&Feature::TraversalEncoded].requests,
        0
    );
    let report = waf_report("/safe?q=../%2e%2e/%5c", &options);
    for feature in [
        Feature::Traversal,
        Feature::TraversalEncoded,
        Feature::BackslashPath,
    ] {
        assert_eq!(report.summary.features[&feature].requests, 0);
    }
    for path in ["/%00", "/%0a", "/%0d"] {
        assert_eq!(
            waf_report(path, &options).summary.features[&Feature::ControlChar].requests,
            0
        );
    }
}

#[test]
fn path_parameter_traversal_matches_exact_dot_prefixes_at_each_decoding_depth() {
    let options = Options::default();
    for path in [
        "/a/..;/admin",
        "/a/..;jsessionid=x/admin",
        "/a/%2e%2e;/admin",
        "/a/..%3b/admin",
        "/a/%2e.%3B/admin",
        "/a/%252e%252e%253b/admin",
        r"/a\..;\admin",
        "/a%5c..%3b%5cadmin",
    ] {
        let report = waf_report(path, &options);
        assert_eq!(
            report.summary.features[&Feature::PathParameterTraversal].requests,
            1,
            "{path}"
        );
        assert_eq!(report.summary.features[&Feature::Traversal].requests, 0);
        assert_eq!(
            report.summary.features[&Feature::TraversalEncoded].requests,
            0
        );
        let example = &report.feature_examples[&Feature::PathParameterTraversal][0];
        assert_eq!(
            example.observed_in.iter().copied().collect::<Vec<_>>(),
            ["path"]
        );
    }
    for path in [
        "/a/...;/b",
        "/a/x..;/b",
        "/a/..b;/c",
        "/a/;/b",
        "/a/safe?p=..;/",
        "/a/safe?p=%2e%2e%3b/",
        "/a/%25252e%25252e%25253b/b",
    ] {
        let report = waf_report(path, &options);
        assert_eq!(
            report.summary.features[&Feature::PathParameterTraversal].requests,
            0,
            "{path}"
        );
        let summary = serde_json::to_value(&report.summary).unwrap();
        assert_eq!(
            summary["features"]["path-parameter-traversal"]["requests"],
            0
        );
    }
    for (path, traversal, encoded) in [("/a/../b", 1, 0), ("/a/..%2f", 0, 1)] {
        let report = waf_report(path, &options);
        assert_eq!(
            report.summary.features[&Feature::Traversal].requests,
            traversal
        );
        assert_eq!(
            report.summary.features[&Feature::TraversalEncoded].requests,
            encoded
        );
        assert_eq!(
            report.summary.features[&Feature::PathParameterTraversal].requests,
            0
        );
    }
    assert_eq!(Feature::ALL.len(), 18);
    assert!(Feature::ALL
        .windows(2)
        .all(|pair| pair[0].label() < pair[1].label()));
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let path = "/private/..;jsessionid=synthetic/admin";
    fs::write(
        &input,
        waf(path, None, "192.0.2.1", 1767225600000).to_string(),
    )
    .unwrap();
    let mut artifacts = Vec::new();
    for name in ["first", "repeat"] {
        let output = dir.path().join(name);
        run(
            &input,
            TelemetryProfile::AwsWaf,
            &HuntTimeRange::default(),
            &options,
            Some(&output),
        )
        .unwrap();
        artifacts
            .push(fs::read_to_string(output.join("sanitized-request-anomalies.json")).unwrap());
    }
    assert_eq!(artifacts[0], artifacts[1]);
    for private in [
        "192.0.2.1",
        path,
        "jsessionid=synthetic",
        input.to_str().unwrap(),
    ] {
        assert!(!artifacts[0].contains(private));
    }
}

#[test]
fn alb_request_placeholders_are_non_http_observations_without_rescue_or_invented_lines() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("alb.txt");
    let normal = include_str!("fixtures/alb/access.txt")
        .lines()
        .next()
        .unwrap()
        .replace(
            "GET https://example.test:443/.env?q=%252e+z HTTP/2.0",
            "GET https://example.test:443/normal HTTP/2.0",
        );
    let rows = [
        normal.clone(),
        normal.replace("GET https://example.test:443/normal HTTP/2.0", "- - - "),
        normal.replace("GET https://example.test:443/normal HTTP/2.0", "-"),
    ];
    fs::write(&input, rows.join("\n")).unwrap();
    let output = dir.path().join("output");
    let report = run(
        &input,
        TelemetryProfile::Alb,
        &HuntTimeRange::default(),
        &Options::default(),
        Some(&output),
    )
    .unwrap();
    assert_eq!(report.summary.parseable_records, 3);
    assert_eq!(report.summary.rescued_records, 0);
    assert_eq!(report.summary.parse_errors, 0);
    assert_eq!(report.summary.targets_unavailable, 2);
    assert_eq!(report.summary.requests_with_features, 2);
    for (feature, counts) in &report.summary.features {
        assert_eq!(
            counts.requests,
            if *feature == Feature::NonHttpRequestLine {
                2
            } else {
                0
            }
        );
    }
    let examples = &report.feature_examples[&Feature::NonHttpRequestLine];
    assert_eq!(
        examples
            .iter()
            .map(|example| example.line_number)
            .collect::<Vec<_>>(),
        [2, 3]
    );
    for example in examples {
        assert!(example.request_line.is_none() && example.raw_target.is_none());
        assert_eq!(
            example.observed_in.iter().copied().collect::<Vec<_>>(),
            ["request-line"]
        );
    }
    let sanitized = fs::read_to_string(output.join("sanitized-request-anomalies.json")).unwrap();
    for private in [
        "192.0.2.10",
        "example.test",
        "/normal",
        input.to_str().unwrap(),
    ] {
        assert!(!sanitized.contains(private));
    }
}

#[test]
fn unavailable_cloudfront_and_waf_targets_do_not_receive_alb_placeholder_features() {
    let dir = tempdir().unwrap();
    let cf = dir.path().join("cloudfront.txt");
    fs::write(&cf, "#Version: 1.0\n#Fields: date time c-ip cs-method cs-uri-stem\n2026-01-01\t00:00:00\t192.0.2.1\t-\t-\n").unwrap();
    let waf = dir.path().join("waf.jsonl");
    fs::write(
        &waf,
        json!({"timestamp":1767225600000_i64,"httpRequest":{"clientIp":"192.0.2.1"}}).to_string(),
    )
    .unwrap();
    for (input, profile) in [
        (&cf, TelemetryProfile::CloudFront),
        (&waf, TelemetryProfile::AwsWaf),
    ] {
        let report = run(
            input,
            profile,
            &HuntTimeRange::default(),
            &Options::default(),
            None,
        )
        .unwrap();
        assert_eq!(report.summary.parseable_records, 1);
        assert_eq!(report.summary.targets_unavailable, 1);
        assert_eq!(report.summary.rescued_records, 0);
        assert_eq!(report.summary.requests_with_features, 0);
        assert_eq!(
            report.summary.features[&Feature::NonHttpRequestLine].requests,
            0
        );
    }
}

#[test]
fn dedicated_combined_recovery_classifies_request_forms_without_changing_hunt() {
    let dir = tempdir().unwrap();
    let requests = [
        (
            "GET http://example.test/path HTTP/1.1",
            Feature::AbsoluteForm,
        ),
        ("CONNECT example.test:443 HTTP/1.1", Feature::AuthorityForm),
        ("OPTIONS * HTTP/1.1", Feature::AsteriskForm),
        (r"\x16\x03\x01\x00\xff", Feature::NonHttpRequestLine),
        ("", Feature::EmptyRequest),
        ("-", Feature::EmptyRequest),
        ("GET /%zz HTTP/1.1", Feature::InvalidPercentEscape),
    ];
    let mut text = format!("{}\n", combined("GET /normal HTTP/1.1", "192.0.2.1", "200"));
    for (request, _) in requests {
        let line = combined(request, "192.0.2.2", "400");
        assert!(parse_combined_line(&line, AccessLogFormat::NginxCombined).is_err());
        text.push_str(&line);
        text.push('\n');
    }
    text.push_str("unrelated malformed record\n");
    let input = dir.path().join("access.log");
    fs::write(&input, text).unwrap();
    let hunt = |name: &str| {
        let output = dir.path().join(name);
        command(dir.path())
            .args(["hunt", "--input"])
            .arg(&input)
            .args([
                "--format",
                "nginx",
                "--no-nuclei",
                "--rules",
                "tests/fixtures/rules",
                "--output",
            ])
            .arg(&output)
            .assert()
            .success();
        fs::read(output.join("sanitized-research.json")).unwrap()
    };
    let before = hunt("before");
    let report = run(
        &input,
        TelemetryProfile::NginxCombined,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    assert_eq!(report.summary.parseable_records, 1);
    assert_eq!(report.summary.rescued_records, 7);
    assert_eq!(report.summary.parse_errors, 1);
    assert_eq!(report.summary.analyzed_requests, 8);
    for (_, feature) in requests {
        assert!(report.summary.features[&feature].requests >= 1);
    }
    assert_eq!(report.summary.features[&Feature::EmptyRequest].requests, 2);
    assert_eq!(report.summary.features[&Feature::AbsoluteForm].requests, 1);
    assert_eq!(
        report.feature_examples[&Feature::AbsoluteForm][0].line_number,
        2
    );
    let after = hunt("after");
    assert_eq!(before, after);
    let hunt: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(hunt["metrics"]["parse_errors"], 8);
    assert_eq!(hunt["metrics"]["total_requests_analyzed"], 1);
    let normal = dir.path().join("normal.log");
    fs::write(
        &normal,
        combined("GET /normal HTTP/1.1", "192.0.2.1", "200"),
    )
    .unwrap();
    let report = run(
        &normal,
        TelemetryProfile::NginxCombined,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    for feature in [
        Feature::AbsoluteForm,
        Feature::AuthorityForm,
        Feature::AsteriskForm,
        Feature::NonHttpRequestLine,
        Feature::EmptyRequest,
    ] {
        assert_eq!(report.summary.features[&feature].requests, 0);
    }
}

#[test]
fn apache_vhost_missing_protocol_and_multilingual_request_lines_remain_observations() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("apache.log");
    fs::write(
        &input,
        format!(
            "example.test:443 {}\nexample.test:443 {}\n",
            combined("CONNECT example.test:443", "192.0.2.1", "400"),
            combined("GET /あ HTTP/1.1", "192.0.2.1", "200")
        ),
    )
    .unwrap();
    for profile in [
        TelemetryProfile::ApacheCombined,
        TelemetryProfile::ApacheVhostCombined,
    ] {
        let report = run(
            &input,
            profile,
            &HuntTimeRange::default(),
            &Options::default(),
            None,
        )
        .unwrap();
        assert_eq!(report.summary.rescued_records, 1);
        assert_eq!(report.summary.parseable_records, 1);
        assert_eq!(report.summary.features[&Feature::AuthorityForm].requests, 1);
        assert_eq!(
            report.summary.features[&Feature::NonHttpRequestLine].requests,
            2
        );
        assert_eq!(report.summary.features[&Feature::InvalidUtf8].requests, 0);
    }
    fs::write(
        &input,
        combined("GET HTTPS://example.test/path HTTP/1.1", "192.0.2.1", "200"),
    )
    .unwrap();
    let report = run(
        &input,
        TelemetryProfile::NginxCombined,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    assert_eq!(report.summary.features[&Feature::AbsoluteForm].requests, 1);
    assert_eq!(
        report.summary.features[&Feature::AbsoluteForm].distinct_paths,
        Some(1)
    );
}

#[test]
fn literal_binary_request_bytes_are_inspected_without_lossy_replacement_or_stopping() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("binary.log");
    let normal = combined("GET /safe HTTP/1.1", "192.0.2.1", "200");
    let binary = combined("BINARY", "192.0.2.2", "400");
    let mut bytes = format!("{normal}\n").into_bytes();
    // Replace only the request payload with synthetic ClientHello-like bytes.
    let (prefix, suffix) = binary.split_once("BINARY").unwrap();
    bytes.extend_from_slice(prefix.as_bytes());
    bytes.extend_from_slice(b"\x16\x03\x01\xff\x00");
    bytes.extend_from_slice(suffix.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(normal.as_bytes());
    fs::write(&input, bytes).unwrap();
    let report = run(
        &input,
        TelemetryProfile::NginxCombined,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    assert_eq!(report.summary.rescued_records, 1);
    assert_eq!(report.summary.parseable_records, 2);
    assert_eq!(report.summary.parse_errors, 0);
    assert_eq!(
        report.summary.features[&Feature::NonHttpRequestLine].requests,
        1
    );
    assert_eq!(report.summary.features[&Feature::InvalidUtf8].requests, 1);
    let example = &report.feature_examples[&Feature::NonHttpRequestLine][0];
    assert_eq!(example.line_number, 2);
    assert!(example.request_line.as_ref().unwrap().contains(r"\xff"));
    assert!(!serde_json::to_string(&report).unwrap().contains('\u{fffd}'));
}

#[test]
fn postdata_body_is_inspected_but_not_retained_and_plus_signs_stay_literal() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("body.log");
    let line = format!(
        r#"{} "application/json" "-" "-" 0.1 postdata[{{\x22value\x22:\x22%2500+\x22}}]"#,
        combined("GET /normal+path HTTP/1.1", "192.0.2.1", "200")
    );
    fs::write(&input, line).unwrap();
    let report = run(
        &input,
        TelemetryProfile::NginxPostdata,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    assert_eq!(report.summary.parseable_records, 1);
    assert_eq!(report.summary.request_bodies_unavailable, 0);
    assert_eq!(
        report.summary.features[&Feature::DoubleEncoding].requests,
        1
    );
    assert_eq!(report.summary.features[&Feature::NulByte].requests, 1);
    let example = &report.feature_examples[&Feature::NulByte][0];
    assert_eq!(example.raw_target.as_deref(), Some("/normal+path"));
    assert!(example.observed_in.contains("request-body"));
    assert!(!serde_json::to_string(&report).unwrap().contains("%2500"));
}

#[test]
fn waf_fixture_preserves_logged_uri_and_args_and_marks_redactions_unavailable() {
    let record = waf(
        "/raw%252e+path",
        Some("q=%2500+value"),
        "192.0.2.1",
        1767225600000,
    );
    let event = shenron::waf::parse_line(&record.to_string()).unwrap();
    assert_eq!(event.uri_path.as_deref(), Some("/raw%252e+path"));
    assert_eq!(event.uri_query.as_deref(), Some("q=%2500+value"));
    assert_eq!(event.uri.as_deref(), Some("/raw%252e+path?q=%2500+value"));
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    fs::write(
        &input,
        format!(
            "{}\n{}\n",
            record,
            waf("REDACTED", Some("REDACTED"), "192.0.2.2", 1767225601000)
        ),
    )
    .unwrap();
    let report = run(
        &input,
        TelemetryProfile::AwsWaf,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    assert_eq!(
        report.summary.features[&Feature::DoubleEncoding].requests,
        1
    );
    assert_eq!(report.summary.features[&Feature::NulByte].requests, 1);
    assert_eq!(report.summary.targets_unavailable, 1);
    assert_eq!(report.summary.paths_unavailable, 1);
    assert_eq!(report.summary.request_bodies_unavailable, 2);
}

#[test]
fn feature_counts_distributions_times_and_distinct_sets_are_request_based() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let a = waf("/%2500/%2500", None, "::ffff:192.0.2.1", 1767225601000);
    let mut b = waf("/%2500/%2500", None, "192.0.2.1", 1767225600000);
    b["responseCodeSent"] = json!(404);
    fs::write(&input, format!("{a}\n{b}\n")).unwrap();
    let report = run(
        &input,
        TelemetryProfile::AwsWaf,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    let feature = &report.summary.features[&Feature::DoubleEncoding];
    assert_eq!(feature.requests, 2);
    assert_eq!(feature.distinct_sources, Some(1));
    assert_eq!(feature.distinct_paths, Some(1));
    assert_eq!(feature.status_classes.success, 1);
    assert_eq!(feature.status_classes.client_error, 1);
    assert_eq!(feature.responses_2xx, 1);
    assert!(feature.first_seen < feature.last_seen);
    assert_eq!(report.sources.len(), 1);
    assert_eq!(report.sources[0].source, "192.0.2.1");
    assert_eq!(report.sources[0].requests_with_features, 2);
    assert_eq!(report.summary.requests_with_features, 2);
}

#[test]
fn exact_caps_disclose_omissions_and_keep_known_keys_counting() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    let lines = [
        ("/%252e/a", "192.0.2.1"),
        ("/%252e/b", "::ffff:192.0.2.1"),
        ("/%252e/c", "192.0.2.2"),
    ]
    .into_iter()
    .map(|(p, ip)| waf(p, None, ip, 1767225600000).to_string())
    .collect::<Vec<_>>()
    .join("\n");
    fs::write(&input, lines).unwrap();
    let options = Options {
        max_examples: 1,
        max_source_ips: 1,
        max_paths_per_feature: 1,
        limit: 1,
        ..Options::default()
    };
    let report = run(
        &input,
        TelemetryProfile::AwsWaf,
        &HuntTimeRange::default(),
        &options,
        None,
    )
    .unwrap();
    let feature = &report.summary.features[&Feature::DoubleEncoding];
    assert_eq!(feature.requests, 3);
    assert_eq!(feature.distinct_sources, None);
    assert_eq!(feature.distinct_sources_at_least, 1);
    assert_eq!(feature.source_observations_beyond_tracking_cap, 1);
    assert_eq!(feature.distinct_paths, None);
    assert_eq!(feature.distinct_paths_at_least, 1);
    assert_eq!(feature.path_observations_beyond_tracking_cap, 2);
    assert_eq!(feature.examples_omitted, 2);
    assert_eq!(report.feature_examples[&Feature::DoubleEncoding].len(), 1);
    assert_eq!(report.summary.requests_beyond_source_tracking_cap, 1);
    assert_eq!(report.sources[0].requests_with_features, 2);
    let options = Options {
        limit: 1,
        ..Options::default()
    };
    let report = run(
        &input,
        TelemetryProfile::AwsWaf,
        &HuntTimeRange::default(),
        &options,
        None,
    )
    .unwrap();
    assert_eq!(report.summary.sources_not_reported, 1);
}

#[test]
fn utc_windows_exclude_rescued_records_without_losing_quality_counts() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log");
    fs::write(&input, combined("OPTIONS * HTTP/1.1", "192.0.2.1", "200")).unwrap();
    let range = HuntTimeRange {
        from: Some("2026-01-02T00:00:00Z".parse().unwrap()),
        to: None,
    };
    let report = run(
        &input,
        TelemetryProfile::NginxCombined,
        &range,
        &Options::default(),
        None,
    )
    .unwrap();
    assert_eq!(report.summary.rescued_records, 1);
    assert_eq!(report.summary.records_outside_time_range, 1);
    assert_eq!(report.summary.analyzed_requests, 0);
    assert_eq!(report.summary.features[&Feature::AsteriskForm].requests, 0);
}

#[test]
fn gzip_artifacts_and_cli_output_are_private_gated_and_byte_reproducible() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.txt");
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(
        format!(
            "\n{}\n",
            combined("GET /private%252e?q=%2500 HTTP/1.1", "192.0.2.7", "200")
        )
        .as_bytes(),
    )
    .unwrap();
    let bytes = gzip.finish().unwrap();
    fs::write(&input, &bytes).unwrap();
    let mut stdout = Vec::new();
    for name in ["a", "b"] {
        let output = dir.path().join(name);
        stdout.push(
            command(dir.path())
                .args(["request-anomalies", "--input"])
                .arg(&input)
                .args(["--format", "nginx", "--output"])
                .arg(&output)
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        );
    }
    assert_eq!(stdout[0], stdout[1]);
    for artifact in [
        "request-anomalies.json",
        "sanitized-request-anomalies.json",
        "run-manifest.json",
    ] {
        assert_eq!(
            fs::read(dir.path().join("a").join(artifact)).unwrap(),
            fs::read(dir.path().join("b").join(artifact)).unwrap()
        );
    }
    let sanitized =
        fs::read_to_string(dir.path().join("a/sanitized-request-anomalies.json")).unwrap();
    let default_stdout = String::from_utf8(stdout[0].clone()).unwrap();
    for private in [
        "192.0.2.7",
        "/private",
        "%252e",
        "%2500",
        "access.txt",
        dir.path().to_str().unwrap(),
    ] {
        assert!(!sanitized.contains(private));
        assert!(!default_stdout.contains(private));
    }
    let manifest = read_json(dir.path().join("a/run-manifest.json"));
    assert_eq!(
        manifest["corpus"][0]["sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    assert_eq!(manifest["decoding_passes"], 2);
    assert_eq!(manifest["plus_is_space"], false);
    let private = read_json(dir.path().join("a/request-anomalies.json"));
    assert_eq!(
        private["feature_examples"]["double-encoding"][0]["line_number"],
        2
    );
    let result = command(dir.path())
        .args(["request-anomalies", "--input"])
        .arg(&input)
        .args([
            "--format",
            "nginx",
            "--output-format",
            "json",
            "--show-examples",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let view: Value = serde_json::from_slice(&result).unwrap();
    assert!(view.get("sources").is_none());
    assert!(view["feature_examples"]["double-encoding"][0]
        .get("source")
        .is_none());
    assert!(view.to_string().contains("/private%252e"));
    command(dir.path())
        .args(["request-anomalies", "--input"])
        .arg(&input)
        .args(["--format", "nginx", "--show-source-ips"])
        .assert()
        .success()
        .stdout(predicates::str::contains("192.0.2.7"));
}

#[test]
fn missing_fields_remain_unavailable_and_source_paths_are_not_invented() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("waf.jsonl");
    fs::write(&input, json!({"httpRequest":{"uri":"/%2500"}}).to_string()).unwrap();
    let report = run(
        &input,
        TelemetryProfile::AwsWaf,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    let counts = &report.summary.features[&Feature::NulByte];
    assert_eq!(counts.requests, 1);
    assert_eq!(counts.distinct_sources, None);
    assert_eq!(counts.distinct_sources_at_least, 0);
    assert_eq!(counts.requests_without_source, 1);
    assert_eq!(counts.requests_without_timestamp, 1);
    assert_eq!(counts.status_classes.unavailable, 1);
    assert_eq!(counts.responses_2xx, 0);
    assert_eq!(report.summary.request_lines_unavailable, 1);
    assert!(counts.first_seen.is_none() && counts.last_seen.is_none());
    fs::write(
        &input,
        combined("CONNECT example.test:443 HTTP/1.1", "192.0.2.1", "200"),
    )
    .unwrap();
    let report = run(
        &input,
        TelemetryProfile::NginxCombined,
        &HuntTimeRange::default(),
        &Options::default(),
        None,
    )
    .unwrap();
    assert_eq!(
        report.summary.features[&Feature::AuthorityForm].distinct_paths,
        None
    );
    assert_eq!(
        report.summary.features[&Feature::AuthorityForm].requests_without_path,
        1
    );
}

#[test]
fn shared_discovery_sorts_before_example_admission_and_rejects_broken_gzip() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("logs");
    fs::create_dir(&input).unwrap();
    for name in ["b.txt", "a.txt"] {
        fs::write(
            input.join(name),
            combined("OPTIONS * HTTP/1.1", "192.0.2.1", "200"),
        )
        .unwrap();
    }
    fs::write(input.join(".private-hidden"), "not a record").unwrap();
    let options = Options {
        max_examples: 1,
        ..Options::default()
    };
    let report = run(
        &input,
        TelemetryProfile::NginxCombined,
        &HuntTimeRange::default(),
        &options,
        None,
    )
    .unwrap();
    assert_eq!(report.summary.input_discovery.files_skipped, 1);
    assert_eq!(report.summary.features[&Feature::AsteriskForm].requests, 2);
    assert!(report.feature_examples[&Feature::AsteriskForm][0]
        .input_file
        .ends_with("a.txt"));
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(combined("OPTIONS * HTTP/1.1", "192.0.2.1", "200").as_bytes())
        .unwrap();
    let mut bytes = gzip.finish().unwrap();
    bytes.truncate(bytes.len() - 7);
    let broken = dir.path().join("broken.gz");
    fs::write(&broken, bytes).unwrap();
    let output = dir.path().join("output");
    assert!(run(
        &broken,
        TelemetryProfile::NginxCombined,
        &HuntTimeRange::default(),
        &options,
        Some(&output)
    )
    .is_err());
    assert!(!output.join("request-anomalies.json").exists());
    assert!(!output.join("sanitized-request-anomalies.json").exists());
    assert!(!output.join("run-manifest.json").exists());
}
