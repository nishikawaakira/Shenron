use std::{fs, io::Write, path::Path};

use assert_cmd::Command;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use shenron::{
    access_log::{parse_combined_line, AccessLogFormat},
    aws_access_log::{
        parse_alb_line, AwsAccessLogFormat, AwsAccessLogLines, CLOUDFRONT_DEFAULT_FIELDS,
    },
    event::{HeaderCapability, LogSource, RawRetention, TelemetryProfile, TrustedProxySet},
    nuclei::coverage_for_telemetry,
};
use tempfile::tempdir;

const ALB: &str = include_str!("fixtures/alb/access.txt");
const CF: &str = include_str!("fixtures/cloudfront/access.txt");
const COOKIE: &str = "DO_NOT_RETAIN_CLOUDFRONT_COOKIE";

fn command(root: &Path) -> Command {
    let mut command = Command::cargo_bin("shenron").unwrap();
    command
        .env("SHENRON_DATA_DIR", root.join("empty-data"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("SHENRON_SLACK_WEBHOOK");
    command
}

fn read_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn alb_unparsed_request(request: &str) -> String {
    ALB.lines()
        .next()
        .unwrap()
        .replace(
            "\"GET https://example.test:443/.env?q=%252e+z HTTP/2.0\"",
            &format!("\"{request}\""),
        )
        .replacen(" 404 ", " 400 ", 1)
}

#[test]
fn alb_unparsed_requests_retain_observed_evidence_without_becoming_parse_errors() {
    for request in ["- - - ", "  -    -\t-  ", "- - -", "-"] {
        let input = alb_unparsed_request(request);
        let mut lines = AwsAccessLogLines::new(
            input.as_bytes(),
            AwsAccessLogFormat::Alb,
            RawRetention::Keep,
        );
        let event = lines.next().unwrap().unwrap();
        assert_eq!(event.source_ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(event.source_port, Some(54321));
        assert_eq!(event.status, Some(400));
        assert_eq!(event.response_bytes, Some(512));
        assert_eq!(
            event.timestamp.unwrap().to_rfc3339(),
            "2026-01-02T03:04:05.123456+00:00"
        );
        assert_eq!(event.user_agent.as_deref(), Some("Fixture/1.0"));
        assert_eq!(event.tls_protocol.as_deref(), Some("TLSv1.3"));
        assert_eq!(event.tls_cipher.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(event.request_id.as_deref(), Some("Root=fixture-request"));
        assert!(event.method.is_none() && event.protocol.is_none() && event.host.is_none());
        assert!(
            event.uri.is_none()
                && event.uri_path.is_none()
                && event.uri_query.is_none()
                && event.uri_fragment.is_none()
        );
        assert!(lines.next().is_none());
        let provenance = lines.parsing_provenance();
        assert_eq!(provenance.alb_unparsed_requests, Some(1));
        assert!(provenance.parse_error_reasons.is_empty());
    }
    let text = format!(
        "{}\n{}\n",
        alb_unparsed_request("GET - HTTP/1.1"),
        alb_unparsed_request("- - - ")
    );
    let mut lines =
        AwsAccessLogLines::new(text.as_bytes(), AwsAccessLogFormat::Alb, RawRetention::Drop);
    assert!(lines.next().unwrap().is_err());
    assert!(lines.next().unwrap().is_ok());
    assert_eq!(
        lines.parsing_provenance().parse_error_reasons,
        [("invalid-request".into(), 1)].into()
    );
    assert_eq!(lines.parsing_provenance().alb_unparsed_requests, Some(1));
    let mut cloudfront = AwsAccessLogLines::new(
        CF.as_bytes(),
        AwsAccessLogFormat::CloudFront,
        RawRetention::Drop,
    );
    assert!(cloudfront.next().unwrap().is_ok());
    assert!(serde_json::to_value(cloudfront.parsing_provenance())
        .unwrap()
        .get("alb_unparsed_requests")
        .is_none());
}

#[test]
fn alb_unparsed_requests_do_not_match_request_patterns_without_changing_cloudfront_matching() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("agent.yml"), "title: Synthetic UA\nid: fixture-agent\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    user_agent|contains: 'Fixture/1.0'\n  condition: selection\nlevel: low\n").unwrap();
    fs::write(dir.path().join("keyword.yml"), "title: Synthetic keyword\nid: fixture-keyword\nlogsource:\n  category: webserver\ndetection:\n  keywords:\n    - 'Fixture/1.0'\n  condition: keywords\nlevel: low\n").unwrap();
    let rules = shenron::sigma::load_rules(dir.path());
    assert_eq!(rules.supported.len(), 2);
    let event = parse_alb_line(&alb_unparsed_request("- - - "), RawRetention::Keep).unwrap();
    for rule in &rules.supported {
        assert!(!rule.matches(&event));
        assert!(!shenron::sigma::EventMatcher::new(&event).matches(rule));
        let mut cloudfront = event.clone();
        cloudfront.log_source = LogSource::CloudFront;
        assert!(rule.matches(&cloudfront));
    }
    let approved = ["synthetic-cve-2024-10001".to_owned()].into();
    let detections =
        shenron::nuclei::validated_detections(Path::new("tests/fixtures/nuclei"), &approved);
    assert!(!detections.is_empty());
    assert!(detections
        .iter()
        .all(|detection| !detection.matches(&event)));
}

#[test]
fn alb_unparsed_requests_reach_hunt_concentration_probe_ioc_and_context() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.txt");
    fs::write(
        &input,
        format!(
            "{}\n{}\n",
            alb_unparsed_request("- - - "),
            ALB.lines().next().unwrap()
        ),
    )
    .unwrap();
    let hunt = dir.path().join("hunt");
    command(dir.path())
        .args(["hunt", "--input"])
        .arg(&input)
        .args([
            "--format",
            "alb",
            "--no-nuclei",
            "--rules",
            "tests/fixtures/rules",
            "--include-source-references",
            "--output",
        ])
        .arg(&hunt)
        .assert()
        .success();
    let summary = read_json(hunt.join("sanitized-research.json"));
    assert_eq!(summary["metrics"]["total_requests_analyzed"], 2);
    assert_eq!(summary["metrics"]["parse_errors"], 0);
    assert!(summary["metrics"].get("parse_error_reasons").is_none());
    assert!(summary["metrics"].get("alb_unparsed_requests").is_none());
    assert!(!summary.to_string().contains("192.0.2.10"));
    assert_eq!(summary["metrics"]["fields_available"]["method"], 1);
    assert_eq!(summary["metrics"]["fields_available"]["uri"], 1);
    let manifest = read_json(hunt.join("run-manifest.json"));
    assert_eq!(
        manifest["inputs"]["corpus"][0]["input_parsing"]["alb_unparsed_requests"],
        1
    );

    let concentration = dir.path().join("concentration");
    command(dir.path())
        .args(["concentration", "--input"])
        .arg(&input)
        .args(["--format", "alb", "--output"])
        .arg(&concentration)
        .assert()
        .success();
    let report = read_json(concentration.join("request-concentration.json"));
    assert_eq!(report["summary"]["total_requests"], 2);
    assert_eq!(report["summary"]["requests_without_uri_path"], 1);
    assert_eq!(report["source_ips"][0]["requests"], 2);
    assert_eq!(report["paths"].as_array().unwrap().len(), 1);
    assert_eq!(report["paths"][0]["requests"], 1);
    let manifest = read_json(concentration.join("run-manifest.json"));
    assert_eq!(
        manifest["corpus"][0]["input_parsing"]["alb_unparsed_requests"],
        1
    );

    let probe = dir.path().join("probe");
    command(dir.path())
        .args(["probe-sources", "--input"])
        .arg(&input)
        .args(["--format", "alb", "--output"])
        .arg(&probe)
        .assert()
        .success();
    let report = read_json(probe.join("sanitized-research.json"));
    assert_eq!(report["parseable_records"], 2);
    assert_eq!(report["requests_without_path"], 1);
    assert_eq!(report["parse_errors"], 0);

    let indicators = dir.path().join("indicators.tsv");
    fs::write(&indicators, "ip\t192.0.2.10\n").unwrap();
    let ioc = dir.path().join("ioc");
    command(dir.path())
        .args(["ioc", "--input"])
        .arg(&input)
        .args(["--format", "alb", "--indicators"])
        .arg(&indicators)
        .arg("--output")
        .arg(&ioc)
        .assert()
        .success();
    let report = read_json(ioc.join("ioc-matches.json"));
    assert_eq!(report["indicators"][0]["matches"], 2);
    assert!(report["indicators"][0]["records"][0]["method"].is_null());
    assert!(report["indicators"][0]["records"][0]["path"].is_null());
    let result = command(dir.path())
        .args(["context", "--input"])
        .arg(&input)
        .args([
            "--format",
            "alb",
            "--source-ip",
            "192.0.2.10",
            "--show-request",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(report["counts"]["parseable_records"], 2);
    assert_eq!(report["counts"]["eligible_records"], 2);
    assert_eq!(report["counts"]["parse_errors"], 0);
    assert_eq!(report["records"].as_array().unwrap().len(), 2);
    assert!(report["records"][0]["method"].is_null());
    assert!(report["records"][0]["uri_path"].is_null());
}

#[test]
fn alb_maps_observed_fields_without_sni_target_status_or_synthetic_timings() {
    let events =
        AwsAccessLogLines::new(ALB.as_bytes(), AwsAccessLogFormat::Alb, RawRetention::Keep)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    assert_eq!(events.len(), 2);
    let event = &events[0];
    assert_eq!(event.log_source, LogSource::Alb);
    assert_eq!(
        event.timestamp.unwrap().to_rfc3339(),
        "2026-01-02T03:04:05.123456+00:00"
    );
    assert_eq!(event.source_ip.as_deref(), Some("192.0.2.10"));
    assert_eq!(event.source_port, Some(54321));
    assert_eq!(event.host.as_deref(), Some("example.test"));
    assert_eq!(event.method.as_deref(), Some("GET"));
    assert_eq!(event.protocol.as_deref(), Some("HTTP/2.0"));
    assert_eq!(event.uri.as_deref(), Some("/.env?q=%252e+z"));
    assert_eq!(event.uri_path.as_deref(), Some("/.env"));
    assert_eq!(event.uri_query.as_deref(), Some("q=%252e+z"));
    assert_eq!(event.status, Some(404));
    assert_eq!(event.response_bytes, Some(512));
    assert_eq!(event.user_agent.as_deref(), Some("Fixture/1.0"));
    assert_eq!(event.tls_protocol.as_deref(), Some("TLSv1.3"));
    assert_eq!(event.tls_cipher.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
    assert_eq!(event.request_id.as_deref(), Some("Root=fixture-request"));
    for event in &events {
        assert!(event.request_time_seconds.is_none());
        assert!(event.client_ip.is_none());
        assert!(event.country.is_none());
        assert!(event.referer.is_none());
        assert!(event.ja3.is_none());
        assert!(event.ja4.is_none());
        assert!(event.waf_action.is_none());
        assert!(event.request_body.is_none());
    }
    assert_eq!(events[1].source_ip.as_deref(), Some("2001:db8::10"));
    assert_eq!(events[1].response_bytes, Some(0));
    assert!(events[1].tls_protocol.is_none());
    assert!(events[1].tls_cipher.is_none());
    assert!(events[1].request_id.is_none());
}

#[test]
fn alb_accepts_tail_evolution_and_uses_the_combined_target_validation() {
    let line = ALB.lines().next().unwrap();
    let base = line.split(" \"sni.example.test\"").next().unwrap();
    for input in [
        base.to_owned(),
        format!("{base} future unknown \"extra fields\""),
        line.to_owned(),
    ] {
        let event = parse_alb_line(&input, RawRetention::Drop).unwrap();
        assert_eq!(event.uri_path.as_deref(), Some("/.env"));
        assert!(event.raw.is_empty());
    }
    let combined = r#"192.0.2.10 - - [02/Jan/2026:03:04:05 +0000] "GET /.env?q=%252e+z HTTP/2.0" 404 512 "-" "Fixture/1.0""#;
    let nginx = parse_combined_line(combined, AccessLogFormat::NginxCombined).unwrap();
    let alb = parse_alb_line(line, RawRetention::Drop).unwrap();
    assert_eq!(
        (alb.uri_path, alb.uri_query, alb.uri_fragment),
        (nginx.uri_path, nginx.uri_query, nginx.uri_fragment)
    );
    for target in ["bad%", "bad%2", "bad%zz"] {
        assert!(parse_alb_line(&line.replace("%252e+z", target), RawRetention::Drop).is_err());
        assert!(parse_combined_line(
            &combined.replace("%252e+z", target),
            AccessLogFormat::NginxCombined
        )
        .is_err());
    }
    let ipv6 = line.replace("example.test:443", "[2001:db8::1]:443");
    assert_eq!(
        parse_alb_line(&ipv6, RawRetention::Drop)
            .unwrap()
            .host
            .as_deref(),
        Some("2001:db8::1")
    );
    let absent = line.replacen(" 404 ", " - ", 1).replacen(" 512 ", " - ", 1);
    let event = parse_alb_line(&absent, RawRetention::Drop).unwrap();
    assert!(event.status.is_none());
    assert!(event.response_bytes.is_none());
}

#[test]
fn cloudfront_maps_fields_decodes_once_and_redacts_cookies_for_both_retention_modes() {
    for retention in [RawRetention::Keep, RawRetention::Drop] {
        let mut lines =
            AwsAccessLogLines::new(CF.as_bytes(), AwsAccessLogFormat::CloudFront, retention);
        let event = lines.next().unwrap().unwrap();
        assert_eq!(lines.line_number(), 3);
        assert_eq!(event.log_source, LogSource::CloudFront);
        assert_eq!(
            event.timestamp.unwrap().to_rfc3339(),
            "2026-01-02T03:04:05+00:00"
        );
        assert_eq!(event.source_ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(event.source_port, Some(54321));
        assert_eq!(event.host.as_deref(), Some("example.test"));
        assert_eq!(event.method.as_deref(), Some("GET"));
        assert_eq!(event.uri_path.as_deref(), Some("/.env"));
        assert_eq!(event.uri_query.as_deref(), Some("q=%252e+z"));
        assert_eq!(event.user_agent.as_deref(), Some("Fixture/1.0 A+B%20"));
        assert_eq!(
            event.referer.as_deref(),
            Some("https://example.test/origin?x=%20+")
        );
        assert_eq!(event.status, Some(404));
        assert_eq!(event.response_bytes, Some(512));
        assert_eq!(event.tls_protocol.as_deref(), Some("TLSv1.3"));
        assert_eq!(event.tls_cipher.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(event.protocol.as_deref(), Some("HTTP/2.0"));
        assert_eq!(event.request_id.as_deref(), Some("fixture-request"));
        assert!(event.client_ip.is_none());
        assert!(event.country.is_none());
        assert!(event.ja3.is_none());
        assert!(event.ja4.is_none());
        assert!(event.waf_action.is_none());
        assert!(!serde_json::to_string(&event).unwrap().contains(COOKIE));
        if retention == RawRetention::Keep {
            assert_eq!(event.raw.split('\t').nth(12), Some("-"));
        } else {
            assert!(event.raw.is_empty());
        }
        let mut trusted = event.clone();
        TrustedProxySet::new(vec!["192.0.2.0/24".parse().unwrap()]).resolve_client_ip(&mut trusted);
        assert_eq!(trusted.client_ip.as_deref(), Some("203.0.113.9"));
        let second = lines.next().unwrap().unwrap();
        assert!(second.host.is_none());
        assert!(second.uri_query.is_none());
        assert!(second.user_agent.is_none());
        assert!(second.referer.is_none());
        assert!(lines.next().is_none());
        assert_eq!(
            lines.parsing_provenance().cloudfront_default_fields,
            Some(false)
        );
        assert!(lines.parsing_provenance().parse_error_reasons.is_empty());
    }
}

#[test]
fn cloudfront_uses_fields_order_and_does_not_carry_headers_between_files() {
    let names = CLOUDFRONT_DEFAULT_FIELDS
        .split_whitespace()
        .collect::<Vec<_>>();
    let values = CF.lines().nth(2).unwrap().split('\t').collect::<Vec<_>>();
    let order = (0..names.len()).rev().collect::<Vec<_>>();
    let text = format!(
        "#Version: 1.0\n#Fields: {}\n{}\n",
        order
            .iter()
            .map(|i| names[*i])
            .collect::<Vec<_>>()
            .join(" "),
        order
            .iter()
            .map(|i| values[*i])
            .collect::<Vec<_>>()
            .join("\t")
    );
    let mut reordered = AwsAccessLogLines::new(
        text.as_bytes(),
        AwsAccessLogFormat::CloudFront,
        RawRetention::Keep,
    );
    let mut event = reordered.next().unwrap().unwrap();
    assert!(!event.raw.contains(COOKIE));
    event.raw.clear();
    let mut original = AwsAccessLogLines::new(
        CF.as_bytes(),
        AwsAccessLogFormat::CloudFront,
        RawRetention::Drop,
    );
    assert_eq!(
        serde_json::to_value(event).unwrap(),
        serde_json::to_value(original.next().unwrap().unwrap()).unwrap()
    );
    let no_header = format!("{}\n", CF.lines().nth(2).unwrap());
    let mut default = AwsAccessLogLines::new(
        no_header.as_bytes(),
        AwsAccessLogFormat::CloudFront,
        RawRetention::Keep,
    );
    assert_eq!(
        default.next().unwrap().unwrap().uri_path.as_deref(),
        Some("/.env")
    );
    assert_eq!(
        default.parsing_provenance().cloudfront_default_fields,
        Some(true)
    );
}

#[test]
fn aws_access_parse_failures_are_reasoned_and_do_not_consume_the_next_record() {
    let mut text = CF.replace("Fixture%2F1.0", "Fixture%ZZ");
    text.push_str("not\ta\tvalid\trecord\n");
    let mut reader = AwsAccessLogLines::new(
        text.as_bytes(),
        AwsAccessLogFormat::CloudFront,
        RawRetention::Drop,
    );
    assert!(reader.next().unwrap().is_err());
    assert!(reader.next().unwrap().is_ok());
    assert!(reader.next().unwrap().is_err());
    assert!(reader.next().is_none());
    assert_eq!(
        reader.parsing_provenance().parse_error_reasons,
        [("invalid-encoding".into(), 1), ("invalid-format".into(), 1)].into()
    );
    assert!(reader.io_error().is_none());
    let duplicate = "#Fields: date time c-ip cs-method cs-uri-stem cs(Cookie) cs(Cookie)\n";
    assert!(AwsAccessLogLines::new(
        duplicate.as_bytes(),
        AwsAccessLogFormat::CloudFront,
        RawRetention::Keep
    )
    .next()
    .unwrap()
    .is_err());
}

#[test]
fn aws_access_capabilities_and_nuclei_coverage_do_not_invent_headers_or_waf_fields() {
    let alb = TelemetryProfile::Alb.capabilities();
    let cf = TelemetryProfile::CloudFront.capabilities();
    for caps in [alb, cf] {
        assert!(
            caps.timestamp
                && caps.source_ip
                && caps.host
                && caps.method
                && caps.uri_path
                && caps.uri_query
        );
        assert!(
            caps.status
                && caps.response_bytes
                && caps.user_agent
                && caps.tls_protocol
                && caps.tls_cipher
        );
        assert!(
            !caps.client_ip
                && !caps.country
                && !caps.ja3
                && !caps.ja4
                && !caps.waf_action
                && !caps.waf_labels
                && !caps.request_body
        );
    }
    assert!(!alb.referer);
    assert!(cf.referer);
    assert_eq!(alb.headers, HeaderCapability::UserAgentOnly);
    assert_eq!(alb.union(alb).headers, HeaderCapability::UserAgentOnly);
    assert_eq!(alb.union(cf).headers, HeaderCapability::RefererAndUserAgent);
    for (source, profile) in [
        (LogSource::Alb, TelemetryProfile::Alb),
        (LogSource::CloudFront, TelemetryProfile::CloudFront),
    ] {
        assert_eq!(source.telemetry_profile(), profile);
        let report = coverage_for_telemetry(Path::new("tests/fixtures/nuclei"), profile, "fixture");
        assert!(report.metrics.http_cve_templates > 0);
        assert!(report.metrics.validated > 0);
    }
}

#[test]
fn aws_access_nuclei_validation_distinguishes_user_agent_referer_and_arbitrary_headers() {
    let dir = tempdir().unwrap();
    for (id, name) in [
        ("agent", "User-Agent"),
        ("referer", "Referer"),
        ("other", "X-Fixture"),
    ] {
        fs::write(dir.path().join(format!("{id}.yaml")), format!("id: fixture-{id}\ninfo:\n  name: Synthetic header\n  severity: low\n  classification:\n    cve-id: CVE-2099-10001\nhttp:\n  - method: GET\n    path:\n      - '{{{{BaseURL}}}}/synthetic-{id}'\n    headers:\n      {name}: 'fixture value'\n    matchers:\n      - type: word\n        words: ['fixture']\n")).unwrap();
    }
    for profile in [TelemetryProfile::Alb, TelemetryProfile::CloudFront] {
        let report = coverage_for_telemetry(dir.path(), profile, "fixture");
        assert_eq!(report.templates.len(), 3);
        for template in report.templates {
            let expected = template.template_id == "fixture-agent"
                || (profile == TelemetryProfile::CloudFront
                    && template.template_id == "fixture-referer");
            assert_eq!(
                template.convertible, expected,
                "{} {profile:?}",
                template.template_id
            );
            assert_eq!(
                template.validated, expected,
                "{} {profile:?}",
                template.template_id
            );
        }
    }
}

#[test]
fn aws_access_invalid_utf8_and_reader_failures_remain_distinct() {
    let mut bytes = b"\xff\xfe\n".to_vec();
    bytes.extend_from_slice(ALB.as_bytes());
    let mut lines = AwsAccessLogLines::new(
        bytes.as_slice(),
        AwsAccessLogFormat::Alb,
        RawRetention::Drop,
    );
    assert!(lines.next().unwrap().is_err());
    assert!(lines.io_error().is_none());
    assert_eq!(lines.filter(Result::is_ok).count(), 2);

    struct Broken;
    impl std::io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected read failure"))
        }
    }
    let mut lines =
        AwsAccessLogLines::new(Broken, AwsAccessLogFormat::CloudFront, RawRetention::Drop);
    assert!(lines.next().unwrap().is_err());
    assert_eq!(lines.io_error(), Some("injected read failure"));
    assert!(lines.next().is_none());
}

#[test]
fn legacy_input_provenance_does_not_gain_aws_parsing_metadata() {
    let legacy = json!({"path":"fixture.log", "byte_length":42, "sha256":"fixture"});
    let parsed: shenron::production::PathProvenance =
        serde_json::from_value(legacy.clone()).unwrap();
    assert!(parsed.input_parsing.is_none());
    assert_eq!(serde_json::to_value(parsed).unwrap(), legacy);
}

#[test]
fn cloudfront_replay_analyses_keep_fallback_provenance_private_and_disclose_parse_reasons() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("headerless.txt");
    fs::write(
        &input,
        format!(
            "{}\nbad\trecord\n",
            CF.lines().skip(2).collect::<Vec<_>>().join("\n")
        ),
    )
    .unwrap();
    let findings = dir.path().join("findings.jsonl");
    fs::write(&findings, "").unwrap();
    for subcommand in ["ablation", "replay", "count-hypotheses"] {
        let output = dir.path().join(format!("{subcommand}.json"));
        let mut cmd = command(dir.path());
        cmd.args([subcommand, "--input"])
            .arg(&input)
            .args([
                "--format",
                "cloudfront",
                "--nuclei-templates",
                "tests/fixtures/nuclei",
                "--nuclei-report",
                "tests/fixtures/production/nuclei-report.json",
                "--output",
            ])
            .arg(&output);
        if subcommand != "ablation" {
            cmd.arg("--findings").arg(&findings);
        }
        cmd.assert().success().stdout(predicates::str::contains(
            "Parse error reasons: invalid-timestamp: 1",
        ));
        let aggregate = read_json(&output);
        assert_eq!(aggregate["total_events_evaluated"], 2);
        assert_eq!(aggregate["parse_errors"], 1);
        assert_eq!(
            aggregate["parse_error_reasons"],
            json!({"invalid-timestamp":1})
        );
        for private in ["192.0.2.10", "/.env", "Fixture/1.0", "example.test", COOKIE] {
            assert!(!aggregate.to_string().contains(private));
        }
        let manifest = read_json(
            dir.path()
                .join(format!("{subcommand}.json.run-manifest.json")),
        );
        assert_eq!(
            manifest["corpus"][0]["input_parsing"]["cloudfront_default_fields"],
            true
        );
        assert_eq!(
            manifest["corpus"][0]["sha256"],
            format!("{:x}", Sha256::digest(fs::read(&input).unwrap()))
        );
    }
}

#[test]
fn alb_and_cloudfront_run_through_hunt_concentration_and_other_shared_readers() {
    let dir = tempdir().unwrap();
    for (format, fixture) in [("alb", "alb"), ("cloudfront", "cloudfront")] {
        let input = format!("tests/fixtures/{fixture}/access.txt");
        let hunt = dir.path().join(format!("hunt-{format}"));
        command(dir.path())
            .args([
                "hunt",
                "--input",
                &input,
                "--format",
                format,
                "--no-nuclei",
                "--rules",
                "tests/fixtures/rules",
                "--output",
            ])
            .arg(&hunt)
            .assert()
            .success();
        let metrics = read_json(hunt.join("sanitized-research.json"));
        assert_eq!(metrics["metrics"]["total_requests_analyzed"], 2);
        assert_eq!(metrics["metrics"]["parse_errors"], 0);
        assert_eq!(metrics["metrics"]["fields_available"]["tls_protocol"], 1);
        assert_eq!(
            metrics["metrics"]["fields_available"]["host"],
            if format == "alb" { 2 } else { 1 }
        );
        let output = dir.path().join(format!("concentration-{format}"));
        command(dir.path())
            .args([
                "concentration",
                "--input",
                &input,
                "--format",
                format,
                "--output",
            ])
            .arg(&output)
            .assert()
            .success();
        let private = read_json(output.join("request-concentration.json"));
        assert_eq!(private["summary"]["total_requests"], 2);
        let manifest = read_json(output.join("run-manifest.json"));
        assert!(
            manifest["corpus"][0]["input_parsing"]["parse_error_reasons"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        if format == "cloudfront" {
            assert_eq!(
                manifest["corpus"][0]["input_parsing"]["cloudfront_default_fields"],
                false
            );
        }
        command(dir.path())
            .args([
                "context",
                "--input",
                &input,
                "--format",
                format,
                "--source-ip",
                "192.0.2.10",
            ])
            .assert()
            .success()
            .stdout(predicates::str::contains("\"parseable_records\": 2"));
        command(dir.path())
            .args(["probe-sources", "--input", &input, "--format", format])
            .assert()
            .success();
    }
}

#[test]
fn cloudfront_private_findings_raw_keywords_references_and_provenance_exclude_cookies() {
    let dir = tempdir().unwrap();
    let rules = dir.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("observable.yml"), "title: Synthetic observable\nid: fixture-observable\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri-stem: '/.env'\n  condition: selection\nlevel: low\n").unwrap();
    fs::write(rules.join("cookie.yml"), format!("title: Cookie must not match\nid: fixture-cookie\nlogsource:\n  category: webserver\ndetection:\n  keywords:\n    - '{COOKIE}'\n  condition: keywords\nlevel: low\n")).unwrap();
    for format in ["alb", "cloudfront"] {
        for reference in [false, true] {
            let input = format!("tests/fixtures/{format}/access.txt");
            let output = dir.path().join(format!("run-{format}-{reference}"));
            let mut cmd = command(dir.path());
            cmd.args([
                "hunt",
                "--input",
                &input,
                "--format",
                format,
                "--no-nuclei",
                "--rules",
            ])
            .arg(&rules)
            .args(["--output"])
            .arg(&output)
            .arg("--uncompressed-findings");
            if reference {
                cmd.arg("--include-source-references");
            }
            cmd.assert().success();
            let findings = fs::read_to_string(output.join("private-findings.jsonl")).unwrap();
            assert_eq!(findings.lines().count(), 1);
            assert!(!findings.contains(COOKIE));
            assert!(!findings.contains("session="));
            let finding: Value = serde_json::from_str(findings.trim()).unwrap();
            assert_eq!(
                finding["log_source"],
                if format == "alb" {
                    "alb"
                } else {
                    "cloud_front"
                }
            );
            let triage = read_json(output.join("triage-view.json"));
            assert_eq!(triage["entities"][0]["behavior_score"]["reachable_max"], 85);
            if reference {
                assert_eq!(
                    finding["source_reference"]["line_number"],
                    if format == "alb" { 1 } else { 3 }
                );
            }
            for entry in fs::read_dir(&output).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    assert!(!fs::read_to_string(path).unwrap().contains(COOKIE));
                }
            }
            let sanitized = fs::read_to_string(output.join("sanitized-research.json")).unwrap();
            for private in ["192.0.2.10", "/.env", "Fixture/1.0", "example.test"] {
                assert!(!sanitized.contains(private));
            }
        }
    }
}
#[test]
fn aws_access_auto_detection_is_unambiguous_and_does_not_infer_headerless_cloudfront() {
    let dir = tempdir().unwrap();
    for fixture in ["alb", "cloudfront"] {
        let input = format!("tests/fixtures/{fixture}/access.txt");
        for format in ["auto", fixture] {
            let output = dir.path().join(format!("{fixture}-{format}"));
            command(dir.path())
                .args([
                    "concentration",
                    "--input",
                    &input,
                    "--format",
                    format,
                    "--output",
                ])
                .arg(&output)
                .assert()
                .success();
        }
        assert_eq!(
            fs::read(
                dir.path()
                    .join(format!("{fixture}-auto/request-concentration.json"))
            )
            .unwrap(),
            fs::read(
                dir.path()
                    .join(format!("{fixture}-{fixture}/request-concentration.json"))
            )
            .unwrap()
        );
    }
    let no_header = dir.path().join("no-header.log");
    fs::write(
        &no_header,
        CF.lines().skip(2).collect::<Vec<_>>().join("\n"),
    )
    .unwrap();
    command(dir.path())
        .args(["concentration", "--input"])
        .arg(&no_header)
        .assert()
        .failure();
    command(dir.path())
        .args(["concentration", "--input"])
        .arg(&no_header)
        .args(["--format", "cloudfront", "--output"])
        .arg(dir.path().join("explicit"))
        .assert()
        .success();
    let manifest = read_json(dir.path().join("explicit/run-manifest.json"));
    assert_eq!(
        manifest["corpus"][0]["input_parsing"]["cloudfront_default_fields"],
        true
    );
    // Existing format decisions remain covered by the original CLI fixtures.
    command(dir.path())
        .args(["daily", "--input", "tests/fixtures/production/waf.jsonl"])
        .assert()
        .success();
    command(dir.path())
        .args(["daily", "--input", "examples/demo/nginx-combined.log"])
        .assert()
        .failure();
}

#[test]
fn cloudfront_gzip_hashes_stored_bytes_and_discloses_reason_counts_reproducibly() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("access.log.gz");
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(format!("{CF}bad\trecord\n").as_bytes())
        .unwrap();
    let bytes = gzip.finish().unwrap();
    fs::write(&input, &bytes).unwrap();
    for name in ["first", "repeat"] {
        command(dir.path())
            .args(["concentration", "--input"])
            .arg(&input)
            .args(["--format", "cloudfront", "--output"])
            .arg(dir.path().join(name))
            .assert()
            .success();
    }
    for artifact in ["request-concentration.json", "sanitized-research.json"] {
        assert_eq!(
            fs::read(dir.path().join("first").join(artifact)).unwrap(),
            fs::read(dir.path().join("repeat").join(artifact)).unwrap()
        );
    }
    let manifest = read_json(dir.path().join("first/run-manifest.json"));
    let mut repeated_manifest = read_json(dir.path().join("repeat/run-manifest.json"));
    let mut stable_manifest = manifest.clone();
    stable_manifest
        .as_object_mut()
        .unwrap()
        .remove("generated_at");
    repeated_manifest
        .as_object_mut()
        .unwrap()
        .remove("generated_at");
    assert_eq!(stable_manifest, repeated_manifest);
    assert_eq!(
        manifest["corpus"][0]["sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    assert_eq!(
        manifest["corpus"][0]["input_parsing"]["parse_error_reasons"],
        json!({"invalid-format":1})
    );
    let sanitized = read_json(dir.path().join("first/sanitized-research.json"));
    assert_eq!(sanitized["parse_errors"], 1);
    assert_eq!(
        sanitized["parse_error_reasons"],
        json!({"invalid-format":1})
    );
}
