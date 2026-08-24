use std::{fs, io::Write};

use assert_cmd::Command;
use flate2::{write::GzEncoder, Compression};
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn scan_emits_two_deterministic_jsonl_findings_and_skips_bad_records() {
    let mut command = Command::cargo_bin("shenron").unwrap();
    command.args([
        "scan",
        "--input",
        "tests/fixtures/aws-waf",
        "--format",
        "aws-waf",
        "--rules",
        "tests/fixtures/rules",
    ]);
    let assertion = command.assert().success().stderr(
        predicate::str::contains("Events processed:    2")
            .and(predicate::str::contains("Findings:            2")),
    );
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout.lines().count(), 2);
    assert!(stdout.contains("CVE-2021-44228"));
    assert!(stdout.contains("known-suspicious-ja4"));
}

#[test]
fn scan_reads_gzip_and_writes_csv() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("waf.jsonl.gz");
    let output = directory.path().join("findings.csv");
    let mut encoder = GzEncoder::new(fs::File::create(&input).unwrap(), Compression::default());
    encoder
        .write_all(include_bytes!("fixtures/aws-waf/malicious.jsonl"))
        .unwrap();
    encoder.finish().unwrap();
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "scan",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "aws-waf",
            "--rules",
            "tests/fixtures/rules",
            "--output",
            output.to_str().unwrap(),
            "--output-format",
            "csv",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Findings:            2"));
    let csv = fs::read_to_string(output).unwrap();
    assert!(csv.starts_with("Timestamp,Level,RuleTitle"));
    assert_eq!(csv.lines().count(), 3);
}

#[test]
fn validate_reports_unsupported_features() {
    Command::cargo_bin("shenron")
        .unwrap()
        .args(["validate-rules", "--rules", "tests/fixtures/rules"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Unsupported:        1")
                .and(predicate::str::contains("modifier(s) `re`")),
        );
}
