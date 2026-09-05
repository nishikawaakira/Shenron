use std::{fs, io::Write};

use assert_cmd::Command;
use flate2::{write::GzEncoder, Compression};
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn hunt_stdout_mode_emits_private_jsonl_without_creating_artifacts() {
    let directory = tempdir().unwrap();
    let project = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::cargo_bin("shenron").unwrap();
    command
        .current_dir(directory.path())
        .env("SHENRON_DATA_DIR", directory.path().join("empty-data"))
        .args([
            "hunt",
            "--input",
            project.join("tests/fixtures/aws-waf").to_str().unwrap(),
            "--format",
            "aws-waf",
            "--rules",
            project.join("tests/fixtures/rules").to_str().unwrap(),
            "--no-nuclei",
        ])
        .env(
            "SHENRON_SLACK_WEBHOOK",
            "https://hooks.invalid/never-contact",
        );
    let assertion = command.assert().success().stderr(
        predicate::str::contains("Requests analyzed: 2")
            .and(predicate::str::contains(
                "No run directory or artifact files were created.",
            ))
            .and(predicate::str::contains(
                "Slack notification skipped (requires --output)",
            )),
    );
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout.lines().count(), 2);
    assert!(stdout.contains("CVE-2021-44228"));
    assert!(stdout.contains("known-suspicious-ja4"));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

    let artifact_output = directory.path().join("run");
    Command::cargo_bin("shenron")
        .unwrap()
        .current_dir(directory.path())
        .args([
            "hunt",
            "--input",
            project.join("tests/fixtures/aws-waf").to_str().unwrap(),
            "--format",
            "aws-waf",
            "--rules",
            project.join("tests/fixtures/rules").to_str().unwrap(),
            "--no-nuclei",
            "--output",
            artifact_output.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(
        stdout.as_bytes(),
        fs::read(artifact_output.join("private-findings.jsonl"))
            .unwrap()
            .as_slice()
    );
    for artifact in [
        "private-findings.jsonl",
        "sanitized-research.json",
        "run-manifest.json",
        "request-concentration.json",
        "triage-view.json",
    ] {
        assert!(
            artifact_output.join(artifact).is_file(),
            "missing {artifact}"
        );
    }
}

#[test]
fn hunt_stdout_mode_requires_output_for_artifact_dependent_options() {
    for arguments in [
        vec!["--report"],
        vec!["--baseline", "prior-run"],
        vec!["--baseline-latest", "run-root"],
        vec!["--observation-store", "memory.jsonl"],
    ] {
        let mut command = Command::cargo_bin("shenron").unwrap();
        command.args([
            "hunt",
            "--input",
            "tests/fixtures/aws-waf/malicious.jsonl",
            "--format",
            "aws-waf",
            "--no-nuclei",
            "--rules",
            "tests/fixtures/rules",
        ]);
        command
            .args(arguments)
            .assert()
            .failure()
            .stderr(predicate::str::contains("requires --output <DIR>"));
    }
}

#[test]
fn hunt_rejects_disabling_both_detection_paths() {
    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "hunt",
            "--input",
            "tests/fixtures/aws-waf/malicious.jsonl",
            "--format",
            "aws-waf",
            "--no-nuclei",
            "--no-sigma",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--no-nuclei and --no-sigma cannot be combined",
        ));
}

#[test]
fn hunt_without_no_nuclei_still_requires_prepared_inputs() {
    let directory = tempdir().unwrap();
    Command::cargo_bin("shenron")
        .unwrap()
        .current_dir(directory.path())
        .env("SHENRON_DATA_DIR", directory.path().join("empty-data"))
        .args([
            "hunt",
            "--input",
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/aws-waf/malicious.jsonl")
                .to_str()
                .unwrap(),
            "--format",
            "aws-waf",
            "--no-sigma",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "first run `shenron nuclei update`",
        ));
}

#[test]
fn hunt_stdout_mode_reads_gzip_and_emits_flattened_csv() {
    let directory = tempdir().unwrap();
    let project = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let input = directory.path().join("waf.jsonl.gz");
    let mut encoder = GzEncoder::new(fs::File::create(&input).unwrap(), Compression::default());
    encoder
        .write_all(include_bytes!("fixtures/aws-waf/malicious.jsonl"))
        .unwrap();
    encoder.finish().unwrap();
    let assertion = Command::cargo_bin("shenron")
        .unwrap()
        .current_dir(directory.path())
        .args([
            "hunt",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "aws-waf",
            "--rules",
            project.join("tests/fixtures/rules").to_str().unwrap(),
            "--no-nuclei",
            "--output-format",
            "csv",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Sigma-matched requests: 1"));
    let csv = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(csv.starts_with("Source,TemplateID,CVEs,Detectability"));
    assert_eq!(csv.lines().count(), 3);
    assert!(csv.contains("sigma,cve-2021-44228-request-side"));
    let mut reader = csv::Reader::from_reader(csv.as_bytes());
    let columns = reader.headers().unwrap().len();
    let records = reader
        .records()
        .map(|record| record.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record.len() == columns));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
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
