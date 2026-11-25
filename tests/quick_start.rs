use std::fs;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::{contains, starts_with};
use tempfile::TempDir;

fn shenron(data: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("shenron").unwrap();
    cmd.env("SHENRON_DATA_DIR", data.path())
        .env_remove("SHENRON_SLACK_WEBHOOK");
    cmd
}

const INPUT: &str = "./tests/fixtures/aws-waf/";

#[test]
fn validate_rules_rejects_a_missing_path() {
    let data = tempfile::tempdir().unwrap();
    shenron(&data)
        .args(["validate-rules", "--rules", "./no-such-dir/"])
        .assert()
        .failure()
        .stderr(contains("./no-such-dir/"))
        .stderr(contains(".yml or .yaml"));
}

#[test]
fn hunt_rejects_an_explicit_directory_without_rule_files() {
    let data = tempfile::tempdir().unwrap();
    let rules = tempfile::tempdir().unwrap();
    fs::write(rules.path().join("README.txt"), "No rule files.").unwrap();
    shenron(&data)
        .args(["hunt", "--input", INPUT, "--no-nuclei", "--rules"])
        .arg(rules.path())
        .assert()
        .failure()
        .stderr(contains(rules.path().display().to_string()))
        .stderr(contains(".yml or .yaml"));
}

#[test]
fn hunt_skips_missing_explicit_rules_only_when_sigma_is_disabled() {
    let data = tempfile::tempdir().unwrap();
    let args = [
        "hunt",
        "--input",
        "./tests/fixtures/production/waf.jsonl",
        "--format",
        "aws-waf",
        "--nuclei-templates",
        "tests/fixtures/nuclei",
        "--nuclei-report",
        "tests/fixtures/production/nuclei-report.json",
        "--rules",
        "./no-such-dir/",
    ];
    let output = shenron(&data)
        .args(args)
        .arg("--no-sigma")
        .assert()
        .success()
        .stdout(contains("synthetic-cve-2024-10001"));
    let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("Sigma pass:"))
            .collect::<Vec<_>>(),
        ["Sigma pass: skipping --rules ./no-such-dir/ because --no-sigma is set."]
    );
    shenron(&data)
        .args(args)
        .assert()
        .failure()
        .stderr(contains("./no-such-dir/").and(contains(".yml or .yaml")));
}

#[test]
fn explicit_unsupported_rules_are_reported_without_failing() {
    let data = tempfile::tempdir().unwrap();
    let rule = "./tests/fixtures/rules/web_unsupported_regex.yml";
    shenron(&data)
        .args(["validate-rules", "--rules", rule])
        .assert()
        .success()
        .stdout(contains("Rules loaded:       1"))
        .stdout(contains("Unsupported:        1"));
    shenron(&data)
        .args(["hunt", "--input", INPUT, "--no-nuclei", "--rules", rule])
        .assert()
        .success()
        .stderr(contains("1 unsupported skipped"));
}

#[test]
fn hunt_allows_an_empty_prepared_rules_directory() {
    let data = tempfile::tempdir().unwrap();
    fs::create_dir(data.path().join("sigma-rules")).unwrap();
    shenron(&data)
        .args(["hunt", "--input", INPUT, "--no-nuclei"])
        .assert()
        .success()
        .stderr(contains("Sigma pass: 0 supported rules from"));
}

#[test]
fn readme_quick_start_validates_rules_and_hunts_the_fixture() {
    let data = tempfile::tempdir().unwrap();
    shenron(&data)
        .args(["validate-rules", "--rules", "./sigma-rules/"])
        .assert()
        .success()
        .stdout(starts_with("SUPPORTED"));
    shenron(&data)
        .args([
            "hunt",
            "--input",
            "./tests/fixtures/aws-waf/",
            "--format",
            "aws-waf",
            "--rules",
            "./tests/fixtures/rules/",
            "--no-nuclei",
        ])
        .assert()
        .success()
        .stdout(starts_with("{"))
        .stderr(contains("Files analyzed:"));
}

#[test]
fn top_level_help_describes_every_command() {
    let data = tempfile::tempdir().unwrap();
    let output = shenron(&data).arg("--help").assert().success();
    let help = std::str::from_utf8(&output.get_output().stdout).unwrap();
    let (_, commands) = help.split_once("Commands:\n").unwrap();
    let (commands, _) = commands.split_once("\nOptions:").unwrap();
    for line in commands
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        assert!(
            line.split_whitespace().nth(1).is_some(),
            "Missing description: {line}"
        );
    }
}
