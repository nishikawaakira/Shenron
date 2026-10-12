use assert_cmd::Command;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};

const LINE: &str = "198.51.100.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /synthetic HTTP/1.1\" 200 10 \"-\" \"fixture-agent\"\n";

fn command(root: &Path) -> Command {
    let mut cmd = Command::cargo_bin("shenron").unwrap();
    cmd.env("SHENRON_DATA_DIR", root.join("empty-data"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("SHENRON_SLACK_WEBHOOK");
    cmd
}

fn read_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn mixed_logs(input: &Path) -> Vec<(String, Vec<u8>)> {
    fs::create_dir(input).unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(LINE.as_bytes()).unwrap();
    let gzip = gzip.finish().unwrap();
    let mut included = Vec::new();
    for (name, data) in [
        ("access_log_20260102", LINE.as_bytes()),
        ("access_log_20260101", gzip.as_slice()),
        ("access.log.2.gz", gzip.as_slice()),
        ("access.log.1", LINE.as_bytes()),
        ("access.log", LINE.as_bytes()),
    ] {
        fs::write(input.join(name), data).unwrap();
        included.push((name.to_owned(), data.to_vec()));
    }
    for name in [".DS_Store", "notes.md"] {
        fs::write(input.join(name), LINE).unwrap();
    }
    included.sort_by(|a, b| a.0.cmp(&b.0));
    included
}

#[test]
fn hunt_prunes_hidden_directories_and_reports_private_exclusions_without_parse_errors() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    for name in [
        "access.log",
        "nested/access_log_20260102",
        ".git/HEAD",
        ".git/objects/abcdef",
        ".cache/access.log",
        "nested/.hidden-dir/access.log",
    ] {
        let path = logs.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            if name.starts_with('.') || name.contains("/.hidden-dir/") {
                "synthetic non-log bytes\n"
            } else {
                LINE
            },
        )
        .unwrap();
    }
    let output = dir.path().join("run");
    let result = command(dir.path())
        .args(["hunt", "--input"])
        .arg(&logs)
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
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("Files skipped: 3 (hidden-directory: 3)"));
    for name in [".git", ".cache", ".hidden-dir", "abcdef"] {
        assert!(!stdout.contains(name));
    }
    let report = read_json(output.join("sanitized-research.json"));
    assert_eq!(report["metrics"]["files_analyzed"], 2);
    assert_eq!(report["metrics"]["total_requests_analyzed"], 2);
    assert_eq!(report["metrics"]["parse_errors"], 0);
    assert_eq!(report["metrics"]["files_skipped"], 3);
    for private in [
        ".git",
        ".cache",
        ".hidden-dir",
        "hidden-directory",
        logs.to_str().unwrap(),
    ] {
        assert!(!report.to_string().contains(private));
    }
    let manifest = read_json(output.join("run-manifest.json"));
    let skipped = manifest["skipped_input_files"].as_array().unwrap();
    assert_eq!(skipped.len(), 3);
    for (entry, name) in skipped.iter().zip([".cache", ".git", "nested/.hidden-dir"]) {
        assert_eq!(entry["path"], logs.join(name).to_str().unwrap());
        assert_eq!(entry["reason"], "hidden-directory");
    }
}

#[test]
fn hunt_context_concentration_and_daily_share_discovery_and_magic_gzip_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    let included = mixed_logs(&logs);
    let disclosure = "Files skipped: 2 (hidden: 1, unsupported-extension: 1)";
    let mut expected_corpus = None;
    for subcommand in ["hunt", "concentration", "daily"] {
        let output = dir.path().join(subcommand);
        let mut cmd = command(dir.path());
        cmd.args([subcommand, "--input"])
            .arg(&logs)
            .args(["--format", "nginx", "--output"])
            .arg(&output);
        if subcommand == "hunt" {
            cmd.args(["--no-nuclei", "--rules", "tests/fixtures/rules"]);
        }
        let result = cmd.assert().success().get_output().clone();
        let stdout = String::from_utf8(result.stdout).unwrap();
        assert!(stdout.contains(disclosure));
        for name in [".DS_Store", "notes.md"] {
            assert!(!stdout.contains(name));
        }
        let report = read_json(output.join("sanitized-research.json"));
        let counts = if subcommand == "hunt" {
            &report["metrics"]
        } else {
            &report
        };
        assert_eq!(counts["files_analyzed"], 5);
        assert_eq!(counts["files_skipped"], 2);
        assert_eq!(counts["total_requests_analyzed"], 5);
        assert_eq!(counts["parse_errors"], 0);
        let sanitized = report.to_string();
        for private in [
            ".DS_Store",
            "notes.md",
            "access_log",
            "fixture-agent",
            "198.51.100.1",
            "hidden",
            "unsupported-extension",
        ] {
            assert!(!sanitized.contains(private), "{private}");
        }
        let manifest = read_json(output.join("run-manifest.json"));
        assert_eq!(
            manifest["skipped_input_files"][0]["path"],
            logs.join(".DS_Store").to_str().unwrap()
        );
        assert_eq!(manifest["skipped_input_files"][0]["reason"], "hidden");
        assert_eq!(
            manifest["skipped_input_files"][1]["reason"],
            "unsupported-extension"
        );
        let corpus = if subcommand == "hunt" {
            &manifest["inputs"]["corpus"]
        } else {
            &manifest["corpus"]
        };
        for (entry, (name, bytes)) in corpus.as_array().unwrap().iter().zip(&included) {
            assert_eq!(entry["path"], logs.join(name).to_str().unwrap());
            assert_eq!(entry["byte_length"], bytes.len());
            assert_eq!(entry["sha256"], format!("{:x}", Sha256::digest(bytes)));
        }
        if let Some(expected) = &expected_corpus {
            assert_eq!(corpus, expected);
        } else {
            expected_corpus = Some(corpus.clone());
        }
    }
    let output = dir.path().join("context.json");
    let result = command(dir.path())
        .args(["context", "--input"])
        .arg(&logs)
        .args([
            "--format",
            "nginx",
            "--source-ip",
            "198.51.100.1",
            "--output",
        ])
        .arg(&output)
        .assert()
        .success()
        .get_output()
        .clone();
    let counts: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(counts["parseable_records"], 5);
    assert_eq!(counts["parse_errors"], 0);
    assert_eq!(counts["files_skipped"], 2);
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .contains(disclosure));
    assert_eq!(read_json(&output)["corpus"], expected_corpus.unwrap());
    assert_eq!(
        read_json(dir.path().join("context.json.run-manifest.json"))["skipped_input_files"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let result = command(dir.path())
        .args(["daily", "--input"])
        .arg(&logs)
        .args(["--format", "nginx", "--output-format", "json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap()["files_skipped"],
        2
    );
    assert!(String::from_utf8(result.stderr)
        .unwrap()
        .contains(disclosure));
}

#[test]
fn processed_index_admits_new_rotations_and_direct_files_ignore_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    fs::create_dir(&logs).unwrap();
    fs::write(logs.join("access.log"), LINE).unwrap();
    let index = dir.path().join("index.json");
    let run = || {
        let result = command(dir.path())
            .args(["daily", "--input"])
            .arg(&logs)
            .args([
                "--format",
                "nginx",
                "--output-format",
                "json",
                "--processed-index",
            ])
            .arg(&index)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&result).unwrap()
    };
    assert_eq!(run()["total_requests"], 1);
    fs::write(logs.join("access.log.1"), LINE).unwrap();
    fs::write(logs.join("access_log"), LINE).unwrap();
    let result = run();
    assert_eq!(result["total_requests"], 2);
    assert_eq!(result["files_skipped_as_processed"], 1);
    assert!(result.get("files_skipped").is_none());
    assert_eq!(run()["files_skipped_as_processed"], 3);
    for name in ["explicit", "explicit.md", ".explicit", "plain.gz"] {
        let input = dir.path().join(name);
        fs::write(&input, LINE).unwrap();
        let result = command(dir.path())
            .args(["daily", "--input"])
            .arg(input)
            .args(["--format", "nginx", "--output-format", "json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let counts: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(counts["total_requests"], 1);
        assert!(counts.get("files_skipped").is_none());
    }
}

#[test]
fn replay_ablation_and_count_hypotheses_keep_skipped_paths_in_private_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    mixed_logs(&logs);
    let findings = dir.path().join("findings.jsonl");
    fs::write(&findings, b"").unwrap();
    for subcommand in ["ablation", "replay", "count-hypotheses"] {
        let output = dir.path().join(format!("{subcommand}.json"));
        let mut cmd = command(dir.path());
        cmd.args([subcommand, "--input"])
            .arg(&logs)
            .args([
                "--format",
                "nginx",
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
            "Files skipped: 2 (hidden: 1, unsupported-extension: 1)",
        ));
        let report = read_json(&output);
        assert_eq!(report["total_events_evaluated"], 5);
        assert_eq!(report["files_skipped"], 2);
        for value in ["notes.md", ".DS_Store", logs.to_str().unwrap()] {
            assert!(!report.to_string().contains(value));
        }
        let manifest = read_json(
            dir.path()
                .join(format!("{subcommand}.json.run-manifest.json")),
        );
        assert_eq!(
            manifest["skipped_input_files"][1]["path"],
            logs.join("notes.md").to_str().unwrap()
        );
    }
}

#[test]
fn automatic_format_detection_accepts_extensionless_gzip_and_explicit_other_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let raw = fs::read("tests/fixtures/production/waf.jsonl").unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&raw).unwrap();
    let stored = gzip.finish().unwrap();
    for name in ["access_log", "explicit.md"] {
        let input = dir.path().join(name);
        fs::write(&input, &stored).unwrap();
        let output = command(dir.path())
            .args(["daily", "--input"])
            .arg(&input)
            .args(["--output-format", "json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let report: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(report["total_requests"], 2);
        assert_eq!(report["telemetry_profile"], "aws-waf");
    }
}

#[cfg(unix)]
#[test]
fn context_rejects_directory_symlinks_while_hunt_discloses_them() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    fs::create_dir(&logs).unwrap();
    fs::write(logs.join("access.log"), LINE).unwrap();
    std::os::unix::fs::symlink("access.log", logs.join("alias.log")).unwrap();
    command(dir.path())
        .args(["context", "--input"])
        .arg(&logs)
        .args(["--format", "nginx", "--source-ip", "198.51.100.1"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("symbolic links inside a corpus"));
    let output = dir.path().join("run");
    command(dir.path())
        .args(["hunt", "--input"])
        .arg(&logs)
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
        .success()
        .stdout(predicates::str::contains("Files skipped: 1 (symlink: 1)"));
    assert_eq!(
        read_json(output.join("sanitized-research.json"))["metrics"]["total_requests_analyzed"],
        1
    );
}
