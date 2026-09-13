use assert_cmd::Command;
use serde_json::Value;
use std::fs;

#[test]
fn context_is_aggregate_by_default_and_request_values_are_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.log");
    fs::write(&input, "198.51.100.1 - - [24/Aug/2026:11:20:30 +0000] \"GET /ordinary?token=secret HTTP/1.1\" 200 12 \"-\" \"-\"\n").unwrap();
    let run = |flags: &[&str]| {
        Command::cargo_bin("shenron")
            .unwrap()
            .args([
                "context",
                "--input",
                input.to_str().unwrap(),
                "--format",
                "apache",
                "--source-ip",
                "198.51.100.1",
                "--from",
                "2026-08-24T00:00:00Z",
                "--to",
                "2026-08-25T00:00:00Z",
            ])
            .args(flags)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    let counts = run(&[]);
    assert_eq!(
        serde_json::from_slice::<Value>(&counts).unwrap()["eligible_records"],
        1
    );
    assert!(!String::from_utf8(counts).unwrap().contains("198.51.100.1"));
    let private = String::from_utf8(run(&["--show-request"])).unwrap();
    assert!(private.contains("/ordinary") && !private.contains("token=secret"));
    assert!(String::from_utf8(run(&["--show-request", "--show-query"]))
        .unwrap()
        .contains("token=secret"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn source_references_preserve_hunt_matches_and_all_other_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("rule.yml"), "title: Ordinary\nid: ordinary\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    uri_path|contains: ordinary\n  condition: selection\nlevel: low\n").unwrap();
    let input = dir.path().join("input.log");
    fs::write(&input, "\nbad\n198.51.100.1 - - [24/Aug/2026:11:20:30 +0000] \"GET /ordinary HTTP/1.1\" 200 12 \"-\" \"-\"\n").unwrap();
    let plain = dir.path().join("plain");
    let referenced = dir.path().join("referenced");
    for (out, references) in [(&plain, false), (&referenced, true)] {
        let mut command = Command::cargo_bin("shenron").unwrap();
        command.env_remove("SHENRON_SLACK_WEBHOOK").args([
            "hunt",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "apache",
            "--no-nuclei",
            "--rules",
            rules.to_str().unwrap(),
            "--uncompressed-findings",
            "--output",
            out.to_str().unwrap(),
        ]);
        if references {
            command.arg("--include-source-references");
        }
        command.assert().success();
    }
    let plain_finding: Value = serde_json::from_str(
        fs::read_to_string(plain.join("private-findings.jsonl"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let mut referenced_finding: Value = serde_json::from_str(
        fs::read_to_string(referenced.join("private-findings.jsonl"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(referenced_finding["source_reference"]["line_number"], 3);
    referenced_finding
        .as_object_mut()
        .unwrap()
        .remove("source_reference");
    assert_eq!(plain_finding, referenced_finding);
    for name in [
        "sanitized-research.json",
        "request-concentration.json",
        "triage-view.json",
        "triage-summary.json",
    ] {
        assert_eq!(
            fs::read(plain.join(name)).unwrap(),
            fs::read(referenced.join(name)).unwrap(),
            "{name}"
        );
    }
}
