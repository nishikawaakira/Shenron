use std::fs;

use assert_cmd::Command;
use chrono::Utc;
use shenron::{
    candidate::{
        build_batch_from_findings, compatibility, export, Backend, CandidateEvidence,
        CompatibilityStatus, DefensiveCandidate, DefensiveCondition, RecommendedAction,
    },
    event::TelemetryProfile,
    nuclei::Detectability,
    production::FindingExplanation,
};
use tempfile::tempdir;

fn candidate(condition: DefensiveCondition) -> DefensiveCandidate {
    DefensiveCandidate {
        schema_version: 1,
        id: "shenron-cve-2099-0001-demo".to_owned(),
        conditions: condition,
        source_findings: Vec::new(),
        cves: vec!["CVE-2099-0001".to_owned()],
        kev: false,
        evidence: CandidateEvidence {
            historical_requests_evaluated: 11,
            known_threat_findings: 1,
            known_threat_findings_matched: 1,
            known_threat_findings_missed: 0,
            other_historical_matches: 0,
            threat_coverage: Some(1.0),
            first_seen: Some(Utc::now()),
            last_seen: Some(Utc::now()),
            replay_completed: true,
        },
        recommended_action: RecommendedAction::Count,
        telemetry_profile: TelemetryProfile::AwsWaf,
        generation_version: "test".to_owned(),
    }
}

#[test]
fn exporters_preserve_conditions_and_refuse_partial_ossec_translation() {
    let directory = tempdir().unwrap();
    let built_candidate = candidate(DefensiveCondition::And {
        conditions: vec![
            DefensiveCondition::MethodEquals {
                value: "GET".to_owned(),
            },
            DefensiveCondition::UriStartsWith {
                value: "/download".to_owned(),
            },
        ],
    });
    let aws = directory.path().join("candidate.aws-waf.json");
    export(
        &built_candidate,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &aws,
        Some(42),
        99_001,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&aws).unwrap()).unwrap();
    assert_eq!(json["Action"], serde_json::json!({"Count": {}}));
    assert_eq!(json["Priority"], 42);
    assert!(aws
        .with_file_name("candidate.aws-waf.evidence.json")
        .exists());

    let terraform = directory.path().join("candidate.tf");
    export(
        &built_candidate,
        Backend::TerraformAwsWaf,
        TelemetryProfile::AwsWaf,
        &terraform,
        Some(42),
        99_001,
    )
    .unwrap();
    let hcl = fs::read_to_string(terraform).unwrap();
    assert!(hcl.contains("action {\n    count {}\n  }"));
    assert!(hcl.contains("uri_path {}"));

    let ja4_candidate = candidate(DefensiveCondition::And {
        conditions: vec![
            DefensiveCondition::UriStartsWith {
                value: "/download".to_owned(),
            },
            DefensiveCondition::Ja4Equals {
                value: "t13d1516h2_111111111111_222222222222".to_owned(),
            },
        ],
    });
    let report = compatibility(
        &ja4_candidate,
        Backend::Ossec,
        TelemetryProfile::NginxCombined,
    );
    assert_eq!(report.status, CompatibilityStatus::PartiallySupported);
    assert!(export(
        &ja4_candidate,
        Backend::Ossec,
        TelemetryProfile::NginxCombined,
        &directory.path().join("candidate.xml"),
        None,
        99_001
    )
    .is_err());
}

#[test]
fn preventive_export_requires_replay_and_does_not_overwrite() {
    let directory = tempdir().unwrap();
    let mut candidate = candidate(DefensiveCondition::UriEquals {
        value: "/safe".to_owned(),
    });
    candidate.evidence.replay_completed = false;
    let output = directory.path().join("candidate.json");
    assert!(export(
        &candidate,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &output,
        Some(1),
        99_001
    )
    .is_err());
    candidate.evidence.replay_completed = true;
    export(
        &candidate,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &output,
        Some(1),
        99_001,
    )
    .unwrap();
    assert!(export(
        &candidate,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &output,
        Some(1),
        99_001
    )
    .is_err());
}

#[test]
fn cli_export_defaults_to_the_candidates_aws_waf_telemetry_profile() {
    let directory = tempdir().unwrap();
    let candidate_path = directory.path().join("candidate.json");
    let output = directory.path().join("candidate.aws-waf.json");
    let candidate = candidate(DefensiveCondition::Ja4Equals {
        value: "t13d1516h2_111111111111_222222222222".to_owned(),
    });
    fs::write(&candidate_path, serde_json::to_vec(&candidate).unwrap()).unwrap();

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "candidate",
            "export",
            "--candidate",
            candidate_path.to_str().unwrap(),
            "--backend",
            "aws-waf-json",
            "--priority",
            "1",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(output.exists());
}

#[test]
fn batch_build_excludes_already_blocked_aws_waf_findings() {
    let finding = |action: &str, path: &str| FindingExplanation {
        template_id: "demo-template".to_owned(),
        cves: vec!["CVE-2099-0001".to_owned()],
        detectability: Detectability::High,
        timestamp: None,
        source_ip: None,
        host: None,
        method: Some("GET".to_owned()),
        uri_path: Some(path.to_owned()),
        uri_query: None,
        waf_action: Some(action.to_owned()),
        waf_rule_id: None,
        waf_rule_type: None,
        waf_labels: Vec::new(),
        waf_non_terminating_rule_ids: Vec::new(),
        headers: Vec::new(),
        ja3: None,
        ja4: None,
        request_id: None,
    };
    let (candidates, stats) = build_batch_from_findings(
        &[finding("ALLOW", "/unblocked"), finding("BLOCK", "/blocked")],
        TelemetryProfile::AwsWaf,
    );
    assert_eq!(stats.candidates, 1);
    assert_eq!(stats.excluded_blocked_findings, 1);
    assert_eq!(
        candidates[0].conditions,
        DefensiveCondition::And {
            conditions: vec![
                DefensiveCondition::MethodEquals {
                    value: "GET".to_owned()
                },
                DefensiveCondition::UriEquals {
                    value: "/unblocked".to_owned()
                }
            ]
        }
    );

    let (candidates, stats) = build_batch_from_findings(
        &[finding("BLOCK", "/blocked")],
        TelemetryProfile::NginxCombined,
    );
    assert_eq!(stats.excluded_blocked_findings, 0);
    assert_eq!(candidates.len(), 1);
}
