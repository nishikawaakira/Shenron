use std::{fs, path::Path};

use assert_cmd::Command;
use chrono::Utc;
use predicates::str::contains;
use shenron::{
    candidate::{
        build_batch_from_findings, compatibility, export, replay, Backend, CandidateEvidence,
        CompatibilityStatus, DefensiveCandidate, DefensiveCondition, RecommendedAction,
    },
    event::TelemetryProfile,
    nuclei::{Detectability, RequestSpecificity},
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
fn replay_measures_known_request_ids_and_other_matching_events() {
    let output = tempdir().unwrap();
    let mut candidate = candidate(DefensiveCondition::UriEquals {
        value: "/vulnerable/execute".to_owned(),
    });
    candidate.source_findings = vec![shenron::candidate::FindingReference {
        template_id: "synthetic-cve-2024-10001".to_owned(),
        timestamp: None,
        request_id: Some("production-allow".to_owned()),
    }];
    candidate.evidence.known_threat_findings = 1;

    let replayed = replay(
        candidate,
        Path::new("tests/fixtures/production/waf.jsonl"),
        TelemetryProfile::AwsWaf,
        &output.path().join("replayed.json"),
    )
    .unwrap();
    assert_eq!(replayed.evidence.historical_requests_evaluated, 2);
    assert_eq!(replayed.evidence.known_threat_findings_matched, 1);
    assert_eq!(replayed.evidence.known_threat_findings_missed, 0);
    assert_eq!(replayed.evidence.other_historical_matches, 1);
    assert_eq!(replayed.evidence.threat_coverage, Some(1.0));
}

#[test]
fn replay_does_not_claim_coverage_without_known_request_ids() {
    let output = tempdir().unwrap();
    let mut candidate = candidate(DefensiveCondition::UriEquals {
        value: "/vulnerable/execute".to_owned(),
    });
    candidate.source_findings = vec![shenron::candidate::FindingReference {
        template_id: "synthetic-cve-2024-10001".to_owned(),
        timestamp: None,
        request_id: None,
    }];
    candidate.evidence.known_threat_findings = 1;

    let replayed = replay(
        candidate,
        Path::new("tests/fixtures/production/waf.jsonl"),
        TelemetryProfile::AwsWaf,
        &output.path().join("replayed.json"),
    )
    .unwrap();
    assert_eq!(replayed.evidence.known_threat_findings_matched, 0);
    assert_eq!(replayed.evidence.known_threat_findings_missed, 1);
    assert_eq!(replayed.evidence.other_historical_matches, 2);
    assert_eq!(replayed.evidence.threat_coverage, None);
}

#[test]
fn replay_refuses_an_output_inside_the_raw_input_tree() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("raw");
    fs::create_dir(&input).unwrap();
    fs::copy(
        "tests/fixtures/production/waf.jsonl",
        input.join("events.jsonl"),
    )
    .unwrap();
    assert!(replay(
        candidate(DefensiveCondition::UriEquals {
            value: "/vulnerable/execute".to_owned(),
        }),
        &input,
        TelemetryProfile::AwsWaf,
        &input.join("candidate-replayed.json"),
    )
    .is_err());
}

#[test]
fn cli_replay_refuses_an_output_inside_the_raw_input_tree() {
    let directory = tempdir().unwrap();
    let input = directory.path().join("raw");
    fs::create_dir(&input).unwrap();
    fs::copy(
        "tests/fixtures/production/waf.jsonl",
        input.join("events.jsonl"),
    )
    .unwrap();
    let candidate_path = directory.path().join("candidate.json");
    fs::write(
        &candidate_path,
        serde_json::to_vec(&candidate(DefensiveCondition::UriEquals {
            value: "/vulnerable/execute".to_owned(),
        }))
        .unwrap(),
    )
    .unwrap();
    let output = input.join("candidate-replayed.json");

    Command::cargo_bin("shenron")
        .unwrap()
        .args([
            "candidate",
            "replay",
            "--candidate",
            candidate_path.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--format",
            "aws-waf",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains(
            "output directory must be separate from immutable raw input",
        ));
}

#[test]
fn compatibility_uses_supported_leaf_count_for_status() {
    let empty = candidate(DefensiveCondition::And {
        conditions: Vec::new(),
    });
    assert_eq!(
        compatibility(&empty, Backend::AwsWafJson, TelemetryProfile::AwsWaf).status,
        CompatibilityStatus::Unsupported
    );

    let mixed = candidate(DefensiveCondition::And {
        conditions: vec![
            DefensiveCondition::UriEquals {
                value: "/oauth/token".to_owned(),
            },
            DefensiveCondition::Ja4Equals {
                value: "t13d1516h2_111111111111_222222222222".to_owned(),
            },
        ],
    });
    assert_eq!(
        compatibility(&mixed, Backend::AwsWafJson, TelemetryProfile::NginxCombined).status,
        CompatibilityStatus::PartiallySupported
    );
}

#[test]
fn export_allows_token_uri_but_refuses_sensitive_headers_and_jwts() {
    let directory = tempdir().unwrap();
    let oauth_candidate = candidate(DefensiveCondition::UriEquals {
        value: "/oauth/token".to_owned(),
    });
    assert!(export(
        &oauth_candidate,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &directory.path().join("oauth.json"),
        Some(1),
        99_001,
    )
    .is_ok());

    let authorization_candidate = candidate(DefensiveCondition::HeaderEquals {
        name: "Authorization".to_owned(),
        value: "Basic not-a-secret".to_owned(),
    });
    assert!(export(
        &authorization_candidate,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &directory.path().join("authorization.json"),
        Some(2),
        99_001,
    )
    .is_err());

    let jwt_candidate = candidate(DefensiveCondition::QueryContains {
        value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0".to_owned(),
    });
    assert!(export(
        &jwt_candidate,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &directory.path().join("jwt.json"),
        Some(3),
        99_001,
    )
    .is_err());
}

#[test]
fn batch_build_excludes_already_blocked_aws_waf_findings() {
    let finding = |action: &str, path: &str| FindingExplanation {
        template_id: "demo-template".to_owned(),
        cves: vec!["CVE-2099-0001".to_owned()],
        detectability: Detectability::High,
        request_specificity: RequestSpecificity::RequestSpecific,
        timestamp: None,
        source_ip: None,
        client_ip: None,
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
        log_source: None,
        source: shenron::production::FindingSource::Nuclei,
        rule_title: None,
        sigma_level: None,
    };
    let (candidates, stats) = build_batch_from_findings(
        &[finding("ALLOW", "/unblocked"), finding("BLOCK", "/blocked")],
        TelemetryProfile::AwsWaf,
        false,
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
        false,
    );
    assert_eq!(stats.excluded_blocked_findings, 0);
    assert_eq!(candidates.len(), 1);
}

#[test]
fn batch_candidate_ids_are_sequential_within_each_cve() {
    let finding = |cve: &str, path: &str| FindingExplanation {
        template_id: format!("template-{cve}"),
        cves: vec![cve.to_owned()],
        detectability: Detectability::High,
        request_specificity: RequestSpecificity::RequestSpecific,
        timestamp: None,
        source_ip: None,
        client_ip: None,
        host: None,
        method: Some("GET".to_owned()),
        uri_path: Some(path.to_owned()),
        uri_query: None,
        waf_action: None,
        waf_rule_id: None,
        waf_rule_type: None,
        waf_labels: Vec::new(),
        waf_non_terminating_rule_ids: Vec::new(),
        headers: Vec::new(),
        ja3: None,
        ja4: None,
        request_id: None,
        log_source: None,
        source: shenron::production::FindingSource::Nuclei,
        rule_title: None,
        sigma_level: None,
    };
    let (candidates, _) = build_batch_from_findings(
        &[
            finding("CVE-2024-10002", "/only"),
            finding("CVE-2024-10001", "/second"),
            finding("CVE-2024-10001", "/first"),
        ],
        TelemetryProfile::NginxCombined,
        false,
    );
    let ids = candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            "shenron-cve-2024-10001-001",
            "shenron-cve-2024-10001-002",
            "shenron-cve-2024-10002-001",
        ]
    );
}

#[test]
fn batch_build_excludes_response_unverified_unless_explicitly_included() {
    let finding = FindingExplanation {
        template_id: "uri-only-template".to_owned(),
        cves: vec!["CVE-2099-0002".to_owned()],
        detectability: Detectability::High,
        request_specificity: RequestSpecificity::ResponseUnverified,
        timestamp: None,
        source_ip: None,
        client_ip: None,
        host: None,
        method: Some("GET".to_owned()),
        uri_path: Some("/uri-only".to_owned()),
        uri_query: None,
        waf_action: None,
        waf_rule_id: None,
        waf_rule_type: None,
        waf_labels: Vec::new(),
        waf_non_terminating_rule_ids: Vec::new(),
        headers: Vec::new(),
        ja3: None,
        ja4: None,
        request_id: None,
        log_source: None,
        source: shenron::production::FindingSource::Nuclei,
        rule_title: None,
        sigma_level: None,
    };
    let findings = vec![finding];
    let (candidates, stats) =
        build_batch_from_findings(&findings, TelemetryProfile::NginxCombined, false);
    assert!(candidates.is_empty());
    assert_eq!(stats.excluded_response_unverified_findings, 1);
    assert_eq!(stats.skipped_incomplete_findings, 0);

    let (candidates, stats) =
        build_batch_from_findings(&findings, TelemetryProfile::NginxCombined, true);
    assert_eq!(candidates.len(), 1);
    assert_eq!(stats.excluded_response_unverified_findings, 0);
}
