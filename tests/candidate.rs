use std::{fs, path::Path};

use assert_cmd::Command;
use chrono::Utc;
use predicates::str::contains;
use shenron::{
    candidate::{
        build_batch_from_findings, build_batch_from_findings_with_sigma, compatibility, export,
        replay, Backend, CandidateEvidence, CandidateEvidenceBasis, CandidateKind,
        CompatibilityStatus, DefensiveCandidate, DefensiveCondition, RecommendedAction,
    },
    event::TelemetryProfile,
    nuclei::{Detectability, RequestSpecificity},
    production::FindingExplanation,
    sigma::load_rules,
};
use tempfile::tempdir;

fn candidate(condition: DefensiveCondition) -> DefensiveCandidate {
    DefensiveCandidate {
        schema_version: 1,
        id: "shenron-cve-2099-0001-demo".to_owned(),
        candidate_kind: CandidateKind::CveNuclei,
        evidence_basis: CandidateEvidenceBasis::ValidatedNucleiRequestIr,
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

#[test]
fn sigma_ttp_candidates_are_opt_in_separate_and_preserve_literal_or() {
    let sigma_finding = FindingExplanation {
        template_id: "shenron-secret-config-file-probe".to_owned(),
        cves: Vec::new(),
        detectability: Detectability::Low,
        request_specificity: RequestSpecificity::ResponseUnverified,
        timestamp: None,
        source_ip: None,
        client_ip: None,
        host: None,
        method: Some("GET".to_owned()),
        uri_path: Some("/.env".to_owned()),
        uri_query: None,
        waf_action: None,
        waf_rule_id: None,
        waf_rule_type: None,
        waf_labels: Vec::new(),
        waf_non_terminating_rule_ids: Vec::new(),
        headers: Vec::new(),
        ja3: None,
        ja4: None,
        request_id: Some("sigma-request".to_owned()),
        log_source: None,
        source: shenron::production::FindingSource::Sigma,
        rule_title: Some("Secret and Configuration File Path Probe".to_owned()),
        sigma_level: Some("medium".to_owned()),
    };
    let findings = vec![sigma_finding];
    let (default_candidates, default_stats) =
        build_batch_from_findings(&findings, TelemetryProfile::AwsWaf, false);
    assert!(default_candidates.is_empty());
    assert_eq!(default_stats.excluded_sigma_findings, 1);

    let rules = load_rules(Path::new("sigma-rules"));
    let (candidates, stats) = build_batch_from_findings_with_sigma(
        &findings,
        TelemetryProfile::AwsWaf,
        false,
        Some(&rules.supported),
    );
    assert_eq!(candidates.len(), 1);
    assert_eq!(stats.sigma_candidates, 1);
    assert_eq!(stats.excluded_sigma_findings, 0);
    let sigma = &candidates[0];
    assert_eq!(sigma.candidate_kind, CandidateKind::SigmaTtp);
    assert_eq!(
        sigma.evidence_basis,
        CandidateEvidenceBasis::SigmaLiteralRequestRule
    );
    assert!(sigma.cves.is_empty());
    let DefensiveCondition::Or { conditions } = &sigma.conditions else {
        panic!("the rule's literal alternatives must remain one OR condition");
    };
    assert!(conditions.len() > 1);
    assert!(conditions.iter().any(|condition| {
        condition
            == &DefensiveCondition::UriContainsAsciiCaseInsensitive {
                value: "/.env".to_owned(),
            }
    }));

    let mut cve_finding = findings[0].clone();
    cve_finding.source = shenron::production::FindingSource::Nuclei;
    cve_finding.template_id = "cve-template".to_owned();
    cve_finding.cves = vec!["CVE-2099-0001".to_owned()];
    cve_finding.request_specificity = RequestSpecificity::RequestSpecific;
    let (mixed, _) = build_batch_from_findings_with_sigma(
        &[findings[0].clone(), cve_finding],
        TelemetryProfile::AwsWaf,
        false,
        Some(&rules.supported),
    );
    assert_eq!(mixed.len(), 2);
    assert_eq!(mixed[0].candidate_kind, CandidateKind::CveNuclei);
    assert_eq!(mixed[1].candidate_kind, CandidateKind::SigmaTtp);
    assert_eq!(mixed[0].cves, ["CVE-2099-0001"]);
    assert!(mixed[1].cves.is_empty());
}

#[test]
fn sigma_ttp_export_requires_replay_remains_count_and_rejects_nonfaithful_backend() {
    let finding = FindingExplanation {
        template_id: "shenron-secret-config-file-probe".to_owned(),
        cves: Vec::new(),
        detectability: Detectability::Low,
        request_specificity: RequestSpecificity::ResponseUnverified,
        timestamp: None,
        source_ip: None,
        client_ip: None,
        host: None,
        method: Some("GET".to_owned()),
        uri_path: Some("/.env".to_owned()),
        uri_query: None,
        waf_action: None,
        waf_rule_id: None,
        waf_rule_type: None,
        waf_labels: Vec::new(),
        waf_non_terminating_rule_ids: Vec::new(),
        headers: Vec::new(),
        ja3: None,
        ja4: None,
        request_id: Some("sigma-request".to_owned()),
        log_source: None,
        source: shenron::production::FindingSource::Sigma,
        rule_title: None,
        sigma_level: Some("medium".to_owned()),
    };
    let rules = load_rules(Path::new("sigma-rules"));
    let (mut candidates, _) = build_batch_from_findings_with_sigma(
        &[finding],
        TelemetryProfile::AwsWaf,
        false,
        Some(&rules.supported),
    );
    let mut sigma = candidates.pop().unwrap();
    let directory = tempdir().unwrap();
    assert!(export(
        &sigma,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &directory.path().join("before-replay.json"),
        Some(1),
        99_001,
    )
    .is_err());
    assert_eq!(
        compatibility(&sigma, Backend::Ossec, TelemetryProfile::AwsWaf).status,
        CompatibilityStatus::Unsupported
    );
    assert!(export(
        &sigma,
        Backend::Ossec,
        TelemetryProfile::AwsWaf,
        &directory.path().join("nonfaithful.xml"),
        None,
        99_001,
    )
    .is_err());

    sigma.evidence.replay_completed = true;
    let output = directory.path().join("count.json");
    export(
        &sigma,
        Backend::AwsWafJson,
        TelemetryProfile::AwsWaf,
        &output,
        Some(1),
        99_001,
    )
    .unwrap();
    let exported: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(exported["Action"], serde_json::json!({"Count": {}}));
    assert_eq!(
        exported["Statement"]["OrStatement"]["Statements"][0]["ByteMatchStatement"]
            ["TextTransformations"][0]["Type"],
        "LOWERCASE"
    );
}

#[test]
fn uppercase_sigma_uri_literals_agree_with_replay_and_count_exports() {
    use shenron::access_log::{parse_combined_line, AccessLogFormat};
    use shenron::production::explain_private_findings;

    for (field, literal, needle, constraint, paths) in [
        (
            "uri_path",
            "/CGI-BIN",
            "/cgi-bin",
            "EXACTLY",
            [
                "/CGI-BIN",
                "/cgi-bin",
                "/CgI-BiN",
                "/cgi-bin/extra",
                "/other",
            ],
        ),
        (
            "cs-uri-stem|contains",
            "ADMIN",
            "admin",
            "CONTAINS",
            [
                "/ADMIN",
                "/admin",
                "/prefix/AdMiN/settings",
                "/admi",
                "/other",
            ],
        ),
    ] {
        let directory = tempdir().unwrap();
        let rule_path = directory.path().join("rule.yml");
        let findings_path = directory.path().join("findings.jsonl");
        fs::write(
            &findings_path,
            serde_json::to_vec(&serde_json::json!({
                "source": "sigma", "template_id": "case-test", "cves": [],
                "detectability": "LOW", "headers": [], "method": "GET",
                "uri_path": paths[0]
            }))
            .unwrap(),
        )
        .unwrap();
        let findings = explain_private_findings(&findings_path).unwrap();
        let mut built = Vec::new();
        for source_literal in [literal, needle] {
            fs::write(
                &rule_path,
                format!(
                    "title: Case test\nid: case-test\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    {field}: '{source_literal}'\n  condition: selection\n"
                ),
            )
            .unwrap();
            let rules = load_rules(&rule_path);
            assert!(rules.unsupported.is_empty());
            let (mut candidates, stats) = build_batch_from_findings_with_sigma(
                &findings,
                TelemetryProfile::NginxCombined,
                false,
                Some(&rules.supported),
            );
            assert_eq!(stats.sigma_candidates, 1);
            built.push(candidates.pop().unwrap());
        }
        // Case alone does not change the serialized candidate, including its
        // evidence and deterministic ID. Already-lowercase inputs stay stable.
        assert_eq!(
            serde_json::to_vec_pretty(&built[0]).unwrap(),
            serde_json::to_vec_pretty(&built[1]).unwrap()
        );
        let expected_condition = if constraint == "EXACTLY" {
            DefensiveCondition::UriEqualsAsciiCaseInsensitive {
                value: needle.into(),
            }
        } else {
            DefensiveCondition::UriContainsAsciiCaseInsensitive {
                value: needle.into(),
            }
        };
        assert_eq!(built[0].conditions, expected_condition);

        let lines = paths.map(|path| format!(
            "192.0.2.1 - - [09/Sep/2026:00:00:00 +0000] \"GET {path} HTTP/1.1\" 404 12 \"-\" \"test\""
        ));
        let log_path = directory.path().join("input.log");
        fs::write(&log_path, lines.join("\n") + "\n").unwrap();
        let replayed = replay(
            built.remove(0),
            &log_path,
            TelemetryProfile::NginxCombined,
            &directory.path().join("replayed.json"),
        )
        .unwrap();
        assert_eq!(replayed.evidence.historical_requests_evaluated, 5);
        assert_eq!(replayed.evidence.other_historical_matches, 3);

        let aws_path = directory.path().join("aws.json");
        let tf_path = directory.path().join("count.tf");
        for (backend, path) in [
            (Backend::AwsWafJson, &aws_path),
            (Backend::TerraformAwsWaf, &tf_path),
        ] {
            export(
                &replayed,
                backend,
                TelemetryProfile::NginxCombined,
                path,
                Some(1),
                99_001,
            )
            .unwrap();
        }
        let aws: serde_json::Value = serde_json::from_slice(&fs::read(aws_path).unwrap()).unwrap();
        let statement = &aws["Statement"]["ByteMatchStatement"];
        assert_eq!(statement["SearchString"], needle);
        assert_eq!(
            statement["TextTransformations"],
            serde_json::json!([{"Priority": 0, "Type": "LOWERCASE"}])
        );
        assert_eq!(statement["PositionalConstraint"], constraint);
        assert_eq!(aws["Action"], serde_json::json!({"Count": {}}));
        let terraform = fs::read_to_string(tf_path).unwrap();
        assert!(terraform.contains(&format!("search_string         = \"{needle}\"")));
        assert!(terraform.contains("type     = \"LOWERCASE\""));
        assert!(terraform.contains("count {}"));

        for (index, line) in lines.iter().enumerate() {
            let event = parse_combined_line(line, AccessLogFormat::NginxCombined).unwrap();
            let normalized = event.uri_path.as_ref().unwrap().to_ascii_lowercase();
            // Evaluate the exported byte-match inputs locally; no AWS/network
            // call is involved. Both forms must predict the same five events.
            let search = statement["SearchString"].as_str().unwrap();
            let exported_match = match statement["PositionalConstraint"].as_str().unwrap() {
                "EXACTLY" => normalized == search,
                "CONTAINS" => normalized.contains(search),
                other => panic!("unexpected positional constraint {other}"),
            };
            assert_eq!(replayed.conditions.matches(&event), index < 3);
            assert_eq!(replayed.conditions.matches(&event), exported_match);
        }
    }
}
