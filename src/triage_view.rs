//! Consolidated, offline triage-priority output for a completed hunt.
//!
//! This module ranks connection/client-IP entities for the order in which a
//! human may review them. It does not assign threat severity or a probability
//! of malice, and a first-seen marker means new and worth review, never
//! malicious.

use std::{collections::BTreeSet, net::IpAddr};

use serde::Serialize;

use crate::{
    event::TelemetryCapabilities,
    production::FindingExplanation,
    reputation::{AsnDatabase, ReputationDatabase},
    triage::{entity_groups, EntityDimension, RequestSequenceSummary, TriagePolicy},
};

const SAFETY_NOTE: &str = "This is a triage priority order (which entity to review first), not a threat severity or a probability of malice. A first-seen mark means new and worth review, never malicious. An ordered request sequence is an observation of what was requested and when; regular intervals or a short span can also result from automation, a crawler, page subresources, or a person clicking quickly. It does not determine automation, attack, exploitation, compromise, abuse, or attacker identity.";

/// Aggregate-only output for a completed hunt. It intentionally contains no
/// entity keys or other raw telemetry values.
#[derive(Debug, Serialize)]
pub struct SanitizedTriageSummary {
    pub report_kind: String,
    pub safety_note: String,
    pub total_entities: usize,
    pub entities_requiring_investigation: usize,
    pub tier_histogram: TriageTierHistogram,
    pub first_seen_entities: usize,
    pub sequence: SanitizedSequenceSummary,
}

/// Numeric-only aggregate of private per-entity sequence observations.
#[derive(Debug, Default, Serialize)]
pub struct SanitizedSequenceSummary {
    pub window_seconds: u64,
    pub retained_observations: usize,
    pub observations_beyond_cap: usize,
    pub observations_without_timestamp: usize,
    pub maximum_distinct_patterns_in_window: usize,
    pub maximum_distinctive_patterns_in_window: usize,
}

/// Cardinalities of behavior-priority tiers, not a threat-severity histogram.
#[derive(Debug, Default, Serialize)]
pub struct TriageTierHistogram {
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
}

/// Private analyst output containing the ranked entity keys.
#[derive(Debug, Serialize)]
pub struct PrivateTriageView {
    pub report_kind: String,
    pub safety_note: String,
    pub entities: Vec<TriageEntity>,
}

/// The score fields used for triage ordering. This deliberately omits score
/// components because those remain available through `production explain`.
#[derive(Debug, Serialize)]
pub struct TriageBehaviorScore {
    pub total: u32,
    pub tier: String,
    pub reachable_max: u32,
}

/// A local ASN enrichment result for a private connection/client-IP entity.
#[derive(Debug, Serialize)]
pub struct TriageAsn {
    pub asn: u32,
    pub org: String,
}

/// The headline from locally supplied reputation opinions. It is an opinion
/// only and never changes the behavior score.
#[derive(Debug, Serialize)]
pub struct TriageReputation {
    pub score: u32,
    pub tier: String,
    pub scope: String,
}

/// One ranked connection/client-IP entity. All values here are private hunt
/// output and must not be copied into a sanitized report.
#[derive(Debug, Serialize)]
pub struct TriageEntity {
    pub key: String,
    pub identity: &'static str,
    pub behavior_score: TriageBehaviorScore,
    pub triage_basis: Option<&'static str>,
    pub requires_investigation: bool,
    pub distinct_templates: usize,
    pub distinct_cves: usize,
    pub distinct_observations: usize,
    pub matching_records: usize,
    pub request_specific_observations: usize,
    pub response_unverified_observations: usize,
    pub resolved_asn: Option<TriageAsn>,
    pub reputation: Option<TriageReputation>,
    pub first_seen: bool,
    pub sequence: RequestSequenceSummary,
}

/// Build a deterministic, private connection/client-IP triage view and its
/// aggregate-only counterpart. Only frozen local findings and optional local
/// ASN/reputation datasets are consulted; no network request is made.
pub fn build_triage_view(
    findings: &[FindingExplanation],
    capabilities: TelemetryCapabilities,
    policy: TriagePolicy,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
    first_seen_source_ips: &BTreeSet<String>,
) -> (SanitizedTriageSummary, PrivateTriageView) {
    let mut entities = entity_groups(
        findings,
        EntityDimension::ConnectionIp,
        policy.clone(),
        capabilities,
    )
    .into_iter()
    .map(|group| {
        let ip = group.key.parse::<IpAddr>().ok();
        let asn = ip.and_then(|ip| asn_database.and_then(|database| database.lookup(ip)));
        let resolved_asn = asn.map(|info| TriageAsn {
            asn: info.asn,
            org: info.org.clone(),
        });
        let reputation = ip
            .and_then(|ip| {
                reputation_database.map(|database| database.lookup(ip, asn.map(|info| info.asn)))
            })
            .and_then(|reputation| {
                Some(TriageReputation {
                    score: reputation.score?,
                    tier: reputation.tier?.label().to_owned(),
                    scope: reputation.score_scope?.to_owned(),
                })
            });
        let identity = group
            .identity
            .expect("connection-IP groups always carry an identity");
        let requires_investigation = group.requires_investigation();
        TriageEntity {
            first_seen: first_seen_source_ips.contains(&group.key),
            key: group.key,
            identity: identity.label(),
            behavior_score: TriageBehaviorScore {
                total: group.score.total,
                tier: group.score.tier.label().to_owned(),
                reachable_max: group.score.reachable_max,
            },
            triage_basis: group.triage_basis,
            requires_investigation,
            distinct_templates: group.distinct_templates,
            distinct_cves: group.distinct_cves,
            distinct_observations: group.distinct_observations,
            matching_records: group.matching_records,
            request_specific_observations: group.request_specific_observations,
            response_unverified_observations: group.response_unverified_observations,
            sequence: group.sequence,
            resolved_asn,
            reputation,
        }
    })
    .collect::<Vec<_>>();

    // This is an ordinal for human review only: behavior score first, then an
    // independent local reputation opinion, then first-seen context, then a
    // stable key tie-breaker. Neither enrichment alters the behavior score.
    entities.sort_by(|left, right| {
        right
            .behavior_score
            .total
            .cmp(&left.behavior_score.total)
            .then_with(|| {
                right
                    .reputation
                    .as_ref()
                    .map(|reputation| reputation.score)
                    .cmp(&left.reputation.as_ref().map(|reputation| reputation.score))
            })
            .then_with(|| right.first_seen.cmp(&left.first_seen))
            .then_with(|| left.key.cmp(&right.key))
            .then_with(|| left.identity.cmp(right.identity))
    });

    let mut tiers = TriageTierHistogram::default();
    for entity in &entities {
        match entity.behavior_score.tier.as_str() {
            "info" => tiers.info += 1,
            "low" => tiers.low += 1,
            "medium" => tiers.medium += 1,
            "high" => tiers.high += 1,
            _ => unreachable!("behavior score tiers are fixed"),
        }
    }
    let first_seen_entities = entities.iter().filter(|entity| entity.first_seen).count();
    let sequence = SanitizedSequenceSummary {
        window_seconds: policy.sequence_window.as_secs(),
        retained_observations: entities
            .iter()
            .map(|entity| entity.sequence.retained_observations)
            .sum(),
        observations_beyond_cap: entities
            .iter()
            .map(|entity| entity.sequence.observations_beyond_cap)
            .sum(),
        observations_without_timestamp: entities
            .iter()
            .map(|entity| entity.sequence.observations_without_timestamp)
            .sum(),
        maximum_distinct_patterns_in_window: entities
            .iter()
            .map(|entity| entity.sequence.maximum_distinct_patterns_in_window)
            .max()
            .unwrap_or(0),
        maximum_distinctive_patterns_in_window: entities
            .iter()
            .map(|entity| entity.sequence.maximum_distinctive_patterns_in_window)
            .max()
            .unwrap_or(0),
    };
    let safety_note = SAFETY_NOTE.to_owned();
    (
        SanitizedTriageSummary {
            report_kind: "SANITIZED_HUNT_TRIAGE".to_owned(),
            safety_note: safety_note.clone(),
            total_entities: entities.len(),
            entities_requiring_investigation: entities
                .iter()
                .filter(|entity| entity.requires_investigation)
                .count(),
            tier_histogram: tiers,
            first_seen_entities,
            sequence,
        },
        PrivateTriageView {
            report_kind: "HUNT_TRIAGE_VIEW_PRIVATE".to_owned(),
            safety_note,
            entities,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::Path};

    use tempfile::tempdir;

    use super::*;
    use crate::{
        event::{LogSource, TelemetryProfile},
        nuclei::{Detectability, RequestSpecificity},
        production::FindingSource,
        reputation::{load_asn_database, load_reputation_database},
    };

    fn finding(ip: &str, template_id: &str, request_id: &str) -> FindingExplanation {
        FindingExplanation {
            template_id: template_id.to_owned(),
            cves: vec![format!("CVE-2026-{template_id}")],
            detectability: Detectability::High,
            request_specificity: RequestSpecificity::RequestSpecific,
            timestamp: Some("2026-01-01T00:00:00Z".to_owned()),
            source_ip: Some(ip.to_owned()),
            client_ip: None,
            host: Some("example.test".to_owned()),
            method: Some("GET".to_owned()),
            uri_path: Some(format!("/distinctive-{template_id}")),
            uri_query: Some("marker=test".to_owned()),
            waf_action: Some("ALLOW".to_owned()),
            waf_rule_id: None,
            waf_rule_type: None,
            waf_labels: Vec::new(),
            waf_non_terminating_rule_ids: Vec::new(),
            headers: Vec::new(),
            ja3: None,
            ja4: None,
            request_id: Some(request_id.to_owned()),
            log_source: Some(LogSource::AwsWaf),
            source: FindingSource::Nuclei,
            rule_title: None,
            sigma_level: None,
        }
    }

    fn write_enrichment(path: &Path) {
        fs::write(
            path.join("asn.csv"),
            "network,autonomous_system_number,autonomous_system_organization\n198.51.100.1/32,64501,EXAMPLE-ASN\n",
        )
        .unwrap();
        fs::write(
            path.join("reputation.jsonl"),
            concat!(
                "{\"scope\":\"ip\",\"value\":\"198.51.100.1\",\"score\":90,\"source\":\"fixture\"}\n",
                "{\"scope\":\"ip\",\"value\":\"198.51.100.2\",\"score\":90,\"source\":\"fixture\"}\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn orders_by_score_then_reputation_then_first_seen_and_keeps_summary_sanitized() {
        let directory = tempdir().unwrap();
        write_enrichment(directory.path());
        let asn = load_asn_database(&directory.path().join("asn.csv")).unwrap();
        let reputation =
            load_reputation_database(&directory.path().join("reputation.jsonl")).unwrap();
        let mut findings = vec![
            finding("198.51.100.1", "one", "one"),
            finding("198.51.100.2", "one", "two"),
            finding("198.51.100.3", "one", "three"),
        ];
        // The fourth entity has more CTI breadth and must come first even
        // without a local reputation opinion.
        findings.extend([
            finding("198.51.100.9", "one", "nine-one"),
            finding("198.51.100.9", "two", "nine-two"),
        ]);
        let first_seen = BTreeSet::from(["198.51.100.2".to_owned()]);
        let (summary, view) = build_triage_view(
            &findings,
            TelemetryProfile::AwsWaf.capabilities(),
            TriagePolicy::default(),
            Some(&asn),
            Some(&reputation),
            &first_seen,
        );

        assert_eq!(
            view.entities
                .iter()
                .map(|entity| &entity.key)
                .collect::<Vec<_>>(),
            vec![
                "198.51.100.9",
                "198.51.100.2",
                "198.51.100.1",
                "198.51.100.3"
            ]
        );
        assert!(view.entities[1].first_seen);
        assert_eq!(view.entities[2].resolved_asn.as_ref().unwrap().asn, 64501);
        assert_eq!(summary.total_entities, 4);
        assert_eq!(summary.first_seen_entities, 1);
        assert_eq!(
            summary.tier_histogram.info
                + summary.tier_histogram.low
                + summary.tier_histogram.medium
                + summary.tier_histogram.high,
            summary.total_entities
        );
        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(!serialized.contains("198.51.100.1"));
        assert!(!serialized.contains("/distinctive-one"));
        assert_eq!(summary.sequence.retained_observations, findings.len());
        let private = serde_json::to_string(&view).unwrap();
        assert!(private.contains("/distinctive-one"));
    }
}
