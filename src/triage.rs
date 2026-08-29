//! Offline behavior-priority triage and scoring for hunt entities.
//!
//! This module ranks entities (connection/client IP addresses and JA4 TLS
//! fingerprints) for human triage using only request-side evidence already
//! present in local private findings. It never contacts a network, resolves
//! external reputation, or attributes an attacker.
//!
//! The behavior score is a triage prioritization ordinal only. It is not a
//! probability of malice, a precision or true-/false-positive estimate, an
//! exploitation, compromise, or vulnerable-product determination, or attacker
//! attribution. Reputation of an IP or ASN, when available, is a separate
//! offline enrichment layer and is intentionally not part of this behavioral
//! score.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{nuclei::RequestSpecificity, production::FindingExplanation};

/// Default breadth threshold: matching request observations for the fixed
/// research baseline.
pub const DEFAULT_BREADTH_OBSERVATIONS: usize = 3;
/// Default breadth threshold: distinct Nuclei template patterns.
pub const DEFAULT_BREADTH_TEMPLATES: usize = 2;
/// Default depth threshold: matching request observations, even for one
/// template.
pub const DEFAULT_DEPTH_OBSERVATIONS: usize = 10;

/// The dimension an entity is grouped by.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EntityDimension {
    /// A connection or verified-forwarded client IP address.
    ConnectionIp,
    /// A JA4 TLS client fingerprint.
    Ja4,
    /// A resolved autonomous system number.
    Asn,
}

/// A locally resolved autonomous system for an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAsn {
    pub asn: u32,
    pub org: String,
}

/// Resolve an IP address through an analyst-supplied local ASN dataset.
///
/// Implementations must not perform network lookups. The triage module owns
/// this trait so it remains independent of any particular ASN dataset format.
pub trait AsnResolver {
    fn resolve(&self, ip: IpAddr) -> Option<ResolvedAsn>;
}

/// Whether an IP group is a verified forwarded client or an observed peer.
///
/// Validated-client and observed-peer groups are intentionally never merged:
/// when forwarded resolution applies to only some requests, one actual sender
/// may appear under both identities. A peer may be a CDN, load balancer, NAT,
/// or proxy and is not attacker attribution.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupingIdentity {
    ValidatedClient,
    ObservedPeer,
}

impl GroupingIdentity {
    pub fn label(self) -> &'static str {
        match self {
            Self::ValidatedClient => "validated-client",
            Self::ObservedPeer => "observed-peer",
        }
    }
}

/// The thresholds used to decide whether a group requires investigation.
#[derive(Clone, Copy)]
pub struct TriagePolicy {
    pub breadth_observations: usize,
    pub breadth_templates: usize,
    pub depth_observations: usize,
    pub window: Option<Duration>,
}

impl Default for TriagePolicy {
    fn default() -> Self {
        Self {
            breadth_observations: DEFAULT_BREADTH_OBSERVATIONS,
            breadth_templates: DEFAULT_BREADTH_TEMPLATES,
            depth_observations: DEFAULT_DEPTH_OBSERVATIONS,
            window: None,
        }
    }
}

impl TriagePolicy {
    pub fn new(
        breadth_observations: Option<usize>,
        breadth_templates: Option<usize>,
        depth_observations: Option<usize>,
        window: Option<Duration>,
    ) -> Self {
        Self {
            breadth_observations: breadth_observations.unwrap_or(DEFAULT_BREADTH_OBSERVATIONS),
            breadth_templates: breadth_templates.unwrap_or(DEFAULT_BREADTH_TEMPLATES),
            depth_observations: depth_observations.unwrap_or(DEFAULT_DEPTH_OBSERVATIONS),
            window,
        }
    }

    pub fn is_default(self) -> bool {
        self.breadth_observations == DEFAULT_BREADTH_OBSERVATIONS
            && self.breadth_templates == DEFAULT_BREADTH_TEMPLATES
            && self.depth_observations == DEFAULT_DEPTH_OBSERVATIONS
            && self.window.is_none()
    }
}

/// A prioritization tier derived from the total behavior score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScoreTier {
    Info,
    Low,
    Medium,
    High,
}

impl ScoreTier {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// One transparent contribution to the total behavior score.
#[derive(Debug, Clone, Serialize)]
pub struct ScoreComponent {
    pub name: &'static str,
    pub points: u32,
    pub detail: String,
}

/// A deterministic, offline behavior-priority score in the range 0..=100.
#[derive(Debug, Clone, Serialize)]
pub struct BehaviorScore {
    pub total: u32,
    pub tier: ScoreTier,
    pub components: Vec<ScoreComponent>,
}

// The score sums capped per-signal contributions. Weights are intentionally
// transparent and total exactly 100 at saturation, so the number is auditable
// rather than an opaque model output. Each contribution is monotonic in its
// signal: adding observed matching behavior can only raise the score.
// Response-unverified (URI-only) groups also have a non-additive total cap of
// 74, so they cannot reach the high tier without request-specific evidence.
const MAX_TEMPLATE_POINTS: u32 = 24;
const MAX_CVE_POINTS: u32 = 16;
const MAX_OBSERVATION_POINTS: u32 = 20;
const MAX_SPREAD_POINTS: u32 = 20;
const MAX_UNBLOCKED_POINTS: u32 = 15;
const WINDOWED_BURST_POINTS: u32 = 5;

/// The observable, offline signals aggregated for one entity. Every field is
/// derived only from local hunt evidence; none involves a network lookup.
#[derive(Debug, Clone)]
pub struct EntitySignals {
    /// Distinct Nuclei template patterns matched by this entity.
    pub distinct_templates: usize,
    /// Distinct CVEs across the matched templates.
    pub distinct_cves: usize,
    /// Distinct matching request observations (deduplicated per request).
    pub distinct_observations: usize,
    /// Observations whose matching Detection IR includes a query, fragment, or
    /// explicit header requirement. If one request matched both categories,
    /// request-specific takes precedence.
    pub request_specific_observations: usize,
    /// The complementary-dimension spread. For a connection-IP entity this is
    /// the number of distinct hosts targeted; for a JA4 entity it is the number
    /// of distinct connection/client IPs sharing the fingerprint. In both cases
    /// a larger value indicates broader automated activity.
    pub spread: usize,
    /// Matching requests the WAF did not block, over matching requests with a
    /// known enforcement outcome. `None` when no matched request has a known
    /// WAF outcome (for example nginx/Apache telemetry).
    pub unblocked_fraction: Option<f64>,
    /// True when the entity met a windowed breadth-or-depth burst test.
    pub windowed_burst: bool,
}

/// Compute the deterministic behavior-priority score for one entity.
pub fn score(signals: &EntitySignals) -> BehaviorScore {
    let mut components = Vec::new();

    let template_points = (signals.distinct_templates as u32 * 3).min(MAX_TEMPLATE_POINTS);
    components.push(ScoreComponent {
        name: "template-breadth",
        points: template_points,
        detail: format!(
            "{} distinct Nuclei template patterns",
            signals.distinct_templates
        ),
    });

    let cve_points = (signals.distinct_cves as u32 * 2).min(MAX_CVE_POINTS);
    components.push(ScoreComponent {
        name: "cve-breadth",
        points: cve_points,
        detail: format!("{} distinct CVEs", signals.distinct_cves),
    });

    let observation_points = (signals.distinct_observations as u32).min(MAX_OBSERVATION_POINTS);
    components.push(ScoreComponent {
        name: "observation-depth",
        points: observation_points,
        detail: format!(
            "{} distinct matching request observations",
            signals.distinct_observations
        ),
    });

    let spread_points = (signals.spread as u32 * 2).min(MAX_SPREAD_POINTS);
    components.push(ScoreComponent {
        name: "spread",
        points: spread_points,
        detail: format!("{} distinct related endpoints or peers", signals.spread),
    });

    let unblocked_points = match signals.unblocked_fraction {
        Some(fraction) => {
            let points = (fraction * MAX_UNBLOCKED_POINTS as f64).round() as u32;
            let points = points.min(MAX_UNBLOCKED_POINTS);
            components.push(ScoreComponent {
                name: "waf-unblocked",
                points,
                detail: format!(
                    "{:.0}% of matched requests with a known WAF outcome were not blocked",
                    fraction * 100.0
                ),
            });
            points
        }
        None => {
            components.push(ScoreComponent {
                name: "waf-unblocked",
                points: 0,
                detail: "no matched request had a known WAF enforcement outcome".to_owned(),
            });
            0
        }
    };

    let burst_points = if signals.windowed_burst {
        WINDOWED_BURST_POINTS
    } else {
        0
    };
    components.push(ScoreComponent {
        name: "windowed-burst",
        points: burst_points,
        detail: if signals.windowed_burst {
            "met a windowed breadth or depth burst".to_owned()
        } else {
            "no windowed burst evaluated or met".to_owned()
        },
    });

    let total = template_points
        + cve_points
        + observation_points
        + spread_points
        + unblocked_points
        + burst_points;
    let total = total.min(100);

    // URI-only evidence cannot by itself receive the highest priority tier:
    // Nuclei response confirmation is unavailable in request telemetry.
    let total = if signals.request_specific_observations == 0 {
        total.min(74)
    } else {
        total
    };
    let tier = if total >= 75 {
        ScoreTier::High
    } else if total >= 50 {
        ScoreTier::Medium
    } else if total >= 25 {
        ScoreTier::Low
    } else {
        ScoreTier::Info
    };

    BehaviorScore {
        total,
        tier,
        components,
    }
}

/// A ranked entity group ready for display, carrying its triage basis and
/// behavior score. Reputation enrichment, when present, is layered on
/// separately by the caller.
pub struct EntityGroup {
    /// The IP address, JA4 fingerprint, or ASN number that identifies the group.
    pub key: String,
    /// Present for connection-IP and ASN groups.
    pub identity: Option<GroupingIdentity>,
    /// Present only for ASN groups.
    pub asn_org: Option<String>,
    pub distinct_templates: usize,
    pub distinct_cves: usize,
    pub distinct_observations: usize,
    pub matching_records: usize,
    pub spread: usize,
    pub request_specific_observations: usize,
    pub response_unverified_observations: usize,
    /// JA4 group count, kept separate from observed peers to avoid merging
    /// verified and unverified identity evidence.
    pub distinct_validated_clients: usize,
    /// JA4 group count, kept separate from verified clients to avoid merging
    /// verified and unverified identity evidence.
    pub distinct_observed_peers: usize,
    pub undated_observations: usize,
    pub triage_basis: Option<&'static str>,
    pub score: BehaviorScore,
}

impl EntityGroup {
    pub fn requires_investigation(&self) -> bool {
        self.triage_basis.is_some()
    }
}

#[derive(Clone)]
struct Observation {
    timestamp: Option<DateTime<Utc>>,
    request_pattern: String,
    template_id: String,
}

#[derive(Default)]
struct EntitySummary {
    matching_records: usize,
    cves: BTreeSet<String>,
    templates: BTreeSet<String>,
    request_patterns: BTreeSet<String>,
    hosts: BTreeSet<String>,
    request_specific_observations: BTreeSet<String>,
    response_unverified_observations: BTreeSet<String>,
    validated_clients: BTreeSet<String>,
    observed_peers: BTreeSet<String>,
    blocked_observations: BTreeSet<String>,
    not_blocked_observations: BTreeSet<String>,
    unknown_outcome_observations: BTreeSet<String>,
    observations: Vec<Observation>,
}

impl EntitySummary {
    fn triage_basis(&self, policy: TriagePolicy) -> Option<&'static str> {
        if policy.window.is_some() {
            return self.windowed_triage_basis(policy);
        }
        let breadth = self.request_patterns.len() >= policy.breadth_observations
            && self.templates.len() >= policy.breadth_templates;
        let depth = self.request_patterns.len() >= policy.depth_observations;
        match (breadth, depth) {
            (true, true) => Some("breadth + depth"),
            (true, false) => Some("breadth"),
            (false, true) => Some("depth"),
            (false, false) => None,
        }
    }

    fn undated_observations(&self) -> usize {
        self.observations
            .iter()
            .filter(|observation| observation.timestamp.is_none())
            .count()
    }

    fn windowed_triage_basis(&self, policy: TriagePolicy) -> Option<&'static str> {
        // CLI parsing bounds durations, but preserve fail-closed behavior if a
        // non-CLI caller supplies a duration chrono cannot represent.
        let window = chrono::Duration::from_std(policy.window?).ok()?;
        let mut observations = self
            .observations
            .iter()
            .filter_map(|observation| {
                observation
                    .timestamp
                    .map(|timestamp| (timestamp, observation))
            })
            .collect::<Vec<_>>();
        observations.sort_by_key(|(timestamp, _)| *timestamp);

        let mut start = 0;
        let mut patterns = BTreeMap::<&str, usize>::new();
        let mut templates = BTreeMap::<&str, usize>::new();
        let mut saw_breadth = false;
        let mut saw_depth = false;
        for end in 0..observations.len() {
            let (_, observation) = observations[end];
            *patterns
                .entry(observation.request_pattern.as_str())
                .or_default() += 1;
            *templates
                .entry(observation.template_id.as_str())
                .or_default() += 1;
            while observations[end]
                .0
                .signed_duration_since(observations[start].0)
                > window
            {
                let (_, observation) = observations[start];
                decrement(&mut patterns, observation.request_pattern.as_str());
                decrement(&mut templates, observation.template_id.as_str());
                start += 1;
            }
            saw_breadth |= patterns.len() >= policy.breadth_observations
                && templates.len() >= policy.breadth_templates;
            saw_depth |= patterns.len() >= policy.depth_observations;
        }
        match (saw_breadth, saw_depth) {
            (true, true) => Some("windowed breadth + depth"),
            (true, false) => Some("windowed breadth"),
            (false, true) => Some("windowed depth"),
            (false, false) => None,
        }
    }

    fn signals(&self, dimension: EntityDimension, windowed_burst: bool) -> EntitySignals {
        let spread = match dimension {
            EntityDimension::ConnectionIp => self.hosts.len(),
            // Do not sum these populations: the same sender can appear once
            // as a verified client and once as an observed peer when forwarded
            // resolution is only available for part of the log.
            EntityDimension::Ja4 | EntityDimension::Asn => {
                self.validated_clients.len().max(self.observed_peers.len())
            }
        };
        let (waf_known, waf_unblocked) = self.known_waf_outcomes();
        let unblocked_fraction = if waf_known == 0 {
            None
        } else {
            Some(waf_unblocked as f64 / waf_known as f64)
        };
        let (request_specific_observations, _) = self.specificity_observations();
        EntitySignals {
            distinct_templates: self.templates.len(),
            distinct_cves: self.cves.len(),
            distinct_observations: self.request_patterns.len(),
            request_specific_observations,
            spread,
            unblocked_fraction,
            windowed_burst,
        }
    }

    fn specificity_observations(&self) -> (usize, usize) {
        let request_specific = self.request_specific_observations.len();
        let response_unverified = self
            .response_unverified_observations
            .difference(&self.request_specific_observations)
            .count();
        (request_specific, response_unverified)
    }

    fn known_waf_outcomes(&self) -> (usize, usize) {
        let conflicted_or_unknown = |observation: &String| {
            self.unknown_outcome_observations.contains(observation)
                || (self.blocked_observations.contains(observation)
                    && self.not_blocked_observations.contains(observation))
        };
        let blocked = self
            .blocked_observations
            .iter()
            .filter(|observation| !conflicted_or_unknown(observation))
            .count();
        let not_blocked = self
            .not_blocked_observations
            .iter()
            .filter(|observation| !conflicted_or_unknown(observation))
            .count();
        (blocked + not_blocked, not_blocked)
    }

    fn record_waf_outcome(&mut self, observation: &str, action: Option<&str>) {
        match action.map(str::to_ascii_uppercase).as_deref() {
            Some("BLOCK") => {
                self.blocked_observations.insert(observation.to_owned());
            }
            Some("ALLOW") | Some("COUNT") => {
                self.not_blocked_observations.insert(observation.to_owned());
            }
            Some(_) => {
                self.unknown_outcome_observations
                    .insert(observation.to_owned());
            }
            None => {}
        }
    }
}

fn decrement(values: &mut BTreeMap<&str, usize>, value: &str) {
    let count = values
        .get_mut(value)
        .expect("window contains each tracked observation");
    *count -= 1;
    if *count == 0 {
        values.remove(value);
    }
}

/// Deduplicate observations to one per logged request so a template that emits
/// several findings for one request does not inflate the repeated-behavior
/// test. Older private findings may lack a request ID, so their available
/// request evidence is used as a deterministic fallback.
fn observation_pattern(finding: &FindingExplanation) -> String {
    if let Some(request_id) = &finding.request_id {
        return format!("request-id:{request_id}");
    }
    format!(
        "timestamp:{:?}\u{1f}host:{:?}\u{1f}method:{:?}\u{1f}path:{:?}\u{1f}query:{:?}",
        finding.timestamp, finding.host, finding.method, finding.uri_path, finding.uri_query
    )
}

fn parse_finding_timestamp(value: Option<&str>) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value?)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

/// Group findings by the requested dimension, apply the triage policy, and
/// compute a behavior score per group. Results are sorted by matching request
/// observations (descending), then distinct templates (descending), then key.
pub fn entity_groups(
    findings: &[FindingExplanation],
    dimension: EntityDimension,
    policy: TriagePolicy,
) -> Vec<EntityGroup> {
    let mut summaries = BTreeMap::<(Option<GroupingIdentity>, String), EntitySummary>::new();
    for finding in findings {
        let (identity, key): (Option<GroupingIdentity>, String) = match dimension {
            EntityDimension::ConnectionIp => {
                if let Some(client_ip) = &finding.client_ip {
                    (Some(GroupingIdentity::ValidatedClient), client_ip.clone())
                } else if let Some(source_ip) = &finding.source_ip {
                    (Some(GroupingIdentity::ObservedPeer), source_ip.clone())
                } else {
                    continue;
                }
            }
            EntityDimension::Ja4 => match &finding.ja4 {
                Some(ja4) => (None, ja4.clone()),
                None => continue,
            },
            // ASN grouping requires a caller-provided local resolver. Use
            // `asn_entity_groups` rather than silently inventing a mapping.
            EntityDimension::Asn => continue,
        };
        let entry = summaries.entry((identity, key)).or_default();
        add_finding_to_summary(entry, finding);
    }
    finalize_entity_groups(summaries, dimension, BTreeMap::new(), policy)
}

/// ASN groups together with the number of findings that had no local ASN
/// resolution and were therefore excluded from ASN aggregation.
pub struct AsnEntityGroups {
    pub groups: Vec<EntityGroup>,
    pub unresolved_findings: usize,
}

/// Group findings by a locally resolved ASN without merging trusted client and
/// observed peer identities. No network lookup is performed: `resolver` is
/// supplied by the caller.
pub fn asn_entity_groups(
    findings: &[FindingExplanation],
    policy: TriagePolicy,
    resolver: &dyn AsnResolver,
) -> AsnEntityGroups {
    let mut summaries = BTreeMap::<(Option<GroupingIdentity>, String), EntitySummary>::new();
    let mut organizations = BTreeMap::<(Option<GroupingIdentity>, String), BTreeSet<String>>::new();
    let mut unresolved_findings = 0;
    for finding in findings {
        let (identity, address) = match finding_identity_and_address(finding) {
            Some(value) => value,
            None => continue,
        };
        let resolved = address
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| resolver.resolve(ip));
        let Some(resolved) = resolved else {
            unresolved_findings += 1;
            continue;
        };
        let key = resolved.asn.to_string();
        let summary_key = (Some(identity), key.clone());
        organizations
            .entry(summary_key.clone())
            .or_default()
            .insert(resolved.org);
        add_finding_to_summary(summaries.entry(summary_key).or_default(), finding);
    }
    AsnEntityGroups {
        groups: finalize_entity_groups(summaries, EntityDimension::Asn, organizations, policy),
        unresolved_findings,
    }
}

fn finding_identity_and_address(finding: &FindingExplanation) -> Option<(GroupingIdentity, &str)> {
    if let Some(client_ip) = finding.client_ip.as_deref() {
        Some((GroupingIdentity::ValidatedClient, client_ip))
    } else {
        finding
            .source_ip
            .as_deref()
            .map(|source_ip| (GroupingIdentity::ObservedPeer, source_ip))
    }
}

fn add_finding_to_summary(summary: &mut EntitySummary, finding: &FindingExplanation) {
    summary.matching_records += 1;
    summary.cves.extend(finding.cves.iter().cloned());
    summary.templates.insert(finding.template_id.clone());
    if let Some(host) = &finding.host {
        summary.hosts.insert(host.clone());
    }
    let request_pattern = observation_pattern(finding);
    summary.request_patterns.insert(request_pattern.clone());
    match &finding.client_ip {
        Some(client_ip) => {
            summary.validated_clients.insert(client_ip.clone());
        }
        None => {
            if let Some(source_ip) = &finding.source_ip {
                summary.observed_peers.insert(source_ip.clone());
            }
        }
    }
    match finding.request_specificity {
        RequestSpecificity::RequestSpecific => {
            summary
                .request_specific_observations
                .insert(request_pattern.clone());
        }
        RequestSpecificity::ResponseUnverified => {
            summary
                .response_unverified_observations
                .insert(request_pattern.clone());
        }
    }
    summary.record_waf_outcome(&request_pattern, finding.waf_action.as_deref());
    summary.observations.push(Observation {
        timestamp: parse_finding_timestamp(finding.timestamp.as_deref()),
        request_pattern,
        template_id: finding.template_id.clone(),
    });
}

fn finalize_entity_groups(
    summaries: BTreeMap<(Option<GroupingIdentity>, String), EntitySummary>,
    dimension: EntityDimension,
    organizations: BTreeMap<(Option<GroupingIdentity>, String), BTreeSet<String>>,
    policy: TriagePolicy,
) -> Vec<EntityGroup> {
    let mut groups = summaries
        .into_iter()
        .map(|((identity, key), summary)| {
            let triage_basis = summary.triage_basis(policy);
            let windowed_burst = policy.window.is_some() && triage_basis.is_some();
            let score = score(&summary.signals(dimension, windowed_burst));
            let (request_specific_observations, response_unverified_observations) =
                summary.specificity_observations();
            EntityGroup {
                asn_org: organizations
                    .get(&(identity, key.clone()))
                    .and_then(|values| values.iter().next().cloned()),
                key,
                identity,
                distinct_templates: summary.templates.len(),
                distinct_cves: summary.cves.len(),
                distinct_observations: summary.request_patterns.len(),
                matching_records: summary.matching_records,
                spread: match dimension {
                    EntityDimension::ConnectionIp => summary.hosts.len(),
                    EntityDimension::Ja4 | EntityDimension::Asn => summary
                        .validated_clients
                        .len()
                        .max(summary.observed_peers.len()),
                },
                request_specific_observations,
                response_unverified_observations,
                distinct_validated_clients: summary.validated_clients.len(),
                distinct_observed_peers: summary.observed_peers.len(),
                undated_observations: summary.undated_observations(),
                triage_basis,
                score,
            }
        })
        .collect::<Vec<_>>();

    groups.sort_by(|left, right| {
        right
            .distinct_observations
            .cmp(&left.distinct_observations)
            .then_with(|| right.distinct_templates.cmp(&left.distinct_templates))
            .then_with(|| left.key.cmp(&right.key))
            .then_with(|| left.identity.cmp(&right.identity))
    });
    groups
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    struct TestAsnResolver;

    impl AsnResolver for TestAsnResolver {
        fn resolve(&self, ip: IpAddr) -> Option<ResolvedAsn> {
            match ip.to_string().as_str() {
                "203.0.113.7" | "203.0.113.8" => Some(ResolvedAsn {
                    asn: 64_501,
                    org: "EXAMPLE-NARROW".to_owned(),
                }),
                _ => None,
            }
        }
    }

    fn signals() -> EntitySignals {
        EntitySignals {
            distinct_templates: 0,
            distinct_cves: 0,
            distinct_observations: 0,
            request_specific_observations: 0,
            spread: 0,
            unblocked_fraction: None,
            windowed_burst: false,
        }
    }

    #[test]
    fn empty_behavior_scores_zero_and_is_info_tier() {
        let scored = score(&signals());
        assert_eq!(scored.total, 0);
        assert_eq!(scored.tier, ScoreTier::Info);
    }

    #[test]
    fn behavior_score_saturates_at_one_hundred() {
        let scored = score(&EntitySignals {
            distinct_templates: 100,
            distinct_cves: 100,
            distinct_observations: 100,
            request_specific_observations: 1,
            spread: 100,
            unblocked_fraction: Some(1.0),
            windowed_burst: true,
        });
        assert_eq!(scored.total, 100);
        assert_eq!(scored.tier, ScoreTier::High);
    }

    #[test]
    fn behavior_score_is_monotonic_in_each_signal() {
        let base = score(&signals()).total;
        let more_templates = score(&EntitySignals {
            distinct_templates: 4,
            ..signals()
        })
        .total;
        let more_observations = score(&EntitySignals {
            distinct_observations: 12,
            ..signals()
        })
        .total;
        assert!(more_templates > base);
        assert!(more_observations > base);
    }

    #[test]
    fn unknown_waf_outcome_contributes_no_unblocked_points() {
        let scored = score(&EntitySignals {
            unblocked_fraction: None,
            ..signals()
        });
        let unblocked = scored
            .components
            .iter()
            .find(|component| component.name == "waf-unblocked")
            .unwrap();
        assert_eq!(unblocked.points, 0);
    }

    #[test]
    fn response_unverified_evidence_cannot_reach_the_high_tier_alone() {
        let uri_only = score(&EntitySignals {
            distinct_templates: 100,
            distinct_cves: 100,
            distinct_observations: 100,
            request_specific_observations: 0,
            spread: 100,
            unblocked_fraction: Some(1.0),
            windowed_burst: true,
        });
        assert_eq!(uri_only.total, 74);
        assert_eq!(uri_only.tier, ScoreTier::Medium);

        let request_specific = score(&EntitySignals {
            request_specific_observations: 1,
            ..EntitySignals {
                distinct_templates: 100,
                distinct_cves: 100,
                distinct_observations: 100,
                request_specific_observations: 0,
                spread: 100,
                unblocked_fraction: Some(1.0),
                windowed_burst: true,
            }
        });
        assert_eq!(request_specific.tier, ScoreTier::High);
    }

    fn finding(
        request_id: &str,
        template_id: &str,
        action: Option<&str>,
        request_specificity: RequestSpecificity,
        client_ip: Option<&str>,
        source_ip: Option<&str>,
        ja4: Option<&str>,
    ) -> FindingExplanation {
        FindingExplanation {
            template_id: template_id.to_owned(),
            cves: vec![format!("CVE-{template_id}")],
            detectability: crate::nuclei::Detectability::High,
            request_specificity,
            timestamp: Some("2026-01-01T00:00:00Z".to_owned()),
            source_ip: source_ip.map(str::to_owned),
            client_ip: client_ip.map(str::to_owned),
            host: Some("example.test".to_owned()),
            method: Some("GET".to_owned()),
            uri_path: Some(format!("/{request_id}")),
            uri_query: None,
            waf_action: action.map(str::to_owned),
            waf_rule_id: None,
            waf_rule_type: None,
            waf_labels: Vec::new(),
            waf_non_terminating_rule_ids: Vec::new(),
            headers: Vec::new(),
            ja3: None,
            ja4: ja4.map(str::to_owned),
            request_id: Some(request_id.to_owned()),
        }
    }

    #[test]
    fn deduplicates_waf_outcomes_per_request_and_excludes_unknown_actions() {
        let findings = vec![
            finding(
                "allow-request",
                "template-a",
                Some("ALLOW"),
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.1"),
                None,
            ),
            finding(
                "allow-request",
                "template-b",
                Some("ALLOW"),
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.1"),
                None,
            ),
            finding(
                "blocked-request",
                "template-c",
                Some("BLOCK"),
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.1"),
                None,
            ),
            finding(
                "unknown-request",
                "template-d",
                Some("CHALLENGE"),
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.1"),
                None,
            ),
        ];
        let group = entity_groups(
            &findings,
            EntityDimension::ConnectionIp,
            TriagePolicy::default(),
        )
        .pop()
        .unwrap();
        let unblocked = group
            .score
            .components
            .iter()
            .find(|component| component.name == "waf-unblocked")
            .unwrap();
        assert_eq!(unblocked.points, 8);
        assert!(unblocked.detail.contains("50%"));
    }

    #[test]
    fn ja4_keeps_validated_clients_and_observed_peers_separate() {
        let findings = vec![
            finding(
                "client-request",
                "template-a",
                None,
                RequestSpecificity::RequestSpecific,
                Some("203.0.113.10"),
                Some("198.51.100.10"),
                Some("t13d1516h2_shared"),
            ),
            finding(
                "peer-request",
                "template-b",
                None,
                RequestSpecificity::RequestSpecific,
                None,
                Some("198.51.100.20"),
                Some("t13d1516h2_shared"),
            ),
        ];
        let group = entity_groups(&findings, EntityDimension::Ja4, TriagePolicy::default())
            .pop()
            .unwrap();
        assert_eq!(group.distinct_validated_clients, 1);
        assert_eq!(group.distinct_observed_peers, 1);
        assert_eq!(group.spread, 1);
    }

    #[test]
    fn groups_multiple_member_ips_under_one_resolved_asn() {
        let findings = vec![
            finding(
                "first",
                "template-a",
                None,
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.7"),
                None,
            ),
            finding(
                "second",
                "template-b",
                None,
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.8"),
                None,
            ),
        ];
        let groups = asn_entity_groups(&findings, TriagePolicy::default(), &TestAsnResolver);
        assert_eq!(groups.unresolved_findings, 0);
        assert_eq!(groups.groups.len(), 1);
        let group = &groups.groups[0];
        assert_eq!(group.key, "64501");
        assert_eq!(group.asn_org.as_deref(), Some("EXAMPLE-NARROW"));
        assert!(group.identity == Some(GroupingIdentity::ObservedPeer));
        assert_eq!(group.spread, 2);
    }

    #[test]
    fn keeps_client_and_peer_identities_separate_within_one_asn() {
        let findings = vec![
            finding(
                "client",
                "template-a",
                None,
                RequestSpecificity::RequestSpecific,
                Some("203.0.113.7"),
                Some("198.51.100.10"),
                None,
            ),
            finding(
                "peer",
                "template-a",
                None,
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.8"),
                None,
            ),
        ];
        let groups = asn_entity_groups(&findings, TriagePolicy::default(), &TestAsnResolver);
        assert_eq!(groups.groups.len(), 2);
        assert!(groups
            .groups
            .iter()
            .any(|group| group.identity == Some(GroupingIdentity::ValidatedClient)));
        assert!(groups
            .groups
            .iter()
            .any(|group| group.identity == Some(GroupingIdentity::ObservedPeer)));
    }

    #[test]
    fn excludes_unresolved_ips_from_asn_groups() {
        let findings = vec![finding(
            "unknown",
            "template-a",
            None,
            RequestSpecificity::RequestSpecific,
            None,
            Some("192.0.2.99"),
            None,
        )];
        let groups = asn_entity_groups(&findings, TriagePolicy::default(), &TestAsnResolver);
        assert!(groups.groups.is_empty());
        assert_eq!(groups.unresolved_findings, 1);
    }
}
