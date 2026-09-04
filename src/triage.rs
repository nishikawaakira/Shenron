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

use crate::{
    event::TelemetryCapabilities,
    nuclei::{path_distinctiveness, PathDistinctiveness, RequestSpecificity},
    production::FindingExplanation,
};

/// Default breadth threshold: matching request observations for the fixed
/// research baseline.
pub const DEFAULT_BREADTH_OBSERVATIONS: usize = 3;
/// Default breadth threshold: distinct Nuclei template patterns.
pub const DEFAULT_BREADTH_TEMPLATES: usize = 2;
/// Default depth threshold: matching request observations, even for one
/// template.
pub const DEFAULT_DEPTH_OBSERVATIONS: usize = 10;
/// Default span for ordered request-sequence observations. This is reporting
/// context only and does not alter triage thresholds or behavior score.
pub const DEFAULT_SEQUENCE_WINDOW_SECONDS: u64 = 10;
/// Exact per-entity cap for private ordered request observations.
pub const DEFAULT_MAX_SEQUENCE_OBSERVATIONS: usize = 100_000;

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
#[derive(Clone)]
pub struct TriagePolicy {
    pub breadth_observations: usize,
    pub breadth_templates: usize,
    pub depth_observations: usize,
    /// Sliding windows evaluated independently. They are sorted and
    /// deduplicated so reports are stable for equivalent CLI input.
    pub windows: Vec<Duration>,
    pub sequence_window: Duration,
    pub max_sequence_observations: usize,
}

impl Default for TriagePolicy {
    fn default() -> Self {
        Self {
            breadth_observations: DEFAULT_BREADTH_OBSERVATIONS,
            breadth_templates: DEFAULT_BREADTH_TEMPLATES,
            depth_observations: DEFAULT_DEPTH_OBSERVATIONS,
            windows: Vec::new(),
            sequence_window: Duration::from_secs(DEFAULT_SEQUENCE_WINDOW_SECONDS),
            max_sequence_observations: DEFAULT_MAX_SEQUENCE_OBSERVATIONS,
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
        Self::with_windows(
            breadth_observations,
            breadth_templates,
            depth_observations,
            window.into_iter().collect(),
        )
    }

    pub fn with_windows(
        breadth_observations: Option<usize>,
        breadth_templates: Option<usize>,
        depth_observations: Option<usize>,
        mut windows: Vec<Duration>,
    ) -> Self {
        windows.retain(|window| !window.is_zero());
        windows.sort_unstable();
        windows.dedup();
        Self {
            breadth_observations: breadth_observations.unwrap_or(DEFAULT_BREADTH_OBSERVATIONS),
            breadth_templates: breadth_templates.unwrap_or(DEFAULT_BREADTH_TEMPLATES),
            depth_observations: depth_observations.unwrap_or(DEFAULT_DEPTH_OBSERVATIONS),
            windows,
            sequence_window: Duration::from_secs(DEFAULT_SEQUENCE_WINDOW_SECONDS),
            max_sequence_observations: DEFAULT_MAX_SEQUENCE_OBSERVATIONS,
        }
    }

    pub fn with_sequence_settings(
        mut self,
        sequence_window: Duration,
        max_sequence_observations: usize,
    ) -> Self {
        if !sequence_window.is_zero() {
            self.sequence_window = sequence_window;
        }
        self.max_sequence_observations = max_sequence_observations;
        self
    }

    pub fn is_default(&self) -> bool {
        self.breadth_observations == DEFAULT_BREADTH_OBSERVATIONS
            && self.breadth_templates == DEFAULT_BREADTH_TEMPLATES
            && self.depth_observations == DEFAULT_DEPTH_OBSERVATIONS
            && self.windows.is_empty()
            && self.sequence_window.as_secs() == DEFAULT_SEQUENCE_WINDOW_SECONDS
            && self.max_sequence_observations == DEFAULT_MAX_SEQUENCE_OBSERVATIONS
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
    /// The raw point ceiling the active telemetry profile and triage dimension
    /// can actually reach. `total` is normalized against this so that a profile
    /// missing a capability (for example no WAF outcome on combined logs) is
    /// not systematically depressed. Equal to 100 when every component is
    /// reachable.
    pub reachable_max: u32,
}

/// Which telemetry-gated score components the active profile and triage
/// dimension can actually reach. Always-reachable components (template-breadth,
/// cve-breadth, observation-depth, path-distinctiveness, windowed-burst) are not
/// listed here; they always count toward the reachable maximum.
#[derive(Debug, Clone, Copy)]
pub struct ReachableComponents {
    /// The complementary-dimension spread can be expressed. An IP or ASN group
    /// spreads over distinct hosts, which needs a host capability; a JA4 group
    /// spreads over source IPs, which every profile records.
    pub spread: bool,
    /// The profile records a WAF enforcement outcome.
    pub waf_unblocked: bool,
}

impl ReachableComponents {
    /// Every component reachable — the full-capability baseline used for score
    /// unit tests and for legacy findings with no recorded telemetry source.
    pub const ALL: Self = Self {
        spread: true,
        waf_unblocked: true,
    };

    fn for_dimension(capabilities: TelemetryCapabilities, dimension: EntityDimension) -> Self {
        Self {
            spread: match dimension {
                EntityDimension::Ja4 => true,
                EntityDimension::ConnectionIp | EntityDimension::Asn => capabilities.host,
            },
            waf_unblocked: capabilities.waf_action,
        }
    }
}

// The score sums capped per-signal contributions. Weights are intentionally
// transparent and total exactly 100 when every reachable component saturates,
// so the number is auditable rather than an opaque model output. Each
// contribution is monotonic in its signal: adding observed matching behavior
// can only raise the score. The total is then normalized against the reachable
// maximum for the active telemetry profile, so a source that structurally
// cannot express a component (for example no WAF outcome on combined logs) is
// not depressed relative to a richer source. Response-unverified (URI-only)
// groups also have a non-additive total cap of 74, so they cannot reach the
// high tier without request-specific evidence.
const MAX_TEMPLATE_POINTS: u32 = 24;
const MAX_CVE_POINTS: u32 = 16;
const MAX_OBSERVATION_POINTS: u32 = 16;
const MAX_DISTINCTIVE_PATH_POINTS: u32 = 4;
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
    /// Distinct matching request observations whose paths are classified as
    /// distinctive. This transparent path heuristic is a triage signal only.
    pub distinctive_observations: usize,
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
    /// Exact sliding-window widths in which the entity met a breadth-or-depth
    /// burst test. Multiple windows still contribute at most five points.
    pub windowed_burst_windows: Vec<u64>,
}

/// Compute the deterministic behavior-priority score for one entity, normalized
/// against the maximum the active telemetry profile and dimension can reach.
pub fn score(signals: &EntitySignals, reachable: ReachableComponents) -> BehaviorScore {
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

    let generic_observations = signals
        .distinct_observations
        .saturating_sub(signals.distinctive_observations);
    // Repetition of generic paths such as /robots.txt remains visible, but it
    // cannot consume the whole depth budget. Distinctive paths receive the
    // direct depth contribution because they are less resistant to accidental
    // request-side matches; this is still not a conclusion about a request.
    let observation_points = (signals.distinctive_observations as u32)
        .saturating_add((generic_observations as u32 / 10).min(2))
        .min(MAX_OBSERVATION_POINTS);
    components.push(ScoreComponent {
        name: "observation-depth",
        points: observation_points,
        detail: format!(
            "{} distinctive and {} generic-path distinct matching request observations",
            signals.distinctive_observations, generic_observations
        ),
    });

    let distinctive_path_points =
        (signals.distinctive_observations as u32).min(MAX_DISTINCTIVE_PATH_POINTS);
    components.push(ScoreComponent {
        name: "path-distinctiveness",
        points: distinctive_path_points,
        detail: format!(
            "{} distinct matching request observations on distinctive paths",
            signals.distinctive_observations
        ),
    });

    let spread_points = if reachable.spread {
        let points = (signals.spread as u32 * 2).min(MAX_SPREAD_POINTS);
        components.push(ScoreComponent {
            name: "spread",
            points,
            detail: format!("{} distinct related endpoints or peers", signals.spread),
        });
        points
    } else {
        components.push(ScoreComponent {
            name: "spread",
            points: 0,
            detail: "spread is unavailable for this telemetry profile (no host field), so it does not count toward the reachable maximum".to_owned(),
        });
        0
    };

    let unblocked_points = match (reachable.waf_unblocked, signals.unblocked_fraction) {
        (true, Some(fraction)) => {
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
        (true, None) => {
            components.push(ScoreComponent {
                name: "waf-unblocked",
                points: 0,
                detail: "no matched request had a known WAF enforcement outcome".to_owned(),
            });
            0
        }
        (false, _) => {
            components.push(ScoreComponent {
                name: "waf-unblocked",
                points: 0,
                detail: "WAF enforcement outcome is unavailable for this telemetry profile, so it does not count toward the reachable maximum".to_owned(),
            });
            0
        }
    };

    let windowed_burst = !signals.windowed_burst_windows.is_empty();
    let burst_points = if windowed_burst {
        WINDOWED_BURST_POINTS
    } else {
        0
    };
    components.push(ScoreComponent {
        name: "windowed-burst",
        points: burst_points,
        detail: if windowed_burst {
            format!(
                "met a windowed breadth or depth burst in {}",
                signals
                    .windowed_burst_windows
                    .iter()
                    .map(|seconds| format_duration_seconds(*seconds))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            "no windowed burst evaluated or met".to_owned()
        },
    });

    let raw_total = template_points
        + cve_points
        + observation_points
        + distinctive_path_points
        + spread_points
        + unblocked_points
        + burst_points;

    // The reachable maximum excludes telemetry-gated components this profile and
    // dimension cannot express. Always-reachable components plus windowed-burst
    // form the baseline; windowed-burst stays counted because it is an analyst
    // choice, not a telemetry limitation.
    let reachable_max = MAX_TEMPLATE_POINTS
        + MAX_CVE_POINTS
        + MAX_OBSERVATION_POINTS
        + MAX_DISTINCTIVE_PATH_POINTS
        + WINDOWED_BURST_POINTS
        + if reachable.spread {
            MAX_SPREAD_POINTS
        } else {
            0
        }
        + if reachable.waf_unblocked {
            MAX_UNBLOCKED_POINTS
        } else {
            0
        };

    // Normalize the raw total to 0..=100 against what this profile can reach.
    // reachable_max is always positive (the baseline alone is 65).
    let total =
        ((raw_total.min(reachable_max) as f64) * 100.0 / reachable_max as f64).round() as u32;
    let total = total.min(100);

    // URI-only evidence cannot by itself receive the highest priority tier:
    // Nuclei response confirmation is unavailable in request telemetry. The cap
    // is on the normalized total, so it holds regardless of profile.
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
        reachable_max,
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
    /// Exact windows and per-window basis that met the configured test. This
    /// increases reporting detail only; the score receives one fixed component.
    pub windowed_burst_windows: Vec<WindowedTriageMatch>,
    pub sequence: RequestSequenceSummary,
    pub triage_basis: Option<&'static str>,
    pub score: BehaviorScore,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowedTriageMatch {
    pub window_seconds: u64,
    pub basis: &'static str,
}

/// One timestamped private request-pattern observation. Pattern strings can
/// contain request paths and therefore must never enter sanitized artifacts.
#[derive(Debug, Clone, Serialize)]
pub struct OrderedRequestObservation {
    pub timestamp: String,
    pub request_pattern: String,
    pub distinctive_path: bool,
}

/// Deterministic sequence context for one private entity group. A short or
/// regular sequence can have many benign or automated causes and is not a
/// determination of automation, attack, abuse, or identity.
#[derive(Debug, Clone, Serialize)]
pub struct RequestSequenceSummary {
    pub window_seconds: u64,
    pub retained_observations: usize,
    pub observations_beyond_cap: usize,
    pub observations_without_timestamp: usize,
    pub maximum_distinct_patterns_in_window: usize,
    pub maximum_distinctive_patterns_in_window: usize,
    pub minimum_interval_seconds: Option<f64>,
    pub median_interval_seconds: Option<f64>,
    pub ordered_observations: Vec<OrderedRequestObservation>,
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

#[derive(Clone)]
struct SequenceObservation {
    timestamp: Option<DateTime<Utc>>,
    request_pattern: String,
    distinctive_path: bool,
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
    distinctive_observations: BTreeSet<String>,
    validated_clients: BTreeSet<String>,
    observed_peers: BTreeSet<String>,
    blocked_observations: BTreeSet<String>,
    not_blocked_observations: BTreeSet<String>,
    unknown_outcome_observations: BTreeSet<String>,
    observations: Vec<Observation>,
    sequence_observation_keys: BTreeSet<String>,
    sequence_observations: Vec<SequenceObservation>,
    sequence_observations_beyond_cap: usize,
}

impl EntitySummary {
    fn triage_evaluation(
        &self,
        policy: &TriagePolicy,
    ) -> (Option<&'static str>, Vec<WindowedTriageMatch>) {
        if !policy.windows.is_empty() {
            let windows = policy
                .windows
                .iter()
                .filter_map(|window| {
                    self.windowed_triage_basis(*window, policy)
                        .map(|basis| WindowedTriageMatch {
                            window_seconds: window.as_secs(),
                            basis,
                        })
                })
                .collect::<Vec<_>>();
            let saw_breadth = windows.iter().any(|item| item.basis.contains("breadth"));
            let saw_depth = windows.iter().any(|item| item.basis.contains("depth"));
            let basis = match (saw_breadth, saw_depth) {
                (true, true) => Some("windowed breadth + depth"),
                (true, false) => Some("windowed breadth"),
                (false, true) => Some("windowed depth"),
                (false, false) => None,
            };
            return (basis, windows);
        }
        let breadth = self.request_patterns.len() >= policy.breadth_observations
            && self.templates.len() >= policy.breadth_templates;
        let depth = self.request_patterns.len() >= policy.depth_observations;
        let basis = match (breadth, depth) {
            (true, true) => Some("breadth + depth"),
            (true, false) => Some("breadth"),
            (false, true) => Some("depth"),
            (false, false) => None,
        };
        (basis, Vec::new())
    }

    fn undated_observations(&self) -> usize {
        self.observations
            .iter()
            .filter(|observation| observation.timestamp.is_none())
            .count()
    }

    fn windowed_triage_basis(
        &self,
        window: Duration,
        policy: &TriagePolicy,
    ) -> Option<&'static str> {
        // CLI parsing bounds durations, but preserve fail-closed behavior if a
        // non-CLI caller supplies a duration chrono cannot represent.
        let window = chrono::Duration::from_std(window).ok()?;
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

    fn signals(
        &self,
        dimension: EntityDimension,
        windowed_burst_windows: Vec<u64>,
    ) -> EntitySignals {
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
            distinctive_observations: self.distinctive_observations.len(),
            request_specific_observations,
            spread,
            unblocked_fraction,
            windowed_burst_windows,
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

    fn sequence_summary(&self, policy: &TriagePolicy) -> RequestSequenceSummary {
        let mut observations = self
            .sequence_observations
            .iter()
            .filter_map(|observation| {
                observation
                    .timestamp
                    .map(|timestamp| (timestamp, observation))
            })
            .collect::<Vec<_>>();
        observations.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.request_pattern.cmp(&right.1.request_pattern))
        });
        let (maximum_distinct_patterns_in_window, maximum_distinctive_patterns_in_window) =
            sequence_window_maxima(&observations, policy.sequence_window);
        let intervals = observations
            .windows(2)
            .map(|pair| {
                pair[1]
                    .0
                    .signed_duration_since(pair[0].0)
                    .num_milliseconds()
            })
            .collect::<Vec<_>>();
        let (minimum_interval_seconds, median_interval_seconds) = interval_statistics(&intervals);
        RequestSequenceSummary {
            window_seconds: policy.sequence_window.as_secs(),
            retained_observations: self.sequence_observations.len(),
            observations_beyond_cap: self.sequence_observations_beyond_cap,
            observations_without_timestamp: self
                .sequence_observations
                .iter()
                .filter(|observation| observation.timestamp.is_none())
                .count(),
            maximum_distinct_patterns_in_window,
            maximum_distinctive_patterns_in_window,
            minimum_interval_seconds,
            median_interval_seconds,
            ordered_observations: observations
                .into_iter()
                .map(|(timestamp, observation)| OrderedRequestObservation {
                    timestamp: timestamp.to_rfc3339(),
                    request_pattern: observation.request_pattern.clone(),
                    distinctive_path: observation.distinctive_path,
                })
                .collect(),
        }
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
    capabilities: TelemetryCapabilities,
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
        add_finding_to_summary(entry, finding, policy.max_sequence_observations);
    }
    finalize_entity_groups(summaries, dimension, BTreeMap::new(), policy, capabilities)
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
    capabilities: TelemetryCapabilities,
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
        add_finding_to_summary(
            summaries.entry(summary_key).or_default(),
            finding,
            policy.max_sequence_observations,
        );
    }
    AsnEntityGroups {
        groups: finalize_entity_groups(
            summaries,
            EntityDimension::Asn,
            organizations,
            policy,
            capabilities,
        ),
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

fn add_finding_to_summary(
    summary: &mut EntitySummary,
    finding: &FindingExplanation,
    max_sequence_observations: usize,
) {
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
    if path_distinctiveness(finding.uri_path.as_deref().unwrap_or_default())
        == PathDistinctiveness::Distinctive
    {
        summary
            .distinctive_observations
            .insert(request_pattern.clone());
    }
    summary.record_waf_outcome(&request_pattern, finding.waf_action.as_deref());
    if summary
        .sequence_observation_keys
        .insert(request_pattern.clone())
    {
        if summary.sequence_observations.len() < max_sequence_observations {
            let visible_pattern = format!(
                "{} {}{}",
                finding.method.as_deref().unwrap_or("<method unavailable>"),
                finding.uri_path.as_deref().unwrap_or("<path unavailable>"),
                finding
                    .uri_query
                    .as_deref()
                    .map(|query| format!("?{query}"))
                    .unwrap_or_default()
            );
            summary.sequence_observations.push(SequenceObservation {
                timestamp: parse_finding_timestamp(finding.timestamp.as_deref()),
                request_pattern: visible_pattern,
                distinctive_path: path_distinctiveness(
                    finding.uri_path.as_deref().unwrap_or_default(),
                ) == PathDistinctiveness::Distinctive,
            });
        } else {
            summary.sequence_observations_beyond_cap += 1;
        }
    }
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
    capabilities: TelemetryCapabilities,
) -> Vec<EntityGroup> {
    let reachable = ReachableComponents::for_dimension(capabilities, dimension);
    let mut groups = summaries
        .into_iter()
        .map(|((identity, key), summary)| {
            let (triage_basis, windowed_burst_windows) = summary.triage_evaluation(&policy);
            let score = score(
                &summary.signals(
                    dimension,
                    windowed_burst_windows
                        .iter()
                        .map(|item| item.window_seconds)
                        .collect(),
                ),
                reachable,
            );
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
                windowed_burst_windows,
                sequence: summary.sequence_summary(&policy),
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

fn format_duration_seconds(seconds: u64) -> String {
    if seconds.is_multiple_of(86_400) {
        format!("{}d", seconds / 86_400)
    } else if seconds.is_multiple_of(3_600) {
        format!("{}h", seconds / 3_600)
    } else if seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

fn sequence_window_maxima(
    observations: &[(DateTime<Utc>, &SequenceObservation)],
    window: Duration,
) -> (usize, usize) {
    let Ok(window) = chrono::Duration::from_std(window) else {
        return (0, 0);
    };
    let mut start = 0usize;
    let mut patterns = BTreeMap::<&str, usize>::new();
    let mut distinctive_patterns = BTreeMap::<&str, usize>::new();
    let mut maximum_patterns = 0usize;
    let mut maximum_distinctive = 0usize;
    for end in 0..observations.len() {
        let observation = observations[end].1;
        *patterns
            .entry(observation.request_pattern.as_str())
            .or_default() += 1;
        if observation.distinctive_path {
            *distinctive_patterns
                .entry(observation.request_pattern.as_str())
                .or_default() += 1;
        }
        while observations[end]
            .0
            .signed_duration_since(observations[start].0)
            > window
        {
            let removed = observations[start].1;
            decrement(&mut patterns, removed.request_pattern.as_str());
            if removed.distinctive_path {
                decrement(&mut distinctive_patterns, removed.request_pattern.as_str());
            }
            start += 1;
        }
        maximum_patterns = maximum_patterns.max(patterns.len());
        maximum_distinctive = maximum_distinctive.max(distinctive_patterns.len());
    }
    (maximum_patterns, maximum_distinctive)
}

fn interval_statistics(intervals_millis: &[i64]) -> (Option<f64>, Option<f64>) {
    if intervals_millis.is_empty() {
        return (None, None);
    }
    let mut sorted = intervals_millis.to_vec();
    sorted.sort_unstable();
    let minimum = sorted[0] as f64 / 1_000.0;
    let middle = sorted.len() / 2;
    let median_millis = if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] as f64 + sorted[middle] as f64) / 2.0
    } else {
        sorted[middle] as f64
    };
    (Some(minimum), Some(median_millis / 1_000.0))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use chrono::TimeZone;

    use super::*;
    use crate::event::TelemetryProfile;

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

    // Most score tests assess signal handling under a full-capability profile;
    // this wrapper keeps them reading against the reachable-all baseline. Tests
    // that exercise profile normalization call `super::score` with explicit
    // `ReachableComponents`.
    fn score(signals: &EntitySignals) -> BehaviorScore {
        super::score(signals, ReachableComponents::ALL)
    }

    fn signals() -> EntitySignals {
        EntitySignals {
            distinct_templates: 0,
            distinct_cves: 0,
            distinct_observations: 0,
            distinctive_observations: 0,
            request_specific_observations: 0,
            spread: 0,
            unblocked_fraction: None,
            windowed_burst_windows: Vec::new(),
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
            distinctive_observations: 100,
            request_specific_observations: 1,
            spread: 100,
            unblocked_fraction: Some(1.0),
            windowed_burst_windows: vec![600],
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
            distinctive_observations: 100,
            request_specific_observations: 0,
            spread: 100,
            unblocked_fraction: Some(1.0),
            windowed_burst_windows: vec![600],
        });
        assert_eq!(uri_only.total, 74);
        assert_eq!(uri_only.tier, ScoreTier::Medium);

        let request_specific = score(&EntitySignals {
            request_specific_observations: 1,
            ..EntitySignals {
                distinct_templates: 100,
                distinct_cves: 100,
                distinct_observations: 100,
                distinctive_observations: 100,
                request_specific_observations: 0,
                spread: 100,
                unblocked_fraction: Some(1.0),
                windowed_burst_windows: vec![600],
            }
        });
        assert_eq!(request_specific.tier, ScoreTier::High);
    }

    #[test]
    fn score_is_normalized_against_the_profile_reachable_maximum() {
        // Identical behavioural evidence, minus the WAF outcome that combined
        // logs cannot record. Without normalization the vhost profile would be
        // depressed by the unreachable waf-unblocked points; with it, the same
        // evidence lands in the same tier.
        let evidence = EntitySignals {
            distinct_templates: 8,
            distinct_cves: 8,
            distinct_observations: 10,
            distinctive_observations: 10,
            request_specific_observations: 5,
            spread: 0,
            unblocked_fraction: None,
            windowed_burst_windows: Vec::new(),
        };
        let aws = super::score(
            &evidence,
            ReachableComponents::for_dimension(
                TelemetryProfile::AwsWaf.capabilities(),
                EntityDimension::ConnectionIp,
            ),
        );
        let vhost = super::score(
            &evidence,
            ReachableComponents::for_dimension(
                TelemetryProfile::ApacheVhostCombined.capabilities(),
                EntityDimension::ConnectionIp,
            ),
        );
        assert_eq!(aws.reachable_max, 100);
        // Vhost cannot reach the 15 waf-unblocked points.
        assert_eq!(vhost.reachable_max, 85);
        assert_eq!(aws.tier, vhost.tier);
        // The vhost total is scaled up toward its own ceiling rather than left
        // structurally below the AWS WAF total.
        assert!(vhost.total >= aws.total);
        // A combined-log profile still lists the unreachable component at 0.
        let waf = vhost
            .components
            .iter()
            .find(|component| component.name == "waf-unblocked")
            .unwrap();
        assert_eq!(waf.points, 0);
        assert!(waf
            .detail
            .contains("unavailable for this telemetry profile"));
    }

    #[test]
    fn distinctive_path_evidence_outranks_repeated_generic_path_evidence() {
        let repeated_generic = score(&EntitySignals {
            distinct_templates: 1,
            distinct_cves: 1,
            distinct_observations: 135,
            distinctive_observations: 0,
            request_specific_observations: 1,
            ..signals()
        });
        let several_distinctive = score(&EntitySignals {
            distinct_templates: 3,
            distinct_cves: 3,
            distinct_observations: 3,
            distinctive_observations: 3,
            request_specific_observations: 1,
            ..signals()
        });
        assert!(several_distinctive.total > repeated_generic.total);
        assert_eq!(
            repeated_generic
                .components
                .iter()
                .find(|component| component.name == "path-distinctiveness")
                .unwrap()
                .points,
            0
        );
        assert_eq!(
            several_distinctive
                .components
                .iter()
                .find(|component| component.name == "path-distinctiveness")
                .unwrap()
                .points,
            3
        );
    }

    #[test]
    fn entity_groups_classify_generic_and_distinctive_paths_for_scoring() {
        let mut generic = finding(
            "generic",
            "generic-template",
            None,
            RequestSpecificity::RequestSpecific,
            None,
            Some("203.0.113.30"),
            None,
        );
        generic.uri_path = Some("/robots.txt".to_owned());
        let mut distinctive = finding(
            "distinctive",
            "distinctive-template",
            None,
            RequestSpecificity::RequestSpecific,
            None,
            Some("203.0.113.31"),
            None,
        );
        distinctive.uri_path = Some("/.env".to_owned());

        let groups = entity_groups(
            &[generic, distinctive],
            EntityDimension::ConnectionIp,
            TriagePolicy::default(),
            TelemetryProfile::AwsWaf.capabilities(),
        );
        let generic_component = groups
            .iter()
            .find(|group| group.key == "203.0.113.30")
            .unwrap()
            .score
            .components
            .iter()
            .find(|component| component.name == "path-distinctiveness")
            .unwrap();
        let distinctive_component = groups
            .iter()
            .find(|group| group.key == "203.0.113.31")
            .unwrap()
            .score
            .components
            .iter()
            .find(|component| component.name == "path-distinctiveness")
            .unwrap();
        assert_eq!(generic_component.points, 0);
        assert_eq!(distinctive_component.points, 1);
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
            log_source: Some(crate::event::LogSource::AwsWaf),
            source: crate::production::FindingSource::Nuclei,
            rule_title: None,
            sigma_level: None,
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
            TelemetryProfile::AwsWaf.capabilities(),
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
        let group = entity_groups(
            &findings,
            EntityDimension::Ja4,
            TriagePolicy::default(),
            TelemetryProfile::AwsWaf.capabilities(),
        )
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
        let groups = asn_entity_groups(
            &findings,
            TriagePolicy::default(),
            &TestAsnResolver,
            TelemetryProfile::AwsWaf.capabilities(),
        );
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
        let groups = asn_entity_groups(
            &findings,
            TriagePolicy::default(),
            &TestAsnResolver,
            TelemetryProfile::AwsWaf.capabilities(),
        );
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
        let groups = asn_entity_groups(
            &findings,
            TriagePolicy::default(),
            &TestAsnResolver,
            TelemetryProfile::AwsWaf.capabilities(),
        );
        assert!(groups.groups.is_empty());
        assert_eq!(groups.unresolved_findings, 1);
    }

    #[test]
    fn multiple_windows_report_each_match_but_add_burst_points_once() {
        let mut findings = vec![
            finding(
                "first",
                "template-a",
                None,
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.40"),
                None,
            ),
            finding(
                "second",
                "template-b",
                None,
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.40"),
                None,
            ),
            finding(
                "third",
                "template-a",
                None,
                RequestSpecificity::RequestSpecific,
                None,
                Some("203.0.113.40"),
                None,
            ),
        ];
        for (finding, timestamp) in findings.iter_mut().zip([
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:05Z",
            "2026-01-01T00:00:10Z",
        ]) {
            finding.timestamp = Some(timestamp.to_owned());
        }
        let policy = TriagePolicy::with_windows(
            Some(3),
            Some(2),
            Some(10),
            vec![Duration::from_secs(3_600), Duration::from_secs(10)],
        );
        let group = entity_groups(
            &findings,
            EntityDimension::ConnectionIp,
            policy,
            TelemetryProfile::AwsWaf.capabilities(),
        )
        .pop()
        .unwrap();
        assert_eq!(
            group
                .windowed_burst_windows
                .iter()
                .map(|item| item.window_seconds)
                .collect::<Vec<_>>(),
            vec![10, 3_600]
        );
        let burst = group
            .score
            .components
            .iter()
            .find(|component| component.name == "windowed-burst")
            .unwrap();
        assert_eq!(burst.points, WINDOWED_BURST_POINTS);
        assert!(burst.detail.contains("10s, 1h"));

        let single = entity_groups(
            &findings,
            EntityDimension::ConnectionIp,
            TriagePolicy::new(None, None, None, Some(Duration::from_secs(10))),
            TelemetryProfile::AwsWaf.capabilities(),
        )
        .pop()
        .unwrap();
        assert_eq!(
            single
                .score
                .components
                .iter()
                .find(|component| component.name == "windowed-burst")
                .unwrap()
                .points,
            WINDOWED_BURST_POINTS
        );
        assert_eq!(single.windowed_burst_windows.len(), 1);
    }

    #[test]
    fn ordered_sequence_reports_short_span_distinct_patterns_and_long_span_absence() {
        let make_findings = |timestamps: [&str; 3]| {
            ["one", "two", "three"]
                .into_iter()
                .zip(timestamps)
                .map(|(request_id, timestamp)| {
                    let mut item = finding(
                        request_id,
                        "template-a",
                        None,
                        RequestSpecificity::RequestSpecific,
                        None,
                        Some("203.0.113.50"),
                        None,
                    );
                    item.timestamp = Some(timestamp.to_owned());
                    item
                })
                .collect::<Vec<_>>()
        };
        let policy = TriagePolicy::default().with_sequence_settings(Duration::from_secs(10), 10);
        let short = entity_groups(
            &make_findings([
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:05Z",
                "2026-01-01T00:00:10Z",
            ]),
            EntityDimension::ConnectionIp,
            policy.clone(),
            TelemetryProfile::AwsWaf.capabilities(),
        )
        .pop()
        .unwrap();
        assert_eq!(short.sequence.maximum_distinct_patterns_in_window, 3);
        assert_eq!(short.sequence.maximum_distinctive_patterns_in_window, 3);
        assert_eq!(short.sequence.ordered_observations.len(), 3);

        let spread = entity_groups(
            &make_findings([
                "2026-01-01T00:00:00Z",
                "2026-01-02T00:00:00Z",
                "2026-01-03T00:00:00Z",
            ]),
            EntityDimension::ConnectionIp,
            policy,
            TelemetryProfile::AwsWaf.capabilities(),
        )
        .pop()
        .unwrap();
        assert_eq!(spread.sequence.maximum_distinct_patterns_in_window, 1);
    }

    #[test]
    fn ordered_sequence_distinguishes_regular_and_irregular_intervals() {
        let group_for_offsets = |offsets: [i64; 3]| {
            let findings = offsets
                .into_iter()
                .enumerate()
                .map(|(index, offset)| {
                    let mut item = finding(
                        &format!("request-{index}"),
                        "template-a",
                        None,
                        RequestSpecificity::RequestSpecific,
                        None,
                        Some("203.0.113.60"),
                        None,
                    );
                    item.timestamp = Some(
                        Utc.timestamp_opt(1_767_225_600 + offset, 0)
                            .unwrap()
                            .to_rfc3339(),
                    );
                    item
                })
                .collect::<Vec<_>>();
            entity_groups(
                &findings,
                EntityDimension::ConnectionIp,
                TriagePolicy::default().with_sequence_settings(Duration::from_secs(30), 10),
                TelemetryProfile::AwsWaf.capabilities(),
            )
            .pop()
            .unwrap()
        };
        let regular = group_for_offsets([0, 5, 10]);
        assert_eq!(regular.sequence.minimum_interval_seconds, Some(5.0));
        assert_eq!(regular.sequence.median_interval_seconds, Some(5.0));
        let irregular = group_for_offsets([0, 1, 21]);
        assert_eq!(irregular.sequence.minimum_interval_seconds, Some(1.0));
        assert_eq!(irregular.sequence.median_interval_seconds, Some(10.5));
    }

    #[test]
    fn ordered_sequence_discloses_undated_and_capped_observations() {
        let mut findings = (0..4)
            .map(|index| {
                finding(
                    &format!("request-{index}"),
                    "template-a",
                    None,
                    RequestSpecificity::RequestSpecific,
                    None,
                    Some("203.0.113.70"),
                    None,
                )
            })
            .collect::<Vec<_>>();
        findings[0].timestamp = None;
        let group = entity_groups(
            &findings,
            EntityDimension::ConnectionIp,
            TriagePolicy::default().with_sequence_settings(Duration::from_secs(10), 2),
            TelemetryProfile::AwsWaf.capabilities(),
        )
        .pop()
        .unwrap();
        assert_eq!(group.sequence.retained_observations, 2);
        assert_eq!(group.sequence.observations_without_timestamp, 1);
        assert_eq!(group.sequence.observations_beyond_cap, 2);
        assert_eq!(group.sequence.ordered_observations.len(), 1);
    }
}
