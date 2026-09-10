//! Deterministic request-volume distribution measurement for local WebEvent streams.
//!
//! These aggregates are triage context only. They do not determine a denial-of-service
//! attempt, attack, abuse, compromise, or attacker identity. Tracking is exact for
//! retained keys and deliberately stops admitting new keys at fixed caps; every such
//! omission is reported as a count rather than approximated.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{event::WebEvent, triage::AsnResolver};

pub const DEFAULT_MAX_TRACKED_PATHS: usize = 100_000;
pub const DEFAULT_MAX_TRACKED_SOURCE_IPS: usize = 1_000_000;
/// Separate bounded tracking for the explicitly selected path focus. This is
/// intentionally independent of the top-level source-IP map so a focus remains
/// useful even if the general distribution reaches its own admission cap.
pub const DEFAULT_MAX_FOCUS_SOURCE_IPS: usize = 1_000_000;
/// Separate bounded tracking for the distinct URI paths retained inside a focus
/// (the sub-paths under a path prefix, or the paths one source IP requested).
pub const DEFAULT_MAX_FOCUS_PATHS: usize = 1_000_000;
/// Exact distinct query-string tracking is bounded per retained path (and per
/// explicit focus) because timestamp-, UUID-, or nonce-like values can make
/// this cardinality grow with every request.
pub const DEFAULT_MAX_QUERY_STRINGS_PER_PATH: usize = 100_000;
/// Query-key names are private request metadata and use a separate bound.
pub const DEFAULT_MAX_QUERY_KEYS_PER_PATH: usize = 10_000;
/// Roughly 1.9 years of one-minute buckets. Both global and focus timelines
/// stop admitting new minutes at this fixed cap and disclose omitted records.
pub const DEFAULT_MAX_MINUTE_BUCKETS: usize = 1_000_000;
/// Default deterministic rate windows: one minute, ten minutes, one hour, and
/// one day. They describe volume shape only and are not alert thresholds.
pub const DEFAULT_RATE_WINDOW_SECONDS: [u64; 4] = [60, 600, 3_600, 86_400];
/// Default minimum request count for including a time bucket in response
/// outcome extrema. This avoids presenting a one-request bucket as a useful
/// minimum or maximum while making no health or availability classification.
pub const DEFAULT_RESPONSE_BUCKET_MINIMUM_REQUESTS: u64 = 10;
/// Descriptive counting threshold only; never a health or attack classification.
pub const DEFAULT_RESPONSE_SUCCESS_SHARE_THRESHOLD_PERCENT: u8 = 50;
pub const DEFAULT_MAX_STATUS_CODES_PER_ENTITY: usize = 128;
pub const DEFAULT_MAX_SOURCE_SEGMENTS: usize = 256;

/// What a `concentration` focus selects. Exact and prefix focuses are keyed on
/// the normalized URI path; the source-IP focus lists what one or more observed
/// connection peers requested. A focus never asserts attack, abuse, or identity.
#[derive(Debug, Clone)]
pub enum FocusSelector {
    /// One exact normalized URI path.
    ExactPath(String),
    /// A path and everything under it (`/api` matches `/api` and `/api/...`).
    PathPrefix(String),
    /// One or more observed connection-peer IP addresses. The ordered set
    /// removes duplicates and keeps private output deterministic.
    SourceIp(BTreeSet<String>),
}

impl FocusSelector {
    /// Stable discriminator recorded in artifacts and used to pick labels.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ExactPath(_) => "exact-path",
            Self::PathPrefix(_) => "path-prefix",
            Self::SourceIp(_) => "source-ip",
        }
    }

    /// A deterministic private display of the analyst-supplied selector. Paths
    /// are returned unchanged; source IPs are joined in sorted order.
    pub fn selector_display(&self) -> String {
        match self {
            Self::ExactPath(value) | Self::PathPrefix(value) => value.clone(),
            Self::SourceIp(values) => values.iter().cloned().collect::<Vec<_>>().join(", "),
        }
    }
}

/// Whether `path` is `prefix` or lies in its subtree. A trailing slash on the
/// prefix is ignored, and the root `/` contains every path. Matching is on
/// path segments, so `/api` does not match `/apixyz`.
fn path_is_under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    if prefix.is_empty() {
        return true;
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}
pub const DEFAULT_FOCUS_IPV4_GROUP_PREFIX: u8 = 24;
pub const DEFAULT_FOCUS_IPV6_GROUP_PREFIX: u8 = 48;

/// Address-prefix sizes used only to derive private focus-path presentation
/// groups from already retained peer-IP counts. They do not affect streaming
/// tracking or individual peer-IP output.
#[derive(Debug, Clone, Copy)]
pub struct FocusPrefixLengths {
    pub ipv4: u8,
    pub ipv6: u8,
}

impl Default for FocusPrefixLengths {
    fn default() -> Self {
        Self {
            ipv4: DEFAULT_FOCUS_IPV4_GROUP_PREFIX,
            ipv6: DEFAULT_FOCUS_IPV6_GROUP_PREFIX,
        }
    }
}
/// A separate cap keeps source-to-path detail bounded even when both top-level
/// key spaces are within their respective limits.
pub const DEFAULT_MAX_TRACKED_SOURCE_PATH_PAIRS: usize = 2_000_000;

#[derive(Debug, Clone, Copy)]
pub struct ConcentrationLimits {
    pub max_source_segments: usize,
    pub max_paths: usize,
    pub max_source_ips: usize,
    pub max_focus_source_ips: usize,
    pub max_focus_paths: usize,
    pub max_source_path_pairs: usize,
    pub max_minute_buckets: usize,
    pub max_query_strings_per_path: usize,
    pub max_query_keys_per_path: usize,
    pub max_status_codes_per_entity: usize,
}

impl Default for ConcentrationLimits {
    fn default() -> Self {
        Self {
            max_paths: DEFAULT_MAX_TRACKED_PATHS,
            max_source_segments: DEFAULT_MAX_SOURCE_SEGMENTS,
            max_source_ips: DEFAULT_MAX_TRACKED_SOURCE_IPS,
            max_focus_source_ips: DEFAULT_MAX_FOCUS_SOURCE_IPS,
            max_focus_paths: DEFAULT_MAX_FOCUS_PATHS,
            max_source_path_pairs: DEFAULT_MAX_TRACKED_SOURCE_PATH_PAIRS,
            max_minute_buckets: DEFAULT_MAX_MINUTE_BUCKETS,
            max_query_strings_per_path: DEFAULT_MAX_QUERY_STRINGS_PER_PATH,
            max_query_keys_per_path: DEFAULT_MAX_QUERY_KEYS_PER_PATH,
            max_status_codes_per_entity: DEFAULT_MAX_STATUS_CODES_PER_ENTITY,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct StatusClassCounts {
    pub informational: u64,
    pub success: u64,
    pub redirection: u64,
    pub client_error: u64,
    /// nginx 499 responses, also retained inside `client_error` for backward
    /// compatibility. Presentation subtracts this subset from ordinary 4xx.
    #[serde(default)]
    pub client_closed_request_499: u64,
    pub server_error: u64,
    pub other: u64,
    pub unavailable: u64,
}

impl StatusClassCounts {
    fn merge(&mut self, other: &Self) {
        self.informational += other.informational;
        self.success += other.success;
        self.redirection += other.redirection;
        self.client_error += other.client_error;
        self.client_closed_request_499 += other.client_closed_request_499;
        self.server_error += other.server_error;
        self.other += other.other;
        self.unavailable += other.unavailable;
    }
    pub fn ordinary_client_error(&self) -> u64 {
        self.client_error
            .saturating_sub(self.client_closed_request_499)
    }

    fn total_observations(&self) -> u64 {
        self.informational
            + self.success
            + self.redirection
            + self.client_error
            + self.server_error
            + self.other
            + self.unavailable
    }
}

/// Aggregate response outcomes from status-capable telemetry. Shares use all
/// observed requests, including unavailable/other outcomes in the denominator.
/// They are measurements, not a health, outage, or availability judgment.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ResponseOutcomeSummary {
    pub counts: StatusClassCounts,
    pub success_share: f64,
    pub redirection_share: f64,
    /// Ordinary 4xx excluding the separately reported nginx 499 subset.
    pub ordinary_client_error_share: f64,
    pub client_closed_request_499_share: f64,
    pub server_error_share: f64,
}

/// Response-outcome extrema over one existing request-rate bucket width.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WindowedResponseOutcomeSummary {
    pub bucket_width_seconds: u64,
    pub minimum_requests_per_bucket: u64,
    pub eligible_buckets: usize,
    pub buckets_below_minimum: usize,
    pub minimum_success_share: Option<f64>,
    pub maximum_server_error_share: Option<f64>,
    pub observations_without_timestamp: u64,
    pub observations_beyond_bucket_cap: u64,
    #[serde(default)]
    pub minimum_success_bucket_start: Option<DateTime<Utc>>,
    #[serde(default)]
    pub maximum_server_error_bucket_start: Option<DateTime<Utc>>,
    #[serde(default)]
    pub success_share_threshold_percent: Option<u8>,
    /// Eligible buckets strictly below the configured percentage; not an alert.
    #[serde(default)]
    pub buckets_below_success_threshold: usize,
}

/// Exact retained code counts. Admission follows input order. Repeated
/// observations of an unretained code increment the omission count each time.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StatusCodeCounts {
    // JSON object keys are strings. Explicit parsing also supports serde's
    // buffered `flatten` path in PrivatePathConcentration.
    #[serde(deserialize_with = "deserialize_status_code_counts")]
    pub counts: BTreeMap<u16, u64>,
    pub observations_beyond_cap: u64,
    pub maximum_codes: usize,
}

fn deserialize_status_code_counts<'de, D>(deserializer: D) -> Result<BTreeMap<u16, u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BTreeMap::<String, u64>::deserialize(deserializer)?
        .into_iter()
        .map(|(code, count)| {
            code.parse::<u16>()
                .map(|code| (code, count))
                .map_err(serde::de::Error::custom)
        })
        .collect()
}

impl Default for StatusCodeCounts {
    fn default() -> Self {
        Self {
            counts: BTreeMap::new(),
            observations_beyond_cap: 0,
            maximum_codes: DEFAULT_MAX_STATUS_CODES_PER_ENTITY,
        }
    }
}

impl StatusCodeCounts {
    fn record(&mut self, status: Option<u16>, maximum: usize) {
        self.maximum_codes = maximum;
        if let Some(status) = status {
            self.add(status, 1);
        }
    }

    fn add(&mut self, status: u16, count: u64) {
        if let Some(current) = self.counts.get_mut(&status) {
            *current += count;
        } else if self.counts.len() < self.maximum_codes {
            self.counts.insert(status, count);
        } else {
            self.observations_beyond_cap += count;
        }
    }

    fn merge(&mut self, other: &Self) {
        self.observations_beyond_cap += other.observations_beyond_cap;
        for (&code, &count) in &other.counts {
            self.add(code, count);
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathConcentrationSummary {
    pub requests: u64,
    pub request_share: f64,
    /// Exact unless source-IP tracking reached its disclosed cap.
    pub distinct_source_ips: usize,
    /// Requests divided by retained distinct observed source IPs. Zero when no
    /// source IP was retained; source-IP cap disclosures still apply.
    #[serde(default)]
    pub requests_per_source_ip: f64,
    pub response_status_classes: StatusClassCounts,
    #[serde(default)]
    pub response_status_codes: Option<StatusCodeCounts>,
    /// `None` when the selected telemetry profile does not expose response bytes.
    pub response_bytes: Option<u64>,
    /// Requests for this path that carried a query component, including an
    /// explicitly empty query.
    #[serde(default)]
    pub requests_with_query: u64,
    /// Exact retained query-string cardinality unless
    /// `query_strings_beyond_tracking_cap` is non-zero. Query values are never
    /// serialized into either private or sanitized artifacts.
    #[serde(default)]
    pub distinct_query_strings: usize,
    /// Observations on previously unretained query strings after the fixed cap
    /// was reached. This is an omission count, not an estimated cardinality.
    #[serde(default)]
    pub query_strings_beyond_tracking_cap: u64,
    /// Exact retained query-key cardinality unless
    /// `query_keys_beyond_tracking_cap` is non-zero.
    #[serde(default)]
    pub distinct_query_keys: usize,
    /// Query-key observations not admitted after the fixed key-name cap.
    #[serde(default)]
    pub query_keys_beyond_tracking_cap: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestRateSummary {
    pub peak_requests_per_minute: Option<u64>,
    pub median_requests_per_minute: Option<f64>,
    pub peak_to_median_ratio: Option<f64>,
    pub observations_without_timestamp: u64,
}

/// Request-volume statistics for one exact UTC bucket width. These are volume
/// measurements, not a determination of attack, automation, or intent.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct WindowedRequestRateSummary {
    pub bucket_width_seconds: u64,
    pub peak_requests: Option<u64>,
    pub median_requests: Option<f64>,
    pub peak_to_median_ratio: Option<f64>,
    pub observations_without_timestamp: u64,
    /// Records in new buckets omitted after the deterministic bucket cap.
    pub observations_beyond_bucket_cap: u64,
}

/// Aggregate-only focus output. The requested path and observed peer IPs stay
/// exclusively in the private artifact, even though the path was supplied by
/// the analyst on the command line.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SanitizedFocusSummary {
    /// Focus discriminator: `exact-path`, `path-prefix`, or `source-ip`.
    /// Defaulted for artifacts written before non-exact focuses existed.
    #[serde(default = "exact_path_kind")]
    pub focus_kind: String,
    pub total_requests: u64,
    pub distinct_source_ips: usize,
    /// Focus requests divided by retained distinct observed source IPs. Zero
    /// when no source IP was retained; `source_ips_beyond_cap` remains visible.
    #[serde(default)]
    pub requests_per_source_ip: f64,
    pub source_ips_beyond_cap: u64,
    /// Distinct URI paths inside the focus (sub-paths of a prefix, or the union
    /// requested by selected source IPs). Zero for an exact-path focus.
    #[serde(default)]
    pub distinct_uri_paths: usize,
    #[serde(default)]
    pub paths_beyond_cap: u64,
    pub peak_requests_per_minute: Option<u64>,
    pub median_requests_per_minute: Option<f64>,
    /// Multiple simultaneous bucket widths, sorted by width. No selector value
    /// or other private request value is included.
    #[serde(default)]
    pub request_rates: Vec<WindowedRequestRateSummary>,
    #[serde(default)]
    pub requests_with_query: u64,
    /// Exact retained cardinality unless the disclosed cap count is non-zero.
    #[serde(default)]
    pub distinct_query_strings: usize,
    #[serde(default)]
    pub query_strings_beyond_tracking_cap: u64,
    #[serde(default)]
    pub distinct_query_keys: usize,
    #[serde(default)]
    pub query_keys_beyond_tracking_cap: u64,
}

fn exact_path_kind() -> String {
    "exact-path".to_owned()
}

/// Aggregate-only output safe to include in a sanitized artifact. It contains
/// no URI paths, IP addresses, hosts, headers, or other raw request values.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestConcentrationSummary {
    #[serde(default)]
    pub source_segment_diversity: Option<SourceSegmentDiversitySummary>,
    pub total_requests: u64,
    /// Exact unless `paths_beyond_tracking_cap` is non-zero.
    pub distinct_uri_paths: usize,
    /// Exact unless `source_ips_beyond_tracking_cap` is non-zero.
    pub distinct_source_ips: usize,
    pub requests_without_uri_path: u64,
    pub requests_without_source_ip: u64,
    /// Requests on new paths that could not be retained after the path cap.
    pub paths_beyond_tracking_cap: u64,
    /// Requests from new source IPs that could not be retained after the source cap.
    pub source_ips_beyond_tracking_cap: u64,
    /// Requests whose new source/path association could not be retained.
    pub source_path_pairs_beyond_tracking_cap: u64,
    pub top_path: Option<PathConcentrationSummary>,
    pub top_ten_paths_request_share: f64,
    pub top_ten_source_ips_request_share: f64,
    pub requests_per_minute: RequestRateSummary,
    /// Multiple simultaneous bucket widths, sorted by width. The existing
    /// per-minute field above remains for artifact compatibility.
    #[serde(default)]
    pub request_rates: Vec<WindowedRequestRateSummary>,
    /// `None` when the telemetry profile cannot expose response status.
    #[serde(default)]
    pub response_outcomes: Option<ResponseOutcomeSummary>,
    /// Uses the same admitted buckets as `request_rates`; unavailable when the
    /// telemetry profile cannot expose status.
    #[serde(default)]
    pub response_outcome_windows: Option<Vec<WindowedResponseOutcomeSummary>>,
    #[serde(default)]
    pub response_status_codes: Option<StatusCodeCounts>,
    /// Present only when `production concentration --path` selected an exact
    /// URI path. This aggregate is safe for sanitized output.
    #[serde(default)]
    pub focus: Option<SanitizedFocusSummary>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivatePathConcentration {
    pub uri_path: String,
    #[serde(flatten)]
    pub summary: PathConcentrationSummary,
    /// Retained query-key names only. Full query strings and values are never
    /// serialized. CLI display remains gated by `--show-paths`.
    #[serde(default)]
    pub query_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateSourceConcentration {
    #[serde(default)]
    pub path_segment_diversity: Option<SourceSegmentDiversity>,
    pub source_ip: String,
    pub requests: u64,
    /// The exact most-requested retained path for this IP. It is unavailable
    /// when any of the IP's source/path pairs exceeded the pair cap.
    pub most_requested_uri_path: Option<String>,
    /// Per-peer response outcomes. These are private observational counts, not
    /// an attack, exploitation, compromise, or attribution determination.
    #[serde(default)]
    pub response_status_classes: StatusClassCounts,
    #[serde(default)]
    pub response_status_codes: Option<StatusCodeCounts>,
    #[serde(default)]
    pub response_outcomes: Option<ResponseOutcomeSummary>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PrivateFocusSource {
    pub source_ip: String,
    pub requests: u64,
    #[serde(default)]
    pub response_status_classes: StatusClassCounts,
    #[serde(default)]
    pub response_status_codes: Option<StatusCodeCounts>,
    #[serde(default)]
    pub response_outcomes: Option<ResponseOutcomeSummary>,
}

/// One retained URI path inside a focus, with its request count. For a
/// path-prefix focus these are the sub-paths; for a source-IP focus these are
/// the paths the selected peers requested. Private: the path is a raw request
/// value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrivateFocusPath {
    pub uri_path: String,
    pub requests: u64,
    #[serde(default)]
    pub response_status_classes: StatusClassCounts,
    #[serde(default)]
    pub response_status_codes: Option<StatusCodeCounts>,
}

/// A private address-block aggregation of retained focus-path peers. A common
/// prefix is not evidence of a common owner, operator, or actor.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateFocusPrefixGroup {
    pub network_prefix: String,
    pub requests: u64,
    pub request_share: f64,
    pub distinct_source_ips: usize,
    #[serde(default)]
    pub response_status_classes: StatusClassCounts,
    #[serde(default)]
    pub response_status_codes: Option<StatusCodeCounts>,
    #[serde(default)]
    pub response_outcomes: Option<ResponseOutcomeSummary>,
}

/// A private routing-level aggregation of retained focus peers. An ASN is not
/// evidence that one operator controls the traffic and is not attribution.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateFocusAsnGroup {
    pub asn: u32,
    pub organization: String,
    pub requests: u64,
    pub request_share: f64,
    pub distinct_source_ips: usize,
}

/// Private ASN enrichment derived from retained focus peers. Unresolved peers
/// and their requests are disclosed rather than inferred or discarded.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PrivateFocusAsnSummary {
    pub groups: Vec<PrivateFocusAsnGroup>,
    pub unresolved_source_ips: usize,
    pub unresolved_requests: u64,
}

/// One retained private time-series point. Epoch minutes avoid locale and
/// timezone ambiguity; report renderers label them as UTC.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MinuteRequestCount {
    pub minute_epoch: i64,
    pub requests: u64,
}

/// Private aggregate counts for one retained UTC epoch minute, split into the
/// five standard HTTP status classes. Raw request values are not represented.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct StatusClassMinuteCount {
    pub minute_epoch: i64,
    pub informational: u64,
    pub success: u64,
    pub redirection: u64,
    pub client_error: u64,
    pub server_error: u64,
}

/// Private detail for one exact URI-path focus. Connection-peer IPs are not
/// client/attacker attribution: they can be CDN, LB, NAT, or proxy addresses.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateFocusSummary {
    #[serde(default)]
    pub response_status_codes: Option<StatusCodeCounts>,
    /// Focus discriminator: `exact-path`, `path-prefix`, or `source-ip`.
    #[serde(default = "exact_path_kind")]
    pub focus_kind: String,
    /// The analyst-supplied path or deterministic comma-separated IP set this
    /// focus selected. Kept in sync with `uri_path` for compatibility.
    #[serde(default)]
    pub selector: String,
    pub uri_path: String,
    pub total_requests: u64,
    pub distinct_source_ips: usize,
    #[serde(default)]
    pub requests_per_source_ip: f64,
    pub source_ips_beyond_cap: u64,
    /// Retained URI paths inside the focus, most-requested first. Empty for an
    /// exact-path focus (there is only the one path).
    #[serde(default)]
    pub paths: Vec<PrivateFocusPath>,
    #[serde(default)]
    pub paths_beyond_cap: u64,
    pub peak_requests_per_minute: Option<u64>,
    pub median_requests_per_minute: Option<f64>,
    pub response_status_classes: StatusClassCounts,
    pub sources: Vec<PrivateFocusSource>,
    /// Derived after streaming from `sources`; omitted from artifacts created
    /// before prefix grouping support.
    #[serde(default)]
    pub network_prefix_groups: Vec<PrivateFocusPrefixGroup>,
    /// Present only when an analyst supplied a local ASN dataset. ASN and
    /// organization values remain confined to this private artifact.
    #[serde(default)]
    pub asn: Option<PrivateFocusAsnSummary>,
    /// Private minute-resolution series, ordered by epoch minute.
    #[serde(default)]
    pub requests_per_minute_series: Vec<MinuteRequestCount>,
    /// Focus-path records in new minute buckets omitted after the fixed cap.
    #[serde(default)]
    pub minute_buckets_beyond_cap: u64,
    #[serde(default)]
    pub requests_with_query: u64,
    /// Retained exact query cardinality when the cap count is zero. Full query
    /// strings and values are never serialized.
    #[serde(default)]
    pub distinct_query_strings: usize,
    #[serde(default)]
    pub query_strings_beyond_tracking_cap: u64,
    #[serde(default)]
    pub distinct_query_keys: usize,
    #[serde(default)]
    pub query_keys_beyond_tracking_cap: u64,
    /// Retained key names are private and displayed by the CLI only with
    /// `--show-paths`. Query values are never stored here.
    #[serde(default)]
    pub query_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateRequestConcentrationReport {
    pub report_kind: String,
    pub safety_note: String,
    pub summary: RequestConcentrationSummary,
    pub paths: Vec<PrivatePathConcentration>,
    pub source_ips: Vec<PrivateSourceConcentration>,
    /// Omitted from historical artifacts created before path focus support.
    #[serde(default)]
    pub focus: Option<PrivateFocusSummary>,
    /// Private minute-resolution series, ordered by epoch minute.
    #[serde(default)]
    pub requests_per_minute_series: Vec<MinuteRequestCount>,
    /// Private aggregate-only status-class series, ordered by epoch minute.
    /// It is absent from sanitized output and defaults empty for old artifacts.
    #[serde(default)]
    pub status_class_requests_per_minute_series: Vec<StatusClassMinuteCount>,
    /// Global records in new minute buckets omitted after the fixed cap.
    #[serde(default)]
    pub minute_buckets_beyond_cap: u64,
}

#[derive(Debug, Default)]
struct PathAccumulator {
    requests: u64,
    source_ips: BTreeSet<String>,
    status_classes: StatusClassCounts,
    status_codes: StatusCodeCounts,
    response_bytes: u64,
    query_shape: QueryShapeAccumulator,
}

#[derive(Debug, Default)]
struct SourceAccumulator {
    segments: BTreeSet<String>,
    segments_404: BTreeSet<String>,
    segments_beyond_cap: u64,
    segments_404_beyond_cap: u64,
    paths_unavailable: u64,
    requests: u64,
    status_classes: StatusClassCounts,
    status_codes: StatusCodeCounts,
}

/// Counts only: segment strings never enter any artifact. Capped counts are
/// retained lower bounds; omissions count observations, not distinct segments.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceSegmentDiversity {
    pub distinct_segments: usize,
    pub distinct_404_segments: Option<usize>,
    pub observations_beyond_cap: u64,
    pub observations_404_beyond_cap: Option<u64>,
    pub observations_without_path: u64,
    pub maximum_segments: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceSegmentDiversitySummary {
    pub maximum_404_segments: Option<usize>,
    pub median_404_segments: Option<f64>,
    /// Retained sources with at least one retained 404 segment, not a classification.
    #[serde(default)]
    pub sources_with_404_segments: Option<usize>,
    #[serde(default)]
    pub median_404_segments_among_sources_with_404_segments: Option<f64>,
    pub sources_beyond_cap: usize,
    pub sources_404_beyond_cap: Option<usize>,
    pub observations_beyond_cap: u64,
    pub observations_404_beyond_cap: Option<u64>,
    pub observations_without_path: u64,
    pub retained_sources: usize,
    pub maximum_segments_per_source: usize,
}

impl SourceAccumulator {
    fn record_segments(&mut self, path: Option<&str>, status: Option<u16>, limit: usize) {
        let Some(path) = path else {
            self.paths_unavailable += 1;
            return;
        };
        // Preserve spelling and empty segments: no decoding or case folding.
        let segment = path
            .strip_prefix('/')
            .unwrap_or(path)
            .split('/')
            .next()
            .unwrap_or("");
        fn retain(set: &mut BTreeSet<String>, omitted: &mut u64, segment: &str, limit: usize) {
            if !set.contains(segment) {
                if set.len() < limit {
                    set.insert(segment.to_owned());
                } else {
                    *omitted += 1;
                }
            }
        }
        retain(
            &mut self.segments,
            &mut self.segments_beyond_cap,
            segment,
            limit,
        );
        if status == Some(404) {
            retain(
                &mut self.segments_404,
                &mut self.segments_404_beyond_cap,
                segment,
                limit,
            );
        }
    }

    fn segment_summary(&self, status_available: bool, limit: usize) -> SourceSegmentDiversity {
        SourceSegmentDiversity {
            distinct_segments: self.segments.len(),
            distinct_404_segments: status_available.then_some(self.segments_404.len()),
            observations_beyond_cap: self.segments_beyond_cap,
            observations_404_beyond_cap: status_available.then_some(self.segments_404_beyond_cap),
            observations_without_path: self.paths_unavailable,
            maximum_segments: limit,
        }
    }
}

#[derive(Debug, Default)]
struct QueryShapeAccumulator {
    requests_with_query: u64,
    query_strings: BTreeSet<String>,
    query_strings_beyond_tracking_cap: u64,
    query_keys: BTreeSet<String>,
    query_keys_beyond_tracking_cap: u64,
}

/// A one-pass bounded accumulator. Key admission follows first observation in
/// input order; rendered reports are sorted independently for deterministic output.
#[derive(Debug)]
pub struct RequestConcentration {
    limits: ConcentrationLimits,
    response_bytes_available: bool,
    status_available: bool,
    response_bucket_minimum_requests: u64,
    response_success_share_threshold_percent: u8,
    total_requests: u64,
    status_classes: StatusClassCounts,
    status_codes: StatusCodeCounts,
    paths: BTreeMap<String, PathAccumulator>,
    source_ips: BTreeMap<String, SourceAccumulator>,
    source_path_pairs: BTreeMap<String, BTreeMap<String, u64>>,
    source_path_pair_count: usize,
    source_ips_with_incomplete_path_pairs: BTreeSet<String>,
    minute_buckets: BTreeMap<i64, u64>,
    status_minute_buckets: BTreeMap<i64, StatusClassCounts>,
    minute_buckets_beyond_cap: u64,
    requests_without_uri_path: u64,
    requests_without_source_ip: u64,
    paths_beyond_tracking_cap: u64,
    source_ips_beyond_tracking_cap: u64,
    source_path_pairs_beyond_tracking_cap: u64,
    observations_without_timestamp: u64,
    rate_window_seconds: Vec<u64>,
    rate_buckets: BTreeMap<u64, BTreeMap<i64, u64>>,
    rate_buckets_beyond_cap: BTreeMap<u64, u64>,
    status_rate_buckets: BTreeMap<u64, BTreeMap<i64, StatusClassCounts>>,
    focus: Option<FocusSelector>,
    focus_total: u64,
    focus_sources: BTreeMap<String, SourceAccumulator>,
    focus_paths: BTreeMap<String, SourceAccumulator>,
    focus_minute_buckets: BTreeMap<i64, u64>,
    focus_minute_buckets_beyond_cap: u64,
    focus_observations_without_timestamp: u64,
    focus_rate_buckets: BTreeMap<u64, BTreeMap<i64, u64>>,
    focus_rate_buckets_beyond_cap: BTreeMap<u64, u64>,
    focus_status_classes: StatusClassCounts,
    focus_status_codes: StatusCodeCounts,
    focus_source_ips_beyond_cap: u64,
    focus_paths_beyond_cap: u64,
    focus_query_shape: QueryShapeAccumulator,
}

impl RequestConcentration {
    pub fn new(response_bytes_available: bool) -> Self {
        Self::with_limits_and_rate_windows(
            response_bytes_available,
            ConcentrationLimits::default(),
            &DEFAULT_RATE_WINDOW_SECONDS,
        )
    }

    pub fn with_limits(response_bytes_available: bool, limits: ConcentrationLimits) -> Self {
        Self::with_limits_and_rate_windows(
            response_bytes_available,
            limits,
            &DEFAULT_RATE_WINDOW_SECONDS,
        )
    }

    pub fn with_capabilities(response_bytes_available: bool, status_available: bool) -> Self {
        Self::with_capabilities_and_rate_windows(
            response_bytes_available,
            status_available,
            ConcentrationLimits::default(),
            &DEFAULT_RATE_WINDOW_SECONDS,
        )
    }

    /// Construct an accumulator with explicit simultaneous rate windows. Zero
    /// widths are ignored; remaining widths are sorted and deduplicated.
    pub fn with_limits_and_rate_windows(
        response_bytes_available: bool,
        limits: ConcentrationLimits,
        rate_window_seconds: &[u64],
    ) -> Self {
        Self::with_capabilities_and_rate_windows(
            response_bytes_available,
            true,
            limits,
            rate_window_seconds,
        )
    }

    /// Construct with explicit telemetry capabilities. Existing public
    /// constructors retain status support for backward-compatible unit use;
    /// production paths use this variant with their telemetry profile.
    pub fn with_capabilities_and_rate_windows(
        response_bytes_available: bool,
        status_available: bool,
        limits: ConcentrationLimits,
        rate_window_seconds: &[u64],
    ) -> Self {
        let rate_window_seconds = normalize_rate_windows(rate_window_seconds);
        let rate_buckets = rate_window_seconds
            .iter()
            .map(|seconds| (*seconds, BTreeMap::new()))
            .collect();
        let rate_buckets_beyond_cap = rate_window_seconds
            .iter()
            .map(|seconds| (*seconds, 0))
            .collect();
        let status_rate_buckets = rate_window_seconds
            .iter()
            .map(|seconds| (*seconds, BTreeMap::new()))
            .collect();
        let focus_rate_buckets = rate_window_seconds
            .iter()
            .map(|seconds| (*seconds, BTreeMap::new()))
            .collect();
        let focus_rate_buckets_beyond_cap = rate_window_seconds
            .iter()
            .map(|seconds| (*seconds, 0))
            .collect();
        Self {
            limits,
            response_bytes_available,
            status_available,
            response_bucket_minimum_requests: DEFAULT_RESPONSE_BUCKET_MINIMUM_REQUESTS,
            response_success_share_threshold_percent:
                DEFAULT_RESPONSE_SUCCESS_SHARE_THRESHOLD_PERCENT,
            total_requests: 0,
            status_classes: StatusClassCounts::default(),
            status_codes: StatusCodeCounts {
                maximum_codes: limits.max_status_codes_per_entity,
                ..StatusCodeCounts::default()
            },
            paths: BTreeMap::new(),
            source_ips: BTreeMap::new(),
            source_path_pairs: BTreeMap::new(),
            source_path_pair_count: 0,
            source_ips_with_incomplete_path_pairs: BTreeSet::new(),
            minute_buckets: BTreeMap::new(),
            status_minute_buckets: BTreeMap::new(),
            minute_buckets_beyond_cap: 0,
            requests_without_uri_path: 0,
            requests_without_source_ip: 0,
            paths_beyond_tracking_cap: 0,
            source_ips_beyond_tracking_cap: 0,
            source_path_pairs_beyond_tracking_cap: 0,
            observations_without_timestamp: 0,
            rate_window_seconds,
            rate_buckets,
            rate_buckets_beyond_cap,
            status_rate_buckets,
            focus: None,
            focus_total: 0,
            focus_sources: BTreeMap::new(),
            focus_paths: BTreeMap::new(),
            focus_minute_buckets: BTreeMap::new(),
            focus_minute_buckets_beyond_cap: 0,
            focus_observations_without_timestamp: 0,
            focus_rate_buckets,
            focus_rate_buckets_beyond_cap,
            focus_status_classes: StatusClassCounts::default(),
            focus_status_codes: StatusCodeCounts {
                maximum_codes: limits.max_status_codes_per_entity,
                ..StatusCodeCounts::default()
            },
            focus_source_ips_beyond_cap: 0,
            focus_paths_beyond_cap: 0,
            focus_query_shape: QueryShapeAccumulator::default(),
        }
    }

    /// Configure the inclusion floor for response-outcome window extrema.
    /// This changes reporting only and never classifies a bucket.
    pub fn set_response_bucket_minimum_requests(&mut self, minimum: u64) {
        self.response_bucket_minimum_requests = minimum;
    }

    /// Counts eligible buckets strictly below this percentage. No classification
    /// is made. Invalid settings are rejected, never silently clamped.
    pub fn set_response_success_share_threshold_percent(
        &mut self,
        percent: u8,
    ) -> Result<(), &'static str> {
        if percent > 100 {
            return Err("response success share threshold must be 0 through 100 percent");
        }
        self.response_success_share_threshold_percent = percent;
        Ok(())
    }

    /// Enable a focus for subsequent observations. It is used only by
    /// `concentration`; hunt keeps the default `None` focus.
    pub fn focus_on(&mut self, selector: FocusSelector) {
        self.focus = Some(selector);
    }

    /// Convenience for an exact-path focus.
    pub fn focus_on_path(&mut self, path: impl Into<String>) {
        self.focus_on(FocusSelector::ExactPath(path.into()));
    }

    pub fn observe(&mut self, event: &WebEvent) {
        self.total_requests += 1;
        record_status_class(&mut self.status_classes, event.status);
        self.status_codes
            .record(event.status, self.limits.max_status_codes_per_entity);
        self.observe_minute(event.timestamp, event.status);

        let path = event.uri_path.as_deref();
        let source_ip = event.source_ip.as_deref();
        let path_tracked = path.is_some_and(|path| self.track_path(path, event));
        let source_tracked =
            source_ip.is_some_and(|source_ip| self.track_source_ip(source_ip, event.status, path));

        if path.is_none() {
            self.requests_without_uri_path += 1;
        }
        if source_ip.is_none() {
            self.requests_without_source_ip += 1;
        }

        if let (Some(path), Some(source_ip)) = (path, source_ip) {
            if path_tracked && source_tracked {
                self.track_source_path_pair(source_ip, path);
            }
        }
        self.observe_focus(event);
    }

    pub fn summary(&self) -> RequestConcentrationSummary {
        let sorted_paths = self.sorted_paths();
        let sorted_sources = self.sorted_sources();
        let top_path = sorted_paths
            .first()
            .map(|(_, item)| self.path_summary(item));
        let top_ten_paths_request_share = self.share(
            sorted_paths
                .iter()
                .take(10)
                .map(|(_, item)| item.requests)
                .sum(),
        );
        let top_ten_source_ips_request_share = self.share(
            sorted_sources
                .iter()
                .take(10)
                .map(|(_, item)| item.requests)
                .sum(),
        );
        let (peak, median, ratio) = self.request_rate();
        RequestConcentrationSummary {
            source_segment_diversity: Some(self.source_segment_summary()),
            total_requests: self.total_requests,
            distinct_uri_paths: self.paths.len(),
            distinct_source_ips: self.source_ips.len(),
            requests_without_uri_path: self.requests_without_uri_path,
            requests_without_source_ip: self.requests_without_source_ip,
            paths_beyond_tracking_cap: self.paths_beyond_tracking_cap,
            source_ips_beyond_tracking_cap: self.source_ips_beyond_tracking_cap,
            source_path_pairs_beyond_tracking_cap: self.source_path_pairs_beyond_tracking_cap,
            top_path,
            top_ten_paths_request_share,
            top_ten_source_ips_request_share,
            requests_per_minute: RequestRateSummary {
                peak_requests_per_minute: peak,
                median_requests_per_minute: median,
                peak_to_median_ratio: ratio,
                observations_without_timestamp: self.observations_without_timestamp,
            },
            request_rates: self.windowed_rate_summaries(
                &self.rate_buckets,
                &self.rate_buckets_beyond_cap,
                self.observations_without_timestamp,
            ),
            response_outcomes: self
                .status_available
                .then(|| response_outcome_summary(&self.status_classes)),
            response_status_codes: self.status_available.then(|| self.status_codes.clone()),
            response_outcome_windows: self.status_available.then(|| {
                self.windowed_response_outcome_summaries(
                    &self.status_rate_buckets,
                    &self.rate_buckets_beyond_cap,
                    self.observations_without_timestamp,
                )
            }),
            focus: self.sanitized_focus_summary(),
        }
    }

    pub fn private_report(&self) -> PrivateRequestConcentrationReport {
        self.private_report_with_query_keys(false)
    }

    /// Build the private artifact. Query-key names remain excluded by default
    /// and are included only for the standalone CLI's explicit `--show-paths`
    /// opt-in. Full query strings and values are never serialized.
    pub fn private_report_with_query_keys(
        &self,
        include_query_keys: bool,
    ) -> PrivateRequestConcentrationReport {
        PrivateRequestConcentrationReport {
            report_kind: "REQUEST_CONCENTRATION_PRIVATE".to_owned(),
            safety_note: "Private analyst artifact: URI paths and observed connection-peer IPs are included. Request-volume distribution is not a determination of a denial-of-service attempt, attack, abuse, compromise, or attacker identity.".to_owned(),
            summary: self.summary(),
            paths: self
                .sorted_paths()
                .into_iter()
                .map(|(path, item)| PrivatePathConcentration {
                    uri_path: path.clone(),
                    summary: self.path_summary(item),
                    query_keys: if include_query_keys {
                        item.query_shape.query_keys.iter().cloned().collect()
                    } else {
                        Vec::new()
                    },
                })
                .collect(),
            source_ips: self
                .sorted_sources()
                .into_iter()
                .map(|(source_ip, item)| PrivateSourceConcentration {
                    path_segment_diversity: Some(item.segment_summary(self.status_available, self.limits.max_source_segments)),
                    source_ip: source_ip.clone(),
                    requests: item.requests,
                    most_requested_uri_path: self.most_requested_path(source_ip),
                    response_status_classes: item.status_classes.clone(),
                    response_status_codes: self.status_available.then(|| item.status_codes.clone()),
                    response_outcomes: self.status_available.then(|| response_outcome_summary(&item.status_classes)),
                })
                .collect(),
            focus: self.private_focus_summary(include_query_keys),
            requests_per_minute_series: Self::minute_series(&self.minute_buckets),
            status_class_requests_per_minute_series: Self::status_minute_series(
                &self.status_minute_buckets,
            ),
            minute_buckets_beyond_cap: self.minute_buckets_beyond_cap,
        }
    }

    fn observe_focus(&mut self, event: &WebEvent) {
        let Some(selector) = &self.focus else {
            return;
        };
        let path = event.uri_path.as_deref();
        let source_ip = event.source_ip.as_deref();
        let matches = match selector {
            FocusSelector::ExactPath(value) => path == Some(value.as_str()),
            FocusSelector::PathPrefix(value) => path.is_some_and(|path| path_is_under(path, value)),
            FocusSelector::SourceIp(values) => source_ip.is_some_and(|ip| values.contains(ip)),
        };
        // An exact-path focus has only the one path, so a per-path breakdown
        // would merely echo the selector; skip it for that kind.
        let track_paths = !matches!(selector, FocusSelector::ExactPath(_));
        if !matches {
            return;
        }
        self.focus_total += 1;
        if let Some(timestamp) = event.timestamp {
            Self::track_minute_bucket(
                &mut self.focus_minute_buckets,
                &mut self.focus_minute_buckets_beyond_cap,
                self.limits.max_minute_buckets,
                timestamp.timestamp().div_euclid(60),
            );
            Self::track_rate_windows(
                &self.rate_window_seconds,
                &mut self.focus_rate_buckets,
                &mut self.focus_rate_buckets_beyond_cap,
                self.limits.max_minute_buckets,
                timestamp,
            );
        } else {
            self.focus_observations_without_timestamp += 1;
        }
        record_status_class(&mut self.focus_status_classes, event.status);
        self.focus_status_codes
            .record(event.status, self.limits.max_status_codes_per_entity);
        Self::observe_query_shape(
            &mut self.focus_query_shape,
            event.uri_query.as_deref(),
            self.limits.max_query_strings_per_path,
            self.limits.max_query_keys_per_path,
        );
        if let Some(source_ip) = source_ip {
            if let Some(item) = self.focus_sources.get_mut(source_ip) {
                item.requests += 1;
                record_status_class(&mut item.status_classes, event.status);
                item.status_codes
                    .record(event.status, self.limits.max_status_codes_per_entity);
            } else if self.focus_sources.len() < self.limits.max_focus_source_ips {
                let mut item = SourceAccumulator {
                    requests: 1,
                    ..SourceAccumulator::default()
                };
                record_status_class(&mut item.status_classes, event.status);
                item.status_codes
                    .record(event.status, self.limits.max_status_codes_per_entity);
                self.focus_sources.insert(source_ip.to_owned(), item);
            } else {
                self.focus_source_ips_beyond_cap += 1;
            }
        }
        if let (true, Some(path)) = (track_paths, path) {
            if self.focus_paths.contains_key(path)
                || self.focus_paths.len() < self.limits.max_focus_paths
            {
                let item = self.focus_paths.entry(path.to_owned()).or_default();
                item.requests += 1;
                record_status_class(&mut item.status_classes, event.status);
                item.status_codes
                    .record(event.status, self.limits.max_status_codes_per_entity);
            } else {
                self.focus_paths_beyond_cap += 1;
            }
        }
    }

    fn sanitized_focus_summary(&self) -> Option<SanitizedFocusSummary> {
        self.focus.as_ref().map(|selector| {
            let (peak, median, _) = Self::request_rate_for(&self.focus_minute_buckets);
            SanitizedFocusSummary {
                focus_kind: selector.kind().to_owned(),
                total_requests: self.focus_total,
                distinct_source_ips: self.focus_sources.len(),
                requests_per_source_ip: requests_per_distinct_source(
                    self.focus_total,
                    self.focus_sources.len(),
                ),
                source_ips_beyond_cap: self.focus_source_ips_beyond_cap,
                distinct_uri_paths: self.focus_paths.len(),
                paths_beyond_cap: self.focus_paths_beyond_cap,
                peak_requests_per_minute: peak,
                median_requests_per_minute: median,
                request_rates: self.windowed_rate_summaries(
                    &self.focus_rate_buckets,
                    &self.focus_rate_buckets_beyond_cap,
                    self.focus_observations_without_timestamp,
                ),
                requests_with_query: self.focus_query_shape.requests_with_query,
                distinct_query_strings: self.focus_query_shape.query_strings.len(),
                query_strings_beyond_tracking_cap: self
                    .focus_query_shape
                    .query_strings_beyond_tracking_cap,
                distinct_query_keys: self.focus_query_shape.query_keys.len(),
                query_keys_beyond_tracking_cap: self
                    .focus_query_shape
                    .query_keys_beyond_tracking_cap,
            }
        })
    }

    fn private_focus_summary(&self, include_query_keys: bool) -> Option<PrivateFocusSummary> {
        self.focus.as_ref().map(|selector| {
            let (peak, median, _) = Self::request_rate_for(&self.focus_minute_buckets);
            let selector_display = selector.selector_display();
            let mut sources = self
                .focus_sources
                .iter()
                .map(|(source_ip, item)| PrivateFocusSource {
                    source_ip: source_ip.clone(),
                    requests: item.requests,
                    response_status_classes: item.status_classes.clone(),
                    response_status_codes: self.status_available.then(|| item.status_codes.clone()),
                    response_outcomes: self
                        .status_available
                        .then(|| response_outcome_summary(&item.status_classes)),
                })
                .collect::<Vec<_>>();
            sources.sort_by(|left, right| {
                right
                    .requests
                    .cmp(&left.requests)
                    .then_with(|| left.source_ip.cmp(&right.source_ip))
            });
            let mut paths = self
                .focus_paths
                .iter()
                .map(|(uri_path, item)| PrivateFocusPath {
                    uri_path: uri_path.clone(),
                    requests: item.requests,
                    response_status_classes: item.status_classes.clone(),
                    response_status_codes: self.status_available.then(|| item.status_codes.clone()),
                })
                .collect::<Vec<_>>();
            paths.sort_by(|left, right| {
                right
                    .requests
                    .cmp(&left.requests)
                    .then_with(|| left.uri_path.cmp(&right.uri_path))
            });
            PrivateFocusSummary {
                response_status_codes: self
                    .status_available
                    .then(|| self.focus_status_codes.clone()),
                focus_kind: selector.kind().to_owned(),
                selector: selector_display.clone(),
                uri_path: selector_display,
                total_requests: self.focus_total,
                distinct_source_ips: self.focus_sources.len(),
                requests_per_source_ip: requests_per_distinct_source(
                    self.focus_total,
                    self.focus_sources.len(),
                ),
                source_ips_beyond_cap: self.focus_source_ips_beyond_cap,
                paths,
                paths_beyond_cap: self.focus_paths_beyond_cap,
                peak_requests_per_minute: peak,
                median_requests_per_minute: median,
                response_status_classes: self.focus_status_classes.clone(),
                sources,
                network_prefix_groups: Vec::new(),
                asn: None,
                requests_per_minute_series: Self::minute_series(&self.focus_minute_buckets),
                minute_buckets_beyond_cap: self.focus_minute_buckets_beyond_cap,
                requests_with_query: self.focus_query_shape.requests_with_query,
                distinct_query_strings: self.focus_query_shape.query_strings.len(),
                query_strings_beyond_tracking_cap: self
                    .focus_query_shape
                    .query_strings_beyond_tracking_cap,
                distinct_query_keys: self.focus_query_shape.query_keys.len(),
                query_keys_beyond_tracking_cap: self
                    .focus_query_shape
                    .query_keys_beyond_tracking_cap,
                query_keys: if include_query_keys {
                    self.focus_query_shape.query_keys.iter().cloned().collect()
                } else {
                    Vec::new()
                },
            }
        })
    }

    fn observe_minute(&mut self, timestamp: Option<DateTime<Utc>>, status: Option<u16>) {
        let Some(timestamp) = timestamp else {
            self.observations_without_timestamp += 1;
            return;
        };
        let minute_epoch = timestamp.timestamp().div_euclid(60);
        if Self::track_minute_bucket(
            &mut self.minute_buckets,
            &mut self.minute_buckets_beyond_cap,
            self.limits.max_minute_buckets,
            minute_epoch,
        ) {
            record_status_class(
                self.status_minute_buckets.entry(minute_epoch).or_default(),
                status,
            );
        }
        Self::track_rate_windows(
            &self.rate_window_seconds,
            &mut self.rate_buckets,
            &mut self.rate_buckets_beyond_cap,
            self.limits.max_minute_buckets,
            timestamp,
        );
        Self::track_status_rate_windows(
            &self.rate_window_seconds,
            &self.rate_buckets,
            &mut self.status_rate_buckets,
            timestamp,
            status,
        );
    }

    fn track_path(&mut self, path: &str, event: &WebEvent) -> bool {
        let max_query_strings = self.limits.max_query_strings_per_path;
        let max_query_keys = self.limits.max_query_keys_per_path;
        let source_ip_is_tracked = event.source_ip.as_deref().is_some_and(|source_ip| {
            self.source_ips.contains_key(source_ip)
                || self.source_ips.len() < self.limits.max_source_ips
        });
        if let Some(item) = self.paths.get_mut(path) {
            item.requests += 1;
            if source_ip_is_tracked {
                let source_ip = event
                    .source_ip
                    .as_deref()
                    .expect("tracked source IP came from this event");
                if !item.source_ips.contains(source_ip) {
                    item.source_ips.insert(source_ip.to_owned());
                }
            }
            record_status_class(&mut item.status_classes, event.status);
            item.status_codes
                .record(event.status, self.limits.max_status_codes_per_entity);
            if self.response_bytes_available {
                item.response_bytes += event.response_bytes.unwrap_or(0);
            }
            Self::observe_query_shape(
                &mut item.query_shape,
                event.uri_query.as_deref(),
                max_query_strings,
                max_query_keys,
            );
            return true;
        }
        if self.paths.len() >= self.limits.max_paths {
            self.paths_beyond_tracking_cap += 1;
            return false;
        }
        let mut item = PathAccumulator::default();
        item.requests += 1;
        if source_ip_is_tracked {
            item.source_ips.insert(
                event
                    .source_ip
                    .as_deref()
                    .expect("tracked source IP came from this event")
                    .to_owned(),
            );
        }
        record_status_class(&mut item.status_classes, event.status);
        item.status_codes
            .record(event.status, self.limits.max_status_codes_per_entity);
        if self.response_bytes_available {
            item.response_bytes += event.response_bytes.unwrap_or(0);
        }
        Self::observe_query_shape(
            &mut item.query_shape,
            event.uri_query.as_deref(),
            max_query_strings,
            max_query_keys,
        );
        self.paths.insert(path.to_owned(), item);
        true
    }

    fn track_source_ip(
        &mut self,
        source_ip: &str,
        status: Option<u16>,
        path: Option<&str>,
    ) -> bool {
        if let Some(item) = self.source_ips.get_mut(source_ip) {
            item.record_segments(path, status, self.limits.max_source_segments);
            item.requests += 1;
            record_status_class(&mut item.status_classes, status);
            item.status_codes
                .record(status, self.limits.max_status_codes_per_entity);
            return true;
        }
        if self.source_ips.len() >= self.limits.max_source_ips {
            self.source_ips_beyond_tracking_cap += 1;
            return false;
        }
        let mut item = SourceAccumulator {
            requests: 1,
            ..SourceAccumulator::default()
        };
        item.record_segments(path, status, self.limits.max_source_segments);
        record_status_class(&mut item.status_classes, status);
        item.status_codes
            .record(status, self.limits.max_status_codes_per_entity);
        self.source_ips.insert(source_ip.to_owned(), item);
        true
    }

    fn track_source_path_pair(&mut self, source_ip: &str, path: &str) {
        if let Some(paths) = self.source_path_pairs.get_mut(source_ip) {
            if let Some(count) = paths.get_mut(path) {
                *count += 1;
                return;
            }
            if self.source_path_pair_count < self.limits.max_source_path_pairs {
                paths.insert(path.to_owned(), 1);
                self.source_path_pair_count += 1;
                return;
            }
        } else if self.source_path_pair_count < self.limits.max_source_path_pairs {
            self.source_path_pairs
                .insert(source_ip.to_owned(), BTreeMap::from([(path.to_owned(), 1)]));
            self.source_path_pair_count += 1;
            return;
        }

        self.source_path_pairs_beyond_tracking_cap += 1;
        if !self
            .source_ips_with_incomplete_path_pairs
            .contains(source_ip)
        {
            self.source_ips_with_incomplete_path_pairs
                .insert(source_ip.to_owned());
        }
    }

    fn path_summary(&self, item: &PathAccumulator) -> PathConcentrationSummary {
        PathConcentrationSummary {
            requests: item.requests,
            request_share: self.share(item.requests),
            distinct_source_ips: item.source_ips.len(),
            requests_per_source_ip: requests_per_distinct_source(
                item.requests,
                item.source_ips.len(),
            ),
            response_status_classes: item.status_classes.clone(),
            response_status_codes: self.status_available.then(|| item.status_codes.clone()),
            response_bytes: self.response_bytes_available.then_some(item.response_bytes),
            requests_with_query: item.query_shape.requests_with_query,
            distinct_query_strings: item.query_shape.query_strings.len(),
            query_strings_beyond_tracking_cap: item.query_shape.query_strings_beyond_tracking_cap,
            distinct_query_keys: item.query_shape.query_keys.len(),
            query_keys_beyond_tracking_cap: item.query_shape.query_keys_beyond_tracking_cap,
        }
    }

    fn observe_query_shape(
        shape: &mut QueryShapeAccumulator,
        query: Option<&str>,
        maximum_strings: usize,
        maximum_keys: usize,
    ) {
        let Some(query) = query else {
            return;
        };
        shape.requests_with_query += 1;
        if !shape.query_strings.contains(query) {
            if shape.query_strings.len() < maximum_strings {
                shape.query_strings.insert(query.to_owned());
            } else {
                shape.query_strings_beyond_tracking_cap += 1;
            }
        }
        for key in query_keys(query) {
            if shape.query_keys.contains(key) {
                continue;
            }
            if shape.query_keys.len() < maximum_keys {
                shape.query_keys.insert(key.to_owned());
            } else {
                shape.query_keys_beyond_tracking_cap += 1;
            }
        }
    }

    fn sorted_paths(&self) -> Vec<(&String, &PathAccumulator)> {
        let mut values = self.paths.iter().collect::<Vec<_>>();
        values.sort_by(|(left_path, left), (right_path, right)| {
            right
                .requests
                .cmp(&left.requests)
                .then_with(|| left_path.cmp(right_path))
        });
        values
    }

    fn source_segment_summary(&self) -> SourceSegmentDiversitySummary {
        let mut counts = self
            .source_ips
            .values()
            .map(|item| item.segments_404.len())
            .collect::<Vec<_>>();
        counts.sort_unstable();
        let positive_counts = &counts[counts.partition_point(|count| *count == 0)..];
        let positive_median = if positive_counts.is_empty() {
            None
        } else {
            Some(
                (positive_counts[(positive_counts.len() - 1) / 2] as f64
                    + positive_counts[positive_counts.len() / 2] as f64)
                    / 2.0,
            )
        };
        let median = if counts.is_empty() {
            None
        } else {
            Some((counts[(counts.len() - 1) / 2] as f64 + counts[counts.len() / 2] as f64) / 2.0)
        };
        SourceSegmentDiversitySummary {
            maximum_404_segments: self
                .status_available
                .then(|| counts.last().copied())
                .flatten(),
            median_404_segments: self.status_available.then_some(median).flatten(),
            sources_with_404_segments: self.status_available.then_some(positive_counts.len()),
            median_404_segments_among_sources_with_404_segments: self
                .status_available
                .then_some(positive_median)
                .flatten(),
            sources_beyond_cap: self
                .source_ips
                .values()
                .filter(|item| item.segments_beyond_cap > 0)
                .count(),
            sources_404_beyond_cap: self.status_available.then(|| {
                self.source_ips
                    .values()
                    .filter(|item| item.segments_404_beyond_cap > 0)
                    .count()
            }),
            observations_beyond_cap: self
                .source_ips
                .values()
                .map(|item| item.segments_beyond_cap)
                .sum(),
            observations_404_beyond_cap: self.status_available.then(|| {
                self.source_ips
                    .values()
                    .map(|item| item.segments_404_beyond_cap)
                    .sum()
            }),
            observations_without_path: self
                .source_ips
                .values()
                .map(|item| item.paths_unavailable)
                .sum(),
            retained_sources: counts.len(),
            maximum_segments_per_source: self.limits.max_source_segments,
        }
    }

    fn sorted_sources(&self) -> Vec<(&String, &SourceAccumulator)> {
        let mut values = self.source_ips.iter().collect::<Vec<_>>();
        values.sort_by(|(left_ip, left), (right_ip, right)| {
            right
                .requests
                .cmp(&left.requests)
                .then_with(|| left_ip.cmp(right_ip))
        });
        values
    }

    fn most_requested_path(&self, source_ip: &str) -> Option<String> {
        if self
            .source_ips_with_incomplete_path_pairs
            .contains(source_ip)
        {
            return None;
        }
        self.source_path_pairs
            .get(source_ip)?
            .iter()
            .max_by(|(left_path, left), (right_path, right)| {
                left.cmp(right).then_with(|| right_path.cmp(left_path))
            })
            .map(|(path, _)| path.clone())
    }

    fn request_rate(&self) -> (Option<u64>, Option<f64>, Option<f64>) {
        Self::request_rate_for(&self.minute_buckets)
    }

    fn track_minute_bucket(
        buckets: &mut BTreeMap<i64, u64>,
        beyond_cap: &mut u64,
        maximum: usize,
        minute_epoch: i64,
    ) -> bool {
        if !buckets.contains_key(&minute_epoch) && buckets.len() >= maximum {
            *beyond_cap += 1;
            return false;
        }
        *buckets.entry(minute_epoch).or_default() += 1;
        true
    }

    fn minute_series(buckets: &BTreeMap<i64, u64>) -> Vec<MinuteRequestCount> {
        buckets
            .iter()
            .map(|(minute_epoch, requests)| MinuteRequestCount {
                minute_epoch: *minute_epoch,
                requests: *requests,
            })
            .collect()
    }

    fn status_minute_series(
        buckets: &BTreeMap<i64, StatusClassCounts>,
    ) -> Vec<StatusClassMinuteCount> {
        buckets
            .iter()
            .map(|(minute_epoch, counts)| StatusClassMinuteCount {
                minute_epoch: *minute_epoch,
                informational: counts.informational,
                success: counts.success,
                redirection: counts.redirection,
                client_error: counts.client_error,
                server_error: counts.server_error,
            })
            .collect()
    }

    fn request_rate_for(buckets: &BTreeMap<i64, u64>) -> (Option<u64>, Option<f64>, Option<f64>) {
        if buckets.is_empty() {
            return (None, None, None);
        }
        let mut values = buckets.values().copied().collect::<Vec<_>>();
        values.sort_unstable();
        let peak = *values.last().expect("checked non-empty minute buckets");
        let middle = values.len() / 2;
        let median = if values.len().is_multiple_of(2) {
            (values[middle - 1] as f64 + values[middle] as f64) / 2.0
        } else {
            values[middle] as f64
        };
        let ratio = (median != 0.0).then(|| peak as f64 / median);
        (Some(peak), Some(median), ratio)
    }

    fn track_rate_windows(
        widths: &[u64],
        rate_buckets: &mut BTreeMap<u64, BTreeMap<i64, u64>>,
        beyond_caps: &mut BTreeMap<u64, u64>,
        maximum: usize,
        timestamp: DateTime<Utc>,
    ) {
        for width in widths {
            let Ok(width) = i64::try_from(*width) else {
                continue;
            };
            let bucket = timestamp.timestamp().div_euclid(width);
            Self::track_minute_bucket(
                rate_buckets
                    .get_mut(&u64::try_from(width).expect("positive configured rate width"))
                    .expect("all configured rate widths have a bucket map"),
                beyond_caps
                    .get_mut(&u64::try_from(width).expect("positive configured rate width"))
                    .expect("all configured rate widths have a cap counter"),
                maximum,
                bucket,
            );
        }
    }

    fn track_status_rate_windows(
        widths: &[u64],
        admitted_rate_buckets: &BTreeMap<u64, BTreeMap<i64, u64>>,
        status_buckets: &mut BTreeMap<u64, BTreeMap<i64, StatusClassCounts>>,
        timestamp: DateTime<Utc>,
        status: Option<u16>,
    ) {
        for width in widths {
            let Ok(width_i64) = i64::try_from(*width) else {
                continue;
            };
            let bucket = timestamp.timestamp().div_euclid(width_i64);
            if admitted_rate_buckets
                .get(width)
                .is_some_and(|buckets| buckets.contains_key(&bucket))
            {
                record_status_class(
                    status_buckets
                        .get_mut(width)
                        .expect("all configured rate widths have a status map")
                        .entry(bucket)
                        .or_default(),
                    status,
                );
            }
        }
    }

    fn windowed_rate_summaries(
        &self,
        rate_buckets: &BTreeMap<u64, BTreeMap<i64, u64>>,
        beyond_caps: &BTreeMap<u64, u64>,
        observations_without_timestamp: u64,
    ) -> Vec<WindowedRequestRateSummary> {
        self.rate_window_seconds
            .iter()
            .map(|seconds| {
                let (peak, median, ratio) = Self::request_rate_for(
                    rate_buckets
                        .get(seconds)
                        .expect("all configured rate widths have a bucket map"),
                );
                WindowedRequestRateSummary {
                    bucket_width_seconds: *seconds,
                    peak_requests: peak,
                    median_requests: median,
                    peak_to_median_ratio: ratio,
                    observations_without_timestamp,
                    observations_beyond_bucket_cap: *beyond_caps.get(seconds).unwrap_or(&0),
                }
            })
            .collect()
    }

    fn windowed_response_outcome_summaries(
        &self,
        status_buckets: &BTreeMap<u64, BTreeMap<i64, StatusClassCounts>>,
        beyond_caps: &BTreeMap<u64, u64>,
        observations_without_timestamp: u64,
    ) -> Vec<WindowedResponseOutcomeSummary> {
        self.rate_window_seconds
            .iter()
            .map(|seconds| {
                let buckets = status_buckets
                    .get(seconds)
                    .expect("all configured rate widths have a status map");
                let mut minimum_success_share: Option<f64> = None;
                let mut maximum_server_error_share: Option<f64> = None;
                let mut eligible_buckets = 0;
                let mut buckets_below_minimum = 0;
                let mut minimum_success_bucket_start = None;
                let mut maximum_server_error_bucket_start = None;
                let mut minimum_fraction: Option<(u64, u64)> = None;
                let mut maximum_fraction: Option<(u64, u64)> = None;
                let mut buckets_below_success_threshold = 0;
                // BTreeMap order is chronological. Strict rational comparison
                // retains the earliest tied bucket without floating-point ties.
                for (&bucket, counts) in buckets {
                    let total = counts.total_observations();
                    if total < self.response_bucket_minimum_requests {
                        buckets_below_minimum += 1;
                        continue;
                    }
                    eligible_buckets += 1;
                    let success = share(counts.success, total);
                    let server_error = share(counts.server_error, total);
                    let start = bucket
                        .checked_mul(*seconds as i64)
                        .and_then(|epoch| DateTime::from_timestamp(epoch, 0));
                    if minimum_fraction.is_none_or(|(n, d)| {
                        u128::from(counts.success) * u128::from(d)
                            < u128::from(n) * u128::from(total)
                    }) {
                        minimum_fraction = Some((counts.success, total));
                        minimum_success_share = Some(success);
                        minimum_success_bucket_start = start;
                    }
                    if maximum_fraction.is_none_or(|(n, d)| {
                        u128::from(counts.server_error) * u128::from(d)
                            > u128::from(n) * u128::from(total)
                    }) {
                        maximum_fraction = Some((counts.server_error, total));
                        maximum_server_error_share = Some(server_error);
                        maximum_server_error_bucket_start = start;
                    }
                    if u128::from(counts.success) * 100
                        < u128::from(total)
                            * u128::from(self.response_success_share_threshold_percent)
                    {
                        buckets_below_success_threshold += 1;
                    }
                }
                WindowedResponseOutcomeSummary {
                    bucket_width_seconds: *seconds,
                    minimum_requests_per_bucket: self.response_bucket_minimum_requests,
                    eligible_buckets,
                    buckets_below_minimum,
                    minimum_success_share,
                    maximum_server_error_share,
                    minimum_success_bucket_start,
                    maximum_server_error_bucket_start,
                    success_share_threshold_percent: Some(
                        self.response_success_share_threshold_percent,
                    ),
                    buckets_below_success_threshold,
                    observations_without_timestamp,
                    observations_beyond_bucket_cap: *beyond_caps.get(seconds).unwrap_or(&0),
                }
            })
            .collect()
    }

    fn share(&self, count: u64) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            count as f64 / self.total_requests as f64
        }
    }
}

fn normalize_rate_windows(widths: &[u64]) -> Vec<u64> {
    let mut widths = widths
        .iter()
        .copied()
        .filter(|width| *width != 0 && *width <= i64::MAX as u64)
        .collect::<Vec<_>>();
    widths.sort_unstable();
    widths.dedup();
    widths
}

/// Add deterministic network-prefix aggregations to an already-built private
/// focus summary. This deliberately derives only from the retained private
/// source list, so it adds no streaming state and cannot recover peers omitted
/// by the disclosed focus source-IP cap.
pub fn add_focus_prefix_groups(focus: &mut PrivateFocusSummary, prefixes: FocusPrefixLengths) {
    let mut groups = BTreeMap::<
        String,
        (
            u64,
            BTreeSet<String>,
            StatusClassCounts,
            Option<StatusCodeCounts>,
        ),
    >::new();
    for source in &focus.sources {
        let Ok(address) = source.source_ip.parse::<IpAddr>() else {
            continue;
        };
        let prefix = match address {
            IpAddr::V4(_) => prefixes.ipv4,
            IpAddr::V6(_) => prefixes.ipv6,
        };
        let Ok(network) = IpNet::new(address, prefix) else {
            // CLI validation prevents this for configured prefix lengths. A
            // direct library caller with an invalid family-specific length
            // simply receives no derived group for that malformed setting.
            continue;
        };
        let key = format!("{}/{}", network.network(), prefix);
        let (requests, source_ips, classes, codes) = groups.entry(key).or_default();
        *requests += source.requests;
        source_ips.insert(source.source_ip.clone());
        classes.merge(&source.response_status_classes);
        if let Some(source_codes) = &source.response_status_codes {
            codes
                .get_or_insert_with(|| StatusCodeCounts {
                    maximum_codes: source_codes.maximum_codes,
                    ..StatusCodeCounts::default()
                })
                .merge(source_codes);
        }
    }
    let mut prefix_groups = groups
        .into_iter()
        .map(
            |(network_prefix, (requests, source_ips, classes, codes))| PrivateFocusPrefixGroup {
                network_prefix,
                requests,
                request_share: if focus.total_requests == 0 {
                    0.0
                } else {
                    requests as f64 / focus.total_requests as f64
                },
                distinct_source_ips: source_ips.len(),
                response_outcomes: codes.as_ref().map(|_| response_outcome_summary(&classes)),
                response_status_classes: classes,
                response_status_codes: codes,
            },
        )
        .collect::<Vec<_>>();
    prefix_groups.sort_by(|left, right| {
        right
            .requests
            .cmp(&left.requests)
            .then_with(|| left.network_prefix.cmp(&right.network_prefix))
    });
    focus.network_prefix_groups = prefix_groups;
}

/// Add deterministic ASN aggregations to an already-built private focus
/// summary. Resolution is local and uses only retained source counts. An ASN
/// is a routing-level grouping, not an operator, actor, or intent judgment.
pub fn add_focus_asn_groups(focus: &mut PrivateFocusSummary, resolver: &impl AsnResolver) {
    let mut groups = BTreeMap::<u32, (String, u64, BTreeSet<String>)>::new();
    let mut unresolved_source_ips = 0usize;
    let mut unresolved_requests = 0u64;

    for source in &focus.sources {
        let resolved = source
            .source_ip
            .parse::<IpAddr>()
            .ok()
            .and_then(|address| resolver.resolve(address));
        let Some(resolved) = resolved else {
            unresolved_source_ips += 1;
            unresolved_requests += source.requests;
            continue;
        };
        let entry = groups
            .entry(resolved.asn)
            .or_insert_with(|| (resolved.org.clone(), 0, BTreeSet::new()));
        // A malformed or mixed local dataset can name the same ASN more than
        // once. Pick the lexicographically first label for deterministic output.
        if resolved.org < entry.0 {
            entry.0 = resolved.org;
        }
        entry.1 += source.requests;
        entry.2.insert(source.source_ip.clone());
    }

    let mut groups = groups
        .into_iter()
        .map(
            |(asn, (organization, requests, source_ips))| PrivateFocusAsnGroup {
                asn,
                organization,
                requests,
                request_share: if focus.total_requests == 0 {
                    0.0
                } else {
                    requests as f64 / focus.total_requests as f64
                },
                distinct_source_ips: source_ips.len(),
            },
        )
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        right
            .requests
            .cmp(&left.requests)
            .then_with(|| left.asn.cmp(&right.asn))
            .then_with(|| left.organization.cmp(&right.organization))
    });
    focus.asn = Some(PrivateFocusAsnSummary {
        groups,
        unresolved_source_ips,
        unresolved_requests,
    });
}

/// Return literal query-key names in observation order. Shenron deliberately
/// does not decode or interpret them: splitting on `&` and taking the bytes
/// before the first `=` is a transparent request-shape measurement. Empty keys
/// are ignored, and values are never returned or serialized.
fn query_keys(query: &str) -> impl Iterator<Item = &str> {
    query.split('&').filter_map(|component| {
        let key = component.split_once('=').map_or(component, |(key, _)| key);
        (!key.is_empty()).then_some(key)
    })
}

/// Ratio of two observed counts. A zero denominator remains zero rather than
/// producing a non-finite JSON value. This is request-volume context only, not
/// a determination of automation, denial of service, attack, or abuse.
fn requests_per_distinct_source(requests: u64, distinct_source_ips: usize) -> f64 {
    if distinct_source_ips == 0 {
        0.0
    } else {
        requests as f64 / distinct_source_ips as f64
    }
}

fn share(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

fn response_outcome_summary(counts: &StatusClassCounts) -> ResponseOutcomeSummary {
    let total = counts.total_observations();
    ResponseOutcomeSummary {
        counts: counts.clone(),
        success_share: share(counts.success, total),
        redirection_share: share(counts.redirection, total),
        ordinary_client_error_share: share(counts.ordinary_client_error(), total),
        client_closed_request_499_share: share(counts.client_closed_request_499, total),
        server_error_share: share(counts.server_error, total),
    }
}

fn record_status_class(counts: &mut StatusClassCounts, status: Option<u16>) {
    match status {
        Some(100..=199) => counts.informational += 1,
        Some(200..=299) => counts.success += 1,
        Some(300..=399) => counts.redirection += 1,
        Some(499) => {
            counts.client_error += 1;
            counts.client_closed_request_499 += 1;
        }
        Some(400..=498) => counts.client_error += 1,
        Some(500..=599) => counts.server_error += 1,
        Some(_) => counts.other += 1,
        None => counts.unavailable += 1,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeZone;

    use super::*;
    use crate::event::{LogSource, WebEvent};
    use crate::triage::ResolvedAsn;

    struct TestAsnResolver(BTreeMap<IpAddr, ResolvedAsn>);

    impl AsnResolver for TestAsnResolver {
        fn resolve(&self, ip: IpAddr) -> Option<ResolvedAsn> {
            self.0.get(&ip).cloned()
        }
    }

    fn event(path: Option<&str>, source_ip: Option<&str>, minute: Option<i64>) -> WebEvent {
        WebEvent {
            timestamp: minute.map(|minute| Utc.timestamp_opt(minute * 60, 0).unwrap()),
            source_ip: source_ip.map(str::to_owned),
            client_ip: None,
            source_port: None,
            country: None,
            host: None,
            method: Some("GET".to_owned()),
            uri: path.map(str::to_owned),
            uri_path: path.map(str::to_owned),
            uri_query: None,
            uri_fragment: None,
            headers: Vec::new(),
            user_agent: None,
            referer: None,
            status: Some(403),
            response_bytes: Some(10),
            protocol: Some("HTTP/1.1".to_owned()),
            request_id: None,
            ja3: None,
            ja4: None,
            tls_protocol: None,
            tls_cipher: None,
            waf_action: None,
            waf_rule_id: None,
            waf_rule_type: None,
            waf_labels: Vec::new(),
            waf_non_terminating_rule_ids: Vec::new(),
            log_source: LogSource::ApacheCombined,
            raw: String::new(),
        }
    }

    fn event_with_query(path: &str, source_ip: &str, query: Option<String>) -> WebEvent {
        let mut event = event(Some(path), Some(source_ip), Some(0));
        event.uri_query = query.clone();
        event.uri = Some(match query {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        });
        event
    }

    #[test]
    fn measures_top_path_source_convergence_and_minute_rate() {
        let mut concentration = RequestConcentration::new(true);
        for (path, ip, minute) in [
            ("/popular", "198.51.100.1", 0),
            ("/popular", "198.51.100.2", 0),
            ("/popular", "198.51.100.1", 1),
            ("/other", "198.51.100.3", 1),
        ] {
            concentration.observe(&event(Some(path), Some(ip), Some(minute)));
        }
        let summary = concentration.summary();
        let top = summary.top_path.unwrap();
        assert_eq!(top.requests, 3);
        assert_eq!(top.distinct_source_ips, 2);
        assert_eq!(top.requests_per_source_ip, 1.5);
        assert_eq!(top.request_share, 0.75);
        assert_eq!(top.response_status_classes.client_error, 3);
        assert_eq!(top.response_bytes, Some(30));
        assert_eq!(
            summary.requests_per_minute.peak_requests_per_minute,
            Some(2)
        );
        assert_eq!(
            summary.requests_per_minute.median_requests_per_minute,
            Some(2.0)
        );
        assert_eq!(summary.requests_per_minute.peak_to_median_ratio, Some(1.0));
    }

    #[test]
    fn groups_retained_focus_sources_by_asn_and_discloses_unresolved_counts() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on(FocusSelector::ExactPath("/focus".to_owned()));
        for (ip, count) in [("198.51.100.1", 3), ("198.51.101.2", 2), ("203.0.113.9", 1)] {
            for _ in 0..count {
                concentration.observe(&event(Some("/focus"), Some(ip), Some(0)));
            }
        }
        let mut focus = concentration.private_report().focus.unwrap();
        add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
        let resolver = TestAsnResolver(BTreeMap::from([
            (
                "198.51.100.1".parse().unwrap(),
                ResolvedAsn {
                    asn: 64_500,
                    org: "Example Transit".to_owned(),
                },
            ),
            (
                "198.51.101.2".parse().unwrap(),
                ResolvedAsn {
                    asn: 64_500,
                    org: "Example Transit".to_owned(),
                },
            ),
        ]));
        add_focus_asn_groups(&mut focus, &resolver);

        assert_eq!(focus.network_prefix_groups.len(), 3);
        let asn = focus.asn.unwrap();
        assert_eq!(asn.groups.len(), 1);
        assert_eq!(asn.groups[0].asn, 64_500);
        assert_eq!(asn.groups[0].requests, 5);
        assert_eq!(asn.groups[0].distinct_source_ips, 2);
        assert_eq!(asn.groups[0].request_share, 5.0 / 6.0);
        assert_eq!(asn.unresolved_source_ips, 1);
        assert_eq!(asn.unresolved_requests, 1);
    }

    #[test]
    fn keeps_private_minute_series_sorted_and_discloses_bucket_caps() {
        let mut concentration = RequestConcentration::with_limits(
            true,
            ConcentrationLimits {
                max_minute_buckets: 2,
                ..ConcentrationLimits::default()
            },
        );
        concentration.focus_on_path("/target");
        for minute in [2, 0, 2, 3] {
            concentration.observe(&event(Some("/target"), Some("198.51.100.1"), Some(minute)));
        }

        let private = concentration.private_report();
        assert_eq!(
            private.requests_per_minute_series,
            vec![
                MinuteRequestCount {
                    minute_epoch: 0,
                    requests: 1,
                },
                MinuteRequestCount {
                    minute_epoch: 2,
                    requests: 2,
                },
            ]
        );
        assert_eq!(private.minute_buckets_beyond_cap, 1);
        assert_eq!(private.status_class_requests_per_minute_series.len(), 2);
        assert_eq!(
            private
                .status_class_requests_per_minute_series
                .iter()
                .map(|point| point.client_error)
                .sum::<u64>(),
            3
        );
        let focus = private.focus.unwrap();
        assert_eq!(focus.requests_per_minute_series.len(), 2);
        assert_eq!(focus.minute_buckets_beyond_cap, 1);

        let sanitized = serde_json::to_string(&concentration.summary()).unwrap();
        assert!(!sanitized.contains("requests_per_minute_series"));
        assert!(!sanitized.contains("status_class_requests_per_minute_series"));
        assert!(!sanitized.contains("198.51.100.1"));
        assert!(!sanitized.contains("/target"));
    }

    #[test]
    fn loads_private_artifacts_created_before_minute_series_fields() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on_path("/target");
        let mut value = serde_json::to_value(concentration.private_report()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("requests_per_minute_series");
        object.remove("status_class_requests_per_minute_series");
        object.remove("minute_buckets_beyond_cap");
        let focus = object
            .get_mut("focus")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap();
        focus.remove("requests_per_minute_series");
        focus.remove("minute_buckets_beyond_cap");
        let loaded: PrivateRequestConcentrationReport = serde_json::from_value(value).unwrap();
        assert!(loaded.requests_per_minute_series.is_empty());
        assert!(loaded.status_class_requests_per_minute_series.is_empty());
        assert_eq!(loaded.minute_buckets_beyond_cap, 0);
        let focus = loaded.focus.unwrap();
        assert!(focus.requests_per_minute_series.is_empty());
        assert_eq!(focus.minute_buckets_beyond_cap, 0);
    }

    #[test]
    fn keeps_status_class_minute_series_sorted_and_counted_by_class() {
        let mut concentration = RequestConcentration::new(true);
        for (minute, status) in [(2, 200), (0, 404), (0, 201), (1, 302), (1, 500), (1, 101)] {
            let mut observed = event(Some("/status"), Some("198.51.100.1"), Some(minute));
            observed.status = Some(status);
            concentration.observe(&observed);
        }

        assert_eq!(
            concentration
                .private_report()
                .status_class_requests_per_minute_series,
            vec![
                StatusClassMinuteCount {
                    minute_epoch: 0,
                    success: 1,
                    client_error: 1,
                    ..StatusClassMinuteCount::default()
                },
                StatusClassMinuteCount {
                    minute_epoch: 1,
                    informational: 1,
                    redirection: 1,
                    server_error: 1,
                    ..StatusClassMinuteCount::default()
                },
                StatusClassMinuteCount {
                    minute_epoch: 2,
                    success: 1,
                    ..StatusClassMinuteCount::default()
                },
            ]
        );
    }

    #[test]
    fn finds_path_concentration_even_when_sources_are_distributed() {
        let mut concentration = RequestConcentration::new(true);
        for index in 0..200 {
            concentration.observe(&event(
                Some("/shared-resource"),
                Some(&format!("198.51.100.{index}")),
                Some(index),
            ));
        }
        for index in 0..200 {
            concentration.observe(&event(
                Some("/other-resource"),
                Some(&format!("203.0.113.{index}")),
                Some(index),
            ));
        }
        let top = concentration.summary().top_path.unwrap();
        assert_eq!(top.requests, 200);
        assert_eq!(top.distinct_source_ips, 200);
        assert_eq!(top.requests_per_source_ip, 1.0);
        assert_eq!(top.request_share, 0.5);
        assert!(concentration
            .private_report()
            .source_ips
            .iter()
            .all(|source| source.requests * 100 < 400));
    }

    #[test]
    fn requests_per_distinct_source_avoids_a_zero_denominator() {
        assert_eq!(requests_per_distinct_source(12, 3), 4.0);
        let zero = requests_per_distinct_source(12, 0);
        assert_eq!(zero, 0.0);
        assert!(zero.is_finite());
    }

    #[test]
    fn discloses_tracking_caps_and_undated_observations() {
        let mut concentration = RequestConcentration::with_limits(
            true,
            ConcentrationLimits {
                max_paths: 1,
                max_source_ips: 1,
                max_focus_source_ips: 1,
                max_focus_paths: 1,
                max_source_path_pairs: 1,
                max_minute_buckets: 1,
                max_query_strings_per_path: 1,
                max_query_keys_per_path: 1,
                max_status_codes_per_entity: DEFAULT_MAX_STATUS_CODES_PER_ENTITY,
                max_source_segments: DEFAULT_MAX_SOURCE_SEGMENTS,
            },
        );
        concentration.observe(&event(Some("/one"), Some("198.51.100.1"), Some(0)));
        concentration.observe(&event(Some("/two"), Some("198.51.100.2"), None));
        let summary = concentration.summary();
        assert_eq!(summary.paths_beyond_tracking_cap, 1);
        assert_eq!(summary.source_ips_beyond_tracking_cap, 1);
        assert_eq!(
            summary.requests_per_minute.observations_without_timestamp,
            1
        );
    }

    #[test]
    fn marks_response_bytes_unavailable_when_telemetry_lacks_them() {
        let mut concentration = RequestConcentration::new(false);
        concentration.observe(&event(Some("/resource"), Some("198.51.100.1"), Some(0)));
        assert_eq!(
            concentration.summary().top_path.unwrap().response_bytes,
            None
        );
    }

    #[test]
    fn finds_the_most_requested_path_with_the_existing_tie_breaker() {
        let mut concentration = RequestConcentration::new(true);
        for path in ["/zebra", "/alpha", "/zebra", "/alpha"] {
            concentration.observe(&event(Some(path), Some("198.51.100.1"), Some(0)));
        }
        assert_eq!(
            concentration.most_requested_path("198.51.100.1"),
            Some("/alpha".to_owned())
        );
    }

    #[test]
    fn leaves_a_source_top_path_unavailable_after_pair_tracking_is_incomplete() {
        let mut concentration = RequestConcentration::with_limits(
            true,
            ConcentrationLimits {
                max_paths: 10,
                max_source_ips: 10,
                max_focus_source_ips: 10,
                max_focus_paths: 10,
                max_source_path_pairs: 1,
                max_minute_buckets: 10,
                max_query_strings_per_path: 10,
                max_query_keys_per_path: 10,
                max_status_codes_per_entity: DEFAULT_MAX_STATUS_CODES_PER_ENTITY,
                max_source_segments: DEFAULT_MAX_SOURCE_SEGMENTS,
            },
        );
        concentration.observe(&event(Some("/first"), Some("198.51.100.1"), Some(0)));
        concentration.observe(&event(Some("/second"), Some("198.51.100.1"), Some(0)));
        assert_eq!(concentration.most_requested_path("198.51.100.1"), None);
        assert_eq!(concentration.source_path_pair_count, 1);
        assert_eq!(
            concentration
                .summary()
                .source_path_pairs_beyond_tracking_cap,
            1
        );
    }

    #[test]
    fn range_lookup_matches_the_previous_full_map_scan() {
        let mut concentration = RequestConcentration::new(true);
        for source in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
            for path in ["/alpha", "/beta", "/beta", "/gamma", "/gamma", "/gamma"] {
                concentration.observe(&event(Some(path), Some(source), Some(0)));
            }
        }
        for source in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
            let previous_full_scan = concentration
                .source_path_pairs
                .iter()
                .flat_map(|(candidate, paths)| {
                    paths
                        .iter()
                        .map(move |(path, count)| ((candidate, path), count))
                })
                .filter(|((candidate, _), _)| candidate.as_str() == source)
                .max_by(|((_, left_path), left), ((_, right_path), right)| {
                    left.cmp(right).then_with(|| right_path.cmp(left_path))
                })
                .map(|((_, path), _)| path.clone());
            assert_eq!(
                concentration.most_requested_path(source),
                previous_full_scan
            );
        }
    }

    #[test]
    fn focuses_on_one_exact_path_and_sorts_private_sources_deterministically() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on_path("/target");
        for (path, ip, minute) in [
            ("/target", "198.51.100.2", 0),
            ("/target", "198.51.100.1", 0),
            ("/target", "198.51.100.1", 1),
            ("/other", "198.51.100.9", 1),
        ] {
            concentration.observe(&event(Some(path), Some(ip), Some(minute)));
        }
        let focus = concentration.private_report().focus.unwrap();
        assert_eq!(focus.uri_path, "/target");
        assert_eq!(focus.total_requests, 3);
        assert_eq!(focus.distinct_source_ips, 2);
        assert_eq!(focus.peak_requests_per_minute, Some(2));
        assert_eq!(focus.median_requests_per_minute, Some(1.5));
        assert_eq!(
            focus
                .sources
                .iter()
                .map(|source| (source.source_ip.as_str(), source.requests))
                .collect::<Vec<_>>(),
            vec![("198.51.100.1", 2), ("198.51.100.2", 1)]
        );
        let serialized = serde_json::to_string(&concentration.summary()).unwrap();
        assert!(!serialized.contains("/target"));
        assert!(!serialized.contains("198.51.100.1"));
    }

    #[test]
    fn discloses_focus_source_ip_cap_without_adding_new_sources() {
        let mut concentration = RequestConcentration::with_limits(
            true,
            ConcentrationLimits {
                max_paths: 10,
                max_source_ips: 10,
                max_focus_source_ips: 1,
                max_focus_paths: 1,
                max_source_path_pairs: 10,
                max_minute_buckets: 10,
                max_query_strings_per_path: 10,
                max_query_keys_per_path: 10,
                max_status_codes_per_entity: DEFAULT_MAX_STATUS_CODES_PER_ENTITY,
                max_source_segments: DEFAULT_MAX_SOURCE_SEGMENTS,
            },
        );
        concentration.focus_on_path("/target");
        concentration.observe(&event(Some("/target"), Some("198.51.100.1"), Some(0)));
        concentration.observe(&event(Some("/target"), Some("198.51.100.2"), Some(0)));
        let focus = concentration.summary().focus.unwrap();
        assert_eq!(focus.distinct_source_ips, 1);
        assert_eq!(focus.source_ips_beyond_cap, 1);
    }

    #[test]
    fn groups_retained_focus_sources_by_prefix_without_changing_individual_sources() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on_path("/target");
        for host in 1..=10 {
            let source = format!("198.51.100.{host}");
            for _ in 0..100 {
                concentration.observe(&event(Some("/target"), Some(&source), Some(0)));
            }
        }
        for _ in 0..50 {
            concentration.observe(&event(Some("/target"), Some("203.0.113.1"), Some(0)));
        }
        let mut focus = concentration.private_report().focus.unwrap();
        let individual_sources = focus.sources.clone();
        add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
        assert_eq!(focus.network_prefix_groups.len(), 2);
        let top = &focus.network_prefix_groups[0];
        assert_eq!(top.network_prefix, "198.51.100.0/24");
        assert_eq!(top.requests, 1_000);
        assert_eq!(top.distinct_source_ips, 10);
        assert_eq!(top.request_share, 1_000.0 / 1_050.0);
        assert_eq!(focus.sources, individual_sources);
        let sanitized = serde_json::to_string(&concentration.summary()).unwrap();
        assert!(!sanitized.contains("198.51.100.0/24"));
        assert!(!sanitized.contains("198.51.100.1"));
        assert!(!sanitized.contains("/target"));
    }

    #[test]
    fn changing_the_ipv4_prefix_changes_focus_groups() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on_path("/target");
        for source in ["198.51.100.1", "198.51.101.1"] {
            concentration.observe(&event(Some("/target"), Some(source), Some(0)));
        }
        let focus = concentration.private_report().focus.unwrap();
        let mut by_24 = focus.clone();
        add_focus_prefix_groups(&mut by_24, FocusPrefixLengths { ipv4: 24, ipv6: 48 });
        let mut by_16 = focus;
        add_focus_prefix_groups(&mut by_16, FocusPrefixLengths { ipv4: 16, ipv6: 48 });
        assert_eq!(by_24.network_prefix_groups.len(), 2);
        assert_eq!(by_16.network_prefix_groups.len(), 1);
        assert_eq!(
            by_16.network_prefix_groups[0].network_prefix,
            "198.51.0.0/16"
        );
    }

    #[test]
    fn uses_the_default_ipv6_prefix_for_focus_groups() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on_path("/target");
        for source in ["2001:db8:1:1::1", "2001:db8:1:ffff::2"] {
            concentration.observe(&event(Some("/target"), Some(source), Some(0)));
        }
        let mut focus = concentration.private_report().focus.unwrap();
        add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
        assert_eq!(focus.network_prefix_groups.len(), 1);
        assert_eq!(
            focus.network_prefix_groups[0].network_prefix,
            "2001:db8:1::/48"
        );
        assert_eq!(focus.network_prefix_groups[0].distinct_source_ips, 2);
    }

    #[test]
    fn path_is_under_matches_on_segment_boundaries() {
        assert!(path_is_under("/api", "/api"));
        assert!(path_is_under("/api/users", "/api"));
        assert!(path_is_under("/api/users", "/api/"));
        assert!(path_is_under("/anything", "/"));
        assert!(!path_is_under("/apixyz", "/api"));
        assert!(!path_is_under("/ap", "/api"));
    }

    #[test]
    fn path_prefix_focus_lists_subpaths_and_peers() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on(FocusSelector::PathPrefix("/wp-admin".to_owned()));
        for (path, ip) in [
            ("/wp-admin", "198.51.100.1"),
            ("/wp-admin/index.php", "198.51.100.1"),
            ("/wp-admin/index.php", "198.51.100.2"),
            ("/wp-adminx", "198.51.100.9"), // outside the subtree
            ("/other", "198.51.100.9"),
        ] {
            concentration.observe(&event(Some(path), Some(ip), Some(0)));
        }
        let focus = concentration.private_report().focus.unwrap();
        assert_eq!(focus.focus_kind, "path-prefix");
        assert_eq!(focus.total_requests, 3);
        assert_eq!(focus.distinct_source_ips, 2);
        // Sub-paths under the prefix are listed, most-requested first.
        assert_eq!(focus.paths.len(), 2);
        assert_eq!(focus.paths[0].uri_path, "/wp-admin/index.php");
        assert_eq!(focus.paths[0].requests, 2);
    }

    #[test]
    fn source_ip_focus_lists_requested_paths() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on(FocusSelector::SourceIp(
            ["198.51.100.7".to_owned()].into_iter().collect(),
        ));
        for (path, ip) in [
            ("/a", "198.51.100.7"),
            ("/a", "198.51.100.7"),
            ("/b", "198.51.100.7"),
            ("/a", "198.51.100.8"), // different peer, ignored
        ] {
            concentration.observe(&event(Some(path), Some(ip), Some(0)));
        }
        let focus = concentration.private_report().focus.unwrap();
        assert_eq!(focus.focus_kind, "source-ip");
        assert_eq!(focus.selector, "198.51.100.7");
        assert_eq!(focus.total_requests, 3);
        assert_eq!(focus.paths.len(), 2);
        assert_eq!(focus.paths[0].uri_path, "/a");
        assert_eq!(focus.paths[0].requests, 2);
    }

    #[test]
    fn multiple_source_ip_focus_unions_paths_and_retains_per_ip_counts() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on(FocusSelector::SourceIp(
            [
                "198.51.100.2".to_owned(),
                "198.51.100.1".to_owned(),
                "198.51.100.2".to_owned(),
            ]
            .into_iter()
            .collect(),
        ));
        for (path, ip) in [
            ("/shared", "198.51.100.1"),
            ("/one", "198.51.100.1"),
            ("/shared", "198.51.100.2"),
            ("/two", "198.51.100.2"),
            ("/two", "198.51.100.2"),
            ("/ignored", "198.51.100.3"),
        ] {
            concentration.observe(&event(Some(path), Some(ip), Some(0)));
        }

        let focus = concentration.private_report().focus.unwrap();
        assert_eq!(focus.selector, "198.51.100.1, 198.51.100.2");
        assert_eq!(focus.total_requests, 5);
        assert_eq!(
            focus
                .sources
                .iter()
                .map(|source| (source.source_ip.as_str(), source.requests))
                .collect::<Vec<_>>(),
            vec![("198.51.100.2", 3), ("198.51.100.1", 2)]
        );
        assert_eq!(
            focus
                .paths
                .iter()
                .map(|path| (path.uri_path.as_str(), path.requests))
                .collect::<Vec<_>>(),
            vec![("/shared", 2), ("/two", 2), ("/one", 1)]
        );

        let sanitized = serde_json::to_string(&concentration.summary()).unwrap();
        assert!(!sanitized.contains("198.51.100.1"));
        assert!(!sanitized.contains("198.51.100.2"));
        assert!(!sanitized.contains("/shared"));
        assert!(sanitized.contains("source-ip"));
    }

    #[test]
    fn sanitized_focus_summary_contains_no_raw_path_or_ip() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on(FocusSelector::PathPrefix("/secret-area".to_owned()));
        concentration.observe(&event(Some("/secret-area/x"), Some("203.0.113.5"), Some(0)));
        let sanitized = concentration.summary();
        let json = serde_json::to_string(&sanitized).unwrap();
        assert!(!json.contains("/secret-area"));
        assert!(!json.contains("203.0.113.5"));
        assert!(json.contains("path-prefix"));
    }

    #[test]
    fn simultaneous_rate_windows_distinguish_short_spikes_from_long_elevation() {
        let limits = ConcentrationLimits::default();
        let mut short =
            RequestConcentration::with_limits_and_rate_windows(true, limits, &[60, 3_600]);
        short.focus_on_path("/focus");
        for minute in 0..60 {
            short.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(minute)));
        }
        for _ in 0..99 {
            short.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(30)));
        }
        let short_summary = short.summary();
        assert_eq!(
            short_summary.request_rates[0].peak_to_median_ratio,
            Some(100.0)
        );
        assert_eq!(
            short_summary.request_rates[1].peak_to_median_ratio,
            Some(1.0)
        );
        assert_eq!(
            short_summary.focus.as_ref().unwrap().request_rates,
            short_summary.request_rates
        );

        let mut sustained =
            RequestConcentration::with_limits_and_rate_windows(true, limits, &[60, 3_600]);
        sustained.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(0)));
        for minute in 60..120 {
            sustained.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(minute)));
        }
        sustained.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(120)));
        let sustained_summary = sustained.summary();
        assert_eq!(
            sustained_summary.request_rates[0].peak_to_median_ratio,
            Some(1.0)
        );
        assert_eq!(
            sustained_summary.request_rates[1].peak_to_median_ratio,
            Some(60.0)
        );
    }

    #[test]
    fn simultaneous_rate_windows_are_deterministic_and_preserve_single_minute_semantics() {
        let build = || {
            let mut concentration = RequestConcentration::with_limits_and_rate_windows(
                true,
                ConcentrationLimits::default(),
                &[3_600, 60, 600, 60],
            );
            for minute in [0, 0, 1, 10, 11, 59, 60] {
                concentration.observe(&event(
                    Some("/deterministic"),
                    Some("203.0.113.7"),
                    Some(minute),
                ));
            }
            serde_json::to_string(&concentration.summary()).unwrap()
        };
        assert_eq!(build(), build());

        let mut one_minute = RequestConcentration::with_limits_and_rate_windows(
            true,
            ConcentrationLimits::default(),
            &[60],
        );
        for minute in [0, 0, 1] {
            one_minute.observe(&event(Some("/one"), Some("192.0.2.1"), Some(minute)));
        }
        let summary = one_minute.summary();
        let rate = &summary.request_rates[0];
        assert_eq!(
            rate.peak_requests,
            summary.requests_per_minute.peak_requests_per_minute
        );
        assert_eq!(
            rate.median_requests,
            summary.requests_per_minute.median_requests_per_minute
        );
        assert_eq!(
            rate.peak_to_median_ratio,
            summary.requests_per_minute.peak_to_median_ratio
        );
    }

    #[test]
    fn measures_reused_query_strings_and_keys_for_one_path_and_focus() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on_path("/asset");
        for index in 0..10_000 {
            concentration.observe(&event_with_query(
                "/asset",
                "198.51.100.1",
                Some(format!("v={:03}", index % 1_000)),
            ));
        }

        let summary = concentration.summary();
        let top = summary.top_path.unwrap();
        assert_eq!(top.requests, 10_000);
        assert_eq!(top.request_share, 1.0);
        assert_eq!(top.distinct_source_ips, 1);
        assert_eq!(top.response_status_classes.client_error, 10_000);
        assert_eq!(top.response_bytes, Some(100_000));
        assert_eq!(top.requests_with_query, 10_000);
        assert_eq!(top.distinct_query_strings, 1_000);
        assert_eq!(top.distinct_query_keys, 1);
        assert_eq!(top.query_strings_beyond_tracking_cap, 0);
        let focus = summary.focus.unwrap();
        assert_eq!(focus.requests_with_query, 10_000);
        assert_eq!(focus.distinct_query_strings, 1_000);
        assert_eq!(focus.distinct_query_keys, 1);
        assert_eq!(
            concentration.private_report_with_query_keys(true).paths[0].query_keys,
            vec!["v"]
        );
    }

    #[test]
    fn measures_unique_or_absent_queries_without_dividing_by_zero() {
        let mut unique = RequestConcentration::new(true);
        for index in 0..100 {
            unique.observe(&event_with_query(
                "/unique",
                "198.51.100.2",
                Some(format!("nonce={index}")),
            ));
        }
        let unique = unique.summary().top_path.unwrap();
        assert_eq!(unique.distinct_query_strings as u64, unique.requests);

        let mut absent = RequestConcentration::new(true);
        absent.observe(&event_with_query("/plain", "198.51.100.3", None));
        let absent = absent.summary().top_path.unwrap();
        assert_eq!(absent.requests_with_query, 0);
        assert_eq!(absent.distinct_query_strings, 0);
        assert_eq!(absent.distinct_query_keys, 0);
        assert_eq!(
            absent.requests_with_query as f64 / absent.requests as f64,
            0.0
        );

        let empty = RequestConcentration::new(true).summary();
        assert_eq!(empty.total_requests, 0);
        assert!(empty.top_path.is_none());
    }

    #[test]
    fn query_tracking_caps_are_disclosed_without_serializing_query_values() {
        let mut concentration = RequestConcentration::with_limits(
            true,
            ConcentrationLimits {
                max_query_strings_per_path: 2,
                max_query_keys_per_path: 1,
                ..ConcentrationLimits::default()
            },
        );
        concentration.focus_on_path("/private-query");
        for query in [
            "first=secret-one",
            "second=secret-two",
            "third=secret-three",
        ] {
            concentration.observe(&event_with_query(
                "/private-query",
                "203.0.113.8",
                Some(query.to_owned()),
            ));
        }
        let summary = concentration.summary();
        let top = summary.top_path.as_ref().unwrap();
        assert_eq!(top.distinct_query_strings, 2);
        assert_eq!(top.query_strings_beyond_tracking_cap, 1);
        assert_eq!(top.distinct_query_keys, 1);
        assert_eq!(top.query_keys_beyond_tracking_cap, 2);

        let sanitized = serde_json::to_string(&summary).unwrap();
        let private = serde_json::to_string(&concentration.private_report()).unwrap();
        let opted_in =
            serde_json::to_string(&concentration.private_report_with_query_keys(true)).unwrap();
        for value in [
            "secret-one",
            "secret-two",
            "secret-three",
            "first=",
            "second=",
        ] {
            assert!(!sanitized.contains(value));
            assert!(!private.contains(value));
            assert!(!opted_in.contains(value));
        }
        assert!(!sanitized.contains("first"));
        assert!(!private.contains("first"));
        assert!(opted_in.contains("first"));
    }

    #[test]
    fn records_status_classes_for_each_private_observed_peer() {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on_path("/status");
        for status in [Some(101), Some(204), Some(302), Some(404), Some(503), None] {
            let mut request = event(Some("/status"), Some("198.51.100.9"), Some(0));
            request.status = status;
            concentration.observe(&request);
        }
        let private = concentration.private_report();
        let source = &private.source_ips[0];
        assert_eq!(source.requests, 6);
        assert_eq!(source.response_status_classes.informational, 1);
        assert_eq!(source.response_status_classes.success, 1);
        assert_eq!(source.response_status_classes.redirection, 1);
        assert_eq!(source.response_status_classes.client_error, 1);
        assert_eq!(source.response_status_classes.server_error, 1);
        assert_eq!(source.response_status_classes.unavailable, 1);
        assert_eq!(
            private.focus.unwrap().sources[0].response_status_classes,
            source.response_status_classes
        );
    }

    #[test]
    fn summarizes_corpus_response_outcomes_and_separates_499_from_other_4xx() {
        let mut concentration = RequestConcentration::new(true);
        for status in [200, 302, 404, 499, 502] {
            let mut request = event(Some("/status"), Some("198.51.100.9"), Some(0));
            request.status = Some(status);
            concentration.observe(&request);
        }
        let summary = concentration.summary();
        assert_eq!(summary.total_requests, 5);
        let top_path = summary.top_path.as_ref().unwrap();
        assert_eq!(top_path.requests, 5);
        assert_eq!(top_path.request_share, 1.0);
        assert_eq!(top_path.distinct_source_ips, 1);
        assert_eq!(top_path.requests_per_source_ip, 5.0);
        let outcome = summary.response_outcomes.unwrap();
        assert_eq!(outcome.counts.success, 1);
        assert_eq!(outcome.counts.redirection, 1);
        assert_eq!(outcome.counts.client_error, 2);
        assert_eq!(outcome.counts.ordinary_client_error(), 1);
        assert_eq!(outcome.counts.client_closed_request_499, 1);
        assert_eq!(outcome.counts.server_error, 1);
        assert_eq!(outcome.success_share, 0.2);
        assert_eq!(outcome.ordinary_client_error_share, 0.2);
        assert_eq!(outcome.client_closed_request_499_share, 0.2);
        assert_eq!(outcome.server_error_share, 0.2);
    }

    #[test]
    fn response_windows_expose_short_zero_success_periods_without_labeling_them() {
        let mut concentration = RequestConcentration::with_limits_and_rate_windows(
            true,
            ConcentrationLimits::default(),
            &[60, 86_400],
        );
        for minute in 0..1_440 {
            for source in 0..10 {
                let mut request = event(
                    Some("/status"),
                    Some(&format!("198.51.100.{source}")),
                    Some(minute),
                );
                request.status = Some(if (1_085..1_097).contains(&minute) {
                    504
                } else {
                    200
                });
                concentration.observe(&request);
            }
        }
        let windows = concentration.summary().response_outcome_windows.unwrap();
        let minute = windows
            .iter()
            .find(|item| item.bucket_width_seconds == 60)
            .unwrap();
        let day = windows
            .iter()
            .find(|item| item.bucket_width_seconds == 86_400)
            .unwrap();
        assert_eq!(minute.minimum_success_share, Some(0.0));
        assert_eq!(minute.maximum_server_error_share, Some(1.0));
        assert!(day.minimum_success_share.unwrap() > 0.99);
        assert!(day.maximum_server_error_share.unwrap() < 0.01);
    }

    #[test]
    fn response_window_floor_excludes_sparse_buckets_and_status_can_be_unavailable() {
        let mut concentration = RequestConcentration::with_limits_and_rate_windows(
            true,
            ConcentrationLimits::default(),
            &[60],
        );
        concentration.set_response_bucket_minimum_requests(10);
        let mut sparse = event(Some("/status"), Some("198.51.100.1"), Some(0));
        sparse.status = Some(503);
        concentration.observe(&sparse);
        for source in 0..10 {
            let mut dense = event(
                Some("/status"),
                Some(&format!("203.0.113.{source}")),
                Some(1),
            );
            dense.status = Some(200);
            concentration.observe(&dense);
        }
        let window = &concentration.summary().response_outcome_windows.unwrap()[0];
        assert_eq!(window.eligible_buckets, 1);
        assert_eq!(window.buckets_below_minimum, 1);
        assert_eq!(window.minimum_success_share, Some(1.0));
        assert_eq!(window.maximum_server_error_share, Some(0.0));

        let unavailable = RequestConcentration::with_capabilities(true, false).summary();
        assert!(unavailable.response_outcomes.is_none());
        assert!(unavailable.response_outcome_windows.is_none());
    }

    #[test]
    fn old_concentration_json_without_response_fields_remains_readable() {
        let summary = RequestConcentration::new(true).summary();
        let mut value = serde_json::to_value(summary).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("response_outcomes");
        object.remove("response_outcome_windows");
        object.remove("response_status_codes");
        object.remove("source_segment_diversity");
        let decoded: RequestConcentrationSummary = serde_json::from_value(value).unwrap();
        assert!(decoded.response_outcomes.is_none());
        assert!(decoded.response_outcome_windows.is_none());
        assert!(decoded.response_status_codes.is_none());
        assert!(decoded.source_segment_diversity.is_none());
    }

    #[test]
    fn segment_medians_disclose_their_distinct_denominators() {
        let mut accumulator = RequestConcentration::new(true);
        for (ip, segments, status) in [
            ("198.51.100.1", 2, 404),
            ("198.51.100.2", 5, 404),
            ("198.51.100.3", 1, 200),
            ("198.51.100.4", 1, 200),
            ("198.51.100.5", 1, 200),
        ] {
            for segment in 0..segments {
                let mut e = event(
                    Some(&format!("/private-segment-{segment}/x")),
                    Some(ip),
                    None,
                );
                e.status = Some(status);
                accumulator.observe(&e);
            }
        }
        let summary = accumulator.summary();
        let stats = summary.source_segment_diversity.as_ref().unwrap();
        assert_eq!(stats.median_404_segments, Some(0.0));
        assert_eq!(stats.sources_with_404_segments, Some(2));
        assert_eq!(
            stats.median_404_segments_among_sources_with_404_segments,
            Some(3.5)
        );
        assert_eq!(stats.maximum_404_segments, Some(5));
        assert_eq!(stats.retained_sources, 5);
        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(!serialized.contains("198.51.100"));
        assert!(!serialized.contains("private-segment"));
        let mut legacy = serde_json::to_value(stats).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("sources_with_404_segments");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("median_404_segments_among_sources_with_404_segments");
        let legacy: SourceSegmentDiversitySummary = serde_json::from_value(legacy).unwrap();
        assert_eq!(legacy.median_404_segments, Some(0.0));
        assert_eq!(legacy.sources_with_404_segments, None);
    }

    #[test]
    fn empty_404_subset_and_missing_status_remain_distinct() {
        for status_available in [true, false] {
            let mut accumulator = RequestConcentration::with_capabilities(true, status_available);
            let mut e = event(Some("/private"), Some("198.51.100.1"), None);
            e.status = Some(200);
            accumulator.observe(&e);
            let stats = accumulator.summary().source_segment_diversity.unwrap();
            assert_eq!(stats.median_404_segments, status_available.then_some(0.0));
            assert_eq!(
                stats.sources_with_404_segments,
                status_available.then_some(0)
            );
            assert_eq!(
                stats.median_404_segments_among_sources_with_404_segments,
                None
            );
        }
    }

    #[test]
    fn first_segments_measure_breadth_without_normalizing_or_exposing_values() {
        let mut accumulator = RequestConcentration::new(true);
        for path in ["/images/a", "/images/b", "/images/c"] {
            let mut e = event(Some(path), Some("198.51.100.1"), Some(0));
            e.status = Some(404);
            accumulator.observe(&e);
        }
        for path in ["/", "/Images/a", "/images/a", "/%69mages/a"] {
            let mut e = event(Some(path), Some("198.51.100.2"), Some(0));
            e.status = Some(404);
            accumulator.observe(&e);
        }
        let private = accumulator.private_report();
        assert_eq!(
            private.source_ips[0]
                .path_segment_diversity
                .as_ref()
                .unwrap()
                .distinct_404_segments,
            Some(4)
        );
        assert_eq!(
            private.source_ips[1]
                .path_segment_diversity
                .as_ref()
                .unwrap()
                .distinct_404_segments,
            Some(1)
        );
        let stats = private.summary.source_segment_diversity.as_ref().unwrap();
        assert_eq!(stats.maximum_404_segments, Some(4));
        assert_eq!(stats.median_404_segments, Some(2.5));
        assert_eq!(private.summary.total_requests, 7);
        assert_eq!(
            private
                .summary
                .response_outcomes
                .as_ref()
                .unwrap()
                .counts
                .client_error,
            7
        );
        assert_eq!(
            private.summary.requests_per_minute.peak_requests_per_minute,
            Some(7)
        );
        let safe = serde_json::to_string(&private.summary).unwrap();
        for raw in ["198.51.100", "images", "Images", "%69mages"] {
            assert!(!safe.contains(raw));
        }
    }

    #[test]
    fn first_segment_caps_and_missing_capabilities_remain_explicit() {
        let mut accumulator = RequestConcentration::with_limits(
            true,
            ConcentrationLimits {
                max_source_segments: 1,
                ..ConcentrationLimits::default()
            },
        );
        for path in [Some("/"), Some("/a"), Some("/a"), None] {
            let mut e = event(path, Some("198.51.100.1"), None);
            e.status = Some(404);
            accumulator.observe(&e);
        }
        let summary = accumulator.summary().source_segment_diversity.unwrap();
        assert_eq!(summary.maximum_404_segments, Some(1));
        assert_eq!(summary.sources_beyond_cap, 1);
        assert_eq!(summary.sources_404_beyond_cap, Some(1));
        assert_eq!(summary.observations_404_beyond_cap, Some(2));
        assert_eq!(summary.observations_without_path, 1);
        let mut unavailable = RequestConcentration::with_capabilities(true, false);
        unavailable.observe(&event(Some("/"), Some("198.51.100.1"), None));
        let private = unavailable.private_report();
        assert_eq!(
            private.source_ips[0]
                .path_segment_diversity
                .as_ref()
                .unwrap()
                .distinct_segments,
            1
        );
        assert!(private.source_ips[0]
            .path_segment_diversity
            .as_ref()
            .unwrap()
            .distinct_404_segments
            .is_none());
        assert!(private
            .summary
            .source_segment_diversity
            .unwrap()
            .maximum_404_segments
            .is_none());
    }

    #[test]
    fn response_window_times_use_earliest_ties_and_disclose_threshold_counts() {
        let mut concentration = RequestConcentration::with_limits_and_rate_windows(
            true,
            ConcentrationLimits::default(),
            &[60],
        );
        concentration.set_response_bucket_minimum_requests(2);
        concentration
            .set_response_success_share_threshold_percent(50)
            .unwrap();
        // Deliberately unordered input: equal extrema must select the earliest UTC bucket.
        for (minute, statuses) in [
            (Some(3), [504, 504]),
            (Some(1), [502, 502]),
            (Some(2), [200, 499]),
            (Some(0), [200, 200]),
            (None, [504, 504]),
        ] {
            for status in statuses {
                let mut observation = event(Some("/private"), Some("198.51.100.1"), minute);
                observation.status = Some(status);
                concentration.observe(&observation);
            }
        }
        let window = &concentration.summary().response_outcome_windows.unwrap()[0];
        assert_eq!(
            window.minimum_success_bucket_start,
            Some(Utc.timestamp_opt(60, 0).unwrap())
        );
        assert_eq!(
            window.maximum_server_error_bucket_start,
            window.minimum_success_bucket_start
        );
        assert_eq!(window.minimum_success_share, Some(0.0));
        assert_eq!(window.maximum_server_error_share, Some(1.0));
        assert_eq!(window.buckets_below_success_threshold, 2); // 50% itself is not below 50%.
        assert_eq!(window.observations_without_timestamp, 2);
        concentration
            .set_response_success_share_threshold_percent(51)
            .unwrap();
        assert_eq!(
            concentration.summary().response_outcome_windows.unwrap()[0]
                .buckets_below_success_threshold,
            3
        );
        assert!(concentration
            .set_response_success_share_threshold_percent(101)
            .is_err());
    }

    #[test]
    fn individual_codes_sources_and_focus_prefixes_preserve_class_totals() {
        for selector in [
            FocusSelector::ExactPath("/private-status".to_owned()),
            FocusSelector::PathPrefix("/private-status".to_owned()),
            FocusSelector::SourceIp(BTreeSet::from([
                "198.51.100.1".to_owned(),
                "198.51.100.2".to_owned(),
            ])),
        ] {
            let mut concentration = RequestConcentration::new(true);
            concentration.focus_on(selector);
            for (ip, statuses) in [
                ("198.51.100.1", vec![499, 499]),
                ("198.51.100.2", vec![502, 504, 429, 401, 403, 200]),
            ] {
                for status in statuses {
                    let mut observation = event(Some("/private-status"), Some(ip), Some(0));
                    observation.status = Some(status);
                    concentration.observe(&observation);
                }
            }
            let summary = concentration.summary();
            let codes = &summary.response_status_codes.as_ref().unwrap().counts;
            for code in [502, 504, 429, 401, 403, 200] {
                assert_eq!(codes[&code], 1);
            }
            assert_eq!(codes[&499], 2);
            let classes = &summary.response_outcomes.as_ref().unwrap().counts;
            assert_eq!(classes.server_error, codes[&502] + codes[&504]);
            assert_eq!(classes.client_error, 5); // 499 remains part of the existing 4xx count.
            assert_eq!(classes.ordinary_client_error(), 3);
            let private = concentration.private_report();
            let json = serde_json::to_string(&private).unwrap();
            let decoded: PrivateRequestConcentrationReport = serde_json::from_str(&json).unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
            assert_eq!(private.paths[0].summary.requests, 8);
            assert_eq!(private.paths[0].summary.request_share, 1.0);
            assert_eq!(private.paths[0].summary.distinct_source_ips, 2);
            assert_eq!(private.paths[0].summary.response_bytes, Some(80));
            assert_eq!(
                private.paths[0]
                    .summary
                    .response_status_codes
                    .as_ref()
                    .unwrap()
                    .counts,
                *codes
            );
            let source = private
                .source_ips
                .iter()
                .find(|source| source.source_ip == "198.51.100.1")
                .unwrap();
            assert_eq!(
                source
                    .response_outcomes
                    .as_ref()
                    .unwrap()
                    .client_closed_request_499_share,
                1.0
            );
            assert_eq!(
                source
                    .response_outcomes
                    .as_ref()
                    .unwrap()
                    .server_error_share,
                0.0
            );
            let mut focus = private.focus.unwrap();
            assert_eq!(focus.response_status_codes.as_ref().unwrap().counts, *codes);
            assert!(focus.sources.iter().any(|source| source
                .response_status_codes
                .as_ref()
                .unwrap()
                .counts
                .contains_key(&504)));
            add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
            let group = &focus.network_prefix_groups[0];
            assert_eq!(group.response_status_codes.as_ref().unwrap().counts, *codes);
            assert_eq!(
                group
                    .response_outcomes
                    .as_ref()
                    .unwrap()
                    .client_closed_request_499_share,
                0.25
            );
            assert_eq!(
                group.response_outcomes.as_ref().unwrap().success_share,
                0.125
            );
            let sanitized = serde_json::to_string(&summary).unwrap();
            for private_value in ["/private-status", "198.51.100", "\"source_ip\":"] {
                assert!(!sanitized.contains(private_value));
            }
        }
    }

    #[test]
    fn status_code_caps_bound_each_entity_without_dropping_class_counts() {
        let mut concentration = RequestConcentration::with_limits(
            true,
            ConcentrationLimits {
                max_status_codes_per_entity: 1,
                ..ConcentrationLimits::default()
            },
        );
        concentration.focus_on(FocusSelector::PathPrefix("/private".to_owned()));
        for status in [Some(502), Some(504), Some(504), Some(502), None] {
            let mut observation = event(Some("/private/status"), Some("198.51.100.1"), Some(0));
            observation.status = status;
            concentration.observe(&observation);
        }
        let mut private = concentration.private_report();
        add_focus_prefix_groups(
            private.focus.as_mut().unwrap(),
            FocusPrefixLengths::default(),
        );
        let focus = private.focus.as_ref().unwrap();
        for codes in [
            &private.summary.response_status_codes,
            &private.paths[0].summary.response_status_codes,
            &private.source_ips[0].response_status_codes,
            &focus.response_status_codes,
            &focus.sources[0].response_status_codes,
            &focus.paths[0].response_status_codes,
            &focus.network_prefix_groups[0].response_status_codes,
        ] {
            let codes = codes.as_ref().unwrap();
            assert_eq!(codes.maximum_codes, 1);
            assert_eq!(codes.counts, BTreeMap::from([(502, 2)]));
            assert_eq!(codes.observations_beyond_cap, 2);
        }
        let classes = &private.summary.response_outcomes.as_ref().unwrap().counts;
        assert_eq!(classes.server_error, 4);
        assert_eq!(classes.unavailable, 1);
        assert_eq!(private.summary.total_requests, 5);
        // Additive fields are absent in older private artifacts.
        let mut old_source = serde_json::to_value(&private.source_ips[0]).unwrap();
        old_source
            .as_object_mut()
            .unwrap()
            .remove("response_status_codes");
        old_source
            .as_object_mut()
            .unwrap()
            .remove("response_outcomes");
        let source: PrivateSourceConcentration = serde_json::from_value(old_source).unwrap();
        assert!(source.response_status_codes.is_none());
        assert!(source.response_outcomes.is_none());
    }
}
