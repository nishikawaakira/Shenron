use crate::waf_summary::{PrivateJa4Sources, PrivateWafSummary, WafActionCounts, WafSummary};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

/// A separate cap keeps source-to-path detail bounded even when both top-level
/// key spaces are within their respective limits.
pub const DEFAULT_MAX_TRACKED_SOURCE_PATH_PAIRS: usize = 2_000_000;

pub const DEFAULT_MAX_PATHS_PER_SOURCE_PREFIX: usize = 5_000;

pub const DEFAULT_MAX_SOURCE_PREFIX_PATH_PAIRS: usize = 10_000_000;

/// Independent of legacy path tracking; at most one name per admitted pair.
pub const DEFAULT_MAX_SOURCE_PREFIX_PATHS: usize = 10_000_000;

#[derive(Debug, Clone, Copy)]
pub struct ConcentrationLimits {
    pub max_paths_per_source_prefix: usize,
    pub max_source_prefix_path_pairs: usize,
    pub max_source_prefix_paths: usize,
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
    pub max_waf_values_per_entity: usize,
    pub max_waf_values: usize,
    pub max_ja4_source_associations: usize,
}

impl Default for ConcentrationLimits {
    fn default() -> Self {
        Self {
            max_paths_per_source_prefix: DEFAULT_MAX_PATHS_PER_SOURCE_PREFIX,
            max_source_prefix_path_pairs: DEFAULT_MAX_SOURCE_PREFIX_PATH_PAIRS,
            max_source_prefix_paths: DEFAULT_MAX_SOURCE_PREFIX_PATHS,
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
            max_waf_values_per_entity: 256,
            max_waf_values: 100_000,
            max_ja4_source_associations: 2_000_000,
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
    pub(super) fn merge(&mut self, other: &Self) {
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

    pub fn total_observations(&self) -> u64 {
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
    /// None means no measurable eligible buckets. Old numeric counts still deserialize.
    #[serde(default)]
    pub buckets_below_success_threshold: Option<usize>,
    /// Excluded before the minimum-request check; counts are not double counted.
    #[serde(default)]
    pub buckets_without_status: usize,
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
    pub(super) fn record(&mut self, status: Option<u16>, maximum: usize) {
        self.maximum_codes = maximum;
        if let Some(status) = status {
            self.add(status, 1);
        }
    }

    pub(super) fn add(&mut self, status: u16, count: u64) {
        if let Some(current) = self.counts.get_mut(&status) {
            *current += count;
        } else if self.counts.len() < self.maximum_codes {
            self.counts.insert(status, count);
        } else {
            self.observations_beyond_cap += count;
        }
    }

    pub(super) fn merge(&mut self, other: &Self) {
        self.observations_beyond_cap += other.observations_beyond_cap;
        for (&code, &count) in &other.counts {
            self.add(code, count);
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathConcentrationSummary {
    #[serde(default)]
    pub waf_actions: Option<WafActionCounts>,
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
    pub waf: Option<WafSummary>,
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
    pub waf: Option<PrivateWafSummary>,
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
    /// Opt-in sum of recorded response bytes, like the path sum. Absent when
    /// disabled or no byte value is available; a recorded zero remains zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    /// Opt-in disclosure of observations missing bytes (including unsupported
    /// telemetry). Partial byte sums are not estimates of missing values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_bytes_unavailable: Option<u64>,
}

pub const SOURCE_PREFIX_NOTE: &str = "Grouping observed peers by address prefix is an arithmetic aggregation, not a claim of shared operator, ownership, or coordination. Carrier-grade NAT and mobile ranges place unrelated visitors in one prefix; a high prefix total can be many ordinary visitors. The per-source maximum is reported alongside the total for that reason.";

pub const SOURCE_PREFIX_ASN_NOTE: &str = "A resolved ASN is a registry attribute of the address range, not a statement about who sent the requests. Consumer ISP, hosting, CDN and cloud ranges all appear here; separating them is an operator judgement that depends on country and period, and Shenron does not make it.";

pub const SOURCE_PREFIX_PATH_NOTE: &str = "Distinct and once-requested path counts describe how a prefix moved through the site, not why. Search and social crawlers visit many paths once; ordinary visitors behind one carrier address revisit popular pages. Neither count, alone or together, identifies automation, scraping or an attack.";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourcePrefixAsn {
    pub asn: u32,
    pub organization: String,
    pub distinct_source_ips: usize,
    pub requests: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateSourcePrefix {
    pub prefix: String,
    pub requests: u64,
    pub response_bytes: Option<u64>,
    pub response_bytes_unavailable: u64,
    pub distinct_source_ips: usize,
    pub max_requests_per_source_ip: u64,
    /// None when path tracking is incomplete; ties use lexical path order.
    pub most_requested_uri_path: Option<String>,
    pub path_observations_unavailable: u64,
    pub response_status_classes: StatusClassCounts,
    /// Routing-level attributes of observed addresses, not evidence that one
    /// operator controls the traffic. Absent without a local ASN resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asns: Option<Vec<SourcePrefixAsn>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_source_ips: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_requests: Option<u64>,
    /// Exact over retained peers unless a prefix/path tracking cap omitted requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct_uri_paths: Option<u64>,
    /// Unavailable after a per-prefix, global pair, or shared path-table rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_paths_requested_once: Option<u64>,
    /// Requests rejected by the per-prefix cap (global omissions are separate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_paths_beyond_prefix_cap: Option<u64>,
    /// Requests rejected by the global prefix/path pair cap for this prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_paths_beyond_global_cap: Option<u64>,
    /// Requests rejected by the shared path-name table, separate from pair caps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_paths_beyond_path_table_cap: Option<u64>,
}

/// Counts/configuration only. These diagnostics never enter sanitized artifacts.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SourcePrefixPathTracking {
    pub prefix_path_pairs_retained: usize,
    pub maximum_prefix_path_pairs: usize,
    pub prefixes_beyond_prefix_path_pair_cap: usize,
    pub prefix_paths_retained: usize,
    pub maximum_prefix_paths: usize,
    pub requests_beyond_prefix_path_table_cap: u64,
    pub prefixes_beyond_prefix_path_table_cap: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourcePrefixAggregation {
    pub safety_note: String,
    pub ipv4_prefix_bits: u8,
    pub ipv6_prefix_bits: u8,
    /// Groups derive from retained sources, so cannot exceed this source cap.
    pub maximum_prefixes: usize,
    pub requests_without_source_ip: u64,
    pub requests_with_invalid_source_ip: u64,
    pub requests_beyond_source_tracking_cap: u64,
    /// Path-count omissions only: these requests remain in group request totals
    /// and must not be added to the three request-volume omission counts above.
    #[serde(default)]
    pub requests_beyond_prefix_path_pair_cap: u64,
    #[serde(flatten)]
    pub path_tracking: SourcePrefixPathTracking,
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
    #[serde(default)]
    pub waf: Option<PrivateWafSummary>,
    #[serde(default)]
    pub ja4_sources: Option<Vec<PrivateJa4Sources>>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_prefixes: Option<Vec<PrivateSourcePrefix>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_prefix_aggregation: Option<SourcePrefixAggregation>,
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
    /// Distinct first segments for 400..=498 responses; 499 is excluded.
    #[serde(default)]
    pub distinct_4xx_segments: Option<usize>,
    #[serde(default)]
    pub observations_4xx_beyond_cap: Option<u64>,
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
    /// Corpus-wide 400..=498 responses, including requests without retained sources or paths.
    #[serde(default)]
    pub corpus_4xx_requests: Option<u64>,
    /// Unavailable when status is not exposed or no corpus client-error responses exist.
    #[serde(default)]
    pub maximum_4xx_segments: Option<usize>,
    #[serde(default)]
    pub median_4xx_segments: Option<f64>,
    #[serde(default)]
    pub sources_with_4xx_segments: Option<usize>,
    #[serde(default)]
    pub median_4xx_segments_among_sources_with_4xx_segments: Option<f64>,
    #[serde(default)]
    pub sources_4xx_beyond_cap: Option<usize>,
    #[serde(default)]
    pub observations_4xx_beyond_cap: Option<u64>,
}
