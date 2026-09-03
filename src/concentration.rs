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

use crate::event::WebEvent;

pub const DEFAULT_MAX_TRACKED_PATHS: usize = 100_000;
pub const DEFAULT_MAX_TRACKED_SOURCE_IPS: usize = 1_000_000;
/// Separate bounded tracking for the explicitly selected path focus. This is
/// intentionally independent of the top-level source-IP map so a focus remains
/// useful even if the general distribution reaches its own admission cap.
pub const DEFAULT_MAX_FOCUS_SOURCE_IPS: usize = 1_000_000;
/// Separate bounded tracking for the distinct URI paths retained inside a focus
/// (the sub-paths under a path prefix, or the paths one source IP requested).
pub const DEFAULT_MAX_FOCUS_PATHS: usize = 1_000_000;
/// Roughly 1.9 years of one-minute buckets. Both global and focus timelines
/// stop admitting new minutes at this fixed cap and disclose omitted records.
pub const DEFAULT_MAX_MINUTE_BUCKETS: usize = 1_000_000;

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
    pub max_paths: usize,
    pub max_source_ips: usize,
    pub max_focus_source_ips: usize,
    pub max_focus_paths: usize,
    pub max_source_path_pairs: usize,
    pub max_minute_buckets: usize,
}

impl Default for ConcentrationLimits {
    fn default() -> Self {
        Self {
            max_paths: DEFAULT_MAX_TRACKED_PATHS,
            max_source_ips: DEFAULT_MAX_TRACKED_SOURCE_IPS,
            max_focus_source_ips: DEFAULT_MAX_FOCUS_SOURCE_IPS,
            max_focus_paths: DEFAULT_MAX_FOCUS_PATHS,
            max_source_path_pairs: DEFAULT_MAX_TRACKED_SOURCE_PATH_PAIRS,
            max_minute_buckets: DEFAULT_MAX_MINUTE_BUCKETS,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StatusClassCounts {
    pub informational: u64,
    pub success: u64,
    pub redirection: u64,
    pub client_error: u64,
    pub server_error: u64,
    pub other: u64,
    pub unavailable: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathConcentrationSummary {
    pub requests: u64,
    pub request_share: f64,
    /// Exact unless source-IP tracking reached its disclosed cap.
    pub distinct_source_ips: usize,
    pub response_status_classes: StatusClassCounts,
    /// `None` when the selected telemetry profile does not expose response bytes.
    pub response_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestRateSummary {
    pub peak_requests_per_minute: Option<u64>,
    pub median_requests_per_minute: Option<f64>,
    pub peak_to_median_ratio: Option<f64>,
    pub observations_without_timestamp: u64,
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
    pub source_ips_beyond_cap: u64,
    /// Distinct URI paths inside the focus (sub-paths of a prefix, or the union
    /// requested by selected source IPs). Zero for an exact-path focus.
    #[serde(default)]
    pub distinct_uri_paths: usize,
    #[serde(default)]
    pub paths_beyond_cap: u64,
    pub peak_requests_per_minute: Option<u64>,
    pub median_requests_per_minute: Option<f64>,
}

fn exact_path_kind() -> String {
    "exact-path".to_owned()
}

/// Aggregate-only output safe to include in a sanitized artifact. It contains
/// no URI paths, IP addresses, hosts, headers, or other raw request values.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestConcentrationSummary {
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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateSourceConcentration {
    pub source_ip: String,
    pub requests: u64,
    /// The exact most-requested retained path for this IP. It is unavailable
    /// when any of the IP's source/path pairs exceeded the pair cap.
    pub most_requested_uri_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrivateFocusSource {
    pub source_ip: String,
    pub requests: u64,
}

/// One retained URI path inside a focus, with its request count. For a
/// path-prefix focus these are the sub-paths; for a source-IP focus these are
/// the paths the selected peers requested. Private: the path is a raw request
/// value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrivateFocusPath {
    pub uri_path: String,
    pub requests: u64,
}

/// A private address-block aggregation of retained focus-path peers. A common
/// prefix is not evidence of a common owner, operator, or actor.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateFocusPrefixGroup {
    pub network_prefix: String,
    pub requests: u64,
    pub request_share: f64,
    pub distinct_source_ips: usize,
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
    /// Private minute-resolution series, ordered by epoch minute.
    #[serde(default)]
    pub requests_per_minute_series: Vec<MinuteRequestCount>,
    /// Focus-path records in new minute buckets omitted after the fixed cap.
    #[serde(default)]
    pub minute_buckets_beyond_cap: u64,
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
    response_bytes: u64,
}

#[derive(Debug, Default)]
struct SourceAccumulator {
    requests: u64,
}

/// A one-pass bounded accumulator. Key admission follows first observation in
/// input order; rendered reports are sorted independently for deterministic output.
#[derive(Debug)]
pub struct RequestConcentration {
    limits: ConcentrationLimits,
    response_bytes_available: bool,
    total_requests: u64,
    paths: BTreeMap<String, PathAccumulator>,
    source_ips: BTreeMap<String, SourceAccumulator>,
    source_path_pairs: BTreeMap<(String, String), u64>,
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
    focus: Option<FocusSelector>,
    focus_total: u64,
    focus_sources: BTreeMap<String, u64>,
    focus_paths: BTreeMap<String, u64>,
    focus_minute_buckets: BTreeMap<i64, u64>,
    focus_minute_buckets_beyond_cap: u64,
    focus_status_classes: StatusClassCounts,
    focus_source_ips_beyond_cap: u64,
    focus_paths_beyond_cap: u64,
}

impl RequestConcentration {
    pub fn new(response_bytes_available: bool) -> Self {
        Self::with_limits(response_bytes_available, ConcentrationLimits::default())
    }

    pub fn with_limits(response_bytes_available: bool, limits: ConcentrationLimits) -> Self {
        Self {
            limits,
            response_bytes_available,
            total_requests: 0,
            paths: BTreeMap::new(),
            source_ips: BTreeMap::new(),
            source_path_pairs: BTreeMap::new(),
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
            focus: None,
            focus_total: 0,
            focus_sources: BTreeMap::new(),
            focus_paths: BTreeMap::new(),
            focus_minute_buckets: BTreeMap::new(),
            focus_minute_buckets_beyond_cap: 0,
            focus_status_classes: StatusClassCounts::default(),
            focus_source_ips_beyond_cap: 0,
            focus_paths_beyond_cap: 0,
        }
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
        self.observe_minute(event.timestamp, event.status);

        let path = event.uri_path.as_deref();
        let source_ip = event.source_ip.as_deref();
        let path_tracked = path.is_some_and(|path| self.track_path(path, event));
        let source_tracked = source_ip.is_some_and(|source_ip| self.track_source_ip(source_ip));

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
            focus: self.sanitized_focus_summary(),
        }
    }

    pub fn private_report(&self) -> PrivateRequestConcentrationReport {
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
                })
                .collect(),
            source_ips: self
                .sorted_sources()
                .into_iter()
                .map(|(source_ip, item)| PrivateSourceConcentration {
                    source_ip: source_ip.clone(),
                    requests: item.requests,
                    most_requested_uri_path: self.most_requested_path(source_ip),
                })
                .collect(),
            focus: self.private_focus_summary(),
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
        }
        record_status_class(&mut self.focus_status_classes, event.status);
        if let Some(source_ip) = source_ip {
            if self.focus_sources.contains_key(source_ip)
                || self.focus_sources.len() < self.limits.max_focus_source_ips
            {
                *self.focus_sources.entry(source_ip.to_owned()).or_default() += 1;
            } else {
                self.focus_source_ips_beyond_cap += 1;
            }
        }
        if let (true, Some(path)) = (track_paths, path) {
            if self.focus_paths.contains_key(path)
                || self.focus_paths.len() < self.limits.max_focus_paths
            {
                *self.focus_paths.entry(path.to_owned()).or_default() += 1;
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
                source_ips_beyond_cap: self.focus_source_ips_beyond_cap,
                distinct_uri_paths: self.focus_paths.len(),
                paths_beyond_cap: self.focus_paths_beyond_cap,
                peak_requests_per_minute: peak,
                median_requests_per_minute: median,
            }
        })
    }

    fn private_focus_summary(&self) -> Option<PrivateFocusSummary> {
        self.focus.as_ref().map(|selector| {
            let (peak, median, _) = Self::request_rate_for(&self.focus_minute_buckets);
            let selector_display = selector.selector_display();
            let mut sources = self
                .focus_sources
                .iter()
                .map(|(source_ip, requests)| PrivateFocusSource {
                    source_ip: source_ip.clone(),
                    requests: *requests,
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
                .map(|(uri_path, requests)| PrivateFocusPath {
                    uri_path: uri_path.clone(),
                    requests: *requests,
                })
                .collect::<Vec<_>>();
            paths.sort_by(|left, right| {
                right
                    .requests
                    .cmp(&left.requests)
                    .then_with(|| left.uri_path.cmp(&right.uri_path))
            });
            PrivateFocusSummary {
                focus_kind: selector.kind().to_owned(),
                selector: selector_display.clone(),
                uri_path: selector_display,
                total_requests: self.focus_total,
                distinct_source_ips: self.focus_sources.len(),
                source_ips_beyond_cap: self.focus_source_ips_beyond_cap,
                paths,
                paths_beyond_cap: self.focus_paths_beyond_cap,
                peak_requests_per_minute: peak,
                median_requests_per_minute: median,
                response_status_classes: self.focus_status_classes.clone(),
                sources,
                network_prefix_groups: Vec::new(),
                requests_per_minute_series: Self::minute_series(&self.focus_minute_buckets),
                minute_buckets_beyond_cap: self.focus_minute_buckets_beyond_cap,
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
    }

    fn track_path(&mut self, path: &str, event: &WebEvent) -> bool {
        if !self.paths.contains_key(path) && self.paths.len() >= self.limits.max_paths {
            self.paths_beyond_tracking_cap += 1;
            return false;
        }
        let item = self.paths.entry(path.to_owned()).or_default();
        item.requests += 1;
        if let Some(source_ip) = &event.source_ip {
            if self.source_ips.contains_key(source_ip)
                || self.source_ips.len() < self.limits.max_source_ips
            {
                item.source_ips.insert(source_ip.clone());
            }
        }
        record_status_class(&mut item.status_classes, event.status);
        if self.response_bytes_available {
            item.response_bytes += event.response_bytes.unwrap_or(0);
        }
        true
    }

    fn track_source_ip(&mut self, source_ip: &str) -> bool {
        if !self.source_ips.contains_key(source_ip)
            && self.source_ips.len() >= self.limits.max_source_ips
        {
            self.source_ips_beyond_tracking_cap += 1;
            return false;
        }
        self.source_ips
            .entry(source_ip.to_owned())
            .or_default()
            .requests += 1;
        true
    }

    fn track_source_path_pair(&mut self, source_ip: &str, path: &str) {
        let key = (source_ip.to_owned(), path.to_owned());
        if !self.source_path_pairs.contains_key(&key)
            && self.source_path_pairs.len() >= self.limits.max_source_path_pairs
        {
            self.source_path_pairs_beyond_tracking_cap += 1;
            self.source_ips_with_incomplete_path_pairs
                .insert(source_ip.to_owned());
            return;
        }
        *self.source_path_pairs.entry(key).or_default() += 1;
    }

    fn path_summary(&self, item: &PathAccumulator) -> PathConcentrationSummary {
        PathConcentrationSummary {
            requests: item.requests,
            request_share: self.share(item.requests),
            distinct_source_ips: item.source_ips.len(),
            response_status_classes: item.status_classes.clone(),
            response_bytes: self.response_bytes_available.then_some(item.response_bytes),
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
        let start = (source_ip.to_owned(), String::new());
        self.source_path_pairs
            .range(start..)
            .take_while(|((candidate, _), _)| candidate == source_ip)
            .max_by(|((_, left_path), left), ((_, right_path), right)| {
                left.cmp(right).then_with(|| right_path.cmp(left_path))
            })
            .map(|((_, path), _)| path.clone())
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

    fn share(&self, count: u64) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            count as f64 / self.total_requests as f64
        }
    }
}

/// Add deterministic network-prefix aggregations to an already-built private
/// focus summary. This deliberately derives only from the retained private
/// source list, so it adds no streaming state and cannot recover peers omitted
/// by the disclosed focus source-IP cap.
pub fn add_focus_prefix_groups(focus: &mut PrivateFocusSummary, prefixes: FocusPrefixLengths) {
    let mut groups = BTreeMap::<String, (u64, BTreeSet<String>)>::new();
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
        let (requests, source_ips) = groups.entry(key).or_default();
        *requests += source.requests;
        source_ips.insert(source.source_ip.clone());
    }
    let mut prefix_groups = groups
        .into_iter()
        .map(
            |(network_prefix, (requests, source_ips))| PrivateFocusPrefixGroup {
                network_prefix,
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
    prefix_groups.sort_by(|left, right| {
        right
            .requests
            .cmp(&left.requests)
            .then_with(|| left.network_prefix.cmp(&right.network_prefix))
    });
    focus.network_prefix_groups = prefix_groups;
}

fn record_status_class(counts: &mut StatusClassCounts, status: Option<u16>) {
    match status {
        Some(100..=199) => counts.informational += 1,
        Some(200..=299) => counts.success += 1,
        Some(300..=399) => counts.redirection += 1,
        Some(400..=499) => counts.client_error += 1,
        Some(500..=599) => counts.server_error += 1,
        Some(_) => counts.other += 1,
        None => counts.unavailable += 1,
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::event::{LogSource, WebEvent};

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
            waf_action: None,
            waf_rule_id: None,
            waf_rule_type: None,
            waf_labels: Vec::new(),
            waf_non_terminating_rule_ids: Vec::new(),
            log_source: LogSource::ApacheCombined,
            raw: String::new(),
        }
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
        assert_eq!(top.request_share, 0.5);
        assert!(concentration
            .private_report()
            .source_ips
            .iter()
            .all(|source| source.requests * 100 < 400));
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
            },
        );
        concentration.observe(&event(Some("/first"), Some("198.51.100.1"), Some(0)));
        concentration.observe(&event(Some("/second"), Some("198.51.100.1"), Some(0)));
        assert_eq!(concentration.most_requested_path("198.51.100.1"), None);
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
                .filter(|((candidate, _), _)| candidate == source)
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
}
