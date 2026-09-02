//! Deterministic request-volume distribution measurement for local WebEvent streams.
//!
//! These aggregates are triage context only. They do not determine a denial-of-service
//! attempt, attack, abuse, compromise, or attacker identity. Tracking is exact for
//! retained keys and deliberately stops admitting new keys at fixed caps; every such
//! omission is reported as a count rather than approximated.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::WebEvent;

pub const DEFAULT_MAX_TRACKED_PATHS: usize = 100_000;
pub const DEFAULT_MAX_TRACKED_SOURCE_IPS: usize = 1_000_000;
/// A separate cap keeps source-to-path detail bounded even when both top-level
/// key spaces are within their respective limits.
pub const DEFAULT_MAX_TRACKED_SOURCE_PATH_PAIRS: usize = 2_000_000;

#[derive(Debug, Clone, Copy)]
pub struct ConcentrationLimits {
    pub max_paths: usize,
    pub max_source_ips: usize,
    pub max_source_path_pairs: usize,
}

impl Default for ConcentrationLimits {
    fn default() -> Self {
        Self {
            max_paths: DEFAULT_MAX_TRACKED_PATHS,
            max_source_ips: DEFAULT_MAX_TRACKED_SOURCE_IPS,
            max_source_path_pairs: DEFAULT_MAX_TRACKED_SOURCE_PATH_PAIRS,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateRequestConcentrationReport {
    pub report_kind: String,
    pub safety_note: String,
    pub summary: RequestConcentrationSummary,
    pub paths: Vec<PrivatePathConcentration>,
    pub source_ips: Vec<PrivateSourceConcentration>,
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
    requests_without_uri_path: u64,
    requests_without_source_ip: u64,
    paths_beyond_tracking_cap: u64,
    source_ips_beyond_tracking_cap: u64,
    source_path_pairs_beyond_tracking_cap: u64,
    observations_without_timestamp: u64,
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
            requests_without_uri_path: 0,
            requests_without_source_ip: 0,
            paths_beyond_tracking_cap: 0,
            source_ips_beyond_tracking_cap: 0,
            source_path_pairs_beyond_tracking_cap: 0,
            observations_without_timestamp: 0,
        }
    }

    pub fn observe(&mut self, event: &WebEvent) {
        self.total_requests += 1;
        self.observe_minute(event.timestamp);

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
        }
    }

    fn observe_minute(&mut self, timestamp: Option<DateTime<Utc>>) {
        let Some(timestamp) = timestamp else {
            self.observations_without_timestamp += 1;
            return;
        };
        *self
            .minute_buckets
            .entry(timestamp.timestamp().div_euclid(60))
            .or_default() += 1;
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
        if self.minute_buckets.is_empty() {
            return (None, None, None);
        }
        let mut values = self.minute_buckets.values().copied().collect::<Vec<_>>();
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
                max_source_path_pairs: 1,
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
                max_source_path_pairs: 1,
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
}
