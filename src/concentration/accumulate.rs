use super::{focus::*, rates::*, types::*};
use crate::waf_summary::{Ja4SourceAccumulator, WafActionCounts, WafEntityAccumulator};
use crate::{event::WebEvent, triage::AsnResolver};
use ipnet::IpNet;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[derive(Debug, Default)]
pub(super) struct PrefixPathAccumulator {
    pub(super) paths: BTreeMap<usize, u64>,
    beyond_prefix_cap: u64,
    beyond_global_cap: u64,
    beyond_path_table_cap: u64,
}

#[derive(Debug, Default)]
struct PathAccumulator {
    waf_actions: WafActionCounts,
    requests: u64,
    source_ips: BTreeSet<String>,
    status_classes: StatusClassCounts,
    status_codes: StatusCodeCounts,
    response_bytes: u64,
    query_shape: QueryShapeAccumulator,
}

#[derive(Debug, Default)]
pub(super) struct SourceAccumulator {
    pub(super) prefix: Option<IpNet>,
    pub(super) response_bytes: u64,
    pub(super) response_bytes_observations: u64,
    pub(super) waf: Option<Box<WafEntityAccumulator>>,
    pub(super) segments: BTreeSet<String>,
    pub(super) segments_404: BTreeSet<String>,
    pub(super) segments_4xx: BTreeSet<String>,
    pub(super) segments_beyond_cap: u64,
    pub(super) segments_404_beyond_cap: u64,
    pub(super) segments_4xx_beyond_cap: u64,
    pub(super) paths_unavailable: u64,
    pub(super) requests: u64,
    pub(super) status_classes: StatusClassCounts,
    pub(super) status_codes: StatusCodeCounts,
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
        if matches!(status, Some(400..=498)) {
            retain(
                &mut self.segments_4xx,
                &mut self.segments_4xx_beyond_cap,
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
            distinct_4xx_segments: status_available.then_some(self.segments_4xx.len()),
            observations_4xx_beyond_cap: status_available.then_some(self.segments_4xx_beyond_cap),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct QueryShapeAccumulator {
    pub(super) requests_with_query: u64,
    pub(super) query_strings: BTreeSet<String>,
    pub(super) query_strings_beyond_tracking_cap: u64,
    pub(super) query_keys: BTreeSet<String>,
    pub(super) query_keys_beyond_tracking_cap: u64,
}

/// A one-pass bounded accumulator. Key admission follows first observation in
/// input order; rendered reports are sorted independently for deterministic output.
#[derive(Debug)]
pub struct RequestConcentration {
    source_prefix_lengths: Option<FocusPrefixLengths>,
    waf_capabilities: Option<crate::event::TelemetryCapabilities>,
    waf: WafEntityAccumulator,
    ja4_sources: Ja4SourceAccumulator,
    pub(super) limits: ConcentrationLimits,
    response_bytes_available: bool,
    pub(super) status_available: bool,
    pub(super) response_bucket_minimum_requests: u64,
    pub(super) response_success_share_threshold_percent: u8,
    pub(super) total_requests: u64,
    status_classes: StatusClassCounts,
    status_codes: StatusCodeCounts,
    paths: BTreeMap<String, PathAccumulator>,
    pub(super) source_ips: BTreeMap<String, SourceAccumulator>,
    pub(super) source_path_pairs: BTreeMap<String, BTreeMap<String, u64>>,
    pub(super) source_path_pair_count: usize,
    pub(super) prefix_paths: BTreeMap<IpNet, PrefixPathAccumulator>,
    // Names are owned once, only when a pair is admitted. IDs follow input
    // admission order and are never serialized or used to order report rows.
    pub(super) prefix_path_names: BTreeMap<String, usize>,
    pub(super) prefix_path_pair_count: usize,
    prefix_path_pairs_beyond_cap: u64,
    source_ips_with_incomplete_path_pairs: BTreeSet<String>,
    pub(super) minute_buckets: BTreeMap<i64, u64>,
    pub(super) status_minute_buckets: BTreeMap<i64, StatusClassCounts>,
    pub(super) minute_buckets_beyond_cap: u64,
    requests_without_uri_path: u64,
    requests_without_source_ip: u64,
    paths_beyond_tracking_cap: u64,
    source_ips_beyond_tracking_cap: u64,
    source_path_pairs_beyond_tracking_cap: u64,
    pub(super) observations_without_timestamp: u64,
    pub(super) rate_window_seconds: Vec<u64>,
    pub(super) rate_buckets: BTreeMap<u64, BTreeMap<i64, u64>>,
    pub(super) rate_buckets_beyond_cap: BTreeMap<u64, u64>,
    pub(super) status_rate_buckets: BTreeMap<u64, BTreeMap<i64, StatusClassCounts>>,
    pub(super) focus: Option<FocusSelector>,
    /// Matching-only cache; raw selector spelling and retained source keys stay intact.
    pub(super) focus_source_addresses: Option<BTreeSet<IpAddr>>,
    pub(super) focus_total: u64,
    pub(super) focus_sources: BTreeMap<String, SourceAccumulator>,
    pub(super) focus_paths: BTreeMap<String, SourceAccumulator>,
    pub(super) focus_minute_buckets: BTreeMap<i64, u64>,
    pub(super) focus_minute_buckets_beyond_cap: u64,
    pub(super) focus_observations_without_timestamp: u64,
    pub(super) focus_rate_buckets: BTreeMap<u64, BTreeMap<i64, u64>>,
    pub(super) focus_rate_buckets_beyond_cap: BTreeMap<u64, u64>,
    pub(super) focus_status_classes: StatusClassCounts,
    pub(super) focus_status_codes: StatusCodeCounts,
    pub(super) focus_source_ips_beyond_cap: u64,
    pub(super) focus_paths_beyond_cap: u64,
    pub(super) focus_query_shape: QueryShapeAccumulator,
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
            waf_capabilities: None,
            waf: WafEntityAccumulator::default(),
            ja4_sources: Ja4SourceAccumulator::default(),
            source_prefix_lengths: None,
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
            prefix_paths: BTreeMap::new(),
            prefix_path_names: BTreeMap::new(),
            prefix_path_pair_count: 0,
            prefix_path_pairs_beyond_cap: 0,
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
            focus_source_addresses: None,
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
        self.focus_source_addresses = match &selector {
            FocusSelector::SourceIp(values) => Some(
                values
                    .iter()
                    .filter_map(|value| value.parse::<IpAddr>().ok())
                    .map(|address| address.to_canonical())
                    .collect(),
            ),
            FocusSelector::ExactPath(_) | FocusSelector::PathPrefix(_) => None,
        };
        self.focus = Some(selector);
    }

    /// Convenience for an exact-path focus.
    pub fn focus_on_path(&mut self, path: impl Into<String>) {
        self.focus_on(FocusSelector::ExactPath(path.into()));
    }

    /// Enable private corpus-wide prefix detail before observing any events.
    /// Prefix/path tracking is separately bounded, and defaults stay off.
    pub fn enable_source_prefixes(
        &mut self,
        prefixes: FocusPrefixLengths,
    ) -> Result<(), &'static str> {
        if prefixes.ipv4 > 32 || prefixes.ipv6 > 128 {
            return Err("source prefix lengths must be 0..=32 for IPv4 and 0..=128 for IPv6");
        }
        if self.total_requests != 0 {
            return Err("source prefix aggregation must be configured before observing requests");
        }
        self.source_prefix_lengths = Some(prefixes);
        Ok(())
    }

    /// Configure before observing. Standard combined logs do not allocate
    /// per-source WAF maps or imply absent fields were observed as zero.
    pub fn configure_waf(&mut self, caps: crate::event::TelemetryCapabilities) {
        self.waf.set_maximum(self.limits.max_waf_values);
        self.waf_capabilities =
            (caps.ja3 || caps.ja4 || caps.country || caps.waf_action || caps.waf_labels)
                .then_some(caps);
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
        if let (Some(_), Some(source), Some(path)) = (
            self.source_prefix_lengths,
            source_ip.filter(|_| source_tracked),
            path,
        ) {
            let prefix = self.source_ips.get(source).and_then(|item| item.prefix);
            self.track_prefix_path(prefix, path);
        }
        if self.source_prefix_lengths.is_some() && self.response_bytes_available {
            if let (Some(source), Some(bytes)) =
                (source_ip.filter(|_| source_tracked), event.response_bytes)
            {
                let item = self.source_ips.get_mut(source).expect("retained source");
                item.response_bytes += bytes;
                item.response_bytes_observations += 1;
            }
        }

        if let Some(caps) = self.waf_capabilities {
            self.waf.observe(event, caps, self.limits.max_waf_values);
            if caps.ja4 {
                self.ja4_sources.observe(
                    event,
                    self.limits.max_waf_values,
                    self.limits.max_ja4_source_associations,
                );
            }
            if let Some(source) = source_ip.filter(|_| source_tracked) {
                self.source_ips
                    .get_mut(source)
                    .expect("retained source")
                    .waf
                    .get_or_insert_with(Default::default)
                    .observe(event, caps, self.limits.max_waf_values_per_entity);
            }
            if caps.waf_action {
                if let Some(path) = path.filter(|_| path_tracked) {
                    self.paths
                        .get_mut(path)
                        .expect("retained path")
                        .waf_actions
                        .record(event.waf_action.as_deref());
                }
            }
        }

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
            waf: self.waf_capabilities.map(|caps| {
                let mut summary = self.waf.summary(caps);
                summary.ja4_sources = caps.ja4.then(|| self.ja4_sources.summary());
                summary
            }),
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
        self.private_report_with_query_keys_and_source_asns(include_query_keys, None)
    }

    /// Enrich only opt-in corpus-wide prefix groups using an existing local
    /// resolver. Per-source rows and sanitized summaries remain unchanged.
    pub fn private_report_with_query_keys_and_source_asns(
        &self,
        include_query_keys: bool,
        resolver: Option<&dyn AsnResolver>,
    ) -> PrivateRequestConcentrationReport {
        let prefix_detail = self
            .source_prefix_lengths
            .map(|prefixes| self.source_prefix_report(prefixes, resolver));
        let (source_prefixes, source_prefix_aggregation) = match prefix_detail {
            Some((groups, disclosure)) => (Some(groups), Some(disclosure)),
            None => (None, None),
        };
        PrivateRequestConcentrationReport {
            waf: self.waf_capabilities.map(|caps| self.waf.private(caps)),
            ja4_sources: self.waf_capabilities.filter(|caps| caps.ja4).map(|_| self.ja4_sources.private()),
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
                    waf: self.waf_capabilities.map(|caps| item.waf.as_deref().map(|waf| waf.private(caps)).unwrap_or_default()),
                    path_segment_diversity: Some(item.segment_summary(self.status_available, self.limits.max_source_segments)),
                    source_ip: source_ip.clone(),
                    requests: item.requests,
                    most_requested_uri_path: self.most_requested_path(source_ip),
                    response_status_classes: item.status_classes.clone(),
                    response_status_codes: self.status_available.then(|| item.status_codes.clone()),
                    response_outcomes: self.status_available.then(|| response_outcome_summary(&item.status_classes)),
                    response_bytes: self.source_prefix_lengths.and_then(|_| (item.response_bytes_observations > 0).then_some(item.response_bytes)),
                    response_bytes_unavailable: self.source_prefix_lengths.map(|_| item.requests - item.response_bytes_observations),
                })
                .collect(),
            focus: self.private_focus_summary(include_query_keys),
            requests_per_minute_series: Self::minute_series(&self.minute_buckets),
            status_class_requests_per_minute_series: Self::status_minute_series(
                &self.status_minute_buckets,
            ),
            minute_buckets_beyond_cap: self.minute_buckets_beyond_cap,
            source_prefixes,
            source_prefix_aggregation,
        }
    }

    /// Count paths from retained valid peers in input order, independently of
    /// the legacy path/source-pair trackers. Never infer omitted observations.
    fn track_prefix_path(&mut self, prefix: Option<IpNet>, path: &str) {
        let Some(network) = prefix else {
            return;
        };
        let item = self.prefix_paths.entry(network).or_default();
        let path_id = self.prefix_path_names.get(path).copied();
        if let Some(count) = path_id.and_then(|id| item.paths.get_mut(&id)) {
            *count += 1;
        } else if item.paths.len() >= self.limits.max_paths_per_source_prefix {
            // Per-prefix rejection takes precedence, so no observation is
            // counted twice when both caps have been reached.
            item.beyond_prefix_cap += 1;
        } else if self.prefix_path_pair_count >= self.limits.max_source_prefix_path_pairs {
            item.beyond_global_cap += 1;
            self.prefix_path_pairs_beyond_cap += 1;
        } else if path_id.is_none()
            && self.prefix_path_names.len() >= self.limits.max_source_prefix_paths
        {
            item.beyond_path_table_cap += 1;
        } else {
            let id = path_id.unwrap_or_else(|| {
                let id = self.prefix_path_names.len();
                self.prefix_path_names.insert(path.to_owned(), id);
                id
            });
            item.paths.insert(id, 1);
            self.prefix_path_pair_count += 1;
        }
    }

    /// Derive volumes from retained sources and legacy source/path pairs;
    /// attach the independently bounded streaming prefix/path measurements.
    fn source_prefix_report(
        &self,
        prefixes: FocusPrefixLengths,
        resolver: Option<&dyn AsnResolver>,
    ) -> (Vec<PrivateSourcePrefix>, SourcePrefixAggregation) {
        #[derive(Default)]
        struct PeerTotals<'a> {
            requests: u64,
            bytes: u64,
            byte_observations: u64,
            classes: StatusClassCounts,
            paths: BTreeMap<&'a str, u64>,
        }
        #[derive(Default)]
        struct Group<'a> {
            totals: PeerTotals<'a>,
            sources: usize,
            maximum: u64,
            asns: BTreeMap<u32, SourcePrefixAsn>,
            unresolved_source_ips: usize,
            unresolved_requests: u64,
        }
        let mut peers = BTreeMap::<IpAddr, PeerTotals<'_>>::new();
        let mut groups = BTreeMap::<String, Group<'_>>::new();
        let mut disclosure = SourcePrefixAggregation {
            safety_note: SOURCE_PREFIX_NOTE.to_owned(),
            ipv4_prefix_bits: prefixes.ipv4,
            ipv6_prefix_bits: prefixes.ipv6,
            maximum_prefixes: self.limits.max_source_ips,
            requests_without_source_ip: self.requests_without_source_ip,
            requests_with_invalid_source_ip: 0,
            requests_beyond_source_tracking_cap: self.source_ips_beyond_tracking_cap,
            requests_beyond_prefix_path_pair_cap: self.prefix_path_pairs_beyond_cap,
            path_tracking: SourcePrefixPathTracking {
                prefix_path_pairs_retained: self.prefix_path_pair_count,
                maximum_prefix_path_pairs: self.limits.max_source_prefix_path_pairs,
                prefixes_beyond_prefix_path_pair_cap: self
                    .prefix_paths
                    .values()
                    .filter(|paths| paths.beyond_global_cap > 0)
                    .count(),
                prefix_paths_retained: self.prefix_path_names.len(),
                maximum_prefix_paths: self.limits.max_source_prefix_paths,
                requests_beyond_prefix_path_table_cap: self
                    .prefix_paths
                    .values()
                    .map(|paths| paths.beyond_path_table_cap)
                    .sum(),
                prefixes_beyond_prefix_path_table_cap: self
                    .prefix_paths
                    .values()
                    .filter(|paths| paths.beyond_path_table_cap > 0)
                    .count(),
            },
        };
        if resolver.is_some() {
            disclosure.safety_note.push(' ');
            disclosure.safety_note.push_str(SOURCE_PREFIX_ASN_NOTE);
        }
        disclosure.safety_note.push(' ');
        disclosure.safety_note.push_str(SOURCE_PREFIX_PATH_NOTE);
        for (source, item) in &self.source_ips {
            let Ok(address) = source.parse::<IpAddr>() else {
                disclosure.requests_with_invalid_source_ip += item.requests;
                continue;
            };
            let address = address.to_canonical();
            // Merge retained spellings only here, not in streaming admission
            // or private per-source rows. Mapped IPv4 uses the IPv4 family.
            let peer = peers.entry(address).or_default();
            peer.requests += item.requests;
            peer.bytes += item.response_bytes;
            peer.byte_observations += item.response_bytes_observations;
            peer.classes.merge(&item.status_classes);
            if let Some(paths) = self.source_path_pairs.get(source) {
                for (path, count) in paths {
                    *peer.paths.entry(path).or_default() += count;
                }
            }
        }
        for (address, peer) in peers {
            let bits = if address.is_ipv4() {
                prefixes.ipv4
            } else {
                prefixes.ipv6
            };
            // Prefix lengths were validated before streaming.
            let network = IpNet::new(address, bits)
                .expect("validated source prefix length")
                .trunc();
            let group = groups.entry(network.to_string()).or_default();
            group.totals.requests += peer.requests;
            group.totals.bytes += peer.bytes;
            group.totals.byte_observations += peer.byte_observations;
            group.sources += 1;
            group.maximum = group.maximum.max(peer.requests);
            group.totals.classes.merge(&peer.classes);
            if let Some(resolver) = resolver {
                // Each address has already been canonicalized and merged.
                // Resolve observed addresses, never a prefix representative.
                if let Some(resolved) = resolver.resolve(address) {
                    let entry = group
                        .asns
                        .entry(resolved.asn)
                        .or_insert_with(|| SourcePrefixAsn {
                            asn: resolved.asn,
                            organization: resolved.org.clone(),
                            distinct_source_ips: 0,
                            requests: 0,
                        });
                    if resolved.org < entry.organization {
                        entry.organization = resolved.org;
                    }
                    entry.distinct_source_ips += 1;
                    entry.requests += peer.requests;
                } else {
                    group.unresolved_source_ips += 1;
                    group.unresolved_requests += peer.requests;
                }
            }
            for (path, count) in peer.paths {
                *group.totals.paths.entry(path).or_default() += count;
            }
        }
        let mut result = groups
            .into_iter()
            .map(|(prefix, group)| {
                let empty = PrefixPathAccumulator::default();
                let paths = self
                    .prefix_paths
                    .get(&prefix.parse::<IpNet>().expect("generated prefix"))
                    .unwrap_or(&empty);
                let totals = group.totals;
                let path_observations_unavailable =
                    totals.requests - totals.paths.values().sum::<u64>();
                let most_requested_uri_path = (path_observations_unavailable == 0)
                    .then(|| {
                        totals
                            .paths
                            .iter()
                            .max_by(|(lp, lc), (rp, rc)| lc.cmp(rc).then_with(|| rp.cmp(lp)))
                            .map(|(path, _)| (*path).to_owned())
                    })
                    .flatten();
                PrivateSourcePrefix {
                    prefix,
                    requests: totals.requests,
                    response_bytes: (totals.byte_observations > 0).then_some(totals.bytes),
                    response_bytes_unavailable: totals.requests - totals.byte_observations,
                    distinct_source_ips: group.sources,
                    max_requests_per_source_ip: group.maximum,
                    most_requested_uri_path,
                    path_observations_unavailable,
                    response_status_classes: totals.classes,
                    asns: resolver.map(|_| {
                        let mut asns = group.asns.into_values().collect::<Vec<_>>();
                        asns.sort_by(|left, right| {
                            right
                                .requests
                                .cmp(&left.requests)
                                .then_with(|| left.asn.cmp(&right.asn))
                        });
                        asns
                    }),
                    unresolved_source_ips: resolver.map(|_| group.unresolved_source_ips),
                    unresolved_requests: resolver.map(|_| group.unresolved_requests),
                    distinct_uri_paths: Some(paths.paths.len() as u64),
                    uri_paths_requested_once: (paths.beyond_prefix_cap == 0
                        && paths.beyond_global_cap == 0
                        && paths.beyond_path_table_cap == 0)
                        .then(|| paths.paths.values().filter(|count| **count == 1).count() as u64),
                    uri_paths_beyond_prefix_cap: Some(paths.beyond_prefix_cap),
                    uri_paths_beyond_global_cap: Some(paths.beyond_global_cap),
                    uri_paths_beyond_path_table_cap: (paths.beyond_path_table_cap > 0)
                        .then_some(paths.beyond_path_table_cap),
                }
            })
            .collect::<Vec<_>>();
        result.sort_by(|left, right| {
            right
                .requests
                .cmp(&left.requests)
                .then_with(|| left.prefix.cmp(&right.prefix))
        });
        (result, disclosure)
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
            // Prefix configuration cannot change after observation starts.
            prefix: self.source_prefix_lengths.and_then(|prefixes| {
                crate::event::canonical_ip(source_ip).map(|address| {
                    let bits = if address.is_ipv4() {
                        prefixes.ipv4
                    } else {
                        prefixes.ipv6
                    };
                    IpNet::new(address, bits)
                        .expect("validated source prefix length")
                        .trunc()
                })
            }),
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
            waf_actions: self
                .waf_capabilities
                .filter(|caps| caps.waf_action)
                .map(|_| item.waf_actions.clone()),
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

    pub(super) fn observe_query_shape(
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
        fn median(counts: &[usize]) -> Option<f64> {
            if counts.is_empty() {
                None
            } else {
                Some(
                    (counts[(counts.len() - 1) / 2] as f64 + counts[counts.len() / 2] as f64) / 2.0,
                )
            }
        }
        let mut counts = self
            .source_ips
            .values()
            .map(|item| item.segments_404.len())
            .collect::<Vec<_>>();
        counts.sort_unstable();
        let positive_counts = &counts[counts.partition_point(|count| *count == 0)..];
        let mut counts_4xx = self
            .source_ips
            .values()
            .map(|item| item.segments_4xx.len())
            .collect::<Vec<_>>();
        counts_4xx.sort_unstable();
        let positive_counts_4xx = &counts_4xx[counts_4xx.partition_point(|count| *count == 0)..];
        // The corpus denominator is independent of source/path admission caps.
        // Zero responses is a degenerate measurement, not a site classification.
        let corpus_4xx_requests = self
            .status_available
            .then(|| self.status_classes.ordinary_client_error());
        let measurable_4xx = corpus_4xx_requests.is_some_and(|count| count > 0);
        SourceSegmentDiversitySummary {
            maximum_404_segments: self
                .status_available
                .then(|| counts.last().copied())
                .flatten(),
            median_404_segments: self.status_available.then(|| median(&counts)).flatten(),
            sources_with_404_segments: self.status_available.then_some(positive_counts.len()),
            median_404_segments_among_sources_with_404_segments: self
                .status_available
                .then(|| median(positive_counts))
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
            corpus_4xx_requests,
            maximum_4xx_segments: measurable_4xx.then(|| counts_4xx.last().copied()).flatten(),
            median_4xx_segments: measurable_4xx.then(|| median(&counts_4xx)).flatten(),
            sources_with_4xx_segments: self.status_available.then_some(positive_counts_4xx.len()),
            median_4xx_segments_among_sources_with_4xx_segments: measurable_4xx
                .then(|| median(positive_counts_4xx))
                .flatten(),
            sources_4xx_beyond_cap: self.status_available.then(|| {
                self.source_ips
                    .values()
                    .filter(|item| item.segments_4xx_beyond_cap > 0)
                    .count()
            }),
            observations_4xx_beyond_cap: self.status_available.then(|| {
                self.source_ips
                    .values()
                    .map(|item| item.segments_4xx_beyond_cap)
                    .sum()
            }),
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

    pub(super) fn most_requested_path(&self, source_ip: &str) -> Option<String> {
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
pub(super) fn requests_per_distinct_source(requests: u64, distinct_source_ips: usize) -> f64 {
    if distinct_source_ips == 0 {
        0.0
    } else {
        requests as f64 / distinct_source_ips as f64
    }
}
