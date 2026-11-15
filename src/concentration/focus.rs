use super::{
    accumulate::{requests_per_distinct_source, RequestConcentration, SourceAccumulator},
    rates::*,
    types::*,
};
use crate::{event::WebEvent, triage::AsnResolver};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

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
pub(super) fn path_is_under(path: &str, prefix: &str) -> bool {
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

/// Address-prefix sizes shared by private focus and corpus-wide groups derived
/// from retained peer-IP counts. They do not change streaming admission or
/// individual peer-IP request counts.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
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

impl RequestConcentration {
    pub(super) fn observe_focus(&mut self, event: &WebEvent) {
        let Some(selector) = &self.focus else {
            return;
        };
        let path = event.uri_path.as_deref();
        let source_ip = event.source_ip.as_deref();
        let matches = match selector {
            FocusSelector::ExactPath(value) => path == Some(value.as_str()),
            FocusSelector::PathPrefix(value) => path.is_some_and(|path| path_is_under(path, value)),
            FocusSelector::SourceIp(values) => source_ip.is_some_and(|ip| {
                values.contains(ip)
                    || ip.parse::<IpAddr>().ok().is_some_and(|address| {
                        self.focus_source_addresses
                            .as_ref()
                            .is_some_and(|addresses| addresses.contains(&address.to_canonical()))
                    })
            }),
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

    pub(super) fn sanitized_focus_summary(&self) -> Option<SanitizedFocusSummary> {
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

    pub(super) fn private_focus_summary(
        &self,
        include_query_keys: bool,
    ) -> Option<PrivateFocusSummary> {
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
            BTreeSet<IpAddr>,
            StatusClassCounts,
            Option<StatusCodeCounts>,
        ),
    >::new();
    for source in &focus.sources {
        let Ok(address) = source.source_ip.parse::<IpAddr>() else {
            continue;
        };
        let address = address.to_canonical();
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
        source_ips.insert(address);
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
    let mut groups = BTreeMap::<u32, (String, u64, BTreeSet<IpAddr>)>::new();
    let mut unresolved_addresses = BTreeSet::new();
    let mut invalid_sources = BTreeSet::new();
    let mut unresolved_requests = 0u64;

    for source in &focus.sources {
        let address = source
            .source_ip
            .parse::<IpAddr>()
            .ok()
            .map(|address| address.to_canonical());
        let Some(address) = address else {
            invalid_sources.insert(source.source_ip.as_str());
            unresolved_requests += source.requests;
            continue;
        };
        let Some(resolved) = resolver.resolve(address) else {
            unresolved_addresses.insert(address);
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
        entry.2.insert(address);
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
        unresolved_source_ips: unresolved_addresses.len() + invalid_sources.len(),
        unresolved_requests,
    });
}
