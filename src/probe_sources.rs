//! Bounded, offline request-shape observations, independent of CVE findings.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Write},
    net::IpAddr,
    path::Path,
};

use anyhow::{bail, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    event::{canonical_ip, RawRetention, TelemetryProfile, TrustedProxySet, WebEvent},
    input_discovery::{discover_input_files, InputDiscoverySummary, SkippedInputFile},
    output::write_json_pretty,
    production::{
        ensure_separate_output, stream_events_with_fingerprint, terminal_safe, HuntTimeRange,
        PathProvenance,
    },
    triage::GroupingIdentity,
};

pub const SAFETY_NOTE: &str = "Probe-shaped describes an observed request pattern for review priority, not a determination of an attack, compromise, malicious intent or attacker identity, and not a recommendation to block. Observed peers may be CDNs, load balancers, NATs or proxies. Legitimate monitoring, security assessments and crawlers can have the same shape. No observed 2xx does not establish that a path does not exist.";
const CATALOG: &str = include_str!("../probe-paths/probe-paths.yaml");

#[derive(Debug, Clone, Args, Serialize)]
pub struct Options {
    #[arg(long, default_value_t = 20)]
    pub min_distinct_paths: usize,
    /// Percentage of all source requests with a recorded 400..499 status.
    #[arg(long, default_value_t = 80.0)]
    pub min_client_error_share: f64,
    #[arg(long, default_value_t = 5)]
    pub min_catalog_paths: usize,
    /// Percentage of distinct paths with no observed 2xx anywhere in this corpus.
    #[arg(long, default_value_t = 90.0)]
    pub min_unserved_path_share: f64,
    #[arg(long, default_value_t = 100_000)]
    pub max_source_ips: usize,
    #[arg(long, default_value_t = 5_000)]
    pub max_paths_per_source: usize,
    #[arg(long, default_value_t = 2_000_000)]
    pub max_source_path_pairs: usize,
    #[arg(long, default_value_t = 1_000_000)]
    pub max_success_paths: usize,
    /// Independent per-source limits for minute bins, days, methods and user agents.
    #[arg(long, default_value_t = 1_440)]
    pub max_auxiliary_values: usize,
}

impl Options {
    fn validate(&self) -> Result<()> {
        if [
            self.min_distinct_paths,
            self.min_catalog_paths,
            self.max_source_ips,
            self.max_paths_per_source,
            self.max_source_path_pairs,
            self.max_success_paths,
            self.max_auxiliary_values,
        ]
        .contains(&0)
        {
            bail!("probe-sources counts and tracking limits must be positive finite counts");
        }
        for value in [self.min_client_error_share, self.min_unserved_path_share] {
            if !value.is_finite() || !(0.0..=100.0).contains(&value) {
                bail!("probe-sources shares must be finite percentages between 0 and 100");
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Catalog {
    version: u32,
    categories: Vec<Category>,
}
#[derive(Deserialize)]
struct Category {
    name: String,
    mode: MatchMode,
    source: String,
    patterns: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MatchMode {
    Basename,
    RootTree,
    Exact,
}
impl Catalog {
    fn load() -> Result<Self> {
        let catalog: Self = serde_yaml::from_str(CATALOG)?;
        catalog.validate()?;
        Ok(catalog)
    }

    fn validate(&self) -> Result<()> {
        for category in &self.categories {
            let mut seen = BTreeSet::new();
            for pattern in &category.patterns {
                if pattern.is_empty() || !seen.insert(pattern) {
                    bail!(
                        "empty or duplicate probe catalog pattern in {}",
                        category.name
                    );
                }
                let valid = match category.mode {
                    MatchMode::Basename => !pattern.contains('/'),
                    MatchMode::RootTree | MatchMode::Exact => pattern.starts_with('/'),
                };
                if !valid {
                    bail!("invalid probe catalog pattern shape in {}", category.name);
                }
            }
        }
        Ok(())
    }

    fn matching(&self, path: &str) -> Vec<usize> {
        // Do not decode or fold case. Public convention paths are excluded even
        // if a basename underneath them resembles a catalog entry.
        if [
            "/robots.txt",
            "/favicon.ico",
            "/sitemap.xml",
            "/.well-known",
        ]
        .contains(&path)
            || path.starts_with("/.well-known/")
        {
            return Vec::new();
        }
        self.categories
            .iter()
            .enumerate()
            .filter_map(|(index, category)| {
                category
                    .patterns
                    .iter()
                    .any(|pattern| match category.mode {
                        MatchMode::Basename => path.rsplit('/').next() == Some(pattern.as_str()),
                        MatchMode::RootTree => {
                            path == pattern
                                || path
                                    .strip_prefix(pattern)
                                    .is_some_and(|rest| rest.starts_with('/'))
                        }
                        MatchMode::Exact => path == pattern,
                    })
                    .then_some(index)
            })
            .collect()
    }
}

#[derive(Default, Clone, Serialize)]
pub struct Omissions {
    pub requests_beyond_source_cap: u64,
    pub requests_beyond_source_path_cap: u64,
    pub requests_beyond_global_path_pair_cap: u64,
    pub successful_path_observations_beyond_cap: u64,
    pub minute_observations_beyond_cap: u64,
    pub day_observations_beyond_cap: u64,
    pub method_observations_beyond_cap: u64,
    pub user_agent_observations_beyond_cap: u64,
}
#[derive(Default, Serialize)]
pub struct Summary {
    pub files_analyzed: usize,
    #[serde(flatten)]
    pub input_discovery: InputDiscoverySummary,
    pub parseable_records: u64,
    pub parse_errors: u64,
    pub records_outside_time_range: u64,
    pub undated_records_excluded_by_time_range: u64,
    pub requests_without_source_ip: u64,
    pub requests_with_invalid_source_ip: u64,
    pub requests_without_path: u64,
    pub requests_without_status: u64,
    pub evaluated_sources: usize,
    pub probe_shaped_sources: usize,
    pub evaluated_sources_by_identity: BTreeMap<String, usize>,
    pub probe_shaped_sources_by_identity: BTreeMap<String, usize>,
    pub sources_without_status: usize,
    pub criteria_met: BTreeMap<String, usize>,
    pub criteria_unavailable: BTreeMap<String, usize>,
    pub omissions: Omissions,
}
#[derive(Serialize)]
pub struct Criterion {
    pub value: Option<f64>,
    pub minimum: f64,
    pub met: Option<bool>,
    pub unavailable_reason: Option<&'static str>,
}
impl Criterion {
    fn new(value: Option<f64>, minimum: f64, incomplete: bool, reason: &'static str) -> Self {
        let met = value.and_then(|v| {
            if v >= minimum {
                Some(true)
            } else if incomplete {
                None
            } else {
                Some(false)
            }
        });
        Self {
            value,
            minimum,
            met,
            unavailable_reason: met.is_none().then_some(reason),
        }
    }
}
#[derive(Default, Serialize)]
pub struct CategoryCounts {
    pub requests: u64,
    pub distinct_paths: usize,
}
#[derive(Serialize)]
pub struct Source {
    pub identity: &'static str,
    pub source: String,
    pub source_kind: &'static str,
    pub requests: u64,
    pub distinct_paths: usize,
    pub catalog_requests: u64,
    pub catalog_distinct_paths: usize,
    pub catalog_categories: BTreeMap<String, CategoryCounts>,
    pub client_error_requests: Option<u64>,
    pub client_error_share: Option<f64>,
    pub not_found_requests: Option<u64>,
    pub not_found_share: Option<f64>,
    pub distinct_not_found_paths: Option<usize>,
    pub unserved_path_share: Option<f64>,
    pub status_unavailable: u64,
    pub client_error_condition_applied: bool,
    pub paths_unavailable: u64,
    pub earliest: Option<DateTime<Utc>>,
    pub latest: Option<DateTime<Utc>>,
    pub active_days: Option<usize>,
    pub peak_requests_per_minute: Option<u64>,
    pub timestamps_unavailable: u64,
    pub methods: Vec<String>,
    pub methods_unavailable: u64,
    pub query_requests: u64,
    pub query_share: f64,
    pub distinct_user_agents: Option<usize>,
    pub user_agents_unavailable: u64,
    pub criteria: BTreeMap<String, Criterion>,
    pub label: Option<&'static str>,
    pub omissions: Omissions,
    pub example_paths: Vec<String>,
    pub example_paths_omitted: usize,
    pub top_user_agents: Vec<(String, u64)>,
    pub user_agents_omitted: usize,
}
#[derive(Serialize)]
pub struct Report {
    pub safety_note: &'static str,
    pub thresholds_and_limits: Options,
    pub summary: Summary,
    pub sources: Vec<Source>,
}

#[derive(Default)]
struct PathCounts {
    not_found: bool,
    categories: Vec<usize>,
}
#[derive(Default)]
struct Accumulator {
    raw: String,
    requests: u64,
    paths: BTreeMap<String, PathCounts>,
    catalog_requests: u64,
    category_requests: BTreeMap<usize, u64>,
    status: u64,
    client_errors: u64,
    not_found: u64,
    missing_paths: u64,
    earliest: Option<DateTime<Utc>>,
    latest: Option<DateTime<Utc>>,
    days: BTreeMap<i64, u64>,
    minutes: BTreeMap<i64, u64>,
    missing_times: u64,
    methods: BTreeMap<String, u64>,
    missing_methods: u64,
    agents: BTreeMap<String, u64>,
    missing_agents: u64,
    queries: u64,
    omissions: Omissions,
}
fn increment<K: Ord>(map: &mut BTreeMap<K, u64>, key: K, cap: usize, omissions: &mut u64) {
    if map.contains_key(&key) || map.len() < cap {
        *map.entry(key).or_default() += 1;
    } else {
        *omissions += 1;
    }
}
fn percentage(n: u64, d: u64) -> f64 {
    n as f64 * 100.0 / d as f64
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SourceKey {
    Ip(GroupingIdentity, IpAddr),
    Hostname(String),
}
impl SourceKey {
    fn kind(&self) -> &'static str {
        match self {
            Self::Ip(_, _) => "ip",
            Self::Hostname(_) => "hostname",
        }
    }

    fn identity(&self) -> &'static str {
        match self {
            Self::Ip(identity, _) => identity.label(),
            Self::Hostname(_) => "hostname-peer",
        }
    }
}

// This is syntax validation only, never DNS resolution or an address claim.
fn canonical_hostname(value: &str) -> Option<String> {
    if value.len() > 253 || !value.bytes().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let name = value.strip_suffix('.').unwrap_or(value);
    name.split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        .then(|| name.to_ascii_lowercase())
}

struct Analysis {
    sources: BTreeMap<SourceKey, Accumulator>,
    successful_paths: BTreeMap<String, ()>,
    pairs: usize,
    summary: Summary,
    catalog: Catalog,
}
impl Analysis {
    fn new() -> Result<Self> {
        Ok(Self {
            sources: BTreeMap::new(),
            successful_paths: BTreeMap::new(),
            pairs: 0,
            summary: Summary::default(),
            catalog: Catalog::load()?,
        })
    }
    fn observe(&mut self, event: WebEvent, options: &Options) {
        self.summary.requests_without_path += u64::from(event.uri_path.is_none());
        self.summary.requests_without_status += u64::from(event.status.is_none());
        if event
            .status
            .is_some_and(|status| (200..300).contains(&status))
        {
            if let Some(path) = &event.uri_path {
                if self.successful_paths.contains_key(path)
                    || self.successful_paths.len() < options.max_success_paths
                {
                    self.successful_paths.insert(path.clone(), ());
                } else {
                    self.summary
                        .omissions
                        .successful_path_observations_beyond_cap += 1;
                }
            }
        }
        // Match the established triage identity policy, never merging validated
        // clients with observed peers. The representative remains a raw spelling.
        let Some(peer) = event
            .source_ip
            .as_ref()
            .filter(|value| !value.is_empty() && *value != "-")
        else {
            self.summary.requests_without_source_ip += 1;
            return;
        };
        let (key, raw) = if let Some(ip) = canonical_ip(peer) {
            if let Some(client) = event.client_ip.as_ref() {
                let Some(client_ip) = canonical_ip(client) else {
                    self.summary.requests_with_invalid_source_ip += 1;
                    return;
                };
                (
                    SourceKey::Ip(GroupingIdentity::ValidatedClient, client_ip),
                    client,
                )
            } else {
                (SourceKey::Ip(GroupingIdentity::ObservedPeer, ip), peer)
            }
        } else if let Some(hostname) = canonical_hostname(peer) {
            // Hostname peers cannot establish CIDR trust, even if a caller
            // supplies a client field on an event outside the normal streamer.
            (SourceKey::Hostname(hostname), peer)
        } else {
            self.summary.requests_with_invalid_source_ip += 1;
            return;
        };
        if !self.sources.contains_key(&key) && self.sources.len() >= options.max_source_ips {
            self.summary.omissions.requests_beyond_source_cap += 1;
            return;
        }
        let source = self.sources.entry(key).or_insert_with(|| Accumulator {
            raw: raw.clone(),
            ..Default::default()
        });
        if raw < &source.raw {
            source.raw = raw.clone();
        }
        source.requests += 1;
        source.status += u64::from(event.status.is_some());
        source.client_errors += u64::from(event.status.is_some_and(|s| (400..500).contains(&s)));
        source.not_found += u64::from(event.status == Some(404));
        if let Some(path) = event.uri_path {
            let categories = self.catalog.matching(&path);
            source.catalog_requests += u64::from(!categories.is_empty());
            for category in &categories {
                *source.category_requests.entry(*category).or_default() += 1;
            }
            if !source.paths.contains_key(&path) {
                if source.paths.len() >= options.max_paths_per_source {
                    source.omissions.requests_beyond_source_path_cap += 1;
                } else if self.pairs >= options.max_source_path_pairs {
                    source.omissions.requests_beyond_global_path_pair_cap += 1;
                } else {
                    source.paths.insert(
                        path.clone(),
                        PathCounts {
                            not_found: false,
                            categories,
                        },
                    );
                    self.pairs += 1;
                }
            }
            if let Some(counts) = source.paths.get_mut(&path) {
                counts.not_found |= event.status == Some(404);
            }
        } else {
            source.missing_paths += 1;
        }
        if let Some(time) = event.timestamp {
            source.earliest = Some(source.earliest.map_or(time, |old| old.min(time)));
            source.latest = Some(source.latest.map_or(time, |old| old.max(time)));
            increment(
                &mut source.minutes,
                time.timestamp().div_euclid(60),
                options.max_auxiliary_values,
                &mut source.omissions.minute_observations_beyond_cap,
            );
            increment(
                &mut source.days,
                time.timestamp().div_euclid(86_400),
                options.max_auxiliary_values,
                &mut source.omissions.day_observations_beyond_cap,
            );
        } else {
            source.missing_times += 1;
        }
        if let Some(method) = event.method {
            increment(
                &mut source.methods,
                method,
                options.max_auxiliary_values,
                &mut source.omissions.method_observations_beyond_cap,
            );
        } else {
            source.missing_methods += 1;
        }
        if let Some(agent) = event.user_agent {
            increment(
                &mut source.agents,
                agent,
                options.max_auxiliary_values,
                &mut source.omissions.user_agent_observations_beyond_cap,
            );
        } else {
            source.missing_agents += 1;
        }
        source.queries += u64::from(
            event
                .uri_query
                .as_ref()
                .is_some_and(|query| !query.is_empty()),
        );
    }
    fn finish(mut self, options: &Options) -> Report {
        let mut rows = Vec::new();
        for (key, source) in self.sources {
            let identity = key.identity();
            let incomplete = source.missing_paths > 0
                || source.omissions.requests_beyond_source_path_cap > 0
                || source.omissions.requests_beyond_global_path_pair_cap > 0;
            let catalog_paths = source
                .paths
                .values()
                .filter(|p| !p.categories.is_empty())
                .count();
            let client_share =
                (source.status > 0).then(|| percentage(source.client_errors, source.requests));
            let unserved_share = (source.status > 0
                && !incomplete
                && !source.paths.is_empty()
                && self
                    .summary
                    .omissions
                    .successful_path_observations_beyond_cap
                    == 0)
                .then(|| {
                    percentage(
                        source
                            .paths
                            .keys()
                            .filter(|p| !self.successful_paths.contains_key(*p))
                            .count() as u64,
                        source.paths.len() as u64,
                    )
                });
            let criteria: BTreeMap<String, Criterion> = BTreeMap::from([
                (
                    "distinct_paths".into(),
                    Criterion::new(
                        Some(source.paths.len() as f64),
                        options.min_distinct_paths as f64,
                        incomplete,
                        "path_tracking_incomplete",
                    ),
                ),
                (
                    "client_error_share".into(),
                    Criterion::new(
                        client_share,
                        options.min_client_error_share,
                        false,
                        "no_recorded_status",
                    ),
                ),
                (
                    "catalog_paths".into(),
                    Criterion::new(
                        Some(catalog_paths as f64),
                        options.min_catalog_paths as f64,
                        incomplete,
                        "path_tracking_incomplete",
                    ),
                ),
                (
                    "unserved_path_share".into(),
                    Criterion::new(
                        unserved_share,
                        options.min_unserved_path_share,
                        false,
                        "no_status_or_incomplete_path_observations",
                    ),
                ),
            ]);
            let labeled = criteria["distinct_paths"].met == Some(true)
                && (source.status == 0 || criteria["client_error_share"].met == Some(true))
                && (criteria["catalog_paths"].met == Some(true)
                    || criteria["unserved_path_share"].met == Some(true));
            for (name, criterion) in &criteria {
                *self.summary.criteria_met.entry(name.clone()).or_default() +=
                    usize::from(criterion.met == Some(true));
                *self
                    .summary
                    .criteria_unavailable
                    .entry(name.clone())
                    .or_default() += usize::from(criterion.met.is_none());
            }
            self.summary.probe_shaped_sources += usize::from(labeled);
            *self
                .summary
                .evaluated_sources_by_identity
                .entry(identity.into())
                .or_default() += 1;
            *self
                .summary
                .probe_shaped_sources_by_identity
                .entry(identity.into())
                .or_default() += usize::from(labeled);
            self.summary.sources_without_status += usize::from(source.status == 0);
            let mut agents: Vec<_> = source.agents.into_iter().collect();
            agents.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let agent_count = agents.len();
            agents.truncate(10);
            let categories = self
                .catalog
                .categories
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    (
                        c.name.clone(),
                        CategoryCounts {
                            requests: source.category_requests.get(&i).copied().unwrap_or(0),
                            distinct_paths: source
                                .paths
                                .values()
                                .filter(|p| p.categories.contains(&i))
                                .count(),
                        },
                    )
                })
                .collect();
            let total = &mut self.summary.omissions;
            total.requests_beyond_source_path_cap +=
                source.omissions.requests_beyond_source_path_cap;
            total.requests_beyond_global_path_pair_cap +=
                source.omissions.requests_beyond_global_path_pair_cap;
            total.minute_observations_beyond_cap += source.omissions.minute_observations_beyond_cap;
            total.day_observations_beyond_cap += source.omissions.day_observations_beyond_cap;
            total.method_observations_beyond_cap += source.omissions.method_observations_beyond_cap;
            total.user_agent_observations_beyond_cap +=
                source.omissions.user_agent_observations_beyond_cap;
            rows.push(Source {
                identity,
                source: source.raw,
                source_kind: key.kind(),
                requests: source.requests,
                distinct_paths: source.paths.len(),
                catalog_requests: source.catalog_requests,
                catalog_distinct_paths: catalog_paths,
                catalog_categories: categories,
                client_error_requests: (source.status > 0).then_some(source.client_errors),
                client_error_share: client_share,
                not_found_requests: (source.status > 0).then_some(source.not_found),
                not_found_share: (source.status > 0)
                    .then(|| percentage(source.not_found, source.requests)),
                distinct_not_found_paths: (source.status > 0)
                    .then(|| source.paths.values().filter(|p| p.not_found).count()),
                unserved_path_share: unserved_share,
                status_unavailable: source.requests - source.status,
                client_error_condition_applied: source.status > 0,
                paths_unavailable: source.missing_paths,
                earliest: source.earliest,
                latest: source.latest,
                active_days: (source.earliest.is_some()
                    && source.omissions.day_observations_beyond_cap == 0)
                    .then_some(source.days.len()),
                peak_requests_per_minute: (source.omissions.minute_observations_beyond_cap == 0)
                    .then(|| source.minutes.values().copied().max())
                    .flatten(),
                timestamps_unavailable: source.missing_times,
                methods: source.methods.into_keys().collect(),
                methods_unavailable: source.missing_methods,
                query_requests: source.queries,
                query_share: percentage(source.queries, source.requests),
                distinct_user_agents: (source.missing_agents < source.requests
                    && source.omissions.user_agent_observations_beyond_cap == 0)
                    .then_some(agent_count),
                user_agents_unavailable: source.missing_agents,
                criteria,
                label: labeled.then_some("probe-shaped"),
                omissions: source.omissions,
                example_paths: source.paths.keys().take(20).cloned().collect(),
                example_paths_omitted: source.paths.len().saturating_sub(20),
                top_user_agents: agents,
                user_agents_omitted: agent_count.saturating_sub(10),
            });
        }
        rows.sort_by(|a, b| {
            b.label
                .is_some()
                .cmp(&a.label.is_some())
                .then(b.distinct_paths.cmp(&a.distinct_paths))
                .then(b.requests.cmp(&a.requests))
                .then(a.identity.cmp(b.identity))
                .then(a.source.cmp(&b.source))
        });
        self.summary.evaluated_sources = rows.len();
        Report {
            safety_note: SAFETY_NOTE,
            thresholds_and_limits: options.clone(),
            summary: self.summary,
            sources: rows,
        }
    }
}

/// Analyze one selected corpus in a single fingerprinted pass. No network access.
pub fn run(
    input: &Path,
    profile: TelemetryProfile,
    time_range: &HuntTimeRange,
    proxies: &TrustedProxySet,
    options: &Options,
    output: Option<&Path>,
) -> Result<Report> {
    options.validate()?;
    time_range.validate()?;
    if let Some(output) = output {
        ensure_separate_output(input, output)?;
    }
    let discovery = discover_input_files(input, Some(profile))?;
    let mut analysis = Analysis::new()?;
    let catalog_version = analysis.catalog.version;
    let catalog_sources: BTreeMap<_, _> = analysis
        .catalog
        .categories
        .iter()
        .map(|c| (c.name.clone(), c.source.clone()))
        .collect();
    analysis.summary.files_analyzed = discovery.files.len();
    analysis.summary.input_discovery = discovery.summary;
    let mut corpus = Vec::new();
    for path in discovery.files {
        corpus.push(stream_events_with_fingerprint(
            &path,
            profile,
            proxies,
            RawRetention::Drop,
            |event| {
                match event {
                    Ok(event) => {
                        analysis.summary.parseable_records += 1;
                        if time_range.includes(event.timestamp) {
                            analysis.observe(event, options);
                        } else {
                            analysis.summary.records_outside_time_range += 1;
                            analysis.summary.undated_records_excluded_by_time_range +=
                                u64::from(event.timestamp.is_none());
                        }
                    }
                    Err(_) => analysis.summary.parse_errors += 1,
                }
                Ok(())
            },
        )?);
    }
    let report = analysis.finish(options);
    if let Some(output) = output {
        fs::create_dir_all(output)?;
        #[derive(Serialize)]
        struct Manifest<'a> {
            safety_note: &'static str,
            request_shape_safety_note: &'static str,
            telemetry_profile: TelemetryProfile,
            thresholds_and_limits: &'a Options,
            from: Option<DateTime<Utc>>,
            to: Option<DateTime<Utc>>,
            trusted_proxies: Vec<String>,
            catalog_version: u32,
            catalog_sha256: String,
            catalog_sources: BTreeMap<String, String>,
            corpus: Vec<PathProvenance>,
            skipped_inputs: &'a [SkippedInputFile],
        }
        write_json_pretty(output.join("run-manifest.json"), &Manifest {
            safety_note: "Private input paths and configuration; review before sharing. Corpus hashes identify input bytes, not a Shenron finding.",
            request_shape_safety_note: SAFETY_NOTE,
            telemetry_profile: profile, thresholds_and_limits: options, from: time_range.from, to: time_range.to,
            trusted_proxies: proxies.configured_proxy_networks(), catalog_version,
            catalog_sha256: format!("{:x}", Sha256::digest(CATALOG.as_bytes())), catalog_sources, corpus,
            skipped_inputs: &report.summary.input_discovery.skipped,
        })?;
        write_json_pretty(output.join("probe-sources.json"), &report)?;
        write_json_pretty(output.join("sanitized-research.json"), &report.summary)?;
        fs::write(
            output.join("probe-source-ips.txt"),
            ip_list(&report, "observed-peer"),
        )?;
        if !proxies.configured_proxy_networks().is_empty() {
            fs::write(
                output.join("probe-source-validated-client-ips.txt"),
                ip_list(&report, "validated-client"),
            )?;
        }
    }
    Ok(report)
}

fn ip_list(report: &Report, identity: &str) -> String {
    let addresses: BTreeSet<_> = report
        .sources
        .iter()
        .filter(|source| source.label.is_some() && source.identity == identity)
        .filter_map(|source| canonical_ip(&source.source))
        .collect();
    addresses
        .into_iter()
        .map(|address| format!("{address}\n"))
        .collect()
}

/// Human-readable output; sanitize only untrusted values, never layout text.
pub fn write_text(
    mut writer: impl Write,
    report: &Report,
    show_ips: bool,
    show_paths: bool,
    limit: usize,
) -> io::Result<()> {
    let summary = &report.summary;
    writeln!(
        writer,
        "Probe-source request-shape observations (aggregate counts by default):"
    )?;
    writeln!(writer, "{}", SAFETY_NOTE)?;
    if let Some(disclosure) = summary.input_discovery.disclosure() {
        writeln!(writer, "{disclosure}")?;
    }
    for (name, count) in [
        ("Files analyzed", summary.files_analyzed as u64),
        ("Parseable records", summary.parseable_records),
        ("Parse errors", summary.parse_errors),
        ("Evaluated sources", summary.evaluated_sources as u64),
        ("Probe-shaped sources", summary.probe_shaped_sources as u64),
    ] {
        writeln!(writer, "  {name}: {count}")?;
    }
    for (identity, evaluated) in &summary.evaluated_sources_by_identity {
        writeln!(
            writer,
            "  {identity}: {evaluated} evaluated / {} probe-shaped",
            summary
                .probe_shaped_sources_by_identity
                .get(identity)
                .copied()
                .unwrap_or(0)
        )?;
    }
    for (name, met) in &summary.criteria_met {
        let unavailable = summary.criteria_unavailable.get(name).copied().unwrap_or(0);
        writeln!(
            writer,
            "  Condition {name}: {met} met / {} not met / {unavailable} unavailable",
            summary.evaluated_sources - met - unavailable
        )?;
    }
    for (name, count) in [
        (
            "Records outside time range",
            summary.records_outside_time_range,
        ),
        (
            "Undated records excluded by time range",
            summary.undated_records_excluded_by_time_range,
        ),
        (
            "Requests without source",
            summary.requests_without_source_ip,
        ),
        (
            "Requests with invalid source",
            summary.requests_with_invalid_source_ip,
        ),
        ("Requests without path", summary.requests_without_path),
        ("Requests without status", summary.requests_without_status),
        (
            "Sources without status (4xx condition not applied)",
            summary.sources_without_status as u64,
        ),
    ] {
        if count > 0 {
            writeln!(writer, "  {name}: {count}")?;
        }
    }
    let omissions = &summary.omissions;
    for (name, count) in [
        ("source cap", omissions.requests_beyond_source_cap),
        ("source path cap", omissions.requests_beyond_source_path_cap),
        (
            "global source/path pair cap",
            omissions.requests_beyond_global_path_pair_cap,
        ),
        (
            "corpus successful-path cap",
            omissions.successful_path_observations_beyond_cap,
        ),
        ("minute cap", omissions.minute_observations_beyond_cap),
        ("day cap", omissions.day_observations_beyond_cap),
        ("method cap", omissions.method_observations_beyond_cap),
        (
            "user-agent cap",
            omissions.user_agent_observations_beyond_cap,
        ),
    ] {
        if count > 0 {
            writeln!(
                writer,
                "  Tracking-cap omissions ({name}): {count} observations"
            )?;
        }
    }
    let shown = if show_ips {
        report.sources.len().min(limit)
    } else {
        0
    };
    let share =
        |value: Option<f64>| value.map_or_else(|| "unavailable".to_owned(), |v| format!("{v:.1}%"));
    let timestamp = |value: Option<DateTime<Utc>>| {
        value.map_or_else(
            || "unavailable".to_owned(),
            |v| v.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        )
    };
    for source in report.sources.iter().take(shown) {
        writeln!(writer, "  {} ({}): {} / requests {} / distinct paths {} / 4xx {} / catalog paths {} / unserved {} / {}..{}",
            terminal_safe(&source.source), source.identity, source.label.unwrap_or("not labeled"), source.requests,
            source.distinct_paths, share(source.client_error_share), source.catalog_distinct_paths,
            share(source.unserved_path_share), timestamp(source.earliest), timestamp(source.latest))?;
        let conditions = source
            .criteria
            .iter()
            .map(|(name, criterion)| {
                let value = if name.ends_with("share") {
                    share(criterion.value)
                } else {
                    criterion
                        .value
                        .map_or_else(|| "unavailable".into(), |v| v.to_string())
                };
                let state = match criterion.met {
                    Some(true) => "met".to_owned(),
                    Some(false) => "not met".to_owned(),
                    None => format!(
                        "unavailable: {}",
                        criterion.unavailable_reason.unwrap_or("unavailable")
                    ),
                };
                format!(
                    "{name} {value} >= {}{} ({state})",
                    criterion.minimum,
                    if name.ends_with("share") { "%" } else { "" }
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        writeln!(writer, "    Conditions: {conditions}; 4xx gate {}; missing status/path: {}/{}; path-cap omissions: {}; retained paths not displayed: {}",
            if source.client_error_condition_applied {"applied"} else {"not applied"}, source.status_unavailable,
            source.paths_unavailable, source.omissions.requests_beyond_source_path_cap + source.omissions.requests_beyond_global_path_pair_cap,
            source.distinct_paths - if show_paths {source.example_paths.len()} else {0})?;
        if show_paths {
            for path in &source.example_paths {
                writeln!(writer, "      {}", terminal_safe(path))?;
            }
        }
    }
    writeln!(
        writer,
        "Sources not displayed: {}",
        report.sources.len() - shown
    )
}

/// Explicit display projection: private values never enter the default view.
pub fn display(
    report: &Report,
    show_ips: bool,
    show_paths: bool,
    limit: usize,
) -> serde_json::Value {
    let shown = if show_ips {
        report.sources.len().min(limit)
    } else {
        0
    };
    let mut value = serde_json::json!({"safety_note": SAFETY_NOTE, "summary": report.summary,
        "sources_not_displayed": report.sources.len() - shown});
    if show_ips {
        value["sources"] = serde_json::Value::Array(report.sources.iter().take(shown).map(|s| {
            let mut row = serde_json::json!({"identity":s.identity,"source":s.source,"source_kind":s.source_kind,"requests":s.requests,
                "label":s.label,"criteria":s.criteria,"status_unavailable":s.status_unavailable,
                "client_error_condition_applied":s.client_error_condition_applied,"omissions":s.omissions,
                "paths_not_displayed":s.distinct_paths - if show_paths {s.example_paths.len()} else {0}});
            if show_paths { row["example_paths"] = serde_json::json!(s.example_paths); }
            row
        }).collect());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestArgs {
        #[command(flatten)]
        options: Options,
    }
    fn options() -> Options {
        TestArgs::parse_from(["probe"]).options
    }
    fn event(ip: &str, path: &str, status: Option<u16>) -> WebEvent {
        let mut event = crate::waf::parse_line(
            &serde_json::json!({
                "timestamp":1767225600000_i64, "action":"ALLOW",
                "httpRequest":{"clientIp":ip,"uri":path,"httpMethod":"GET","args":"","headers":[]}
            })
            .to_string(),
        )
        .unwrap();
        event.status = status;
        event
    }

    #[test]
    fn catalog_modes_are_case_sensitive_bounded_and_exclude_public_conventions() {
        let catalog = Analysis::new().unwrap().catalog;
        assert_eq!(
            catalog
                .categories
                .iter()
                .map(|c| c.patterns.len())
                .collect::<Vec<_>>(),
            [50, 5, 8, 5]
        );
        for (path, expected) in [
            ("/nested/alfa3.php", true),
            ("/r57shell.php", true),
            ("/wp-content/plugins/example/php-reverse-shell.php", true),
            ("/deep/jspspy_k8.jsp", true),
            ("/index.php", false),
            ("/admin.php", false),
            ("/test.php", false),
            ("/ALFA3.PHP", false),
            ("/wp-content/plugins/example/up.php", true),
            ("/wp-contentish", false),
            ("/.env", true),
            ("/.env-help", false),
            ("/administrator/install", true),
            ("/robots.txt", false),
            ("/favicon.ico", false),
            ("/sitemap.xml", false),
            ("/.well-known/alfa3.php", false),
        ] {
            assert_eq!(!catalog.matching(path).is_empty(), expected, "{path}");
        }
        for path in [
            "/r57shell.php",
            "/nested/obfuscated-phpshell.php",
            "/wp-content/plugins/example/php-reverse-shell.php",
        ] {
            assert!(
                catalog.matching(path).contains(&0),
                "basename category: {path}"
            );
        }
        // Secret vocabulary is a stricter exact-path subset of the bundled
        // Sigma rule; no second, independently sourced secret list is inferred.
        let sigma: serde_yaml::Value = serde_yaml::from_str(include_str!(
            "../sigma-rules/secret-and-config-file-probe.yml"
        ))
        .unwrap();
        let patterns = sigma["detection"]["selection"]["uri_path|contains"]
            .as_sequence()
            .unwrap();
        for path in &catalog.categories[2].patterns {
            assert!(
                patterns.iter().any(|p| path.contains(p.as_str().unwrap())),
                "{path}"
            );
        }
    }

    #[test]
    fn corpus_success_from_other_sources_and_partial_status_keep_denominators() {
        let options = options();
        let mut analysis = Analysis::new().unwrap();
        for status in [Some(404), None, Some(499), Some(301)] {
            analysis.observe(event("192.0.2.1", "/shared", status), &options);
        }
        analysis.observe(event("192.0.2.1", "/only-missing", Some(404)), &options);
        analysis.observe(event("198.51.100.1", "/shared", Some(200)), &options);
        let report = analysis.finish(&options);
        let source = &report.sources[0];
        assert_eq!(source.client_error_requests, Some(3));
        assert_eq!(source.client_error_share, Some(60.0));
        assert_eq!(source.not_found_requests, Some(2));
        assert_eq!(source.distinct_not_found_paths, Some(2));
        assert_eq!(source.status_unavailable, 1);
        assert_eq!(source.unserved_path_share, Some(50.0));
    }

    #[test]
    fn source_and_auxiliary_caps_preserve_existing_keys_and_disclose_all_rejections() {
        let mut options = options();
        options.max_auxiliary_values = 1;
        options.max_paths_per_source = 1;
        options.max_source_path_pairs = 2;
        let mut analysis = Analysis::new().unwrap();
        for index in 0..3 {
            let mut e = event(
                "2001:DB8::1",
                if index == 1 { "/other" } else { "/same" },
                Some(404),
            );
            e.timestamp = Some(DateTime::from_timestamp(1767225600 + index * 86_400, 0).unwrap());
            e.method = Some(format!("METHOD{index}"));
            e.user_agent = Some(format!("synthetic-agent-{index}"));
            e.uri_query = Some("synthetic-private-query".into());
            analysis.observe(e, &options);
        }
        analysis.observe(event("2001:db8::1", "/same", Some(404)), &options);
        analysis.observe(event("invalid!source", "/same", Some(404)), &options);
        let mut missing = event("192.0.2.1", "/same", None);
        missing.source_ip = None;
        analysis.observe(missing, &options);
        let report = analysis.finish(&options);
        assert_eq!(report.sources.len(), 1);
        let source = &report.sources[0];
        assert_eq!(source.requests, 4);
        assert_eq!(source.source, "2001:DB8::1");
        assert_eq!(source.distinct_paths, 1);
        assert_eq!(source.query_share, 75.0);
        assert_eq!(source.omissions.requests_beyond_source_path_cap, 1);
        assert_eq!(source.omissions.minute_observations_beyond_cap, 2);
        assert_eq!(source.omissions.day_observations_beyond_cap, 2);
        assert_eq!(source.omissions.method_observations_beyond_cap, 3);
        assert_eq!(source.omissions.user_agent_observations_beyond_cap, 2);
        assert!(source.active_days.is_none());
        assert!(source.peak_requests_per_minute.is_none());
        assert!(source.distinct_user_agents.is_none());
        assert_eq!(report.summary.requests_with_invalid_source_ip, 1);
        assert_eq!(report.summary.requests_without_source_ip, 1);
    }

    #[test]
    fn unavailable_status_needs_catalog_evidence_and_unserved_alternative_is_independent() {
        let options = options();
        assert_eq!(
            (options.min_distinct_paths, options.min_catalog_paths),
            (20, 5)
        );
        assert_eq!(
            (
                options.min_client_error_share,
                options.min_unserved_path_share
            ),
            (80.0, 90.0)
        );
        let mut analysis = Analysis::new().unwrap();
        for index in 0..20 {
            analysis.observe(
                event("192.0.2.1", &format!("/uncatalogued/{index}"), None),
                &options,
            );
            analysis.observe(
                event("192.0.2.2", &format!("/uncatalogued/{index}"), Some(404)),
                &options,
            );
        }
        let report = analysis.finish(&options);
        assert_eq!(report.summary.probe_shaped_sources, 1);
        assert_eq!(report.sources[0].source, "192.0.2.2");
        assert_eq!(report.sources[0].catalog_distinct_paths, 0);
        assert_eq!(report.sources[0].unserved_path_share, Some(100.0));
        let absent = &report.sources[1];
        assert!(absent.label.is_none());
        assert!(!absent.client_error_condition_applied);
        assert!(absent.criteria["client_error_share"].met.is_none());
    }

    #[test]
    fn inclusive_defaults_pass_with_catalog_alternative_at_exact_boundaries() {
        let options = options();
        let mut analysis = Analysis::new().unwrap();
        for index in 0..20 {
            let path = if index < 5 {
                format!("/synthetic-{index}/alfa3.php")
            } else {
                format!("/ordinary-{index}")
            };
            analysis.observe(
                event("192.0.2.1", &path, Some(if index < 16 { 404 } else { 200 })),
                &options,
            );
        }
        let report = analysis.finish(&options);
        let source = &report.sources[0];
        assert_eq!(source.label, Some("probe-shaped"));
        assert_eq!(source.distinct_paths, 20);
        assert_eq!(source.client_error_share, Some(80.0));
        assert_eq!(source.catalog_distinct_paths, 5);
        assert_eq!(source.unserved_path_share, Some(80.0));
        assert_eq!(source.criteria["unserved_path_share"].met, Some(false));
    }

    #[test]
    fn catalog_load_validates_version_uniqueness_and_pattern_shapes() {
        let catalog = Catalog::load().unwrap();
        assert_eq!(catalog.version, 2);
        let mut seen = BTreeSet::new();
        for category in &catalog.categories {
            for pattern in &category.patterns {
                assert!(seen.insert(pattern));
            }
        }
        for pattern in ["", "alfa3.php", "/bad-basename.php"] {
            let mut invalid = Catalog::load().unwrap();
            invalid.categories[0].patterns.push(pattern.into());
            assert!(invalid.validate().is_err(), "{pattern:?}");
        }
        for category in [1, 2] {
            let mut invalid = Catalog::load().unwrap();
            invalid.categories[category]
                .patterns
                .push("missing-leading-slash".into());
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn hostname_syntax_and_missing_values_are_bounded_without_dns_or_client_trust() {
        assert_eq!(
            canonical_hostname("Crawl.Example.NET."),
            Some("crawl.example.net".into())
        );
        for value in [
            "",
            "-",
            "123.456",
            ".example",
            "peer..example",
            "peer.example..",
            "peer_name.example",
            "peer name.example",
            "péér.example",
            "peer!example.test",
        ] {
            assert!(canonical_hostname(value).is_none(), "{value:?}");
        }
        let longest = format!(
            "{}.{}.{}.{}.test",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(56)
        );
        assert_eq!(longest.len(), 253);
        assert!(canonical_hostname(&longest).is_some());
        assert!(canonical_hostname(&format!("{longest}.")).is_none());
        assert!(canonical_hostname(&format!("{}.test", "a".repeat(64))).is_none());
        let options = options();
        let mut analysis = Analysis::new().unwrap();
        for value in ["", "-", "bad!value", "peer name.example"] {
            let mut e = event("192.0.2.1", "/", Some(404));
            e.source_ip = Some(value.into());
            analysis.observe(e, &options);
        }
        let mut hostname = event("peer.example", "/", Some(404));
        hostname.client_ip = Some("192.0.2.1".into());
        analysis.observe(hostname, &options);
        let report = analysis.finish(&options);
        assert_eq!(report.summary.requests_without_source_ip, 2);
        assert_eq!(report.summary.requests_with_invalid_source_ip, 2);
        assert_eq!(report.sources[0].identity, "hostname-peer");
        assert_eq!(report.sources[0].source, "peer.example");
    }

    #[test]
    fn json_display_has_explicit_source_kind_and_fixed_structure() {
        let options = options();
        let mut analysis = Analysis::new().unwrap();
        analysis.observe(event("192.0.2.1", "/alfa3.php", Some(404)), &options);
        let report = analysis.finish(&options);
        let mut view = display(&report, true, true, 1);
        assert_eq!(
            view["summary"]["evaluated_sources_by_identity"],
            serde_json::json!({"observed-peer":1})
        );
        assert_eq!(
            view["summary"]["probe_shaped_sources_by_identity"],
            serde_json::json!({"observed-peer":0})
        );
        view["summary"]
            .as_object_mut()
            .unwrap()
            .remove("evaluated_sources_by_identity");
        view["summary"]
            .as_object_mut()
            .unwrap()
            .remove("probe_shaped_sources_by_identity");
        let expected = serde_json::json!({
            "safety_note":SAFETY_NOTE,"sources_not_displayed":0,
            "summary": {"files_analyzed":0,"parseable_records":0,"parse_errors":0,
                "records_outside_time_range":0,"undated_records_excluded_by_time_range":0,
                "requests_without_source_ip":0,"requests_with_invalid_source_ip":0,"requests_without_path":0,
                "requests_without_status":0,"evaluated_sources":1,"probe_shaped_sources":0,"sources_without_status":0,
                "criteria_met":{"catalog_paths":0,"client_error_share":1,"distinct_paths":0,"unserved_path_share":1},
                "criteria_unavailable":{"catalog_paths":0,"client_error_share":0,"distinct_paths":0,"unserved_path_share":0},
                "omissions": Omissions::default()},
            "sources":[{"identity":"observed-peer","source":"192.0.2.1","source_kind":"ip","requests":1,"label":null,
                "criteria":{
                    "catalog_paths":{"value":1.0,"minimum":5.0,"met":false,"unavailable_reason":null},
                    "client_error_share":{"value":100.0,"minimum":80.0,"met":true,"unavailable_reason":null},
                    "distinct_paths":{"value":1.0,"minimum":20.0,"met":false,"unavailable_reason":null},
                    "unserved_path_share":{"value":100.0,"minimum":90.0,"met":true,"unavailable_reason":null}},
                "status_unavailable":0,"client_error_condition_applied":true,"omissions":Omissions::default(),
                "paths_not_displayed":0,"example_paths":["/alfa3.php"]}]
        });
        assert_eq!(
            serde_json::to_vec_pretty(&view).unwrap(),
            serde_json::to_vec_pretty(&expected).unwrap()
        );
    }
}
