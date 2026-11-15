//! Bounded status-pattern observations over one locally selected corpus.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
};

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    event::{RawRetention, TelemetryProfile, TrustedProxySet, WebEvent},
    identifier_access::path_id,
    input_discovery::{discover_input_files, InputDiscoverySummary, SkippedInputFile},
    output::write_json_pretty_new_batch,
    probe_sources::{self, source_key, SourceKey},
    production::{
        ensure_separate_output, stream_referenced_events, terminal_safe, HuntTimeRange,
        PathProvenance,
    },
};

pub const SAFETY_NOTE: &str = "Rare-success describes observed response-status patterns for human review priority, not a security conclusion or attribution. Success means only a configured status class, not an application outcome. Administrative pages, internal APIs, new releases, monitoring and legitimate integrations can have this shape. Sources may be shared proxies, CDNs or NATs. Preceded-by-probe-shape records time order, not causation.";
const DEFAULT_EXTENSIONS: &str = "css,js,map,png,jpg,jpeg,gif,svg,ico,webp,woff,woff2,ttf";

#[derive(Debug, Clone, clap::Args, Serialize)]
#[group(id = "RareSuccessOptions")]
pub struct Options {
    /// Maximum distinct sources with an observed successful status per path.
    #[arg(long, default_value_t = 2)]
    pub max_sources: usize,
    /// Maximum distinct requesting sources per path, including non-success statuses.
    #[arg(long, default_value_t = 5)]
    pub max_requesting_sources: usize,
    /// Comma-separated response status classes; success describes only these codes.
    #[arg(long, value_delimiter = ',', default_value = "2xx")]
    pub success_status: Vec<String>,
    /// Include only these exact, case-sensitive methods; repeat to select several.
    #[arg(long)]
    pub method: Vec<String>,
    /// Case-insensitive final path extensions to exclude; pass '' to disable.
    #[arg(long, value_delimiter = ',', default_value = DEFAULT_EXTENSIONS)]
    pub exclude_extension: Vec<String>,
    /// Retain literal paths instead of sharing identifier-access ID templates.
    #[arg(long)]
    pub no_collapse_identifiers: bool,
    #[arg(long, default_value_t = 1_000_000)]
    pub max_paths: usize,
    /// Independent global limit on retained (path, source identity) pairs.
    #[arg(long, default_value_t = 2_000_000)]
    pub max_path_source_pairs: usize,
    #[arg(long, default_value_t = 5)]
    pub max_examples: usize,
    /// Maximum path groups displayed when private display is enabled.
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
    /// Shared probe-sources thresholds and its independent tracking bounds.
    #[command(flatten)]
    pub probe: probe_sources::Options,
}

impl Options {
    fn validate(&self) -> Result<()> {
        if [
            self.max_sources,
            self.max_requesting_sources,
            self.max_paths,
            self.max_path_source_pairs,
            self.max_examples,
            self.limit,
        ]
        .contains(&0)
        {
            bail!("rare-success counts and tracking limits must be positive finite counts");
        }
        if self.success_status.is_empty()
            || self
                .success_status
                .iter()
                .any(|s| !matches!(s.as_str(), "1xx" | "2xx" | "3xx" | "4xx" | "5xx"))
        {
            bail!("success-status must contain response classes from 1xx through 5xx");
        }
        if self.method.iter().any(|s| {
            s.is_empty()
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        }) {
            bail!("method must be a nonempty HTTP method token");
        }
        self.probe.validate()
    }

    fn succeeds(&self, status: Option<u16>) -> bool {
        status.is_some_and(|s| {
            self.success_status
                .iter()
                .any(|c| s / 100 == u16::from(c.as_bytes()[0] - b'0'))
        })
    }

    fn extensions(&self) -> BTreeSet<String> {
        self.exclude_extension
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .collect()
    }
}

#[derive(Default, Serialize)]
pub struct Summary {
    pub report_kind: &'static str,
    pub safety_note: &'static str,
    pub files_analyzed: usize,
    #[serde(flatten)]
    pub input_discovery: InputDiscoverySummary,
    pub parseable_records: u64,
    pub parse_errors: u64,
    pub records_outside_time_range: u64,
    pub undated_records_excluded_by_time_range: u64,
    pub requests_excluded_by_method: u64,
    pub selected_requests: u64,
    pub probe_classified_requests: u64,
    pub requests_without_status: u64,
    pub requests_without_timestamp: u64,
    pub requests_without_path: u64,
    pub requests_without_usable_source: u64,
    pub requests_excluded_by_extension: u64,
    pub requests_beyond_path_cap: u64,
    pub requests_beyond_path_source_pair_cap: u64,
    pub failure_observations_beyond_source_cap: u64,
    pub retained_paths: usize,
    pub retained_path_source_pairs: usize,
    pub paths_with_incomplete_source_tracking: usize,
    pub paths_with_unavailable_sources: usize,
    pub reported_paths: usize,
    pub methods: BTreeMap<String, u64>,
    pub method_observations_beyond_cap: u64,
    pub reported_method_observations_beyond_cap: u64,
    pub preceded_by_probe_shape: usize,
    pub successful_sources_preceded_by_probe_shape: usize,
    pub examples_omitted: u64,
    pub probe_evaluated_sources: usize,
    pub probe_shaped_sources: usize,
    pub probe_omissions: probe_sources::Omissions,
}

#[derive(Clone, Serialize)]
pub struct Example {
    pub input_file: String,
    pub line_number: u64,
    pub timestamp: Option<DateTime<Utc>>,
    pub method: Option<String>,
    pub status: Option<u16>,
}

#[derive(Clone, Serialize)]
pub struct SuccessfulSource {
    pub source: String,
    pub source_kind: &'static str,
    pub identity: &'static str,
    pub requests: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub preceded_by_probe_shape: bool,
}

#[derive(Serialize)]
pub struct PathObservation {
    pub path: String,
    pub requests: u64,
    pub successful_requests: u64,
    pub distinct_requesting_sources: usize,
    pub distinct_successful_sources: usize,
    pub methods: BTreeMap<String, u64>,
    pub requests_without_method: u64,
    pub method_observations_beyond_cap: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub response_bytes_min: Option<u64>,
    pub response_bytes_max: Option<u64>,
    pub response_bytes_unavailable: u64,
    pub successful_sources: Vec<SuccessfulSource>,
    pub preceded_by_probe_shape: bool,
    pub examples: Vec<Example>,
    pub examples_omitted: u64,
}

#[derive(Serialize)]
pub struct Report {
    pub safety_note: &'static str,
    pub summary: Summary,
    pub paths: Vec<PathObservation>,
}

#[derive(Default)]
struct SourceAccumulator {
    raw: String,
    successes: u64,
    first_success: Option<DateTime<Utc>>,
    last_success: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct PathAccumulator {
    requests: u64,
    successes: u64,
    sources: BTreeMap<SourceKey, SourceAccumulator>,
    incomplete_sources: bool,
    unavailable_sources: u64,
    methods: BTreeMap<String, u64>,
    missing_methods: u64,
    method_omissions: u64,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
    min_bytes: Option<u64>,
    max_bytes: Option<u64>,
    missing_bytes: u64,
    examples: Vec<Example>,
    examples_omitted: u64,
}

fn times(
    first: &mut Option<DateTime<Utc>>,
    last: &mut Option<DateTime<Utc>>,
    time: Option<DateTime<Utc>>,
) {
    if let Some(time) = time {
        *first = Some(first.map_or(time, |old| old.min(time)));
        *last = Some(last.map_or(time, |old| old.max(time)));
    }
}

fn increment(
    map: &mut BTreeMap<String, u64>,
    key: &str,
    cap: usize,
    omissions: &mut u64,
    count: u64,
) {
    if let Some(value) = map.get_mut(key) {
        *value += count;
    } else if map.len() < cap {
        map.insert(key.to_owned(), count);
    } else {
        *omissions += count;
    }
}

fn sanitized_method(method: &str) -> &str {
    match method {
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "TRACE" | "CONNECT"
        | "PROPFIND" | "PROPPATCH" | "MKCOL" | "COPY" | "MOVE" | "LOCK" | "UNLOCK" => method,
        _ => "(other)",
    }
}

struct Analysis {
    summary: Summary,
    paths: BTreeMap<String, PathAccumulator>,
    pairs: usize,
    probe: probe_sources::Analysis,
    first_failures: BTreeMap<SourceKey, DateTime<Utc>>,
    extensions: BTreeSet<String>,
}

impl Analysis {
    fn new(options: &Options) -> Result<Self> {
        Ok(Self {
            summary: Summary {
                report_kind: "SANITIZED_RARE_SUCCESS",
                safety_note: SAFETY_NOTE,
                ..Summary::default()
            },
            paths: BTreeMap::new(),
            pairs: 0,
            probe: probe_sources::Analysis::new()?,
            first_failures: BTreeMap::new(),
            extensions: options.extensions(),
        })
    }

    fn observe(&mut self, event: WebEvent, file: &Path, line: u64, options: &Options) {
        let source = source_key(&event);
        // Probe classification and the earliest 4xx use all dated methods in
        // the time window; method and static exclusions apply only to candidates.
        if let Some(time) = event.timestamp {
            if event.status.is_some_and(|s| (400..500).contains(&s)) {
                if let Some((key, _)) = &source {
                    if let Some(first) = self.first_failures.get_mut(key) {
                        *first = (*first).min(time);
                    } else if self.first_failures.len() < options.probe.max_source_ips {
                        self.first_failures.insert(key.clone(), time);
                    } else {
                        self.summary.failure_observations_beyond_source_cap += 1;
                    }
                }
            }
            self.summary.probe_classified_requests += 1;
            self.probe.observe(event.clone(), &options.probe);
        }
        if !options.method.is_empty()
            && !event
                .method
                .as_ref()
                .is_some_and(|m| options.method.contains(m))
        {
            self.summary.requests_excluded_by_method += 1;
            return;
        }
        self.summary.selected_requests += 1;
        self.summary.requests_without_status += u64::from(event.status.is_none());
        self.summary.requests_without_timestamp += u64::from(event.timestamp.is_none());
        self.summary.requests_without_usable_source += u64::from(source.is_none());
        let Some(path) = &event.uri_path else {
            self.summary.requests_without_path += 1;
            return;
        };
        if path
            .rsplit('/')
            .next()
            .and_then(|name| name.rsplit_once('.'))
            .is_some_and(|(_, ext)| self.extensions.contains(&ext.to_ascii_lowercase()))
        {
            self.summary.requests_excluded_by_extension += 1;
            return;
        }
        let path = if options.no_collapse_identifiers {
            path.clone()
        } else {
            path.split('/')
                .map(|s| path_id(s).map_or_else(|| s.to_owned(), |(_, template)| template))
                .collect::<Vec<_>>()
                .join("/")
        };
        if !self.paths.contains_key(&path) && self.paths.len() >= options.max_paths {
            self.summary.requests_beyond_path_cap += 1;
            return;
        }
        let retained = self.paths.entry(path).or_default();
        retained.requests += 1;
        let success = options.succeeds(event.status);
        retained.successes += u64::from(success);
        if let Some(method) = &event.method {
            increment(
                &mut retained.methods,
                method,
                options.probe.max_auxiliary_values,
                &mut retained.method_omissions,
                1,
            );
        } else {
            retained.missing_methods += 1;
        }
        times(&mut retained.first, &mut retained.last, event.timestamp);
        if let Some(bytes) = event.response_bytes {
            retained.min_bytes = Some(retained.min_bytes.map_or(bytes, |old| old.min(bytes)));
            retained.max_bytes = Some(retained.max_bytes.map_or(bytes, |old| old.max(bytes)));
        } else {
            retained.missing_bytes += 1;
        }
        if retained.examples.len() < options.max_examples {
            retained.examples.push(Example {
                input_file: file.display().to_string(),
                line_number: line,
                timestamp: event.timestamp,
                method: event.method.clone(),
                status: event.status,
            });
        } else {
            retained.examples_omitted += 1;
        }
        let Some((key, raw)) = source else {
            retained.unavailable_sources += 1;
            return;
        };
        if !retained.sources.contains_key(&key) {
            if self.pairs >= options.max_path_source_pairs {
                retained.incomplete_sources = true;
                self.summary.requests_beyond_path_source_pair_cap += 1;
                return;
            }
            retained.sources.insert(
                key.clone(),
                SourceAccumulator {
                    raw: raw.clone(),
                    ..SourceAccumulator::default()
                },
            );
            self.pairs += 1;
        }
        let source = retained
            .sources
            .get_mut(&key)
            .expect("admitted path/source pair");
        if raw < &source.raw {
            source.raw.clone_from(raw);
        }
        if success {
            source.successes += 1;
            times(
                &mut source.first_success,
                &mut source.last_success,
                event.timestamp,
            );
        }
    }

    fn finish(mut self, options: &Options) -> Report {
        let probe = self.probe.finish(&options.probe);
        self.summary.probe_evaluated_sources = probe.summary.evaluated_sources;
        self.summary.probe_shaped_sources = probe.summary.probe_shaped_sources;
        self.summary.probe_omissions = probe.summary.omissions;
        let labeled: BTreeSet<_> = probe
            .sources
            .into_iter()
            .filter(|s| s.label == Some("probe-shaped"))
            .filter_map(|s| s.key())
            .collect();
        self.summary.retained_paths = self.paths.len();
        self.summary.retained_path_source_pairs = self.pairs;
        let mut paths = Vec::new();
        for (path, retained) in self.paths {
            self.summary.paths_with_incomplete_source_tracking +=
                usize::from(retained.incomplete_sources);
            self.summary.paths_with_unavailable_sources +=
                usize::from(retained.unavailable_sources > 0);
            self.summary.method_observations_beyond_cap += retained.method_omissions;
            if retained.incomplete_sources
                || retained.unavailable_sources > 0
                || retained.successes == 0
                || retained.sources.len() > options.max_requesting_sources
            {
                continue;
            }
            let distinct_successful_sources = retained
                .sources
                .values()
                .filter(|s| s.successes > 0)
                .count();
            let distinct_requesting_sources = retained.sources.len();
            if distinct_successful_sources > options.max_sources {
                continue;
            }
            let sources: Vec<_> = retained
                .sources
                .into_iter()
                .filter(|(_, s)| s.successes > 0)
                .map(|(key, s)| {
                    let preceded = labeled.contains(&key)
                        && self
                            .first_failures
                            .get(&key)
                            .is_some_and(|first| s.last_success.is_some_and(|last| last > *first));
                    SuccessfulSource {
                        source: s.raw,
                        source_kind: key.kind(),
                        identity: key.identity(),
                        requests: s.successes,
                        first_seen: s.first_success,
                        last_seen: s.last_success,
                        preceded_by_probe_shape: preceded,
                    }
                })
                .collect();
            let preceded = sources.iter().any(|s| s.preceded_by_probe_shape);
            self.summary.preceded_by_probe_shape += usize::from(preceded);
            self.summary.successful_sources_preceded_by_probe_shape +=
                sources.iter().filter(|s| s.preceded_by_probe_shape).count();
            for (method, requests) in &retained.methods {
                increment(
                    &mut self.summary.methods,
                    sanitized_method(method),
                    options.probe.max_auxiliary_values,
                    &mut self.summary.reported_method_observations_beyond_cap,
                    *requests,
                );
            }
            self.summary.examples_omitted += retained.examples_omitted;
            paths.push(PathObservation {
                path,
                requests: retained.requests,
                successful_requests: retained.successes,
                distinct_requesting_sources,
                distinct_successful_sources,
                methods: retained.methods,
                requests_without_method: retained.missing_methods,
                method_observations_beyond_cap: retained.method_omissions,
                first_seen: retained.first,
                last_seen: retained.last,
                response_bytes_min: retained.min_bytes,
                response_bytes_max: retained.max_bytes,
                response_bytes_unavailable: retained.missing_bytes,
                successful_sources: sources,
                preceded_by_probe_shape: preceded,
                examples: retained.examples,
                examples_omitted: retained.examples_omitted,
            });
        }
        paths.sort_by(|a, b| {
            b.preceded_by_probe_shape
                .cmp(&a.preceded_by_probe_shape)
                .then(
                    a.distinct_successful_sources
                        .cmp(&b.distinct_successful_sources),
                )
                .then(
                    a.distinct_requesting_sources
                        .cmp(&b.distinct_requesting_sources),
                )
                .then(b.first_seen.cmp(&a.first_seen))
                .then(a.path.cmp(&b.path))
        });
        self.summary.reported_paths = paths.len();
        Report {
            safety_note: SAFETY_NOTE,
            summary: self.summary,
            paths,
        }
    }
}

/// Read each input once, sharing event parsing, physical lines and stored-byte hashes.
pub fn run(
    input: &Path,
    profile: TelemetryProfile,
    range: &HuntTimeRange,
    proxies: &TrustedProxySet,
    options: &Options,
    output: Option<&Path>,
) -> Result<Report> {
    options.validate()?;
    range.validate()?;
    if let Some(output) = output {
        ensure_separate_output(input, output)?;
    }
    let discovery = discover_input_files(input, Some(profile))?;
    let mut analysis = Analysis::new(options)?;
    let (catalog_version, catalog_sha256) = analysis.probe.catalog_provenance();
    analysis.summary.files_analyzed = discovery.files.len();
    analysis.summary.input_discovery = discovery.summary;
    let mut corpus = Vec::new();
    for path in discovery.files {
        let provenance =
            stream_referenced_events(&path, profile, RawRetention::Drop, |line, event| {
                match event {
                    Ok(mut event) => {
                        analysis.summary.parseable_records += 1;
                        proxies.resolve_client_ip(&mut event);
                        if range.includes(event.timestamp) {
                            analysis.observe(event, &path, line, options);
                        } else {
                            analysis.summary.records_outside_time_range += 1;
                            analysis.summary.undated_records_excluded_by_time_range +=
                                u64::from(event.timestamp.is_none());
                        }
                    }
                    Err(_) => analysis.summary.parse_errors += 1,
                }
                Ok(())
            })?;
        analysis.summary.input_discovery.record_parsing(&provenance);
        corpus.push(provenance);
    }
    let report = analysis.finish(options);
    if let Some(output) = output {
        fs::create_dir_all(output)?;
        #[derive(Serialize)]
        struct Manifest<'a> {
            report_kind: &'static str,
            safety_note: &'static str,
            shenron_version: &'static str,
            telemetry_profile: TelemetryProfile,
            from: Option<DateTime<Utc>>,
            to: Option<DateTime<Utc>>,
            trusted_proxies: Vec<String>,
            options: &'a Options,
            excluded_extensions: BTreeSet<String>,
            probe_catalog_version: u32,
            probe_catalog_sha256: String,
            corpus: Vec<PathProvenance>,
            skipped_inputs: &'a [SkippedInputFile],
        }
        let manifest = Manifest { report_kind: "RUN_MANIFEST", safety_note: "PRIVATE input paths and options. Corpus hashes identify stored bytes, not a security conclusion.",
            shenron_version: env!("CARGO_PKG_VERSION"), telemetry_profile: profile, from: range.from, to: range.to,
            trusted_proxies: proxies.configured_proxy_networks(), options, excluded_extensions: options.extensions(),
            probe_catalog_version: catalog_version, probe_catalog_sha256: catalog_sha256, corpus, skipped_inputs: &report.summary.input_discovery.skipped };
        #[derive(Serialize)]
        #[serde(untagged)]
        enum Artifact<'a> {
            Private(&'a Report),
            Sanitized(&'a Summary),
            Manifest(&'a Manifest<'a>),
        }
        let paths = [
            output.join("rare-success.json"),
            output.join("sanitized-rare-success.json"),
            output.join("run-manifest.json"),
        ];
        write_json_pretty_new_batch(&[
            (paths[0].as_path(), Artifact::Private(&report)),
            (paths[1].as_path(), Artifact::Sanitized(&report.summary)),
            (paths[2].as_path(), Artifact::Manifest(&manifest)),
        ])?;
    }
    Ok(report)
}

pub fn display(
    report: &Report,
    show_paths: bool,
    show_sources: bool,
    limit: usize,
) -> serde_json::Value {
    let mut view = serde_json::json!({"summary": report.summary,
        "paths_not_displayed": report.paths.len().saturating_sub(if show_paths || show_sources { limit } else { 0 })});
    if show_paths || show_sources {
        let rows: Vec<_> = report
            .paths
            .iter()
            .take(limit)
            .map(|path| {
                let mut row = serde_json::to_value(path).expect("path observations serialize");
                if !show_paths {
                    row.as_object_mut().expect("path object").remove("path");
                    row.as_object_mut().expect("path object").remove("examples");
                }
                if !show_sources {
                    row.as_object_mut()
                        .expect("path object")
                        .remove("successful_sources");
                }
                row
            })
            .collect();
        view["paths"] = serde_json::json!(rows);
    }
    view
}

pub fn write_text(
    mut writer: impl Write,
    report: &Report,
    show_paths: bool,
    show_sources: bool,
    limit: usize,
) -> Result<()> {
    let s = &report.summary;
    writeln!(writer, "Rare-success observations\n{SAFETY_NOTE}")?;
    if let Some(disclosure) = s.input_discovery.disclosure() {
        writeln!(writer, "{disclosure}")?;
    }
    writeln!(writer, "Files analyzed: {}\nParseable records: {}\nParse errors: {}\nSelected requests: {}\nReported paths: {}\nPaths preceded by probe shape: {}", s.files_analyzed, s.parseable_records, s.parse_errors, s.selected_requests, s.reported_paths, s.preceded_by_probe_shape)?;
    writeln!(
        writer,
        "Probe-classified requests: {}",
        s.probe_classified_requests
    )?;
    writeln!(writer, "Excluded method/extension requests: {}/{}\nUnavailable status/time/path/source: {}/{}/{}/{}\nOutside time range: {} (undated: {})\nRequests beyond path/pair caps: {}/{}\nPaths with incomplete/unavailable source counts: {}/{}\nFailure observations beyond source cap: {}\nMethod observations beyond caps: {}/{}\nExamples omitted: {}", s.requests_excluded_by_method, s.requests_excluded_by_extension, s.requests_without_status, s.requests_without_timestamp, s.requests_without_path, s.requests_without_usable_source, s.records_outside_time_range, s.undated_records_excluded_by_time_range, s.requests_beyond_path_cap, s.requests_beyond_path_source_pair_cap, s.paths_with_incomplete_source_tracking, s.paths_with_unavailable_sources, s.failure_observations_beyond_source_cap, s.method_observations_beyond_cap, s.reported_method_observations_beyond_cap, s.examples_omitted)?;
    for (method, requests) in &s.methods {
        writeln!(writer, "  Method {}: {requests}", terminal_safe(method))?;
    }
    writeln!(
        writer,
        "Probe-shaped sources: {} / {} evaluated\nProbe tracking omissions: {}",
        s.probe_shaped_sources,
        s.probe_evaluated_sources,
        serde_json::to_string(&s.probe_omissions)?
    )?;
    if show_paths || show_sources {
        for (index, path) in report.paths.iter().take(limit).enumerate() {
            writeln!(
                writer,
                "  Candidate {}: {} requests, {} successful sources, preceded_by_probe_shape={}",
                index + 1,
                path.requests,
                path.distinct_successful_sources,
                path.preceded_by_probe_shape
            )?;
            if show_paths {
                writeln!(writer, "    Path: {}", terminal_safe(&path.path))?;
                for example in &path.examples {
                    writeln!(
                        writer,
                        "    Example: {}:{} time={} method={} status={}",
                        terminal_safe(&example.input_file),
                        example.line_number,
                        example
                            .timestamp
                            .map_or_else(|| "unavailable".into(), |t| t.to_rfc3339()),
                        terminal_safe(example.method.as_deref().unwrap_or("unavailable")),
                        example
                            .status
                            .map_or_else(|| "unavailable".into(), |s| s.to_string())
                    )?;
                }
            }
            if show_sources {
                for source in &path.successful_sources {
                    writeln!(writer, "    Source [{}; {}]: {} ({} successful responses; preceded_by_probe_shape={})", source.identity, source.source_kind, terminal_safe(&source.source), source.requests, source.preceded_by_probe_shape)?;
                }
            }
        }
    }
    let displayed = if show_paths || show_sources {
        limit.min(report.paths.len())
    } else {
        0
    };
    writeln!(
        writer,
        "Path groups not displayed: {}",
        report.paths.len() - displayed
    )?;
    Ok(())
}
