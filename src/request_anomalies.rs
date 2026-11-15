//! Bounded observations of logged request spellings, with command-local recovery.

mod features;
mod reader;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Write},
    path::Path,
};

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    access_log::MAX_COMBINED_LINE_BYTES,
    concentration::{record_status_class, StatusClassCounts},
    event::{canonical_address_or_raw, RawRetention, TelemetryProfile},
    input_discovery::{discover_input_files, InputDiscoverySummary},
    output::write_json_pretty_new_batch,
    production::{
        ensure_separate_output, stream_referenced_events, terminal_safe, with_fingerprinted_input,
        HuntTimeRange, PathProvenance,
    },
};

pub use features::Feature;

pub const SAFETY_NOTE: &str = "Request-string shape observations only, not a determination of attack, successful exploitation, compromise, intent, or identity. Client bugs, multilingual filenames, old proxies and health checks can produce the same shapes. An observed 2xx response does not establish successful exploitation. Sources are observed connection peers and may be proxies, CDNs or NATs.";

#[derive(Debug, Clone, clap::Args, Serialize)]
pub struct Options {
    /// Flag targets strictly longer than this many logged request-target bytes.
    #[arg(long, default_value_t = 2048)]
    pub max_target_length: usize,
    /// Maximum retained examples per feature, in sorted file/physical-line order.
    #[arg(long, default_value_t = 10)]
    pub max_examples: usize,
    /// Maximum source rows and distinct sources retained per feature.
    #[arg(long, default_value_t = 100_000)]
    pub max_source_ips: usize,
    /// Maximum distinct raw paths retained per feature; independent of other commands.
    #[arg(long, default_value_t = 100_000)]
    pub max_paths_per_feature: usize,
    /// Source rows retained in private output and available for explicit display.
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_target_length: 2048,
            max_examples: 10,
            max_source_ips: 100_000,
            max_paths_per_feature: 100_000,
            limit: 20,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FeatureSummary {
    pub requests: u64,
    pub distinct_sources: Option<usize>,
    pub distinct_sources_at_least: usize,
    pub source_observations_beyond_tracking_cap: u64,
    pub requests_without_source: u64,
    pub distinct_paths: Option<usize>,
    pub distinct_paths_at_least: usize,
    pub path_observations_beyond_tracking_cap: u64,
    pub requests_without_path: u64,
    pub status_classes: StatusClassCounts,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub requests_without_timestamp: u64,
    pub responses_2xx: u64,
    pub examples_omitted: u64,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub report_kind: &'static str,
    pub safety_note: &'static str,
    pub files_analyzed: usize,
    #[serde(flatten)]
    pub input_discovery: InputDiscoverySummary,
    pub parseable_records: u64,
    pub rescued_records: u64,
    pub parse_errors: u64,
    pub records_outside_time_range: u64,
    pub undated_records_excluded_by_time_range: u64,
    pub analyzed_requests: u64,
    pub requests_with_features: u64,
    pub targets_unavailable: u64,
    pub paths_unavailable: u64,
    pub request_bodies_unavailable: u64,
    pub request_lines_unavailable: u64,
    pub sources_unavailable: u64,
    pub requests_beyond_source_tracking_cap: u64,
    pub tracked_sources: usize,
    pub sources_not_reported: usize,
    pub features: BTreeMap<Feature, FeatureSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Example {
    pub input_file: String,
    pub line_number: u64,
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub raw_target: Option<String>,
    /// Logged request line, useful when no HTTP target can be identified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_line: Option<String>,
    pub observed_in: BTreeSet<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SourceSummary {
    pub source: String,
    pub requests_with_features: u64,
    pub features: BTreeMap<Feature, u64>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub safety_note: &'static str,
    pub summary: Summary,
    pub feature_examples: BTreeMap<Feature, Vec<Example>>,
    pub sources: Vec<SourceSummary>,
}

#[derive(Default)]
struct FeatureAccumulator {
    summary: FeatureSummary,
    sources: BTreeSet<String>,
    paths: BTreeSet<Vec<u8>>,
    examples: Vec<Example>,
}

struct Analysis {
    summary: Summary,
    features: BTreeMap<Feature, FeatureAccumulator>,
    sources: BTreeMap<String, SourceSummary>,
}

impl Analysis {
    fn new(files: usize, discovery: InputDiscoverySummary) -> Self {
        Self {
            summary: Summary {
                report_kind: "SANITIZED_REQUEST_ANOMALIES",
                safety_note: SAFETY_NOTE,
                files_analyzed: files,
                input_discovery: discovery,
                parseable_records: 0,
                rescued_records: 0,
                parse_errors: 0,
                records_outside_time_range: 0,
                undated_records_excluded_by_time_range: 0,
                analyzed_requests: 0,
                requests_with_features: 0,
                targets_unavailable: 0,
                paths_unavailable: 0,
                request_bodies_unavailable: 0,
                request_lines_unavailable: 0,
                sources_unavailable: 0,
                requests_beyond_source_tracking_cap: 0,
                tracked_sources: 0,
                sources_not_reported: 0,
                features: BTreeMap::new(),
            },
            features: Feature::ALL
                .into_iter()
                .map(|feature| (feature, FeatureAccumulator::default()))
                .collect(),
            sources: BTreeMap::new(),
        }
    }

    fn error(&mut self, reason: &str) {
        self.summary.parse_errors += 1;
        *self
            .summary
            .input_discovery
            .parse_error_reasons
            .entry(reason.to_owned())
            .or_default() += 1;
    }

    fn observe(
        &mut self,
        mut row: reader::Observation,
        input: &Path,
        line: u64,
        range: &HuntTimeRange,
        options: &Options,
    ) {
        if row.rescued {
            self.summary.rescued_records += 1;
        } else {
            self.summary.parseable_records += 1;
        }
        if !range.includes(row.timestamp) {
            self.summary.records_outside_time_range += 1;
            self.summary.undated_records_excluded_by_time_range +=
                u64::from(row.timestamp.is_none());
            return;
        }
        if row
            .source
            .as_deref()
            .is_some_and(|source| source.is_empty() || source == "-" || source == "REDACTED")
        {
            row.source = None;
        }
        self.summary.analyzed_requests += 1;
        self.summary.targets_unavailable += u64::from(row.target.is_none());
        self.summary.paths_unavailable += u64::from(row.path.is_none());
        self.summary.request_bodies_unavailable += u64::from(row.body.is_none());
        self.summary.request_lines_unavailable += u64::from(row.request_line.is_none());
        self.summary.sources_unavailable += u64::from(row.source.is_none());
        if let Some(target) = &row.target {
            features::inspect_bytes(target, "target", &mut row.features);
            if target.len() > options.max_target_length {
                features::mark(&mut row.features, Feature::LongTarget, "target");
            }
        } else if let Some(path) = &row.path {
            features::inspect_bytes(path, "path", &mut row.features);
        }
        if let Some(path) = &row.path {
            features::inspect_path(path, &mut row.features);
        }
        if let Some(body) = &row.body {
            features::inspect_bytes(body, "request-body", &mut row.features);
        }
        if row.features.contains_key(&Feature::NonHttpRequestLine) {
            if let Some(line) = &row.request_line {
                features::inspect_bytes(
                    &reader::log_bytes(line),
                    "request-line",
                    &mut row.features,
                );
            }
        }
        if row.features.is_empty() {
            return;
        }
        self.summary.requests_with_features += 1;
        let source = row.source.as_deref().map(canonical_address_or_raw);
        if let (Some(key), Some(raw)) = (&source, &row.source) {
            if self.sources.contains_key(key) || self.sources.len() < options.max_source_ips {
                let source = self
                    .sources
                    .entry(key.clone())
                    .or_insert_with(|| SourceSummary {
                        source: raw.clone(),
                        requests_with_features: 0,
                        features: BTreeMap::new(),
                    });
                if raw < &source.source {
                    source.source.clone_from(raw);
                }
                source.requests_with_features += 1;
                for feature in row.features.keys() {
                    *source.features.entry(*feature).or_default() += 1;
                }
            } else {
                self.summary.requests_beyond_source_tracking_cap += 1;
            }
        }
        for (feature, origins) in row.features {
            let item = self.features.entry(feature).or_default();
            item.summary.requests += 1;
            record_status_class(&mut item.summary.status_classes, row.status);
            item.summary.responses_2xx += u64::from(
                row.status
                    .is_some_and(|status| (200..300).contains(&status)),
            );
            if let Some(time) = row.timestamp {
                item.summary.first_seen = Some(
                    item.summary
                        .first_seen
                        .map_or(time, |previous| previous.min(time)),
                );
                item.summary.last_seen = Some(
                    item.summary
                        .last_seen
                        .map_or(time, |previous| previous.max(time)),
                );
            } else {
                item.summary.requests_without_timestamp += 1;
            }
            if let Some(source) = &source {
                if item.sources.contains(source) || item.sources.len() < options.max_source_ips {
                    item.sources.insert(source.clone());
                } else {
                    item.summary.source_observations_beyond_tracking_cap += 1;
                }
            } else {
                item.summary.requests_without_source += 1;
            }
            if let Some(path) = &row.path {
                if item.paths.contains(path) || item.paths.len() < options.max_paths_per_feature {
                    item.paths.insert(path.clone());
                } else {
                    item.summary.path_observations_beyond_tracking_cap += 1;
                }
            } else {
                item.summary.requests_without_path += 1;
            }
            if item.examples.len() < options.max_examples {
                item.examples.push(Example {
                    input_file: input.display().to_string(),
                    line_number: line,
                    timestamp: row.timestamp,
                    source: row.source.clone(),
                    raw_target: row.target.as_deref().map(reader::byte_spelling),
                    request_line: row.rescued.then(|| row.request_line.clone()).flatten(),
                    observed_in: origins,
                });
            } else {
                item.summary.examples_omitted += 1;
            }
        }
    }

    fn finish(mut self, options: &Options) -> Report {
        let mut examples = BTreeMap::new();
        for (feature, mut item) in self.features {
            item.summary.distinct_sources_at_least = item.sources.len();
            item.summary.distinct_sources = (item.summary.source_observations_beyond_tracking_cap
                == 0
                && item.summary.requests_without_source == 0)
                .then_some(item.sources.len());
            item.summary.distinct_paths_at_least = item.paths.len();
            item.summary.distinct_paths = (item.summary.path_observations_beyond_tracking_cap == 0
                && item.summary.requests_without_path == 0)
                .then_some(item.paths.len());
            item.examples.sort_by(|a, b| {
                a.timestamp
                    .cmp(&b.timestamp)
                    .then_with(|| a.input_file.cmp(&b.input_file))
                    .then(a.line_number.cmp(&b.line_number))
            });
            self.summary.features.insert(feature, item.summary);
            examples.insert(feature, item.examples);
        }
        self.summary.tracked_sources = self.sources.len();
        let mut sources = self.sources.into_iter().collect::<Vec<_>>();
        sources.sort_by(|(a_key, a), (b_key, b)| {
            b.requests_with_features
                .cmp(&a.requests_with_features)
                .then(a_key.cmp(b_key))
        });
        self.summary.sources_not_reported = sources.len().saturating_sub(options.limit);
        Report {
            safety_note: SAFETY_NOTE,
            summary: self.summary,
            feature_examples: examples,
            sources: sources
                .into_iter()
                .take(options.limit)
                .map(|(_, source)| source)
                .collect(),
        }
    }
}

/// Analyze immutable local inputs; recovery is confined to this command.
pub fn run(
    input: &Path,
    profile: TelemetryProfile,
    range: &HuntTimeRange,
    options: &Options,
    output: Option<&Path>,
) -> Result<Report> {
    if [
        options.max_target_length,
        options.max_examples,
        options.max_source_ips,
        options.max_paths_per_feature,
        options.limit,
    ]
    .contains(&0)
    {
        bail!("request-anomalies limits must be positive finite counts");
    }
    range.validate()?;
    if let Some(output) = output {
        ensure_separate_output(input, output)?;
    }
    let discovery = discover_input_files(input, Some(profile))?;
    let mut analysis = Analysis::new(discovery.files.len(), discovery.summary);
    let mut corpus = Vec::new();
    for path in discovery.files {
        let provenance = if let Some(format) = reader::format(profile) {
            with_fingerprinted_input(&path, |decoded| {
                let mut decoded = BufReader::new(decoded);
                let mut bytes = Vec::new();
                let mut line = 0;
                loop {
                    bytes.clear();
                    if decoded.read_until(b'\n', &mut bytes)? == 0 {
                        break;
                    }
                    line += 1;
                    if bytes.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    if bytes.len() > MAX_COMBINED_LINE_BYTES {
                        analysis.error("line-too-long");
                        continue;
                    }
                    while bytes.last().is_some_and(|b| matches!(*b, b'\r' | b'\n')) {
                        bytes.pop();
                    }
                    match reader::combined(&bytes, format) {
                        Ok(row) => analysis.observe(row, &path, line, range, options),
                        Err(reason) => analysis.error(reason),
                    }
                }
                Ok(())
            })?
        } else {
            stream_referenced_events(&path, profile, RawRetention::Drop, |line, event| {
                match event {
                    Ok(event) => {
                        analysis.observe(reader::event(event), &path, line, range, options)
                    }
                    Err(_) => {
                        analysis.summary.parse_errors += 1;
                        if profile == TelemetryProfile::AwsWaf {
                            *analysis
                                .summary
                                .input_discovery
                                .parse_error_reasons
                                .entry("invalid-json".into())
                                .or_default() += 1;
                        }
                    }
                }
                Ok(())
            })?
        };
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
            decoding_passes: u8,
            plus_is_space: bool,
            options: &'a Options,
            corpus: Vec<PathProvenance>,
            skipped_inputs: &'a [crate::input_discovery::SkippedInputFile],
        }
        let manifest = Manifest { report_kind: "RUN_MANIFEST", safety_note: "PRIVATE input paths and options. Input hashes identify stored bytes, not a security finding.",
            shenron_version: env!("CARGO_PKG_VERSION"), telemetry_profile: profile, from: range.from, to: range.to,
            decoding_passes: 2, plus_is_space: false, options, corpus, skipped_inputs: &report.summary.input_discovery.skipped };
        #[derive(Serialize)]
        #[serde(untagged)]
        enum Artifact<'a> {
            Private(&'a Report),
            Sanitized(&'a Summary),
            Manifest(&'a Manifest<'a>),
        }
        let paths = [
            output.join("request-anomalies.json"),
            output.join("sanitized-request-anomalies.json"),
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

pub fn display(report: &Report, show_examples: bool, show_sources: bool) -> serde_json::Value {
    let mut view = serde_json::json!({"summary": report.summary});
    if show_sources {
        view["sources"] =
            serde_json::to_value(&report.sources).expect("source summaries serialize");
    }
    if show_examples {
        let mut examples = report.feature_examples.clone();
        if !show_sources {
            for rows in examples.values_mut() {
                for row in rows {
                    row.source = None;
                }
            }
        }
        view["feature_examples"] = serde_json::to_value(examples).expect("examples serialize");
    }
    view
}

pub fn write_text(
    mut writer: impl Write,
    report: &Report,
    show_examples: bool,
    show_sources: bool,
) -> Result<()> {
    let s = &report.summary;
    writeln!(writer, "Request anomaly observations\n{}", SAFETY_NOTE)?;
    if let Some(disclosure) = s.input_discovery.disclosure() {
        writeln!(writer, "{disclosure}")?;
    }
    writeln!(writer, "Files analyzed: {}\nParseable records: {}\nRescued records: {}\nParse errors: {}\nRequests analyzed: {}\nRequests with features: {}", s.files_analyzed, s.parseable_records, s.rescued_records, s.parse_errors, s.analyzed_requests, s.requests_with_features)?;
    writeln!(writer, "Unavailable target/path/body/source observations: {}/{}/{}/{}\nUnavailable request-line observations: {}\nOutside time range: {} (undated: {})\nSource requests beyond tracking cap: {}\nTracked source rows not reported: {}", s.targets_unavailable, s.paths_unavailable, s.request_bodies_unavailable, s.sources_unavailable, s.request_lines_unavailable, s.records_outside_time_range, s.undated_records_excluded_by_time_range, s.requests_beyond_source_tracking_cap, s.sources_not_reported)?;
    for (feature, counts) in &s.features {
        writeln!(writer, "{}: {} requests, sources >= {}, paths >= {}, 2xx {} (not an exploitation determination); source/path cap omissions {}/{}, examples omitted {}", feature.label(), counts.requests, counts.distinct_sources_at_least, counts.distinct_paths_at_least, counts.responses_2xx, counts.source_observations_beyond_tracking_cap, counts.path_observations_beyond_tracking_cap, counts.examples_omitted)?;
        writeln!(writer, "  status 1xx/2xx/3xx/4xx/5xx/other/unavailable: {}/{}/{}/{}/{}/{}/{}; first={} last={} undated={}",
            counts.status_classes.informational, counts.status_classes.success, counts.status_classes.redirection,
            counts.status_classes.client_error, counts.status_classes.server_error, counts.status_classes.other,
            counts.status_classes.unavailable, counts.first_seen.map(|t| t.to_rfc3339()).unwrap_or_else(|| "unavailable".into()),
            counts.last_seen.map(|t| t.to_rfc3339()).unwrap_or_else(|| "unavailable".into()), counts.requests_without_timestamp)?;
        if show_examples {
            for row in &report.feature_examples[feature] {
                write!(
                    writer,
                    "  {}:{} time={} target={}",
                    terminal_safe(&row.input_file),
                    row.line_number,
                    row.timestamp
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| "unavailable".into()),
                    terminal_safe(row.raw_target.as_deref().unwrap_or("<unavailable>"))
                )?;
                if let Some(request) = &row.request_line {
                    write!(writer, " request-line={}", terminal_safe(request))?;
                }
                if show_sources {
                    write!(
                        writer,
                        " source={}",
                        terminal_safe(row.source.as_deref().unwrap_or("<unavailable>"))
                    )?;
                }
                writeln!(writer)?;
            }
        }
    }
    if show_sources {
        for source in &report.sources {
            writeln!(
                writer,
                "Source {}: {} requests with features; {}",
                terminal_safe(&source.source),
                source.requests_with_features,
                source
                    .features
                    .iter()
                    .map(|(f, n)| format!("{}: {n}", f.label()))
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
    }
    Ok(())
}
