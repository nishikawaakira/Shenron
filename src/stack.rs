//! Bounded field-value frequencies over a single offline corpus.
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    net::IpAddr,
    path::Path,
};

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    concentration::{record_status_class, StatusClassCounts},
    event::{
        canonical_ip, HeaderCapability, RawRetention, TelemetryProfile, TrustedProxySet, WebEvent,
    },
    input_discovery::{discover_input_files, InputDiscoverySummary, SkippedInputFile},
    output::write_json_pretty_new_batch,
    production::{
        ensure_separate_output, stream_referenced_events, terminal_safe, HuntTimeRange,
        PathProvenance,
    },
};

pub const SAFETY_NOTE: &str = "Rarity describes observed frequency in this selected corpus, not a determination of maliciousness, attack or automation. New clients and legitimate monitoring tools can have rare values. Observed peers may be shared proxies, CDNs or NATs. Capped fields omit unadmitted values, so their rare-value lists are incomplete; no omitted distinct count is estimated.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Field {
    ContentType,
    Country,
    HeaderName,
    Host,
    Ja3,
    Ja4,
    Method,
    PathDepth,
    PathExtension,
    Protocol,
    QueryKey,
    Status,
    TlsCipher,
    TlsProtocol,
    UserAgent,
}

impl Field {
    pub fn label(self) -> &'static str {
        match self {
            Self::ContentType => "content-type",
            Self::Country => "country",
            Self::HeaderName => "header-name",
            Self::Host => "host",
            Self::Ja3 => "ja3",
            Self::Ja4 => "ja4",
            Self::Method => "method",
            Self::PathDepth => "path-depth",
            Self::PathExtension => "path-extension",
            Self::Protocol => "protocol",
            Self::QueryKey => "query-key",
            Self::Status => "status",
            Self::TlsCipher => "tls-cipher",
            Self::TlsProtocol => "tls-protocol",
            Self::UserAgent => "user-agent",
        }
    }

    fn available(self, profile: TelemetryProfile) -> bool {
        let c = profile.capabilities();
        match self {
            Self::ContentType => {
                c.headers == HeaderCapability::Arbitrary
                    || profile == TelemetryProfile::NginxPostdata
            }
            Self::Country => c.country,
            Self::HeaderName => c.headers == HeaderCapability::Arbitrary,
            Self::Host => c.host,
            Self::Ja3 => c.ja3,
            Self::Ja4 => c.ja4,
            Self::Method => c.method,
            Self::PathDepth | Self::PathExtension => c.uri_path,
            // There is no separate protocol capability; the supported HTTP
            // parsers expose the protocol alongside their structured request.
            Self::Protocol => c.method && c.uri_path,
            Self::QueryKey => c.uri_query,
            Self::Status => c.status,
            Self::TlsCipher => c.tls_cipher,
            Self::TlsProtocol => c.tls_protocol,
            Self::UserAgent => c.user_agent,
        }
    }
}

#[derive(Debug, Clone, clap::Args, Serialize)]
#[group(id = "StackOptions")]
pub struct Options {
    /// Fields to count; repeat or use a comma-separated list. Values remain private.
    #[arg(
        long = "field",
        value_enum,
        value_delimiter = ',',
        default_value = "method,user-agent,path-extension,query-key,status"
    )]
    pub fields: Vec<Field>,
    #[arg(long, default_value_t = 25)]
    pub rarest: usize,
    #[arg(long, default_value_t = 10)]
    pub top: usize,
    #[arg(long, default_value_t = 200_000)]
    pub max_values_per_field: usize,
    /// Independent per-field budget for value/peer and value/verified-client pairs.
    #[arg(long, default_value_t = 2_000_000)]
    pub max_source_pairs_per_field: usize,
    /// Unicode character limit on terminal-safe values in stdout only.
    #[arg(long, default_value_t = 160)]
    pub max_display_length: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            fields: vec![
                Field::Method,
                Field::UserAgent,
                Field::PathExtension,
                Field::QueryKey,
                Field::Status,
            ],
            rarest: 25,
            top: 10,
            max_values_per_field: 200_000,
            max_source_pairs_per_field: 2_000_000,
            max_display_length: 160,
        }
    }
}

impl Options {
    fn validate(&self) -> Result<()> {
        if self.fields.is_empty()
            || [
                self.rarest,
                self.top,
                self.max_values_per_field,
                self.max_source_pairs_per_field,
                self.max_display_length,
            ]
            .contains(&0)
        {
            bail!("stack requires selected fields and positive finite display/tracking counts");
        }
        Ok(())
    }
}

fn recorded(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty() && *v != "-" && *v != "REDACTED")
}

fn values(field: Field, event: &WebEvent) -> BTreeSet<Cow<'_, str>> {
    let mut values = BTreeSet::new();
    let scalar = match field {
        Field::Method => event.method.as_deref(),
        Field::UserAgent => event.user_agent.as_deref(),
        Field::Host => event.host.as_deref(),
        Field::Country => event.country.as_deref(),
        Field::Ja3 => event.ja3.as_deref(),
        Field::Ja4 => event.ja4.as_deref(),
        Field::Protocol => event.protocol.as_deref(),
        Field::TlsCipher => event.tls_cipher.as_deref(),
        Field::TlsProtocol => event.tls_protocol.as_deref(),
        _ => None,
    };
    if let Some(value) = recorded(scalar) {
        values.insert(Cow::Borrowed(value));
    }
    match field {
        Field::ContentType => {
            if let Some(value) = recorded(event.content_type.as_deref()) {
                values.insert(Cow::Borrowed(value));
            }
            for header in &event.headers {
                if header.name.eq_ignore_ascii_case("content-type") {
                    if let Some(value) = recorded(Some(&header.value)) {
                        values.insert(Cow::Borrowed(value));
                    }
                }
            }
        }
        Field::HeaderName => {
            for header in &event.headers {
                if let Some(name) = recorded(Some(&header.name)) {
                    values.insert(Cow::Owned(name.to_ascii_lowercase()));
                }
            }
        }
        Field::QueryKey => {
            if let Some(query) = recorded(event.uri_query.as_deref()) {
                for pair in query.split('&').filter(|pair| !pair.is_empty()) {
                    let key = pair.split_once('=').map_or(pair, |(key, _)| key);
                    if !key.is_empty() {
                        values.insert(Cow::Borrowed(key));
                    }
                }
            }
        }
        Field::PathExtension => {
            if let Some(path) = recorded(event.uri_path.as_deref()) {
                let name = path.rsplit('/').next().unwrap_or("");
                let extension = name
                    .rsplit_once('.')
                    .filter(|(base, ext)| !base.is_empty() && !ext.is_empty())
                    .map_or_else(|| "(none)".into(), |(_, ext)| ext.to_lowercase());
                values.insert(Cow::Owned(extension));
            }
        }
        Field::PathDepth => {
            if let Some(path) = recorded(event.uri_path.as_deref()) {
                values.insert(Cow::Owned(
                    path.split('/')
                        .filter(|s| !s.is_empty())
                        .count()
                        .to_string(),
                ));
            }
        }
        Field::Status => {
            if let Some(status) = event.status {
                values.insert(Cow::Owned(status.to_string()));
            }
        }
        _ => {}
    }
    values
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Histogram {
    pub requests_1: usize,
    pub requests_2_to_9: usize,
    pub requests_10_to_99: usize,
    pub requests_100_to_999: usize,
    pub requests_1000_or_more: usize,
}

impl Histogram {
    fn add(&mut self, requests: u64) {
        match requests {
            1 => self.requests_1 += 1,
            2..=9 => self.requests_2_to_9 += 1,
            10..=99 => self.requests_10_to_99 += 1,
            100..=999 => self.requests_100_to_999 += 1,
            _ => self.requests_1000_or_more += 1,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldSummary {
    pub availability: &'static str,
    pub unavailable_requests: u64,
    pub requests_with_values: Option<u64>,
    pub requests_without_value: Option<u64>,
    pub distinct_values: Option<usize>,
    pub distinct_values_at_least: Option<usize>,
    pub histogram: Option<Histogram>,
    pub requests_beyond_value_cap: u64,
    /// Rejected per-request distinct value observations, not untracked unique values.
    pub value_observations_beyond_cap: u64,
    pub retained_source_pairs: usize,
    pub peer_observations_beyond_source_pair_cap: u64,
    pub client_observations_beyond_source_pair_cap: u64,
}

#[derive(Serialize)]
pub struct Summary {
    pub report_kind: &'static str,
    pub safety_note: &'static str,
    pub files_analyzed: usize,
    #[serde(flatten)]
    pub input_discovery: InputDiscoverySummary,
    pub parseable_records: u64,
    pub parse_errors: u64,
    pub requests_outside_time_range: u64,
    pub undated_records_excluded_by_time_range: u64,
    pub analyzed_requests: u64,
    pub requests_without_peer_ip: u64,
    pub requests_with_invalid_peer_ip: u64,
    pub fields: BTreeMap<Field, FieldSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceCounts {
    pub distinct_sources: Option<usize>,
    pub distinct_sources_at_least: usize,
    pub source_observations_unavailable: u64,
    pub source_observations_beyond_cap: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValueMetrics {
    pub value: String,
    pub requests: u64,
    #[serde(flatten)]
    pub peers: SourceCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_sources: Option<SourceCounts>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub requests_without_timestamp: u64,
    pub response_status_classes: StatusClassCounts,
}

#[derive(Serialize)]
pub struct FieldReport {
    pub values: Vec<ValueMetrics>,
    pub rarest: Vec<ValueMetrics>,
    pub top: Vec<ValueMetrics>,
    pub values_not_in_rarest: usize,
    pub values_not_in_top: usize,
}

#[derive(Serialize)]
pub struct Report {
    pub safety_note: &'static str,
    pub summary: Summary,
    pub fields: BTreeMap<Field, FieldReport>,
}

#[derive(Default)]
struct Sources {
    addresses: BTreeSet<IpAddr>,
    unavailable: u64,
    omissions: u64,
}
impl Sources {
    fn observe(&mut self, ip: Option<IpAddr>, pairs: &mut usize, cap: usize) {
        if let Some(ip) = ip {
            if self.addresses.contains(&ip) {
                return;
            }
            if *pairs < cap {
                self.addresses.insert(ip);
                *pairs += 1;
            } else {
                self.omissions += 1;
            }
        } else {
            self.unavailable += 1;
        }
    }
    fn report(&self) -> SourceCounts {
        SourceCounts {
            distinct_sources: (self.unavailable == 0 && self.omissions == 0)
                .then_some(self.addresses.len()),
            distinct_sources_at_least: self.addresses.len(),
            source_observations_unavailable: self.unavailable,
            source_observations_beyond_cap: self.omissions,
        }
    }
}

#[derive(Default)]
struct ValueAccumulator {
    requests: u64,
    peers: Sources,
    clients: Sources,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
    missing_times: u64,
    statuses: StatusClassCounts,
}
impl ValueAccumulator {
    fn observe(
        &mut self,
        event: &WebEvent,
        peer: Option<IpAddr>,
        client: Option<IpAddr>,
        track_clients: bool,
        pairs: &mut usize,
        cap: usize,
    ) {
        self.requests += 1;
        self.peers.observe(peer, pairs, cap);
        if track_clients {
            self.clients.observe(client, pairs, cap);
        }
        if let Some(time) = event.timestamp {
            self.first = Some(self.first.map_or(time, |old| old.min(time)));
            self.last = Some(self.last.map_or(time, |old| old.max(time)));
        } else {
            self.missing_times += 1;
        }
        record_status_class(&mut self.statuses, event.status);
    }
    fn report(self, value: String, track_clients: bool) -> ValueMetrics {
        ValueMetrics {
            value,
            requests: self.requests,
            peers: self.peers.report(),
            client_sources: track_clients.then(|| self.clients.report()),
            first_seen: self.first,
            last_seen: self.last,
            requests_without_timestamp: self.missing_times,
            response_status_classes: self.statuses,
        }
    }
}

struct FieldAccumulator {
    available: bool,
    missing: u64,
    with_values: u64,
    unavailable: u64,
    omitted_requests: u64,
    omitted_values: u64,
    pairs: usize,
    values: BTreeMap<String, ValueAccumulator>,
}
impl FieldAccumulator {
    fn observe(
        &mut self,
        field: Field,
        event: &WebEvent,
        peer: Option<IpAddr>,
        client: Option<IpAddr>,
        track_clients: bool,
        options: &Options,
    ) {
        if !self.available {
            self.unavailable += 1;
            return;
        }
        let values = values(field, event);
        if values.is_empty() {
            self.missing += 1;
            return;
        }
        self.with_values += 1;
        let mut rejected = false;
        for value in values {
            if let Some(data) = self.values.get_mut(value.as_ref()) {
                data.observe(
                    event,
                    peer,
                    client,
                    track_clients,
                    &mut self.pairs,
                    options.max_source_pairs_per_field,
                );
                continue;
            }
            if self.values.len() >= options.max_values_per_field {
                self.omitted_values += 1;
                rejected = true;
                continue;
            }
            let mut data = ValueAccumulator::default();
            data.observe(
                event,
                peer,
                client,
                track_clients,
                &mut self.pairs,
                options.max_source_pairs_per_field,
            );
            self.values.insert(value.into_owned(), data);
        }
        self.omitted_requests += u64::from(rejected);
    }
    fn finish(self, options: &Options, track_clients: bool) -> (FieldSummary, FieldReport) {
        let mut histogram = Histogram::default();
        let peer_omissions = self.values.values().map(|v| v.peers.omissions).sum();
        let client_omissions = self.values.values().map(|v| v.clients.omissions).sum();
        let mut values: Vec<_> = self
            .values
            .into_iter()
            .map(|(value, data)| {
                histogram.add(data.requests);
                data.report(value, track_clients)
            })
            .collect();
        let summary = FieldSummary {
            availability: if self.available {
                "available"
            } else {
                "unavailable"
            },
            unavailable_requests: self.unavailable,
            requests_with_values: self.available.then_some(self.with_values),
            requests_without_value: self.available.then_some(self.missing),
            distinct_values: (self.available && self.omitted_values == 0).then_some(values.len()),
            distinct_values_at_least: self.available.then_some(values.len()),
            histogram: self.available.then_some(histogram),
            requests_beyond_value_cap: self.omitted_requests,
            value_observations_beyond_cap: self.omitted_values,
            retained_source_pairs: self.pairs,
            peer_observations_beyond_source_pair_cap: peer_omissions,
            client_observations_beyond_source_pair_cap: client_omissions,
        };
        let source_order = |a: &ValueMetrics, b: &ValueMetrics, descending: bool| {
            a.peers
                .distinct_sources
                .is_none()
                .cmp(&b.peers.distinct_sources.is_none())
                .then_with(|| {
                    if descending {
                        b.peers.distinct_sources.cmp(&a.peers.distinct_sources)
                    } else {
                        a.peers.distinct_sources.cmp(&b.peers.distinct_sources)
                    }
                })
        };
        values.sort_by(|a, b| {
            a.requests
                .cmp(&b.requests)
                .then_with(|| source_order(a, b, false))
                .then(a.value.cmp(&b.value))
        });
        let rarest = values.iter().take(options.rarest).cloned().collect();
        values.sort_by(|a, b| {
            b.requests
                .cmp(&a.requests)
                .then_with(|| source_order(a, b, true))
                .then(a.value.cmp(&b.value))
        });
        let top = values.iter().take(options.top).cloned().collect();
        values.sort_by(|a, b| a.value.cmp(&b.value));
        let report = FieldReport {
            values_not_in_rarest: values.len().saturating_sub(options.rarest),
            values_not_in_top: values.len().saturating_sub(options.top),
            values,
            rarest,
            top,
        };
        (summary, report)
    }
}

/// Count selected fields in one shared, fingerprinted input pass; no network lookup.
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
    let mut summary = Summary {
        report_kind: "SANITIZED_STACK",
        safety_note: SAFETY_NOTE,
        files_analyzed: discovery.files.len(),
        input_discovery: discovery.summary,
        parseable_records: 0,
        parse_errors: 0,
        requests_outside_time_range: 0,
        undated_records_excluded_by_time_range: 0,
        analyzed_requests: 0,
        requests_without_peer_ip: 0,
        requests_with_invalid_peer_ip: 0,
        fields: BTreeMap::new(),
    };
    let track_clients = !proxies.configured_proxy_networks().is_empty();
    let mut fields: BTreeMap<_, _> = options
        .fields
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|field| {
            (
                field,
                FieldAccumulator {
                    available: field.available(profile),
                    missing: 0,
                    with_values: 0,
                    unavailable: 0,
                    omitted_requests: 0,
                    omitted_values: 0,
                    pairs: 0,
                    values: BTreeMap::new(),
                },
            )
        })
        .collect();
    let mut corpus = Vec::new();
    for path in discovery.files {
        let provenance =
            stream_referenced_events(&path, profile, RawRetention::Drop, |_, event| {
                match event {
                    Ok(mut event) => {
                        summary.parseable_records += 1;
                        if !range.includes(event.timestamp) {
                            summary.requests_outside_time_range += 1;
                            summary.undated_records_excluded_by_time_range +=
                                u64::from(event.timestamp.is_none());
                        } else {
                            proxies.resolve_client_ip(&mut event);
                            summary.analyzed_requests += 1;
                            let raw_peer = recorded(event.source_ip.as_deref());
                            let peer = raw_peer.and_then(canonical_ip);
                            let client = event.client_ip.as_deref().and_then(canonical_ip);
                            summary.requests_without_peer_ip += u64::from(raw_peer.is_none());
                            summary.requests_with_invalid_peer_ip +=
                                u64::from(raw_peer.is_some() && peer.is_none());
                            for (field, data) in &mut fields {
                                data.observe(*field, &event, peer, client, track_clients, options);
                            }
                        }
                    }
                    Err(_) => summary.parse_errors += 1,
                }
                Ok(())
            })?;
        summary.input_discovery.record_parsing(&provenance);
        corpus.push(provenance);
    }
    let mut private = BTreeMap::new();
    for (field, data) in fields {
        let (field_summary, report) = data.finish(options, track_clients);
        summary.fields.insert(field, field_summary);
        private.insert(field, report);
    }
    let report = Report {
        safety_note: SAFETY_NOTE,
        summary,
        fields: private,
    };
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
            corpus: Vec<PathProvenance>,
            skipped_inputs: &'a [SkippedInputFile],
        }
        let manifest = Manifest { report_kind: "RUN_MANIFEST", safety_note: "PRIVATE input paths and configuration; hashes identify stored bytes, not a security finding.",
            shenron_version: env!("CARGO_PKG_VERSION"), telemetry_profile: profile, from: range.from, to: range.to,
            trusted_proxies: proxies.configured_proxy_networks(), options, corpus, skipped_inputs: &report.summary.input_discovery.skipped };
        #[derive(Serialize)]
        #[serde(untagged)]
        enum Artifact<'a> {
            Private(&'a Report),
            Sanitized(&'a Summary),
            Manifest(&'a Manifest<'a>),
        }
        let paths = [
            output.join("stack.json"),
            output.join("sanitized-stack.json"),
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

fn displayed_value(value: &str, limit: usize) -> (String, bool) {
    let safe = terminal_safe(value);
    let truncated = safe.chars().count() > limit;
    (safe.chars().take(limit).collect(), truncated)
}

pub fn display(report: &Report, show_values: bool, options: &Options) -> serde_json::Value {
    let mut view = serde_json::json!({"summary": report.summary});
    if show_values {
        let fields: BTreeMap<_, _> = report.fields.iter().map(|(field, data)| {
            let rows = |items: &[ValueMetrics]| items.iter().map(|item| {
                let mut value = serde_json::to_value(item).expect("value metrics serialize");
                let (text, truncated) = displayed_value(&item.value, options.max_display_length);
                value["value"] = serde_json::json!(text); value["value_truncated"] = serde_json::json!(truncated); value
            }).collect::<Vec<_>>();
            (*field, serde_json::json!({"rarest":rows(&data.rarest),"top":rows(&data.top),
                "values_not_in_rarest":data.values_not_in_rarest,"values_not_in_top":data.values_not_in_top}))
        }).collect();
        view["fields"] = serde_json::to_value(fields).expect("display fields serialize");
    }
    view
}

pub fn write_text(
    mut writer: impl Write,
    report: &Report,
    show_values: bool,
    options: &Options,
) -> Result<()> {
    let s = &report.summary;
    writeln!(writer, "Field frequency observations\n{SAFETY_NOTE}")?;
    if let Some(disclosure) = s.input_discovery.disclosure() {
        writeln!(writer, "{disclosure}")?;
    }
    writeln!(writer, "Files analyzed: {}\nParseable records: {}\nParse errors: {}\nRequests analyzed: {}\nOutside time range: {} (undated: {})\nUnavailable/invalid peer IP observations: {}/{}", s.files_analyzed, s.parseable_records, s.parse_errors, s.analyzed_requests,
        s.requests_outside_time_range, s.undated_records_excluded_by_time_range, s.requests_without_peer_ip, s.requests_with_invalid_peer_ip)?;
    for (field, summary) in &s.fields {
        if summary.availability == "unavailable" {
            writeln!(
                writer,
                "  {}: unavailable ({} requests)",
                field.label(),
                summary.unavailable_requests
            )?;
            continue;
        }
        let distinct = summary.distinct_values.map_or_else(
            || format!("at least {}", summary.distinct_values_at_least.unwrap_or(0)),
            |n| n.to_string(),
        );
        writeln!(
            writer,
            "  {}: {} distinct values; {} requests without a value",
            field.label(),
            distinct,
            summary.requests_without_value.unwrap_or(0)
        )?;
        if let Some(h) = &summary.histogram {
            writeln!(
                writer,
                "    Histogram 1 / 2-9 / 10-99 / 100-999 / 1000+: {} / {} / {} / {} / {}",
                h.requests_1,
                h.requests_2_to_9,
                h.requests_10_to_99,
                h.requests_100_to_999,
                h.requests_1000_or_more
            )?;
        }
        writeln!(writer, "    Value-cap omissions: {} requests / {} value observations; source-pair omissions: {} peer / {} client observations", summary.requests_beyond_value_cap, summary.value_observations_beyond_cap, summary.peer_observations_beyond_source_pair_cap, summary.client_observations_beyond_source_pair_cap)?;
        if show_values {
            let rows = &report.fields[field];
            for (label, values) in [("Rarest", &rows.rarest), ("Top", &rows.top)] {
                writeln!(writer, "    {label}:")?;
                for row in values {
                    let (value, truncated) =
                        displayed_value(&row.value, options.max_display_length);
                    writeln!(
                        writer,
                        "      {}{}: {} requests, {} peer IPs",
                        value,
                        if truncated { " [truncated]" } else { "" },
                        row.requests,
                        row.peers.distinct_sources.map_or_else(
                            || format!(
                                "unavailable (at least {})",
                                row.peers.distinct_sources_at_least
                            ),
                            |n| n.to_string()
                        )
                    )?;
                    if let Some(clients) = &row.client_sources {
                        writeln!(
                            writer,
                            "        Verified client IPs: {}",
                            clients.distinct_sources.map_or_else(
                                || format!(
                                    "unavailable (at least {})",
                                    clients.distinct_sources_at_least
                                ),
                                |n| n.to_string()
                            )
                        )?;
                    }
                }
            }
            writeln!(
                writer,
                "    Values not in rarest/top lists: {}/{}",
                rows.values_not_in_rarest, rows.values_not_in_top
            )?;
        }
    }
    Ok(())
}
