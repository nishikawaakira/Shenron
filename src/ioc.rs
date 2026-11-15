//! Offline retrospective matches against operator-provided private indicators.
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    hash::{Hash, Hasher},
    io::{BufRead, BufReader, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Args;
use ipnet::IpNet;
use serde::Serialize;

use crate::{
    event::{canonical_ip, RawRetention, TelemetryProfile, TrustedProxySet, WebEvent},
    input_discovery::{discover_input_files, InputDiscoverySummary},
    output::write_json_pretty_new_batch,
    production::{
        ensure_separate_output, stream_referenced_events, terminal_safe, with_fingerprinted_input,
        HuntTimeRange, PathProvenance,
    },
};

mod indicators;
use indicators::{load_indicators, Atom, Indicator, IndicatorFile};

pub const SAFETY_NOTE: &str = "A match records only that an observed request matched an operator-provided indicator. It is not a determination of compromise, an attack, attacker identity, intent or a shared operator. CDN, NAT and shared-cloud addresses can also match unrelated users. Indicator values and labels may be sensitive CTI; review private artifacts before sharing. Analysis is local and offline; no blocking or deployment is performed.";

#[derive(Debug, Clone, Args, Serialize)]
pub struct Options {
    /// Maximum accepted unique indicators; later candidate records are counted, not retained.
    #[arg(long, default_value_t = 1_000_000)]
    pub max_indicators: usize,
    #[arg(long, default_value_t = 100)]
    pub max_records_per_indicator: usize,
    /// Exact distinct observed peers retained per indicator; omissions make the count a lower bound.
    #[arg(long, default_value_t = 100_000)]
    pub max_sources_per_indicator: usize,
}

#[derive(Default, Serialize)]
pub struct Summary {
    pub files_analyzed: usize,
    #[serde(flatten)]
    pub input_discovery: InputDiscoverySummary,
    pub indicator_files: usize,
    pub indicator_records: u64,
    pub loaded_indicators: usize,
    pub loaded_by_type: BTreeMap<String, u64>,
    pub rejected_by_reason: BTreeMap<String, u64>,
    pub duplicate_records: u64,
    pub comment_or_empty_records: u64,
    pub ignored_stix_objects: u64,
    pub records_beyond_indicator_cap: u64,
    pub parseable_records: u64,
    pub parse_errors: u64,
    pub records_outside_time_range: u64,
    pub undated_records_excluded_by_time_range: u64,
    pub analyzed_requests: u64,
    pub matched_indicators: usize,
    /// Distinct input records matching at least one indicator, not indicator/event pairs.
    pub matched_requests: u64,
    pub indicator_matches: u64,
    pub source_ip_matches: u64,
    pub client_ip_matches: u64,
    pub outside_validity_requests: u64,
    pub outside_validity_indicator_matches: u64,
    pub validity_unavailable_matches: u64,
    pub records_beyond_retention_cap: u64,
    pub source_observations_beyond_cap: u64,
    pub matches_without_source_ip: u64,
    pub matches_with_invalid_source_ip: u64,
    /// Fixed field names only; no indicator or log value is a key.
    pub observations_without_field: BTreeMap<String, u64>,
}

impl Summary {
    fn reject(&mut self, reason: &str) {
        *self.rejected_by_reason.entry(reason.into()).or_default() += 1;
    }
}

#[derive(Serialize)]
struct MatchRecord {
    timestamp: Option<DateTime<Utc>>,
    input_file: String,
    line_number: u64,
    method: Option<String>,
    path: Option<String>,
    status: Option<u16>,
    source_ip: Option<String>,
    client_ip: Option<String>,
    matched_on: BTreeSet<&'static str>,
    outside_validity: Option<bool>,
}

#[derive(Serialize)]
struct IndicatorMatches {
    #[serde(flatten)]
    indicator: Indicator,
    matches: u64,
    source_ip_matches: u64,
    client_ip_matches: u64,
    distinct_source_ips: Option<usize>,
    distinct_source_ips_at_least: usize,
    source_observations_beyond_cap: u64,
    matches_without_source_ip: u64,
    matches_with_invalid_source_ip: u64,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    matches_without_timestamp: u64,
    outside_validity_matches: u64,
    validity_unavailable_matches: u64,
    records_omitted: u64,
    records: Vec<MatchRecord>,
    #[serde(skip)]
    sources: BTreeSet<IpAddr>,
}

impl IndicatorMatches {
    fn new(indicator: Indicator) -> Self {
        Self {
            indicator,
            matches: 0,
            source_ip_matches: 0,
            client_ip_matches: 0,
            distinct_source_ips: Some(0),
            distinct_source_ips_at_least: 0,
            source_observations_beyond_cap: 0,
            matches_without_source_ip: 0,
            matches_with_invalid_source_ip: 0,
            first_seen: None,
            last_seen: None,
            matches_without_timestamp: 0,
            outside_validity_matches: 0,
            validity_unavailable_matches: 0,
            records_omitted: 0,
            records: Vec::new(),
            sources: BTreeSet::new(),
        }
    }

    fn observe(
        &mut self,
        event: &WebEvent,
        path: &Path,
        line_number: u64,
        matched_on: BTreeSet<&'static str>,
        options: &Options,
    ) -> Option<bool> {
        self.matches += 1;
        self.source_ip_matches += u64::from(matched_on.contains("source_ip"));
        self.client_ip_matches += u64::from(matched_on.contains("client_ip"));
        match event.source_ip.as_deref() {
            None => self.matches_without_source_ip += 1,
            Some(raw) => match canonical_ip(raw) {
                None => self.matches_with_invalid_source_ip += 1,
                Some(ip) if self.sources.contains(&ip) => {}
                Some(ip) if self.sources.len() < options.max_sources_per_indicator => {
                    self.sources.insert(ip);
                }
                Some(_) => self.source_observations_beyond_cap += 1,
            },
        }
        if let Some(time) = event.timestamp {
            self.first_seen = Some(self.first_seen.map_or(time, |v| v.min(time)));
            self.last_seen = Some(self.last_seen.map_or(time, |v| v.max(time)));
        } else {
            self.matches_without_timestamp += 1;
        }
        let outside = if self.indicator.valid_from.is_none() && self.indicator.valid_until.is_none()
        {
            Some(false)
        } else {
            event.timestamp.map(|time| {
                self.indicator.valid_from.is_some_and(|v| time < v)
                    || self.indicator.valid_until.is_some_and(|v| time >= v)
            })
        };
        self.outside_validity_matches += u64::from(outside == Some(true));
        self.validity_unavailable_matches += u64::from(outside.is_none());
        if self.records.len() < options.max_records_per_indicator {
            self.records.push(MatchRecord {
                timestamp: event.timestamp,
                input_file: path.display().to_string(),
                line_number,
                method: event.method.clone(),
                path: event.uri_path.clone(),
                status: event.status,
                source_ip: event.source_ip.clone(),
                client_ip: event.client_ip.clone(),
                matched_on,
                outside_validity: outside,
            });
        } else {
            self.records_omitted += 1;
        }
        outside
    }
}

#[derive(Serialize)]
pub struct Report {
    safety_note: &'static str,
    pub summary: Summary,
    indicators: Vec<IndicatorMatches>,
}

type StringIndex = HashMap<String, Vec<usize>>;

// Address-only equality permits borrowed HashSet lookup while retaining every
// indicator attached to that exact address, without a second address table.
#[derive(Eq)]
struct ExactIp {
    address: IpAddr,
    indicators: Vec<usize>,
}

impl PartialEq for ExactIp {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Hash for ExactIp {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl Borrow<IpAddr> for ExactIp {
    fn borrow(&self) -> &IpAddr {
        &self.address
    }
}

#[derive(Default)]
struct Index {
    ips: HashSet<ExactIp>,
    v4: BTreeMap<u8, HashMap<u32, Vec<usize>>>,
    v6: BTreeMap<u8, HashMap<u128, Vec<usize>>>,
    paths: StringIndex,
    prefixes: StringIndex,
    prefix_lengths: BTreeSet<usize>,
    agents: StringIndex,
    ja3: StringIndex,
    ja4: StringIndex,
    hosts: StringIndex,
    urls: HashMap<String, StringIndex>,
}

impl Index {
    fn new(indicators: &[IndicatorMatches]) -> Self {
        let mut index = Self::default();
        for (id, row) in indicators.iter().enumerate() {
            for atom in &row.indicator.atoms {
                match atom {
                    Atom::Ip(ip) => {
                        let mut entry = index.ips.take(ip).unwrap_or_else(|| ExactIp {
                            address: *ip,
                            indicators: Vec::new(),
                        });
                        entry.indicators.push(id);
                        index.ips.insert(entry);
                    }
                    Atom::Cidr(IpNet::V4(net)) => index
                        .v4
                        .entry(net.prefix_len())
                        .or_default()
                        .entry(u32::from(net.network()))
                        .or_default()
                        .push(id),
                    Atom::Cidr(IpNet::V6(net)) => index
                        .v6
                        .entry(net.prefix_len())
                        .or_default()
                        .entry(u128::from(net.network()))
                        .or_default()
                        .push(id),
                    Atom::Path(value) => index.paths.entry(value.clone()).or_default().push(id),
                    Atom::Prefix(value) => {
                        index.prefix_lengths.insert(value.len());
                        index.prefixes.entry(value.clone()).or_default().push(id)
                    }
                    Atom::Agent(value) => index.agents.entry(value.clone()).or_default().push(id),
                    Atom::Ja3(value) => index.ja3.entry(value.clone()).or_default().push(id),
                    Atom::Ja4(value) => index.ja4.entry(value.clone()).or_default().push(id),
                    Atom::Host(value) => index.hosts.entry(value.clone()).or_default().push(id),
                    Atom::Url(host, path) => index
                        .urls
                        .entry(host.clone())
                        .or_default()
                        .entry(path.clone())
                        .or_default()
                        .push(id),
                }
            }
        }
        index
    }

    fn address(
        &self,
        raw: &str,
        field: &'static str,
        hits: &mut BTreeMap<usize, BTreeSet<&'static str>>,
    ) {
        let Ok(address) = raw.parse::<IpAddr>() else {
            return;
        };
        let canonical = address.to_canonical();
        add_hits(
            hits,
            self.ips.get(&canonical).map(|entry| &entry.indicators),
            field,
        );
        if let IpAddr::V4(ip) = canonical {
            for (&bits, table) in &self.v4 {
                let mask = u32::MAX.checked_shl(u32::from(32 - bits)).unwrap_or(0);
                add_hits(hits, table.get(&(u32::from(ip) & mask)), field);
            }
            // Preserve mapped-network membership without extending native IPv4 to ::/0.
            let mapped = u128::from(ip.to_ipv6_mapped());
            for (&bits, table) in self.v6.range(96..) {
                let mask = u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0);
                add_hits(hits, table.get(&(mapped & mask)), field);
            }
        }
        if let IpAddr::V6(ip) = address {
            for (&bits, table) in &self.v6 {
                let mask = u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0);
                add_hits(hits, table.get(&(u128::from(ip) & mask)), field);
            }
        }
    }

    fn matches(&self, event: &WebEvent) -> BTreeMap<usize, BTreeSet<&'static str>> {
        let mut hits = BTreeMap::new();
        if let Some(ip) = &event.source_ip {
            self.address(ip, "source_ip", &mut hits);
        }
        if let Some(ip) = &event.client_ip {
            self.address(ip, "client_ip", &mut hits);
        }
        if let Some(path) = &event.uri_path {
            add_hits(&mut hits, self.paths.get(path), "path");
            if !self.prefixes.is_empty() {
                for &end in self.prefix_lengths.range(..=path.len()) {
                    if path.is_char_boundary(end) {
                        add_hits(&mut hits, self.prefixes.get(&path[..end]), "path");
                    }
                }
            }
        }
        for (value, table, field) in [
            (&event.user_agent, &self.agents, "user-agent"),
            (&event.ja3, &self.ja3, "ja3"),
            (&event.ja4, &self.ja4, "ja4"),
        ] {
            if let Some(value) = value {
                add_hits(&mut hits, table.get(value), field);
            }
        }
        if let Some(host) = &event.host {
            let normalized = normalize_host(host);
            add_hits(&mut hits, self.hosts.get(&normalized), "host");
            if let Some(path) = &event.uri_path {
                if let Some(paths) = self.urls.get(&normalized) {
                    add_hits(&mut hits, paths.get(path), "url");
                }
                // Non-default URL ports require an explicitly recorded host port.
                if let Some(port) = host_port(host).1 {
                    if let Some(paths) = self.urls.get(&format!("{normalized}:{port}")) {
                        add_hits(&mut hits, paths.get(path), "url");
                    }
                }
            }
        }
        hits
    }
}

/// Split only an explicit numeric authority port, never an unbracketed IPv6 tail.
fn host_port(value: &str) -> (&str, Option<&str>) {
    let Some((host, port)) = value.rsplit_once(':') else {
        return (value, None);
    };
    let bracketed = host.starts_with('[') && host.ends_with(']');
    if !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && (bracketed || !host.contains(':'))
    {
        (host, Some(port))
    } else {
        (value, None)
    }
}

fn normalize_host(value: &str) -> String {
    let host = host_port(value).0;
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

fn add_hits(
    hits: &mut BTreeMap<usize, BTreeSet<&'static str>>,
    ids: Option<&Vec<usize>>,
    field: &'static str,
) {
    if let Some(ids) = ids {
        for id in ids {
            hits.entry(*id).or_default().insert(field);
        }
    }
}

/// Read local indicators and corpus records once, retaining private evidence separately.
pub fn run(
    input: &Path,
    profile: TelemetryProfile,
    range: &HuntTimeRange,
    proxies: &TrustedProxySet,
    indicator_paths: &[PathBuf],
    options: &Options,
    output: Option<&Path>,
) -> Result<Report> {
    if options.max_indicators == 0
        || options.max_records_per_indicator == 0
        || options.max_sources_per_indicator == 0
    {
        bail!("ioc tracking limits must be positive finite counts");
    }
    if indicator_paths.is_empty() {
        bail!("at least one indicator file is required");
    }
    range.validate()?;
    if let Some(output) = output {
        ensure_separate_output(input, output)?;
        for path in indicator_paths {
            ensure_separate_output(path, output)?;
        }
        for name in [
            "ioc-matches.json",
            "sanitized-ioc.json",
            "run-manifest.json",
        ] {
            let path = output.join(name);
            if path.symlink_metadata().is_ok() {
                bail!("refusing to overwrite existing output: {}", path.display());
            }
        }
    }
    let mut summary = Summary::default();
    let (indicators, indicator_files) = load_indicators(indicator_paths, options, &mut summary)?;
    let mut rows: Vec<_> = indicators.into_iter().map(IndicatorMatches::new).collect();
    let index = Index::new(&rows);
    let discovery = discover_input_files(input, Some(profile))?;
    summary.files_analyzed = discovery.files.len();
    summary.input_discovery = discovery.summary;
    let mut corpus = Vec::new();
    for path in discovery.files {
        corpus.push(stream_referenced_events(
            &path,
            profile,
            RawRetention::Drop,
            |line_number, result| {
                let mut event = match result {
                    Ok(event) => event,
                    Err(_) => {
                        summary.parse_errors += 1;
                        return Ok(());
                    }
                };
                summary.parseable_records += 1;
                if !range.includes(event.timestamp) {
                    summary.records_outside_time_range += 1;
                    summary.undated_records_excluded_by_time_range +=
                        u64::from(event.timestamp.is_none());
                    return Ok(());
                }
                proxies.resolve_client_ip(&mut event);
                summary.analyzed_requests += 1;
                for (field, absent) in [
                    (
                        "source_ip",
                        event.source_ip.as_deref().and_then(canonical_ip).is_none(),
                    ),
                    ("client_ip", event.client_ip.is_none()),
                    ("path", event.uri_path.is_none()),
                    ("user-agent", event.user_agent.is_none()),
                    ("ja3", event.ja3.is_none()),
                    ("ja4", event.ja4.is_none()),
                    ("host", event.host.is_none()),
                ] {
                    if absent {
                        *summary
                            .observations_without_field
                            .entry(field.into())
                            .or_default() += 1;
                    }
                }
                let hits = index.matches(&event);
                summary.matched_requests += u64::from(!hits.is_empty());
                let mut outside = false;
                for (id, fields) in hits {
                    summary.source_ip_matches += u64::from(fields.contains("source_ip"));
                    summary.client_ip_matches += u64::from(fields.contains("client_ip"));
                    summary.indicator_matches += 1;
                    outside |=
                        rows[id].observe(&event, &path, line_number, fields, options) == Some(true);
                }
                summary.outside_validity_requests += u64::from(outside);
                Ok(())
            },
        )?);
    }
    for row in &mut rows {
        row.distinct_source_ips_at_least = row.sources.len();
        row.distinct_source_ips =
            (row.source_observations_beyond_cap == 0).then_some(row.sources.len());
        summary.matched_indicators += usize::from(row.matches > 0);
        summary.outside_validity_indicator_matches += row.outside_validity_matches;
        summary.validity_unavailable_matches += row.validity_unavailable_matches;
        summary.records_beyond_retention_cap += row.records_omitted;
        summary.source_observations_beyond_cap += row.source_observations_beyond_cap;
        summary.matches_without_source_ip += row.matches_without_source_ip;
        summary.matches_with_invalid_source_ip += row.matches_with_invalid_source_ip;
    }
    let report = Report {
        safety_note: SAFETY_NOTE,
        summary,
        indicators: rows,
    };
    if let Some(output) = output {
        #[derive(Serialize)]
        struct Manifest<'a> {
            safety_note: &'static str,
            shenron_version: &'static str,
            telemetry_profile: TelemetryProfile,
            options: &'a Options,
            from: Option<DateTime<Utc>>,
            to: Option<DateTime<Utc>>,
            trusted_proxies: Vec<String>,
            indicators: Vec<IndicatorFile>,
            corpus: Vec<PathProvenance>,
            skipped_inputs: &'a [crate::input_discovery::SkippedInputFile],
        }
        let manifest = Manifest {
            safety_note: SAFETY_NOTE,
            shenron_version: env!("CARGO_PKG_VERSION"),
            telemetry_profile: profile,
            options,
            from: range.from,
            to: range.to,
            trusted_proxies: proxies.configured_proxy_networks(),
            indicators: indicator_files,
            corpus,
            skipped_inputs: &report.summary.input_discovery.skipped,
        };
        #[derive(Serialize)]
        #[serde(untagged)]
        enum Artifact<'a> {
            Private(&'a Report),
            Sanitized(&'a Summary),
            Manifest(Manifest<'a>),
        }
        fs::create_dir_all(output)?;
        let paths = [
            output.join("ioc-matches.json"),
            output.join("sanitized-ioc.json"),
            output.join("run-manifest.json"),
        ];
        write_json_pretty_new_batch(&[
            (paths[0].as_path(), Artifact::Private(&report)),
            (paths[1].as_path(), Artifact::Sanitized(&report.summary)),
            (paths[2].as_path(), Artifact::Manifest(manifest)),
        ])?;
    }
    Ok(report)
}

pub fn write_text(
    mut out: impl Write,
    report: &Report,
    show_matches: bool,
    limit: usize,
) -> Result<()> {
    writeln!(out, "{SAFETY_NOTE}")?;
    if let Some(disclosure) = report.summary.input_discovery.disclosure() {
        writeln!(out, "{disclosure}")?;
    }
    writeln!(out, "IOC summary (aggregate counts only):")?;
    // Summary keys are fixed, or validated type/reason codes; never operator values.
    let summary = serde_json::to_value(&report.summary)?;
    for (key, value) in summary.as_object().expect("summary object") {
        writeln!(out, "  {key}: {value}")?;
    }
    let mut displayed = 0;
    let mut total = 0;
    for row in &report.indicators {
        for record in &row.records {
            total += 1;
            if show_matches && (limit == 0 || displayed < limit) {
                writeln!(out, "  {}: {} / values {} / label {} / {}:{} / timestamp {} / {} {} / status {:?} / matched_on {} / outside_validity {}",
                    displayed + 1, row.indicator.indicator_type,
                    terminal_safe(&row.indicator.values.join(" OR ")),
                    terminal_safe(row.indicator.label.as_deref().unwrap_or("-")),
                    terminal_safe(&record.input_file), record.line_number,
                    record.timestamp.map(|v| v.to_rfc3339()).unwrap_or_else(|| "unavailable".into()),
                    terminal_safe(record.method.as_deref().unwrap_or("-")), terminal_safe(record.path.as_deref().unwrap_or("-")),
                    record.status, record.matched_on.iter().copied().collect::<Vec<_>>().join(","),
                    record.outside_validity.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".into()))?;
                displayed += 1;
            }
        }
    }
    writeln!(
        out,
        "Retained match records not displayed: {}",
        total - displayed
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_prefix_lengths_preserve_all_boundary_matches_for_multibyte_paths() {
        let prefixes = [
            "/",
            "/a",
            "/abc",
            "/a/é",
            "/a/é/案",
            "/a/é/案内",
            "/other",
            "/不存在",
        ];
        let rows: Vec<_> = prefixes
            .iter()
            .map(|prefix| {
                IndicatorMatches::new(Indicator {
                    indicator_type: "path-prefix".into(),
                    values: vec![(*prefix).into()],
                    label: None,
                    input_file: "synthetic.tsv".into(),
                    record_number: 1,
                    valid_from: None,
                    valid_until: None,
                    atoms: vec![Atom::Prefix((*prefix).into())],
                })
            })
            .collect();
        let index = Index::new(&rows);
        assert_eq!(
            index.prefix_lengths,
            prefixes.iter().map(|prefix| prefix.len()).collect()
        );
        for path in [
            "/",
            "/a",
            "/a/é",
            "/a/é/案内/page",
            "/abc/end",
            "/不存在/page",
            "/none/é",
            "",
        ] {
            let mut event = crate::access_log::parse_combined_line(
                "192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"fixture\"",
                crate::access_log::AccessLogFormat::NginxCombined).unwrap();
            event.uri_path = Some(path.into());
            let mut reference = BTreeMap::new();
            // Reference the old implementation, including all UTF-8 character boundaries.
            for end in path
                .char_indices()
                .map(|(i, _)| i)
                .chain(std::iter::once(path.len()))
            {
                add_hits(&mut reference, index.prefixes.get(&path[..end]), "path");
            }
            assert_eq!(index.matches(&event), reference, "{path}");
            assert!(Index::default().matches(&event).is_empty());
        }
    }

    #[test]
    fn indexed_cidrs_match_shared_membership_for_all_prefix_lengths_and_mapped_peers() {
        let mut networks = Vec::new();
        for bits in 0..=32 {
            networks.push(
                IpNet::new("192.0.2.7".parse().unwrap(), bits)
                    .unwrap()
                    .trunc(),
            );
        }
        for ip in ["2001:db8::7", "::ffff:192.0.2.7"] {
            for bits in 0..=128 {
                networks.push(IpNet::new(ip.parse().unwrap(), bits).unwrap().trunc());
            }
        }
        let rows: Vec<_> = networks
            .iter()
            .map(|net| {
                IndicatorMatches::new(Indicator {
                    indicator_type: "cidr".into(),
                    values: vec![net.to_string()],
                    label: None,
                    input_file: "synthetic.tsv".into(),
                    record_number: 1,
                    valid_from: None,
                    valid_until: None,
                    atoms: vec![Atom::Cidr(*net)],
                })
            })
            .collect();
        let index = Index::new(&rows);
        for raw in [
            "192.0.2.0",
            "192.0.2.7",
            "192.0.2.255",
            "192.0.3.0",
            "198.51.100.1",
            "::ffff:192.0.2.0",
            "::ffff:192.0.2.7",
            "::ffff:192.0.2.255",
            "2001:db8::",
            "2001:DB8::7",
            "2001:db8::8",
            "not-an-ip",
        ] {
            let mut actual = BTreeMap::new();
            index.address(raw, "source_ip", &mut actual);
            let expected: BTreeSet<_> = raw
                .parse::<IpAddr>()
                .ok()
                .into_iter()
                .flat_map(|ip| {
                    networks.iter().enumerate().filter_map(move |(i, net)| {
                        crate::event::ip_matches_network(ip, net).then_some(i)
                    })
                })
                .collect();
            assert_eq!(
                actual.keys().copied().collect::<BTreeSet<_>>(),
                expected,
                "{raw}"
            );
        }
    }
}
