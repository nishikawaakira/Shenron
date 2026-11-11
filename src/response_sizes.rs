//! Offline size differences and character-position observations, never recovered content.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
    sync::OnceLock,
};

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use clap::Args;
use regex::Regex;
use serde::Serialize;

use crate::{
    access_log::{AccessLogLines, AccessLogParseError},
    event::{canonical_address_or_raw, RawRetention, TelemetryProfile, TrustedProxySet, WebEvent},
    input_discovery::{discover_input_files, InputDiscoverySummary},
    output::write_json_pretty_new_batch,
    production::{
        ensure_separate_output, stream_events_with_fingerprint, terminal_safe,
        with_fingerprinted_input, HuntTimeRange,
    },
};

pub const SAFETY_NOTE: &str = "Response-size estimates describe lengths, never content, and are not a determination of data disclosure. They assume the response is not compressed, does not vary over time, and repeats the request in the same way for the control and the read. fit_rate checks only parity for HEX-wrapped reads; CAST-only reads are unchecked. Positions probed by character-by-character reads are not lengths.";

#[derive(Debug, Clone, Args, Serialize)]
pub struct Options {
    /// Maximum retained matching requests; later observations are counted as omitted.
    #[arg(long, default_value_t = 1_000_000)]
    pub max_observations: usize,
}

#[derive(Default, Serialize)]
pub struct Summary {
    files_analyzed: usize,
    #[serde(flatten)]
    pub input_discovery: InputDiscoverySummary,
    parseable_records: u64,
    parse_errors: u64,
    truncated_body: u64,
    error_log_lines: u64,
    invalid_utf8_lines: u64,
    records_outside_time_range: u64,
    analyzed_requests: u64,
    requests_without_shape: u64,
    requests_with_multiple_shapes: u64,
    requests_with_unsupported_decoding: u64,
    requests_without_required_fields: u64,
    observations_beyond_cap: u64,
    retained_observations: usize,
    groups_without_control: usize,
    requests_without_control: u64,
    control_requests: u64,
    paired_requests: u64,
    length: u64,
    empty_or_null: u64,
    negative_estimate: u64,
    not_fitting: u64,
    character_requests: u64,
    paired_expressions: usize,
    character_expressions: usize,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Peer {
    identity: &'static str,
    source: String,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Group {
    host: Option<String>,
    peer: Peer,
    method: String,
    path: String,
    status: u16,
    target_shape: String,
    body_shape: String,
    multiplier: i128,
}

struct Observation {
    expression: String,
    response_bytes: u64,
    request_bytes: usize,
    timestamp: DateTime<Utc>,
    control_length: Option<i128>,
}

#[derive(Serialize)]
struct Estimate {
    #[serde(flatten)]
    peer: Peer,
    timestamp: DateTime<Utc>,
    baseline_timestamp: DateTime<Utc>,
    baseline_length: i128,
    multiplier: i128,
    response_byte_delta: i128,
    request_byte_delta: i128,
    adjusted_delta: i128,
    outcome: &'static str,
    estimated_length: Option<i128>,
}

#[derive(Default, Serialize)]
struct PairedExpression {
    host: Option<String>,
    expression: String,
    requests: u64,
    distinct_sources: usize,
    estimated_lengths: BTreeSet<i128>,
    negative_candidates: Vec<NegativeCandidate>,
    negative_estimate: u64,
    empty_or_null: u64,
    not_fitting: u64,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    estimates: Vec<Estimate>,
    #[serde(skip)]
    sources: BTreeSet<Peer>,
    #[serde(skip)]
    negative_counts: BTreeMap<i128, u64>,
}

#[derive(Serialize)]
struct NegativeCandidate {
    value: i128,
    requests: u64,
}

#[derive(Serialize)]
struct SizeCount {
    response_bytes: u64,
    requests: u64,
}

#[derive(Default, Serialize)]
struct CharacterExpression {
    host: Option<String>,
    expression: String,
    requests: u64,
    distinct_sources: usize,
    positions_probed: usize,
    max_position: u64,
    response_sizes_by_status: BTreeMap<u16, Vec<SizeCount>>,
    response_size_requests_not_displayed_by_status: BTreeMap<u16, u64>,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    sources: BTreeSet<Peer>,
    #[serde(skip)]
    positions: BTreeSet<u64>,
    #[serde(skip)]
    sizes: BTreeMap<u16, BTreeMap<u64, u64>>,
}

#[derive(Default, Serialize)]
struct HostFit {
    host: Option<String>,
    fitting: u64,
    not_fitting: u64,
    fit_rate: Option<f64>,
    parity_unchecked_reads: u64,
}

#[derive(Serialize)]
pub struct Report {
    safety_note: &'static str,
    pub summary: Summary,
    paired_expressions: Vec<PairedExpression>,
    character_expressions: Vec<CharacterExpression>,
    host_fit_rates: Vec<HostFit>,
}

fn unescape_nginx(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"\\x") && i + 3 < bytes.len() {
            if let Some(v) = hex_pair(bytes[i + 2], bytes[i + 3]) {
                result.push(v);
                i += 4;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    result
}

fn hex_pair(a: u8, b: u8) -> Option<u8> {
    Some(((a as char).to_digit(16)? * 16 + (b as char).to_digit(16)?) as u8)
}

enum DecodePart {
    Target,
    Body,
    FormBody,
}

fn decode(mut bytes: Vec<u8>, part: DecodePart) -> Option<String> {
    // Locate query spans before percent decoding: an encoded plus stays literal.
    let mut query = matches!(part, DecodePart::FormBody);
    for byte in &mut bytes {
        match *byte {
            b'?' => query = true,
            b'"' if matches!(part, DecodePart::Body) => query = false,
            b if b.is_ascii_whitespace() && matches!(part, DecodePart::Body) => query = false,
            b'+' if query => *byte = b' ',
            _ => {}
        }
    }
    for _ in 0..2 {
        let mut result = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Some(v) = hex_pair(bytes[i + 1], bytes[i + 2]) {
                    result.push(v);
                    i += 3;
                    continue;
                }
            }
            result.push(bytes[i]);
            i += 1;
        }
        bytes = result;
    }
    String::from_utf8(bytes).ok()
}

fn normalized(expression: &str) -> String {
    expression
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

// SQL quotes, doubled quote characters and backslash escapes do not alter nesting.
fn closing(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    let mut quote = None;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                if bytes.get(i + 1) == Some(&q) {
                    i += 2;
                    continue;
                }
                quote = None;
            }
        } else {
            match b {
                b'\'' | b'"' | b'`' => quote = Some(b),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

struct Shape {
    start: usize,
    end: usize,
    multiplier: i128,
}

fn shapes(text: &str) -> Vec<Shape> {
    static START: OnceLock<Regex> = OnceLock::new();
    static END: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    let start = START.get_or_init(|| Regex::new(r"(?i)\bcast\s*\(\s*\(").unwrap());
    let end = END.get_or_init(|| Regex::new(r"(?i)^\s*as\s+char\s*\)").unwrap());
    let hex = HEX.get_or_init(|| Regex::new(r"(?i)\bhex\s*\(\s*$").unwrap());
    let mut accepted_end = 0;
    start
        .find_iter(text)
        .filter_map(|m| {
            // Inner CASTs belong to the accepted outer expression, not a second shape.
            if m.start() < accepted_end {
                return None;
            }
            let open = m.end() - 1;
            let close = closing(text, open)?;
            let suffix = end.find(&text[close + 1..])?;
            let mut wrapper_end = close + 1 + suffix.end();
            let multiplier = if hex.is_match(&text[..m.start()]) {
                let remaining = &text[wrapper_end..];
                let trimmed = remaining.trim_start();
                if !trimmed.starts_with(')') {
                    return None;
                }
                wrapper_end += remaining.len() - trimmed.len() + 1;
                2
            } else {
                1
            };
            accepted_end = wrapper_end;
            Some(Shape {
                start: open + 1,
                end: close,
                multiplier,
            })
        })
        .collect()
}

fn constant_length(expression: &str) -> Option<i128> {
    static SELECT: OnceLock<Regex> = OnceLock::new();
    let re = SELECT.get_or_init(|| Regex::new(r"(?is)^\s*select\s+(.+?)\s*$").unwrap());
    let c = re.captures(expression)?;
    let value = &c[1];
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        if value.len() > 1 && value.starts_with('0') {
            return None;
        }
        return Some(value.len() as i128);
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return (!hex.is_empty()
            && hex.len() % 2 == 0
            && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some((hex.len() / 2) as i128);
    }
    let inner = value.strip_prefix('\'')?.strip_suffix('\'')?;
    // Backslash string interpretation depends on SQL mode, so it is not a known control.
    if !inner.is_ascii() || inner.contains('\\') {
        return None;
    }
    let mut chars = inner.chars();
    let mut count = 0;
    while let Some(c) = chars.next() {
        if c == '\'' && chars.next() != Some('\'') {
            return None;
        }
        count += 1;
    }
    Some(count)
}

fn select_argument(argument: &str) -> Option<&str> {
    let argument = argument.trim();
    if argument.starts_with('(') && closing(argument, 0)? == argument.len() - 1 {
        let inner = argument[1..argument.len() - 1].trim();
        if starts_select(inner) {
            return innermost_select(inner);
        }
        return None;
    }
    None
}

fn inner_select(argument: &str) -> Option<&str> {
    let argument = argument.trim();
    if argument.starts_with('(') {
        return select_argument(argument);
    }
    static WRAPPER: OnceLock<Regex> = OnceLock::new();
    let wrapper = WRAPPER.get_or_init(|| Regex::new(r"(?i)^(coalesce|ifnull)\s*\(").unwrap());
    let m = wrapper.find(argument)?;
    let end = closing(argument, m.end() - 1)?;
    if end != argument.len() - 1 {
        return None;
    }
    let first = arguments(&argument[m.end()..end]);
    if first.len() != 2 {
        return None;
    }
    if argument[..m.end()]
        .to_ascii_lowercase()
        .starts_with("coalesce")
    {
        return select_argument(first[0]);
    }
    static CAST: OnceLock<Regex> = OnceLock::new();
    static NCHAR: OnceLock<Regex> = OnceLock::new();
    let cast = CAST
        .get_or_init(|| Regex::new(r"(?i)^cast\s*\(\s*\(").unwrap())
        .find(first[0])?;
    let close = closing(first[0], cast.end() - 1)?;
    if !NCHAR
        .get_or_init(|| Regex::new(r"(?i)^\s*as\s+nchar\s*\)\s*$").unwrap())
        .is_match(&first[0][close + 1..])
    {
        return None;
    }
    select_argument(&first[0][cast.end() - 1..=close])
}

fn starts_select(text: &str) -> bool {
    text.get(..6)
        .is_some_and(|v| v.eq_ignore_ascii_case("select"))
        && text.as_bytes().get(6).is_some_and(u8::is_ascii_whitespace)
}

// Keep one innermost SELECT. Independent innermost subqueries are ambiguous.
fn innermost_select(text: &str) -> Option<&str> {
    let mut stack = Vec::new();
    let mut quote = None;
    let mut deepest = None;
    let mut ambiguous = false;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                if bytes.get(i + 1) == Some(&q) {
                    i += 2;
                    continue;
                }
                quote = None;
            }
        } else {
            match b {
                b'\'' | b'"' | b'`' => quote = Some(b),
                b'(' => stack.push(i + 1),
                b')' => {
                    let start = stack.pop()?;
                    let candidate = text[start..i].trim();
                    if starts_select(candidate) {
                        if let Some((previous_start, previous_end, _)) = deepest {
                            if !(start <= previous_start && i >= previous_end) {
                                ambiguous = true;
                            }
                        } else {
                            deepest = Some((start, i, candidate));
                        }
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    if ambiguous {
        None
    } else {
        Some(deepest.map_or(text, |(_, _, expression)| expression))
    }
}

fn arguments(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut result = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                if let Some(end) = closing(text, i) {
                    i = end;
                } else {
                    return Vec::new();
                }
            }
            b'\'' | b'"' | b'`' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        if bytes.get(i + 1) == Some(&quote) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
            }
            b',' => {
                result.push(text[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    result.push(text[start..].trim());
    result
}

fn character_shapes(text: &str) -> Vec<(String, u64)> {
    static START: OnceLock<Regex> = OnceLock::new();
    let re = START.get_or_init(|| {
        Regex::new(r"(?i)\b(?:ascii|ord)\s*\(\s*(?:substring|substr|mid)\s*\(").unwrap()
    });
    re.find_iter(text)
        .filter_map(|m| {
            let end = closing(text, m.end() - 1)?;
            let args = arguments(&text[m.end()..end]);
            if args.len() != 3 || args[2] != "1" || !text[end + 1..].trim_start().starts_with(')') {
                return None;
            }
            let position = args[1].parse::<u64>().ok().filter(|p| *p > 0)?;
            Some((normalized(inner_select(args[0])?), position))
        })
        .collect()
}

fn times(first: &mut Option<DateTime<Utc>>, last: &mut Option<DateTime<Utc>>, time: DateTime<Utc>) {
    *first = Some(first.map_or(time, |v| v.min(time)));
    *last = Some(last.map_or(time, |v| v.max(time)));
}

#[derive(Default)]
struct Analysis {
    summary: Summary,
    groups: BTreeMap<Group, Vec<Observation>>,
    characters: BTreeMap<(Option<String>, String), CharacterExpression>,
}

impl Analysis {
    fn observe(&mut self, event: WebEvent, options: &Options) {
        self.summary.analyzed_requests += 1;
        let target = event.uri.as_deref().unwrap_or("");
        let body = event.request_body.as_deref().unwrap_or("");
        let target_bytes = unescape_nginx(target);
        let body_bytes = unescape_nginx(body);
        let request_bytes = target_bytes.len() + body_bytes.len();
        let body_part = if event.content_type.as_deref().is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        }) {
            DecodePart::FormBody
        } else {
            DecodePart::Body
        };
        let (Some(decoded_target), Some(decoded_body)) = (
            decode(target_bytes, DecodePart::Target),
            decode(body_bytes, body_part),
        ) else {
            self.summary.requests_with_unsupported_decoding += 1;
            return;
        };
        let mut candidates = Vec::new();
        let mut characters = Vec::new();
        for (part, text) in [&decoded_target, &decoded_body].into_iter().enumerate() {
            candidates.extend(shapes(text).into_iter().map(|shape| (part, shape)));
            characters.extend(character_shapes(text));
        }
        if candidates.len() + characters.len() > 1 {
            self.summary.requests_with_multiple_shapes += 1;
            return;
        }
        if candidates.is_empty() && characters.is_empty() {
            self.summary.requests_without_shape += 1;
            return;
        }
        let raw_source = event.client_ip.as_ref().or(event.source_ip.as_ref());
        let (
            Some(source),
            Some(method),
            Some(path),
            Some(status),
            Some(response_bytes),
            Some(timestamp),
        ) = (
            raw_source,
            event.method.as_ref(),
            event.uri_path.as_ref(),
            event.status,
            event.response_bytes,
            event.timestamp,
        )
        else {
            self.summary.requests_without_required_fields += 1;
            return;
        };
        if self.summary.retained_observations >= options.max_observations {
            self.summary.observations_beyond_cap += 1;
            return;
        }
        self.summary.retained_observations += 1;
        let peer = Peer {
            identity: if event.client_ip.is_some() {
                "validated-client"
            } else {
                "observed-peer"
            },
            source: canonical_address_or_raw(source),
        };
        if let Some((expression, position)) = characters.pop() {
            self.summary.character_requests += 1;
            let entry = self
                .characters
                .entry((event.host.clone(), expression.clone()))
                .or_insert_with(|| CharacterExpression {
                    host: event.host.clone(),
                    expression,
                    ..Default::default()
                });
            entry.requests += 1;
            entry.sources.insert(peer);
            entry.positions.insert(position);
            *entry
                .sizes
                .entry(status)
                .or_default()
                .entry(response_bytes)
                .or_default() += 1;
            times(&mut entry.first_seen, &mut entry.last_seen, timestamp);
            return;
        }
        let (part, shape) = candidates.pop().unwrap();
        let mut texts = [decoded_target, decoded_body];
        let expression = texts[part][shape.start..shape.end].to_owned();
        texts[part].replace_range(shape.start..shape.end, "<expression>");
        let [target_shape, body_shape] = texts.map(|t| t.to_ascii_lowercase());
        self.groups
            .entry(Group {
                host: event.host,
                peer,
                method: method.clone(),
                path: path.to_ascii_lowercase(),
                status,
                target_shape,
                body_shape,
                multiplier: shape.multiplier,
            })
            .or_default()
            .push(Observation {
                control_length: constant_length(&expression),
                expression: normalized(&expression),
                response_bytes,
                request_bytes,
                timestamp,
            });
    }

    fn finish(mut self) -> Report {
        let mut paired = BTreeMap::<(Option<String>, String), PairedExpression>::new();
        let mut hosts = BTreeMap::<Option<String>, HostFit>::new();
        for (key, observations) in self.groups {
            // Stable input order breaks equal timestamp ties; controls may arrive later in the file.
            let control = observations
                .iter()
                .enumerate()
                .filter(|(_, o)| o.control_length.is_some())
                .min_by_key(|(i, o)| (o.timestamp, *i));
            let Some((control_index, baseline)) = control else {
                self.summary.groups_without_control += 1;
                self.summary.requests_without_control += observations.len() as u64;
                continue;
            };
            self.summary.control_requests += 1;
            let host = hosts.entry(key.host.clone()).or_insert_with(|| HostFit {
                host: key.host.clone(),
                ..Default::default()
            });
            for (index, read) in observations.iter().enumerate() {
                if index == control_index {
                    continue;
                }
                self.summary.paired_requests += 1;
                let response_delta =
                    i128::from(read.response_bytes) - i128::from(baseline.response_bytes);
                let request_delta = read.request_bytes as i128 - baseline.request_bytes as i128;
                let delta = response_delta - request_delta;
                let estimate = delta / key.multiplier + baseline.control_length.unwrap();
                let outcome = if delta % key.multiplier != 0 {
                    "not_fitting"
                } else if estimate < 0 {
                    "negative_estimate"
                } else if estimate == 0 {
                    "empty_or_null"
                } else {
                    "length"
                };
                let entry = paired
                    .entry((key.host.clone(), read.expression.clone()))
                    .or_insert_with(|| PairedExpression {
                        host: key.host.clone(),
                        expression: read.expression.clone(),
                        ..Default::default()
                    });
                entry.requests += 1;
                entry.sources.insert(key.peer.clone());
                times(&mut entry.first_seen, &mut entry.last_seen, read.timestamp);
                match outcome {
                    "not_fitting" => {
                        entry.not_fitting += 1;
                        self.summary.not_fitting += 1;
                    }
                    "negative_estimate" => {
                        *entry.negative_counts.entry(estimate).or_default() += 1;
                        entry.negative_estimate += 1;
                        self.summary.negative_estimate += 1;
                    }
                    "empty_or_null" => {
                        entry.empty_or_null += 1;
                        self.summary.empty_or_null += 1;
                    }
                    _ => {
                        self.summary.length += 1;
                        entry.estimated_lengths.insert(estimate);
                    }
                }
                if key.multiplier == 2 {
                    if outcome == "not_fitting" {
                        host.not_fitting += 1;
                    } else {
                        host.fitting += 1;
                    }
                } else {
                    host.parity_unchecked_reads += 1;
                }
                entry.estimates.push(Estimate {
                    peer: key.peer.clone(),
                    timestamp: read.timestamp,
                    baseline_timestamp: baseline.timestamp,
                    baseline_length: baseline.control_length.unwrap(),
                    multiplier: key.multiplier,
                    response_byte_delta: response_delta,
                    request_byte_delta: request_delta,
                    adjusted_delta: delta,
                    outcome,
                    estimated_length: (outcome == "length").then_some(estimate),
                });
            }
        }
        for entry in paired.values_mut() {
            entry.distinct_sources = entry.sources.len();
            entry.negative_candidates = entry
                .negative_counts
                .iter()
                .map(|(&value, &requests)| NegativeCandidate { value, requests })
                .collect();
        }
        for entry in self.characters.values_mut() {
            entry.distinct_sources = entry.sources.len();
            entry.positions_probed = entry.positions.len();
            entry.max_position = entry.positions.last().copied().unwrap_or(0);
            for (status, sizes) in &entry.sizes {
                let mut sizes: Vec<_> = sizes
                    .iter()
                    .map(|(&response_bytes, &requests)| SizeCount {
                        response_bytes,
                        requests,
                    })
                    .collect();
                sizes.sort_by_key(|s| (std::cmp::Reverse(s.requests), s.response_bytes));
                entry
                    .response_size_requests_not_displayed_by_status
                    .insert(*status, sizes.iter().skip(3).map(|s| s.requests).sum());
                sizes.truncate(3);
                entry.response_sizes_by_status.insert(*status, sizes);
            }
        }
        for host in hosts.values_mut() {
            let denominator = host.fitting + host.not_fitting;
            host.fit_rate = (denominator > 0).then(|| host.fitting as f64 / denominator as f64);
        }
        self.summary.paired_expressions = paired.len();
        self.summary.character_expressions = self.characters.len();
        Report {
            safety_note: SAFETY_NOTE,
            summary: self.summary,
            paired_expressions: paired.into_values().collect(),
            character_expressions: self.characters.into_values().collect(),
            host_fit_rates: hosts.into_values().collect(),
        }
    }
}

pub fn run(
    input: &Path,
    profile: TelemetryProfile,
    range: &HuntTimeRange,
    proxies: &TrustedProxySet,
    options: &Options,
    output: &Path,
) -> Result<Report> {
    if options.max_observations == 0 {
        bail!("max-observations must be a positive finite count");
    }
    range.validate()?;
    ensure_separate_output(input, output)?;
    let names = [
        "response-sizes.json",
        "sanitized-response-sizes.json",
        "run-manifest.json",
    ];
    for name in names {
        let path = output.join(name);
        if path.symlink_metadata().is_ok() {
            bail!("refusing to overwrite existing output: {}", path.display());
        }
    }
    let discovery = discover_input_files(input, Some(profile))?;
    let mut analysis = Analysis::default();
    analysis.summary.files_analyzed = discovery.files.len();
    analysis.summary.input_discovery = discovery.summary;
    let mut corpus = Vec::new();
    for path in discovery.files {
        let mut consume = |event: Result<WebEvent, String>| -> Result<()> {
            match event {
                Ok(event) => {
                    analysis.summary.parseable_records += 1;
                    if range.includes(event.timestamp) {
                        analysis.observe(event, options);
                    } else {
                        analysis.summary.records_outside_time_range += 1;
                    }
                }
                Err(_) => analysis.summary.parse_errors += 1,
            }
            Ok(())
        };
        let mut truncated_body = 0;
        let mut error_log_lines = 0;
        let mut invalid_utf8_lines = 0;
        let provenance = if profile == TelemetryProfile::NginxPostdata {
            with_fingerprinted_input(&path, |reader| {
                let mut lines = AccessLogLines::for_response_sizes(reader);
                while let Some(event) = lines.next() {
                    if let Some(error) = lines.io_error() {
                        bail!("reading decoded input: {error}");
                    }
                    match &event {
                        Err(AccessLogParseError::TruncatedBody) => truncated_body += 1,
                        Err(AccessLogParseError::NginxErrorLog) => error_log_lines += 1,
                        Err(AccessLogParseError::InvalidUtf8) => invalid_utf8_lines += 1,
                        _ => {}
                    }
                    consume(
                        event
                            .map(|mut event| {
                                proxies.resolve_client_ip(&mut event);
                                event
                            })
                            .map_err(|error| error.to_string()),
                    )?;
                }
                Ok(())
            })?
        } else {
            stream_events_with_fingerprint(&path, profile, proxies, RawRetention::Drop, consume)?
        };
        analysis.summary.truncated_body += truncated_body;
        analysis.summary.error_log_lines += error_log_lines;
        analysis.summary.invalid_utf8_lines += invalid_utf8_lines;
        corpus.push(provenance);
    }
    let report = analysis.finish();
    let manifest = serde_json::json!({"safety_note":SAFETY_NOTE, "shenron_version":env!("CARGO_PKG_VERSION"), "telemetry_profile":profile, "options":options, "from":range.from, "to":range.to, "trusted_proxy_networks":proxies.configured_proxy_networks(), "corpus":corpus, "skipped_inputs":report.summary.input_discovery.skipped});
    #[derive(Serialize)]
    #[serde(untagged)]
    enum Artifact<'a> {
        Private(&'a Report),
        Sanitized(&'a Summary),
        Manifest(&'a serde_json::Value),
    }
    fs::create_dir_all(output)?;
    let paths = names.map(|name| output.join(name));
    write_json_pretty_new_batch(&[
        (paths[0].as_path(), Artifact::Private(&report)),
        (paths[1].as_path(), Artifact::Sanitized(&report.summary)),
        (paths[2].as_path(), Artifact::Manifest(&manifest)),
    ])?;
    Ok(report)
}

fn displayed_lengths(lengths: &BTreeSet<i128>) -> String {
    if lengths.is_empty() {
        return "-".into();
    }
    let mut display = lengths
        .iter()
        .take(10)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if lengths.len() > 10 {
        display.push_str(&format!(",... (+{})", lengths.len() - 10));
    }
    display
}

pub fn write_text(
    mut out: impl Write,
    report: &Report,
    show_sources: bool,
    show_expressions: bool,
    limit: usize,
) -> Result<()> {
    writeln!(out, "{SAFETY_NOTE}")?;
    if let Some(disclosure) = report.summary.input_discovery.disclosure() {
        writeln!(out, "{disclosure}")?;
    }
    writeln!(out, "Response-size summary (aggregate counts only):")?;
    let summary = &report.summary;
    for (name, value) in [
        ("Files analyzed", summary.files_analyzed as u64),
        ("Parseable records", summary.parseable_records),
        ("Analyzed requests", summary.analyzed_requests),
        (
            "Retained observations",
            summary.retained_observations as u64,
        ),
        ("Control requests", summary.control_requests),
        ("Paired requests", summary.paired_requests),
        ("Length", summary.length),
        ("Empty or null", summary.empty_or_null),
        ("Negative estimate", summary.negative_estimate),
        ("Not fitting", summary.not_fitting),
        ("Character requests", summary.character_requests),
        ("Paired expressions", summary.paired_expressions as u64),
        (
            "Character expressions",
            summary.character_expressions as u64,
        ),
    ] {
        writeln!(out, "  {name}: {value}")?;
    }
    for (name, value) in [
        ("Parse errors", summary.parse_errors),
        ("Truncated body", summary.truncated_body),
        ("Error log lines", summary.error_log_lines),
        ("Invalid UTF-8 lines", summary.invalid_utf8_lines),
        (
            "Records outside time range",
            summary.records_outside_time_range,
        ),
        ("Requests without shape", summary.requests_without_shape),
        (
            "Requests with multiple shapes",
            summary.requests_with_multiple_shapes,
        ),
        (
            "Requests with unsupported decoding",
            summary.requests_with_unsupported_decoding,
        ),
        (
            "Requests without required fields",
            summary.requests_without_required_fields,
        ),
        ("Observations beyond cap", summary.observations_beyond_cap),
        (
            "Groups without control",
            summary.groups_without_control as u64,
        ),
        ("Requests without control", summary.requests_without_control),
    ] {
        if value > 0 {
            writeln!(out, "  {name}: {value}")?;
        }
    }
    let total = report.paired_expressions.len() + report.character_expressions.len();
    let shown = if show_sources || show_expressions {
        if limit == 0 {
            total
        } else {
            total.min(limit)
        }
    } else {
        0
    };
    for (index, entry) in report.paired_expressions.iter().take(shown).enumerate() {
        write!(out, "  {}: paired requests {} / estimated_lengths {} / negative_estimate {} / empty_or_null {} / not_fitting {}", index + 1, entry.requests, displayed_lengths(&entry.estimated_lengths), entry.negative_estimate, entry.empty_or_null, entry.not_fitting)?;
        if show_sources {
            write!(
                out,
                " / sources {}",
                entry
                    .sources
                    .iter()
                    .map(|p| format!("{}:{}", p.identity, terminal_safe(&p.source)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
        if show_expressions {
            if !entry.negative_candidates.is_empty() {
                write!(
                    out,
                    " / negative: {}",
                    entry
                        .negative_candidates
                        .iter()
                        .map(|candidate| format!("{} x{}", candidate.value, candidate.requests))
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
            }
            write!(
                out,
                " / expression {}",
                terminal_safe(&entry.expression)
                    .chars()
                    .take(300)
                    .collect::<String>()
            )?;
        }
        writeln!(out)?;
    }
    for (index, entry) in report
        .character_expressions
        .iter()
        .take(shown.saturating_sub(report.paired_expressions.len()))
        .enumerate()
    {
        write!(
            out,
            "  {}: Character requests {} / positions_probed {} / max_position {}",
            report.paired_expressions.len() + index + 1,
            entry.requests,
            entry.positions_probed,
            entry.max_position
        )?;
        if show_sources {
            write!(
                out,
                " / sources {}",
                entry
                    .sources
                    .iter()
                    .map(|p| format!("{}:{}", p.identity, terminal_safe(&p.source)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
        if show_expressions {
            write!(
                out,
                " / expression {}",
                terminal_safe(&entry.expression)
                    .chars()
                    .take(300)
                    .collect::<String>()
            )?;
        }
        writeln!(out)?;
    }
    writeln!(out, "Expressions not displayed: {}", total - shown)?;
    Ok(())
}
