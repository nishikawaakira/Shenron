//! Bounded identifier observations, not authorization or response-body analysis.
use std::{
    borrow::Borrow,
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
    rc::Rc,
};

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use clap::Args;
use serde::Serialize;

use crate::{
    concentration::{record_status_class, StatusClassCounts},
    event::{canonical_address_or_raw, RawRetention, TelemetryProfile, TrustedProxySet, WebEvent},
    input_discovery::{discover_input_files, InputDiscoverySummary},
    output::write_json_pretty_new_batch,
    production::{
        ensure_separate_output, stream_events_with_fingerprint, terminal_safe, HuntTimeRange,
    },
};

pub const SAFETY_NOTE: &str = "Identifier-access measurements are not a determination of an attack, an authorization flaw or information disclosure. Content and rejected are status/size-based observations, not response-body or access-control findings. A high rejected-ID share may reflect requests for absent IDs; it does not establish why. Observed peers may be proxies or NATs. Prior writes do not establish ownership or successful creation.";

#[derive(Debug, Clone, Args, Serialize)]
pub struct Options {
    #[arg(long, default_value_t = 20)]
    pub min_distinct_ids: usize,
    #[arg(long)]
    pub exclude_query_param: Vec<String>,
    #[arg(long, default_value_t = 1_000_000)]
    pub max_entries: usize,
    #[arg(long, default_value_t = 100_000)]
    pub max_ids_per_entry: usize,
    #[arg(long, default_value_t = 10_000)]
    pub max_reported_ids_per_entry: usize,
    /// Independent per-peer bound on retained write-ID values.
    #[arg(long, default_value_t = 100_000)]
    pub max_written_ids_per_peer: usize,
    /// Independent per-entry bound on retained (ID, successful response size) pairs.
    #[arg(long, default_value_t = 100_000)]
    pub max_response_size_pairs_per_entry: usize,
}

impl Options {
    fn validate(&self) -> Result<()> {
        if [
            self.min_distinct_ids,
            self.max_entries,
            self.max_ids_per_entry,
            self.max_reported_ids_per_entry,
            self.max_written_ids_per_peer,
            self.max_response_size_pairs_per_entry,
        ]
        .contains(&0)
        {
            bail!("identifier-access counts and tracking limits must be positive finite counts");
        }
        Ok(())
    }
}

#[derive(Default, Serialize)]
pub struct Omissions {
    entry_observations_beyond_cap: u64,
    id_observations_beyond_cap: u64,
    response_size_observations_beyond_cap: u64,
    write_observations_beyond_peer_cap: u64,
    write_observations_beyond_id_cap: u64,
    content_id_values_not_reported: u64,
}

#[derive(Default, Serialize)]
pub struct Summary {
    pub files_analyzed: usize,
    #[serde(flatten)]
    pub input_discovery: InputDiscoverySummary,
    parseable_records: u64,
    parse_errors: u64,
    records_outside_time_range: u64,
    undated_records_excluded_by_time_range: u64,
    analyzed_requests: u64,
    requests_without_status: u64,
    requests_without_timestamp: u64,
    successful_requests_without_response_bytes: u64,
    requests_with_identifiers: u64,
    requests_without_source: u64,
    requests_without_method: u64,
    requests_without_path: u64,
    excluded_query_identifier_observations: u64,
    repeated_query_identifier_observations: u64,
    retained_entries: usize,
    total_entries: Option<usize>,
    entries_at_or_above_minimum: usize,
    sources_at_or_above_minimum: usize,
    entries_below_minimum: usize,
    entries_below_minimum_unproven: usize,
    entries_with_id_cap_omissions: usize,
    reported_entries: usize,
    rejected_share_unavailable: usize,
    rejected_share_below_03: usize,
    rejected_share_03_to_05: usize,
    rejected_share_05_to_08: usize,
    rejected_share_at_least_08: usize,
    timestamp_like_share_at_least_half: usize,
    prefix_extension_share_at_least_half: usize,
    pub omissions: Omissions,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Peer {
    identity: &'static str,
    source: String,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct KeyFields {
    #[serde(flatten)]
    peer: Peer,
    method: String,
    host: Option<String>,
    template: String,
    position: String,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key(Rc<KeyFields>);

impl std::ops::Deref for Key {
    type Target = KeyFields;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Serialize for Key {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_ref().serialize(serializer)
    }
}

// Borrowed composite lookups preserve BTreeMap ordering without allocating keys.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KeyRef<'a> {
    identity: &'a str,
    source: &'a str,
    method: &'a str,
    host: Option<&'a str>,
    template: &'a str,
    position: &'a str,
}
trait Lookup {
    fn key_ref(&self) -> KeyRef<'_>;
}
impl Lookup for Peer {
    fn key_ref(&self) -> KeyRef<'_> {
        KeyRef {
            identity: self.identity,
            source: &self.source,
            method: "",
            host: None,
            template: "",
            position: "",
        }
    }
}
impl Lookup for Key {
    fn key_ref(&self) -> KeyRef<'_> {
        KeyRef {
            method: &self.method,
            host: self.host.as_deref(),
            template: &self.template,
            position: &self.position,
            ..self.peer.key_ref()
        }
    }
}
impl Lookup for KeyRef<'_> {
    fn key_ref(&self) -> KeyRef<'_> {
        *self
    }
}
impl PartialEq for dyn Lookup + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.key_ref() == other.key_ref()
    }
}
impl Eq for dyn Lookup + '_ {}
impl PartialOrd for dyn Lookup + '_ {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for dyn Lookup + '_ {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key_ref().cmp(&other.key_ref())
    }
}
impl<'a> Borrow<dyn Lookup + 'a> for Key {
    fn borrow(&self) -> &(dyn Lookup + 'a) {
        self
    }
}
impl<'a> Borrow<dyn Lookup + 'a> for Peer {
    fn borrow(&self) -> &(dyn Lookup + 'a) {
        self
    }
}
impl KeyRef<'_> {
    fn owned(self, identity: &'static str) -> Key {
        Key(Rc::new(KeyFields {
            peer: Peer {
                identity,
                source: self.source.into(),
            },
            method: self.method.into(),
            host: self.host.map(str::to_owned),
            template: self.template.into(),
            position: self.position.into(),
        }))
    }
}

#[derive(Serialize)]
pub struct Entry {
    #[serde(flatten)]
    key: Key,
    requests: u64,
    distinct_ids: Option<usize>,
    distinct_ids_at_least: usize,
    status_classes: StatusClassCounts,
    dominant_2xx_response_bytes: Option<u64>,
    content_ids: Option<usize>,
    rejected_ids: Option<usize>,
    redirect_only_ids: Option<usize>,
    rejected_id_share: Option<f64>,
    stable_size_ids: Option<usize>,
    repeated_content_ids: Option<usize>,
    adjacent_step_share: Option<f64>,
    adjacent_numeric_pairs: u64,
    numeric_values_outside_u64: u64,
    prefix_extension_share: Option<f64>,
    consecutive_value_pairs: u64,
    timestamp_like_share: Option<f64>,
    self_reference_segment: Option<String>,
    ids_written_by_same_peer: usize,
    ids_written_before_first_content: Option<usize>,
    write_history_incomplete: bool,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    content_id_values: Option<Vec<String>>,
    content_id_values_not_reported: usize,
    id_observations_beyond_cap: u64,
    response_size_observations_beyond_cap: u64,
    successful_responses_without_bytes: u64,
    status_observations_unavailable: u64,
    timestamp_observations_unavailable: u64,
}
#[derive(Serialize)]
pub struct Report {
    safety_note: &'static str,
    pub summary: Summary,
    pub entries: Vec<Entry>,
}

#[derive(Default)]
struct SizeObservations {
    count: u64,
    first: Option<DateTime<Utc>>,
    undated: bool,
}
#[derive(Default)]
struct IdObservations {
    requests: u64,
    received_success: bool,
    received_rejection: bool,
    received_redirect_or_informational: bool,
    received_other: bool,
    sizes: BTreeMap<u64, SizeObservations>,
}
#[derive(Default)]
struct Accumulator {
    key: Option<Key>,
    raw_source: String,
    requests: u64,
    ids: BTreeMap<String, IdObservations>,
    classes: StatusClassCounts,
    size_pairs: usize,
    id_omissions: u64,
    size_omissions: u64,
    missing_bytes: u64,
    missing_times: u64,
    previous: Option<String>,
    numeric_pairs: u64,
    adjacent_pairs: u64,
    numeric_overflow: u64,
    pairs: u64,
    prefix_pairs: u64,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
    self_reference: Option<String>,
}

fn ratio(n: u64, d: u64) -> Option<f64> {
    (d > 0).then(|| n as f64 / d as f64)
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
fn kind(value: &str) -> Option<&'static str> {
    if !value.is_empty() && value.len() <= 20 && value.bytes().all(|c| c.is_ascii_digit()) {
        Some("{num}")
    } else if value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        Some("{uuid}")
    } else {
        None
    }
}
fn path_id(segment: &str) -> Option<(&str, String)> {
    if let Some(kind) = kind(segment) {
        return Some((segment, kind.into()));
    }
    let (id, extension) = segment.rsplit_once('.')?;
    if extension.is_empty()
        || extension.len() > 10
        || !extension.bytes().all(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((id, format!("{}.{}", kind(id)?, extension)))
}
struct Extracted {
    template: String,
    position: String,
    value: String,
    self_reference: Option<String>,
}
fn extract(event: &WebEvent, options: &Options, summary: &mut Summary) -> Vec<Extracted> {
    let Some(path) = &event.uri_path else {
        return Vec::new();
    };
    let segments: Vec<_> = path.split('/').collect();
    let template = segments
        .iter()
        .map(|s| path_id(s).map_or_else(|| (*s).to_owned(), |(_, t)| t))
        .collect::<Vec<_>>()
        .join("/");
    let reference = |before: usize| {
        segments[..before]
            .iter()
            .rev()
            .find(|s| {
                ["me", "my", "self", "mine", "current"]
                    .iter()
                    .any(|word| s.eq_ignore_ascii_case(word))
            })
            .map(|s| (*s).to_owned())
    };
    let mut found = Vec::new();
    for (i, segment) in segments.iter().enumerate() {
        if let Some((value, _)) = path_id(segment) {
            found.push(Extracted {
                template: template.clone(),
                position: format!("path:{i}"),
                value: value.into(),
                self_reference: reference(i),
            });
        }
    }
    let mut names = BTreeSet::new();
    for parameter in event.uri_query.as_deref().unwrap_or("").split('&') {
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if kind(value).is_none() {
            continue;
        }
        if options
            .exclude_query_param
            .iter()
            .any(|excluded| excluded == name)
        {
            summary.excluded_query_identifier_observations += 1;
        } else if !names.insert(name) {
            summary.repeated_query_identifier_observations += 1;
        } else {
            found.push(Extracted {
                template: template.clone(),
                position: format!("query:{name}"),
                value: value.into(),
                self_reference: reference(segments.len()),
            });
        }
    }
    found
}

impl Accumulator {
    fn observe(&mut self, id: &str, event: &WebEvent, options: &Options) {
        self.requests += 1;
        record_status_class(&mut self.classes, event.status);
        times(&mut self.first, &mut self.last, event.timestamp);
        self.missing_times += u64::from(event.timestamp.is_none());
        let numeric = id.parse::<u64>().ok();
        self.numeric_overflow += u64::from(kind(id) == Some("{num}") && numeric.is_none());
        if let Some(previous) = &self.previous {
            self.pairs += 1;
            self.prefix_pairs +=
                u64::from(previous != id && (previous.starts_with(id) || id.starts_with(previous)));
            if let (Some(left), Some(right)) = (previous.parse::<u64>().ok(), numeric) {
                self.numeric_pairs += 1;
                self.adjacent_pairs += u64::from((1..=2).contains(&left.abs_diff(right)));
            }
        }
        let previous = self.previous.get_or_insert_with(String::new);
        previous.clear();
        previous.push_str(id);
        let retained = self.ids.len();
        let observation = if let Some(observation) = self.ids.get_mut(id) {
            observation
        } else {
            if retained >= options.max_ids_per_entry {
                self.id_omissions += 1;
                return;
            }
            self.ids.entry(id.into()).or_default()
        };
        observation.requests += 1;
        observation.received_success |= event.status.is_some_and(|s| (200..300).contains(&s));
        observation.received_rejection |= event.status.is_some_and(|s| (400..600).contains(&s));
        observation.received_redirect_or_informational |= event
            .status
            .is_some_and(|s| (100..200).contains(&s) || (300..400).contains(&s));
        observation.received_other |= event.status.is_some_and(|s| !(100..600).contains(&s));
        if event.status.is_some_and(|s| (200..300).contains(&s)) {
            if let Some(size) = event.response_bytes {
                if !observation.sizes.contains_key(&size) {
                    if self.size_pairs >= options.max_response_size_pairs_per_entry {
                        self.size_omissions += 1;
                        return;
                    }
                    self.size_pairs += 1;
                }
                let sizes = observation.sizes.entry(size).or_default();
                sizes.count += 1;
                sizes.undated |= event.timestamp.is_none();
                if let Some(time) = event.timestamp {
                    sizes.first = Some(sizes.first.map_or(time, |old| old.min(time)));
                }
            } else {
                self.missing_bytes += 1;
            }
        }
    }
}

#[derive(Default)]
struct Writes {
    ids: BTreeMap<String, WriteOrigins>,
    omitted: u64,
}

#[derive(Default)]
struct WriteOrigins {
    earliest: [Option<(Key, Option<DateTime<Utc>>)>; 2],
}
impl WriteOrigins {
    fn record(
        &mut self,
        key: KeyRef<'_>,
        time: Option<DateTime<Utc>>,
        owned: impl FnOnce() -> Key,
    ) {
        if let Some((_, first)) = self
            .earliest
            .iter_mut()
            .flatten()
            .find(|(origin, _)| origin.key_ref() == key)
        {
            if let Some(time) = time {
                *first = Some(first.map_or(time, |old| old.min(time)));
            }
        } else {
            // Two earliest distinct origins suffice to exclude any one Key.
            // Dated origins precede undated ones; ties use the full Key.
            let rank = (time.is_none(), time, key);
            if let Some((last, last_time)) = &self.earliest[1] {
                if rank >= (last_time.is_none(), *last_time, last.key_ref()) {
                    return;
                }
            }
            let index = usize::from(self.earliest[0].is_some());
            self.earliest[index] = Some((owned(), time));
        }
        self.earliest.sort_by(|a, b| match (a, b) {
            (Some((a, ta)), Some((b, tb))) => (ta.is_none(), ta, a).cmp(&(tb.is_none(), tb, b)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        });
    }
    fn other_than(&self, key: &Key) -> Option<&Option<DateTime<Utc>>> {
        self.earliest
            .iter()
            .flatten()
            .find(|(origin, _)| origin != key)
            .map(|(_, time)| time)
    }
}

impl Writes {
    fn record(
        &mut self,
        value: &str,
        key: KeyRef<'_>,
        time: Option<DateTime<Utc>>,
        maximum: usize,
        owned: impl FnOnce() -> Key,
    ) -> bool {
        let retained = self.ids.len();
        let origins = if let Some(origins) = self.ids.get_mut(value) {
            origins
        } else {
            if retained >= maximum {
                self.omitted += 1;
                return false;
            }
            self.ids.entry(value.into()).or_default()
        };
        origins.record(key, time, owned);
        true
    }
}
#[derive(Default)]
struct Analysis {
    entries: BTreeMap<Key, Accumulator>,
    writes: BTreeMap<Peer, Writes>,
    summary: Summary,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
}
impl Analysis {
    fn observe(&mut self, event: WebEvent, options: &Options) {
        self.summary.analyzed_requests += 1;
        self.summary.requests_without_status += u64::from(event.status.is_none());
        self.summary.requests_without_timestamp += u64::from(event.timestamp.is_none());
        self.summary.successful_requests_without_response_bytes += u64::from(
            event.status.is_some_and(|s| (200..300).contains(&s)) && event.response_bytes.is_none(),
        );
        times(&mut self.first, &mut self.last, event.timestamp);
        self.summary.requests_without_path += u64::from(event.uri_path.is_none());
        let ids = extract(&event, options, &mut self.summary);
        if ids.is_empty() {
            return;
        }
        self.summary.requests_with_identifiers += 1;
        let (identity, raw) = if let Some(client) = event.client_ip.as_deref() {
            ("validated-client", Some(client))
        } else {
            ("observed-peer", event.source_ip.as_deref())
        };
        let Some(raw) = raw.filter(|s| !s.is_empty() && *s != "-") else {
            self.summary.requests_without_source += 1;
            return;
        };
        let Some(method) = event.method.as_ref() else {
            self.summary.requests_without_method += 1;
            return;
        };
        let source = canonical_address_or_raw(raw);
        let peer = KeyRef {
            identity,
            source: &source,
            method: "",
            host: None,
            template: "",
            position: "",
        };
        for id in ids {
            let key = KeyRef {
                method,
                host: event.host.as_deref(),
                template: &id.template,
                position: &id.position,
                ..peer
            };
            let retained = self.entries.len();
            let entry = if let Some(entry) = self.entries.get_mut(&key as &dyn Lookup) {
                Some(entry)
            } else if retained < options.max_entries {
                let owned = key.owned(identity);
                Some(
                    self.entries
                        .entry(owned.clone())
                        .or_insert_with(|| Accumulator {
                            key: Some(owned),
                            raw_source: raw.into(),
                            self_reference: id.self_reference,
                            ..Default::default()
                        }),
                )
            } else {
                self.summary.omissions.entry_observations_beyond_cap += 1;
                None
            };
            if ["POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
                let retained = self.writes.len();
                let writes = if let Some(writes) = self.writes.get_mut(&peer as &dyn Lookup) {
                    Some(writes)
                } else if retained < options.max_entries {
                    Some(
                        self.writes
                            .entry(Peer {
                                identity,
                                source: source.clone(),
                            })
                            .or_default(),
                    )
                } else {
                    self.summary.omissions.write_observations_beyond_peer_cap += 1;
                    None
                };
                if let Some(writes) = writes {
                    if !writes.record(
                        &id.value,
                        key,
                        event.timestamp,
                        options.max_written_ids_per_peer,
                        || {
                            entry
                                .as_ref()
                                .and_then(|e| e.key.clone())
                                .unwrap_or_else(|| key.owned(identity))
                        },
                    ) {
                        self.summary.omissions.write_observations_beyond_id_cap += 1;
                    }
                }
            }
            if let Some(entry) = entry {
                if raw < entry.raw_source.as_str() {
                    entry.raw_source.clear();
                    entry.raw_source.push_str(raw);
                }
                entry.observe(&id.value, &event, options);
            }
        }
    }

    fn finish(mut self, options: &Options) -> Report {
        let mut rows = Vec::new();
        let mut qualifying_peers = BTreeSet::new();
        self.summary.retained_entries = self.entries.len();
        self.summary.total_entries = (self.summary.omissions.entry_observations_beyond_cap == 0)
            .then_some(self.entries.len());
        for (mut key, a) in self.entries {
            let complete = a.id_omissions == 0 && a.size_omissions == 0 && a.missing_bytes == 0;
            let mut frequency = BTreeMap::<u64, usize>::new();
            for id in a.ids.values() {
                for size in id.sizes.keys() {
                    *frequency.entry(*size).or_default() += 1;
                }
            }
            let dominant = complete
                .then(|| {
                    frequency
                        .iter()
                        .filter(|(_, count)| **count >= 2)
                        .max_by(|(sa, ca), (sb, cb)| ca.cmp(cb).then_with(|| sb.cmp(sa)))
                        .map(|(size, _)| *size)
                })
                .flatten();
            let mut content = Vec::new();
            let mut rejected = 0;
            let mut redirect_only = 0;
            let mut repeated = 0;
            let mut stable = 0;
            let mut written = 0;
            let mut written_before = 0;
            let writes = self.writes.get(&key.peer);
            let mut numeric = 0;
            let mut timestamp_like = 0;
            for (value, id) in &a.ids {
                let sizes: Vec<_> = id
                    .sizes
                    .iter()
                    .filter(|(size, _)| Some(**size) != dominant)
                    .collect();
                if !sizes.is_empty() {
                    content.push(value.clone());
                    if sizes.iter().map(|(_, s)| s.count).sum::<u64>() >= 2 {
                        repeated += 1;
                        stable += usize::from(sizes.len() == 1);
                    }
                } else if id.received_success || id.received_rejection {
                    rejected += 1;
                } else if id.received_redirect_or_informational && !id.received_other {
                    redirect_only += 1;
                }
                if let Some(write) = writes
                    .and_then(|w| w.ids.get(value))
                    .and_then(|origins| origins.other_than(&key))
                {
                    written += 1;
                    if complete && !sizes.is_empty() && !sizes.iter().any(|(_, s)| s.undated) {
                        let first_content = sizes.iter().filter_map(|(_, s)| s.first).min();
                        written_before +=
                            usize::from(write.zip(first_content).is_some_and(|(w, c)| w < c));
                    }
                }
                if kind(value) == Some("{num}") {
                    numeric += id.requests;
                    if let (Ok(value), Some(first), Some(last)) =
                        (value.parse::<i128>(), self.first, self.last)
                    {
                        let lower = i128::from(first.timestamp_millis()) - 86_400_000;
                        let upper = i128::from(last.timestamp_millis()) + 86_400_000;
                        if (lower..=upper).contains(&(value * 1000))
                            || (lower..=upper).contains(&value)
                        {
                            timestamp_like += id.requests;
                        }
                    }
                }
            }
            let status_available = a.classes.total_observations() > a.classes.unavailable;
            let measurable = complete && status_available;
            let rejected_share = measurable
                .then(|| ratio(rejected as u64, (content.len() + rejected) as u64))
                .flatten();
            let timestamp_share = (a.id_omissions == 0 && self.first.is_some())
                .then(|| ratio(timestamp_like, numeric))
                .flatten();
            let omitted_values = if measurable {
                content
                    .len()
                    .saturating_sub(options.max_reported_ids_per_entry)
            } else {
                0
            };
            self.summary.omissions.id_observations_beyond_cap += a.id_omissions;
            self.summary.omissions.response_size_observations_beyond_cap += a.size_omissions;
            if a.id_omissions > 0 {
                self.summary.entries_with_id_cap_omissions += 1;
            }
            if a.ids.len() >= options.min_distinct_ids {
                self.summary.entries_at_or_above_minimum += 1;
                qualifying_peers.insert(key.peer.clone());
            } else if a.id_omissions == 0 {
                self.summary.entries_below_minimum += 1;
                continue;
            } else {
                self.summary.entries_below_minimum_unproven += 1;
            }
            self.summary.omissions.content_id_values_not_reported += omitted_values as u64;
            match rejected_share {
                None => self.summary.rejected_share_unavailable += 1,
                Some(v) if v < 0.3 => self.summary.rejected_share_below_03 += 1,
                Some(v) if v < 0.5 => self.summary.rejected_share_03_to_05 += 1,
                Some(v) if v < 0.8 => self.summary.rejected_share_05_to_08 += 1,
                Some(_) => self.summary.rejected_share_at_least_08 += 1,
            }
            self.summary.timestamp_like_share_at_least_half +=
                usize::from(timestamp_share.is_some_and(|s| s >= 0.5));
            let prefix_share = ratio(a.prefix_pairs, a.pairs);
            self.summary.prefix_extension_share_at_least_half +=
                usize::from(prefix_share.is_some_and(|s| s >= 0.5));
            Rc::make_mut(&mut key.0).peer.source = a.raw_source;
            rows.push(Entry {
                key,
                requests: a.requests,
                distinct_ids: (a.id_omissions == 0).then_some(a.ids.len()),
                distinct_ids_at_least: a.ids.len(),
                content_ids: measurable.then_some(content.len()),
                rejected_ids: measurable.then_some(rejected),
                redirect_only_ids: measurable.then_some(redirect_only),
                rejected_id_share: rejected_share,
                dominant_2xx_response_bytes: dominant,
                stable_size_ids: measurable.then_some(stable),
                repeated_content_ids: measurable.then_some(repeated),
                adjacent_step_share: ratio(a.adjacent_pairs, a.numeric_pairs),
                adjacent_numeric_pairs: a.numeric_pairs,
                numeric_values_outside_u64: a.numeric_overflow,
                prefix_extension_share: prefix_share,
                consecutive_value_pairs: a.pairs,
                timestamp_like_share: timestamp_share,
                self_reference_segment: a.self_reference,
                ids_written_by_same_peer: written,
                ids_written_before_first_content: measurable.then_some(written_before),
                write_history_incomplete: a.id_omissions > 0
                    || self.summary.omissions.write_observations_beyond_peer_cap > 0
                    || writes.is_some_and(|w| w.omitted > 0),
                first_seen: a.first,
                last_seen: a.last,
                content_id_values: measurable.then(|| {
                    content
                        .into_iter()
                        .take(options.max_reported_ids_per_entry)
                        .collect()
                }),
                content_id_values_not_reported: omitted_values,
                id_observations_beyond_cap: a.id_omissions,
                response_size_observations_beyond_cap: a.size_omissions,
                successful_responses_without_bytes: a.missing_bytes,
                status_observations_unavailable: a.classes.unavailable,
                timestamp_observations_unavailable: a.missing_times,
                status_classes: a.classes,
            });
        }
        rows.sort_by(|a, b| {
            b.rejected_ids
                .cmp(&a.rejected_ids)
                .then(b.distinct_ids_at_least.cmp(&a.distinct_ids_at_least))
                .then(a.key.cmp(&b.key))
        });
        self.summary.sources_at_or_above_minimum = qualifying_peers.len();
        self.summary.reported_entries = rows.len();
        Report {
            safety_note: SAFETY_NOTE,
            summary: self.summary,
            entries: rows,
        }
    }
}

/// Read each input once, retain bounded private observations and write separate artifacts.
pub fn run(
    input: &Path,
    profile: TelemetryProfile,
    range: &HuntTimeRange,
    options: &Options,
    output: &Path,
    corpus_label: Option<&str>,
    proxies: &TrustedProxySet,
) -> Result<Report> {
    options.validate()?;
    range.validate()?;
    ensure_separate_output(input, output)?;
    let names = [
        "identifier-access.json",
        "sanitized-identifier-access.json",
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
        corpus.push(stream_events_with_fingerprint(
            &path,
            profile,
            proxies,
            RawRetention::Drop,
            |event| {
                match event {
                    Ok(event) => {
                        analysis.summary.parseable_records += 1;
                        if range.includes(event.timestamp) {
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
    let mut manifest = serde_json::json!({
        "safety_note":"Private corpus paths and analyst configuration; review before sharing. SHA-256 identifies input bytes, not a Shenron finding.",
        "measurement_safety_note":SAFETY_NOTE, "shenron_version":env!("CARGO_PKG_VERSION"),
        "telemetry_profile":profile, "options":options, "from":range.from,"to":range.to,
        "trusted_proxy_networks":proxies.configured_proxy_networks(), "corpus":corpus,
        "skipped_inputs":report.summary.input_discovery.skipped
    });
    if let Some(label) = corpus_label {
        manifest["corpus_label"] = label.into();
    }
    fs::create_dir_all(output)?;
    #[derive(Serialize)]
    #[serde(untagged)]
    enum Artifact<'a> {
        Private(&'a Report),
        Sanitized(&'a Summary),
        Manifest(&'a serde_json::Value),
    }
    let paths = names.map(|name| output.join(name));
    write_json_pretty_new_batch(&[
        (paths[0].as_path(), Artifact::Private(&report)),
        (paths[1].as_path(), Artifact::Sanitized(&report.summary)),
        (paths[2].as_path(), Artifact::Manifest(&manifest)),
    ])?;
    Ok(report)
}

pub fn write_text(
    mut out: impl Write,
    report: &Report,
    show_paths: bool,
    show_sources: bool,
    limit: usize,
) -> Result<()> {
    writeln!(out, "{SAFETY_NOTE}")?;
    if let Some(disclosure) = report.summary.input_discovery.disclosure() {
        writeln!(out, "{disclosure}")?;
    }
    writeln!(out, "Identifier-access summary (aggregate counts only):")?;
    serde_json::to_writer_pretty(&mut out, &report.summary)?;
    writeln!(out)?;
    let shown = if limit == 0 {
        report.entries.len()
    } else {
        limit.min(report.entries.len())
    };
    for (i, row) in report.entries.iter().take(shown).enumerate() {
        let mut numbers = serde_json::to_value(row)?;
        for key in [
            "identity",
            "source",
            "method",
            "host",
            "template",
            "position",
            "self_reference_segment",
            "content_id_values",
        ] {
            numbers
                .as_object_mut()
                .expect("entry is an object")
                .remove(key);
        }
        writeln!(out, "Entry {}: {}", i + 1, numbers)?;
        if show_sources {
            writeln!(
                out,
                "  Source ({}): {}",
                row.key.peer.identity,
                terminal_safe(&row.key.peer.source)
            )?;
        }
        if show_paths {
            writeln!(
                out,
                "  Template: {} / position: {} / method: {}",
                terminal_safe(&row.key.template),
                terminal_safe(&row.key.position),
                terminal_safe(&row.key.method)
            )?;
        }
    }
    writeln!(
        out,
        "Entries not displayed: {}",
        report.entries.len() - shown
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_log::{parse_combined_line, AccessLogFormat};

    fn options() -> Options {
        Options {
            min_distinct_ids: 1,
            exclude_query_param: Vec::new(),
            max_entries: 100,
            max_ids_per_entry: 100,
            max_reported_ids_per_entry: 100,
            max_written_ids_per_peer: 100,
            max_response_size_pairs_per_entry: 100,
        }
    }
    fn event(method: &str, uri: &str, status: u16, size: u64, second: u8) -> WebEvent {
        parse_combined_line(&format!("example.test:443 192.0.2.10 - - [01/Jan/2026:00:00:{second:02} +0000] \"{method} {uri} HTTP/1.1\" {status} {size} \"-\" \"fixture-agent\""),
            AccessLogFormat::ApacheVhostCombined).unwrap()
    }

    #[test]
    fn identifier_extraction_preserves_suffixes_spelling_and_distinct_positions() {
        let options = options();
        let mut summary = Summary::default();
        let found = extract(&event("GET", "/Me/0012.json/ABCDEF01-2345-6789-abcd-123456789012?code=0001&code=0002&u=abcdef01-2345-6789-abcd-123456789012", 200, 10, 0),
            &options, &mut summary);
        assert_eq!(found.len(), 4);
        assert!(found.iter().all(|v| v.template == "/Me/{num}.json/{uuid}"));
        assert_eq!(found[0].value, "0012");
        assert_eq!(found[0].position, "path:2");
        assert_eq!(found[0].self_reference.as_deref(), Some("Me"));
        assert_eq!(found[1].value, "ABCDEF01-2345-6789-abcd-123456789012");
        assert_eq!(found[2].value, "0001");
        assert_eq!(summary.repeated_query_identifier_observations, 1);
        for rejected in [
            "v1",
            "12.json.more",
            "12.abcdefghijk",
            "%31",
            "-1",
            "123456789012345678901",
        ] {
            assert!(path_id(rejected).is_none(), "{rejected}");
        }
        assert!(path_id("12.JSON").is_some());
        assert!(path_id("abcdef01-2345-6789-abcd-123456789012.json").is_some());
    }

    #[test]
    fn dominant_size_uses_distinct_ids_ties_choose_smallest_and_content_repeats_are_exact() {
        let options = options();
        let mut analysis = Analysis::default();
        // Repeating one ID never outweighs a size returned to two different IDs.
        for _ in 0..10 {
            analysis.observe(event("GET", "/items/1", 200, 100, 0), &options);
        }
        for (id, size) in [
            (2, 800),
            (3, 800),
            (4, 900),
            (5, 900),
            (6, 101),
            (6, 101),
            (7, 102),
            (7, 103),
        ] {
            analysis.observe(
                event("GET", &format!("/items/{id}"), 200, size, 1),
                &options,
            );
        }
        let report = analysis.finish(&options);
        let row = &report.entries[0];
        assert_eq!(row.dominant_2xx_response_bytes, Some(800));
        assert_eq!(row.content_ids, Some(5));
        assert_eq!(row.rejected_ids, Some(2));
        assert_eq!(row.repeated_content_ids, Some(3));
        assert_eq!(row.stable_size_ids, Some(2));
        assert_eq!(
            row.content_id_values.as_ref().unwrap(),
            &["1", "4", "5", "6", "7"]
        );
    }

    #[test]
    fn writes_are_bounded_cross_template_and_require_strictly_prior_dated_content() {
        let mut options = options();
        options.max_written_ids_per_peer = 1;
        let mut analysis = Analysis::default();
        analysis.observe(event("PUT", "/items/1.json", 400, 10, 3), &options);
        analysis.observe(event("PUT", "/items/2.json", 200, 10, 0), &options);
        analysis.observe(event("GET", "/other/1/images", 200, 100, 1), &options);
        analysis.observe(event("GET", "/other/2/images", 200, 101, 2), &options);
        let report = analysis.finish(&options);
        let get = report
            .entries
            .iter()
            .find(|e| e.key.method == "GET")
            .unwrap();
        assert_eq!(get.ids_written_by_same_peer, 1);
        assert_eq!(get.ids_written_before_first_content, Some(0));
        assert!(get.write_history_incomplete);
        assert_eq!(report.summary.omissions.write_observations_beyond_id_cap, 1);

        let mut analysis = Analysis::default();
        analysis.observe(event("PUT", "/items/1.json", 200, 10, 0), &options);
        let mut undated = event("GET", "/other/1/images", 200, 100, 1);
        undated.timestamp = None;
        analysis.observe(undated, &options);
        analysis.observe(event("GET", "/other/1/images", 200, 100, 2), &options);
        let report = analysis.finish(&options);
        let get = report
            .entries
            .iter()
            .find(|e| e.key.method == "GET")
            .unwrap();
        assert_eq!(get.ids_written_before_first_content, Some(0));
        assert_eq!(get.timestamp_observations_unavailable, 1);
    }

    #[test]
    fn identifier_missing_bytes_overflow_and_id_caps_do_not_create_measured_zeroes() {
        let mut options = options();
        options.max_ids_per_entry = 2;
        let mut analysis = Analysis::default();
        let mut missing = event("GET", "/items/18446744073709551616", 200, 1, 0);
        missing.response_bytes = None;
        analysis.observe(missing, &options);
        analysis.observe(event("GET", "/items/2", 404, 1, 1), &options);
        let report = analysis.finish(&options);
        let row = &report.entries[0];
        assert_eq!(row.distinct_ids, Some(2));
        assert_eq!(row.numeric_values_outside_u64, 1);
        assert_eq!(row.adjacent_step_share, None);
        assert_eq!(row.content_ids, None);
        assert_eq!(row.successful_responses_without_bytes, 1);

        let mut analysis = Analysis::default();
        for id in [1, 2, 3, 1] {
            analysis.observe(event("GET", &format!("/items/{id}"), 404, 1, 0), &options);
        }
        let report = analysis.finish(&options);
        assert_eq!(report.entries[0].id_observations_beyond_cap, 1);
        assert_eq!(report.entries[0].status_classes.client_error, 4);
        assert_eq!(report.entries[0].distinct_ids, None);
    }
}
