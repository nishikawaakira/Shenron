//! Offline comparison of self-declared crawler User-Agents with frozen,
//! operator-published network ranges.
//!
//! The comparison is a labeled observation only. Published ranges can be
//! incomplete or stale, intermediaries can change the observed peer, and any
//! client can set a User-Agent string. Nothing here determines impersonation,
//! attack, abuse, compromise, vulnerability, or attacker identity.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::BufReader,
    net::IpAddr,
    path::Path,
};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event::WebEvent;

pub const BOT_RANGE_REPORT_KIND: &str = "PUBLISHED_BOT_RANGE_SNAPSHOT";
pub const BOT_RANGE_PRIVATE_REPORT_KIND: &str = "BOT_RANGE_OBSERVATIONS_PRIVATE";
pub const BOT_RANGE_SAFETY_NOTE: &str = "A User-Agent whose observed peer is outside the named operator's published ranges is only outside that frozen range snapshot. Published ranges can be incomplete or stale, an intermediary can rewrite the peer address, and any client can set a User-Agent. This is a labeled observation for review, not a determination of impersonation, attack, abuse, compromise, vulnerability, or attacker identity.";

/// Download catalog kept as data rather than embedding UA/range pairs in
/// matching code. Several records may contribute to one operator.
#[derive(Debug, Clone, Deserialize)]
pub struct BotRangeSourceDefinition {
    pub operator_id: String,
    pub operator_name: String,
    pub user_agent_patterns: Vec<String>,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BotRangeSourceProvenance {
    pub url: String,
    pub retrieved_at: String,
    pub sha256: String,
    pub records: usize,
    pub invalid_records_excluded: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BotOperatorSnapshot {
    pub operator_id: String,
    pub operator_name: String,
    pub user_agent_patterns: Vec<String>,
    pub cidrs: Vec<String>,
    pub sources: Vec<BotRangeSourceProvenance>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BotRangeSnapshot {
    pub report_kind: String,
    pub generated_at: String,
    pub safety_note: String,
    pub operators: Vec<BotOperatorSnapshot>,
}

#[derive(Debug, Clone)]
struct CompiledOperator {
    operator_id: String,
    operator_name: String,
    user_agent_patterns: Vec<String>,
    ranges: Vec<IpNet>,
}

/// Frozen local matcher database. Loading and lookup perform no network I/O.
#[derive(Debug, Clone)]
pub struct BotRangeDatabase {
    operators: Vec<CompiledOperator>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BotOperatorObservation {
    pub operator_id: String,
    pub operator_name: String,
    pub declared_requests: u64,
    pub within_published_ranges_requests: u64,
    pub within_published_ranges_distinct_source_ips: usize,
    pub outside_published_ranges_requests: u64,
    pub outside_published_ranges_distinct_source_ips: usize,
    pub source_ip_unavailable_requests: u64,
    pub outside_published_ranges_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateBotRangeSource {
    pub source_ip: String,
    pub requests: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateBotOperatorObservation {
    #[serde(flatten)]
    pub summary: BotOperatorObservation,
    pub outside_published_range_sources: Vec<PrivateBotRangeSource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateBotRangeReport {
    pub report_kind: String,
    pub safety_note: String,
    pub operators: Vec<PrivateBotOperatorObservation>,
}

#[derive(Debug, Default)]
struct OperatorAccumulator {
    declared_requests: u64,
    inside_sources: BTreeSet<String>,
    inside_requests: u64,
    outside_sources: BTreeMap<String, u64>,
    outside_requests: u64,
    unavailable_requests: u64,
}

#[derive(Debug, Default)]
pub struct BotRangeAccumulator {
    operators: BTreeMap<String, (String, OperatorAccumulator)>,
}

impl BotRangeDatabase {
    pub fn from_snapshot(snapshot: BotRangeSnapshot) -> Result<Self> {
        if snapshot.report_kind != BOT_RANGE_REPORT_KIND {
            bail!(
                "unsupported bot-range snapshot kind {:?}; expected {BOT_RANGE_REPORT_KIND}",
                snapshot.report_kind
            );
        }
        let mut operators = Vec::new();
        for operator in snapshot.operators {
            let mut ranges = operator
                .cidrs
                .iter()
                .map(|value| {
                    value.parse::<IpNet>().with_context(|| {
                        format!(
                            "invalid published range {value:?} for operator {}",
                            operator.operator_id
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            ranges.sort_by_key(|range| range.to_string());
            operators.push(CompiledOperator {
                operator_id: operator.operator_id,
                operator_name: operator.operator_name,
                user_agent_patterns: operator.user_agent_patterns,
                ranges,
            });
        }
        operators.sort_by(|left, right| left.operator_id.cmp(&right.operator_id));
        Ok(Self { operators })
    }

    pub fn observe(&self, event: &WebEvent, accumulator: &mut BotRangeAccumulator) {
        let Some(user_agent) = event.user_agent.as_deref() else {
            return;
        };
        let normalized_user_agent = user_agent.to_ascii_lowercase();
        for operator in &self.operators {
            if !operator
                .user_agent_patterns
                .iter()
                .any(|pattern| normalized_user_agent.contains(&pattern.to_ascii_lowercase()))
            {
                continue;
            }
            let (_, observed) = accumulator
                .operators
                .entry(operator.operator_id.clone())
                .or_insert_with(|| {
                    (
                        operator.operator_name.clone(),
                        OperatorAccumulator::default(),
                    )
                });
            observed.declared_requests += 1;
            let Some(source_ip) = event.source_ip.as_deref() else {
                observed.unavailable_requests += 1;
                continue;
            };
            let Ok(address) = source_ip.parse::<IpAddr>() else {
                observed.unavailable_requests += 1;
                continue;
            };
            if operator.ranges.iter().any(|range| range.contains(&address)) {
                observed.inside_requests += 1;
                observed.inside_sources.insert(source_ip.to_owned());
            } else {
                observed.outside_requests += 1;
                *observed
                    .outside_sources
                    .entry(source_ip.to_owned())
                    .or_default() += 1;
            }
        }
    }
}

impl BotRangeAccumulator {
    pub fn reports(&self) -> (Vec<BotOperatorObservation>, PrivateBotRangeReport) {
        let mut sanitized = Vec::new();
        let mut private = Vec::new();
        for (operator_id, (operator_name, observed)) in &self.operators {
            let classified = observed.inside_requests + observed.outside_requests;
            let summary = BotOperatorObservation {
                operator_id: operator_id.clone(),
                operator_name: operator_name.clone(),
                declared_requests: observed.declared_requests,
                within_published_ranges_requests: observed.inside_requests,
                within_published_ranges_distinct_source_ips: observed.inside_sources.len(),
                outside_published_ranges_requests: observed.outside_requests,
                outside_published_ranges_distinct_source_ips: observed.outside_sources.len(),
                source_ip_unavailable_requests: observed.unavailable_requests,
                outside_published_ranges_rate: (classified != 0)
                    .then(|| observed.outside_requests as f64 / classified as f64),
            };
            let mut outside_sources = observed
                .outside_sources
                .iter()
                .map(|(source_ip, requests)| PrivateBotRangeSource {
                    source_ip: source_ip.clone(),
                    requests: *requests,
                })
                .collect::<Vec<_>>();
            outside_sources.sort_by(|left, right| {
                right
                    .requests
                    .cmp(&left.requests)
                    .then_with(|| left.source_ip.cmp(&right.source_ip))
            });
            sanitized.push(summary.clone());
            private.push(PrivateBotOperatorObservation {
                summary,
                outside_published_range_sources: outside_sources,
            });
        }
        (
            sanitized,
            PrivateBotRangeReport {
                report_kind: BOT_RANGE_PRIVATE_REPORT_KIND.to_owned(),
                safety_note: BOT_RANGE_SAFETY_NOTE.to_owned(),
                operators: private,
            },
        )
    }
}

pub fn load_bot_range_database(path: &Path) -> Result<BotRangeDatabase> {
    let snapshot: BotRangeSnapshot = serde_json::from_reader(BufReader::new(
        File::open(path)
            .with_context(|| format!("opening bot-range snapshot {}", path.display()))?,
    ))
    .with_context(|| format!("reading bot-range snapshot {}", path.display()))?;
    BotRangeDatabase::from_snapshot(snapshot)
}

/// Parse the built-in public-source catalog. It contains operator labels, UA
/// patterns, and URLs as reviewable data rather than matcher code.
pub fn default_source_catalog() -> Result<Vec<BotRangeSourceDefinition>> {
    parse_source_catalog(include_str!("../data/bot-range-sources.json"))
}

pub fn parse_source_catalog(input: &str) -> Result<Vec<BotRangeSourceDefinition>> {
    let mut sources: Vec<BotRangeSourceDefinition> = serde_json::from_str(input)?;
    sources.sort_by(|left, right| {
        left.operator_id
            .cmp(&right.operator_id)
            .then_with(|| left.url.cmp(&right.url))
    });
    Ok(sources)
}

/// Build a deterministic normalized snapshot from already-downloaded public
/// JSON. The caller owns network retrieval; this function is pure.
pub fn snapshot_from_downloads(
    sources: &[BotRangeSourceDefinition],
    downloads: &BTreeMap<String, Vec<u8>>,
    retrieved_at: &str,
) -> Result<BotRangeSnapshot> {
    let mut operators = BTreeMap::<
        String,
        (
            String,
            BTreeSet<String>,
            BTreeSet<String>,
            Vec<BotRangeSourceProvenance>,
        ),
    >::new();
    for source in sources {
        let bytes = downloads
            .get(&source.url)
            .with_context(|| format!("no downloaded content for {}", source.url))?;
        let parsed = parse_published_ranges(bytes)?;
        let entry = operators
            .entry(source.operator_id.clone())
            .or_insert_with(|| {
                (
                    source.operator_name.clone(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                    Vec::new(),
                )
            });
        if source.operator_name < entry.0 {
            entry.0 = source.operator_name.clone();
        }
        entry.1.extend(source.user_agent_patterns.iter().cloned());
        entry.2.extend(parsed.ranges.iter().cloned());
        entry.3.push(BotRangeSourceProvenance {
            url: source.url.clone(),
            retrieved_at: retrieved_at.to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            records: parsed.ranges.len(),
            invalid_records_excluded: parsed.invalid_records,
        });
    }
    Ok(BotRangeSnapshot {
        report_kind: BOT_RANGE_REPORT_KIND.to_owned(),
        generated_at: retrieved_at.to_owned(),
        safety_note: BOT_RANGE_SAFETY_NOTE.to_owned(),
        operators: operators
            .into_iter()
            .map(
                |(operator_id, (operator_name, patterns, ranges, mut sources))| {
                    sources.sort_by(|left, right| left.url.cmp(&right.url));
                    BotOperatorSnapshot {
                        operator_id,
                        operator_name,
                        user_agent_patterns: patterns.into_iter().collect(),
                        cidrs: ranges.into_iter().collect(),
                        sources,
                    }
                },
            )
            .collect(),
    })
}

/// Extract the common `prefixes[].ipv4Prefix/ipv6Prefix` schema published by
/// supported operators. Invalid entries are reported by omission count at the
/// update layer rather than being accepted into a frozen snapshot.
pub fn published_ranges_from_json(input: &[u8]) -> Result<Vec<String>> {
    Ok(parse_published_ranges(input)?.ranges)
}

struct ParsedPublishedRanges {
    ranges: Vec<String>,
    invalid_records: usize,
}

fn parse_published_ranges(input: &[u8]) -> Result<ParsedPublishedRanges> {
    let value: serde_json::Value = serde_json::from_slice(input)?;
    let prefixes = value
        .get("prefixes")
        .and_then(serde_json::Value::as_array)
        .context("published range JSON has no prefixes array")?;
    let mut ranges = Vec::new();
    let mut invalid_records = 0;
    for entry in prefixes {
        let value = entry
            .get("ipv4Prefix")
            .or_else(|| entry.get("ipv6Prefix"))
            .and_then(serde_json::Value::as_str);
        match value.and_then(|value| value.parse::<IpNet>().ok()) {
            Some(range) => ranges.push(range.to_string()),
            None => invalid_records += 1,
        }
    }
    ranges.sort();
    ranges.dedup();
    Ok(ParsedPublishedRanges {
        ranges,
        invalid_records,
    })
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::event::{LogSource, WebEvent};

    fn event(source_ip: &str, user_agent: &str) -> WebEvent {
        WebEvent {
            timestamp: Some(Utc.timestamp_opt(0, 0).unwrap()),
            source_ip: Some(source_ip.to_owned()),
            client_ip: None,
            source_port: None,
            country: None,
            host: None,
            method: Some("GET".to_owned()),
            uri: Some("/".to_owned()),
            uri_path: Some("/".to_owned()),
            uri_query: None,
            uri_fragment: None,
            headers: Vec::new(),
            user_agent: Some(user_agent.to_owned()),
            referer: None,
            status: Some(200),
            response_bytes: None,
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

    fn database() -> BotRangeDatabase {
        BotRangeDatabase::from_snapshot(BotRangeSnapshot {
            report_kind: BOT_RANGE_REPORT_KIND.to_owned(),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            safety_note: BOT_RANGE_SAFETY_NOTE.to_owned(),
            operators: vec![
                BotOperatorSnapshot {
                    operator_id: "alpha".to_owned(),
                    operator_name: "Alpha".to_owned(),
                    user_agent_patterns: vec!["AlphaBot".to_owned(), "SharedBot".to_owned()],
                    cidrs: vec!["198.51.100.0/24".to_owned(), "2001:db8:1::/48".to_owned()],
                    sources: Vec::new(),
                },
                BotOperatorSnapshot {
                    operator_id: "beta".to_owned(),
                    operator_name: "Beta".to_owned(),
                    user_agent_patterns: vec!["BetaBot".to_owned(), "SharedBot".to_owned()],
                    cidrs: vec!["203.0.113.0/24".to_owned()],
                    sources: Vec::new(),
                },
            ],
        })
        .unwrap()
    }

    #[test]
    fn classifies_inside_outside_and_ipv6_published_ranges() {
        let database = database();
        let mut accumulator = BotRangeAccumulator::default();
        for item in [
            event("198.51.100.7", "AlphaBot/1.0"),
            event("192.0.2.7", "AlphaBot/1.0"),
            event("2001:db8:1::7", "AlphaBot/1.0"),
        ] {
            database.observe(&item, &mut accumulator);
        }
        let (summary, private) = accumulator.reports();
        assert_eq!(summary[0].within_published_ranges_requests, 2);
        assert_eq!(summary[0].outside_published_ranges_requests, 1);
        assert_eq!(summary[0].outside_published_ranges_distinct_source_ips, 1);
        assert_eq!(
            private.operators[0].outside_published_range_sources[0].source_ip,
            "192.0.2.7"
        );
        assert!(!serde_json::to_string(&summary)
            .unwrap()
            .contains("192.0.2.7"));
    }

    #[test]
    fn overlapping_ua_declarations_are_reported_in_stable_operator_order() {
        let database = database();
        let mut accumulator = BotRangeAccumulator::default();
        database.observe(&event("198.51.100.7", "SharedBot/1.0"), &mut accumulator);
        database.observe(&event("203.0.113.7", "SharedBot/1.0"), &mut accumulator);
        let (summary, _) = accumulator.reports();
        assert_eq!(
            summary
                .iter()
                .map(|item| item.operator_id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "beta"]
        );
        assert_eq!(summary[0].within_published_ranges_requests, 1);
        assert_eq!(summary[0].outside_published_ranges_requests, 1);
        assert_eq!(summary[1].within_published_ranges_requests, 1);
        assert_eq!(summary[1].outside_published_ranges_requests, 1);
    }

    #[test]
    fn parses_ipv4_and_ipv6_prefixes_deterministically() {
        let ranges = published_ranges_from_json(
            br#"{"prefixes":[{"ipv6Prefix":"2001:db8::/32"},{"ipv4Prefix":"198.51.100.0/24"}]}"#,
        )
        .unwrap();
        assert_eq!(ranges, vec!["198.51.100.0/24", "2001:db8::/32"]);
    }

    #[test]
    fn freezes_source_url_time_hash_counts_and_exclusions() {
        let sources = parse_source_catalog(
            r#"[{"operator_id":"alpha","operator_name":"Alpha","user_agent_patterns":["AlphaBot"],"url":"file:///alpha.json"}]"#,
        )
        .unwrap();
        let bytes = br#"{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"},{"ipv6Prefix":"bad"}]}"#;
        let snapshot = snapshot_from_downloads(
            &sources,
            &BTreeMap::from([("file:///alpha.json".to_owned(), bytes.to_vec())]),
            "2026-01-02T03:04:05Z",
        )
        .unwrap();
        let provenance = &snapshot.operators[0].sources[0];
        assert_eq!(provenance.url, "file:///alpha.json");
        assert_eq!(provenance.retrieved_at, "2026-01-02T03:04:05Z");
        assert_eq!(provenance.sha256.len(), 64);
        assert_eq!(provenance.records, 1);
        assert_eq!(provenance.invalid_records_excluded, 1);
    }
}
