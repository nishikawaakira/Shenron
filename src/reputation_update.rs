//! Deterministic conversion of public IP/ASN list downloads into local inputs.
//!
//! Network retrieval is deliberately kept in `shenron-lab`; these helpers only
//! parse already-downloaded public text and never receive customer telemetry.

use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use anyhow::{Context, Result};
use serde::Serialize;

pub const SPAMHAUS_DROP_URL: &str = "https://www.spamhaus.org/drop/drop.txt";
pub const FIREHOL_LEVEL1_URL: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";
pub const CINS_URL: &str = "https://cinsscore.com/list/ci-badguys.txt";
pub const BLOCKLIST_DE_URL: &str = "https://lists.blocklist.de/lists/all.txt";
pub const IPTOASN_V4_URL: &str = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";

/// One auditable third-party opinion emitted to the local JSONL dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReputationRecord {
    pub scope: String,
    pub value: String,
    pub score: u32,
    pub source: String,
    pub categories: Vec<String>,
}

/// One non-overlapping IPv4 ASN range emitted to the local TSV dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnRangeRecord {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub asn: u32,
    pub org: String,
}

/// Parse Spamhaus DROP's `CIDR ; description` records.
pub fn parse_spamhaus_drop(input: &str) -> Vec<ReputationRecord> {
    input
        .lines()
        .filter_map(|line| {
            let value = line.trim();
            if value.is_empty() || value.starts_with(';') || value.starts_with('#') {
                return None;
            }
            let cidr = value.split(';').next()?.trim();
            cidr.parse::<ipnet::IpNet>().ok()?;
            Some(reputation_record("cidr", cidr, 95, "spamhaus-drop", "drop"))
        })
        .collect()
}

/// Parse FireHOL level 1 network or IP records, excluding its null route.
pub fn parse_firehol_level1(input: &str) -> Vec<ReputationRecord> {
    input
        .lines()
        .filter_map(|line| parse_address_line(line, 90, "firehol-level1", "firehol"))
        .filter(|record| record.value != "0.0.0.0/8")
        .collect()
}

/// Parse CINS Army one-IP-per-line records.
pub fn parse_cins(input: &str) -> Vec<ReputationRecord> {
    input
        .lines()
        .filter_map(|line| parse_single_ip_line(line, 85, "cins-army", "ci-badguys"))
        .collect()
}

/// Parse blocklist.de one-IP-per-line records.
pub fn parse_blocklist_de(input: &str) -> Vec<ReputationRecord> {
    input
        .lines()
        .filter_map(|line| parse_single_ip_line(line, 80, "blocklist.de", "blocklist.de"))
        .collect()
}

/// Parse iptoasn's downloaded IPv4 TSV, excluding unassigned ASN zero ranges.
pub fn parse_iptoasn_v4(input: &str) -> Vec<AsnRangeRecord> {
    let mut records = input
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() < 5 {
                return None;
            }
            let start = fields[0].trim().parse::<Ipv4Addr>().ok()?;
            let end = fields[1].trim().parse::<Ipv4Addr>().ok()?;
            let asn = fields[2].trim().parse::<u32>().ok()?;
            if asn == 0 || u32::from(start) > u32::from(end) {
                return None;
            }
            Some(AsnRangeRecord {
                start,
                end,
                asn,
                org: tsv_field(fields[4]),
            })
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| u32::from(record.start));
    records
}

/// Write reputation records as one deterministic JSON record per line.
pub fn write_reputation_jsonl(path: &Path, records: &[ReputationRecord]) -> Result<()> {
    let mut records = records.to_vec();
    records.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then_with(|| left.value.cmp(&right.value))
            .then_with(|| left.source.cmp(&right.source))
    });
    let mut output = String::new();
    for record in records {
        output.push_str(&serde_json::to_string(&record)?);
        output.push('\n');
    }
    std::fs::write(path, output)
        .with_context(|| format!("writing reputation dataset {}", path.display()))
}

/// Write sorted IPv4 ASN ranges as `start<TAB>end<TAB>asn<TAB>org`.
pub fn write_asn_ranges(path: &Path, records: &[AsnRangeRecord]) -> Result<()> {
    let mut records = records.to_vec();
    records.sort_by_key(|record| u32::from(record.start));
    let mut output = String::new();
    for record in records {
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            record.start,
            record.end,
            record.asn,
            tsv_field(&record.org)
        ));
    }
    std::fs::write(path, output)
        .with_context(|| format!("writing ASN range dataset {}", path.display()))
}

fn parse_address_line(
    line: &str,
    score: u32,
    source: &str,
    category: &str,
) -> Option<ReputationRecord> {
    let value = leading_value(line)?;
    if value.parse::<IpAddr>().is_ok() {
        Some(reputation_record("ip", value, score, source, category))
    } else if value.parse::<ipnet::IpNet>().is_ok() {
        Some(reputation_record("cidr", value, score, source, category))
    } else {
        None
    }
}

fn parse_single_ip_line(
    line: &str,
    score: u32,
    source: &str,
    category: &str,
) -> Option<ReputationRecord> {
    let value = leading_value(line)?;
    value.parse::<IpAddr>().ok()?;
    Some(reputation_record("ip", value, score, source, category))
}

fn leading_value(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    line.split(|character: char| character.is_whitespace() || character == '#' || character == ';')
        .next()
        .filter(|value| !value.is_empty())
}

fn reputation_record(
    scope: &str,
    value: &str,
    score: u32,
    source: &str,
    category: &str,
) -> ReputationRecord {
    ReputationRecord {
        scope: scope.to_owned(),
        value: value.to_owned(),
        score,
        source: source.to_owned(),
        categories: vec![category.to_owned()],
    }
}

fn tsv_field(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ").trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn converts_public_reputation_lists_without_network_access() {
        assert_eq!(
            parse_spamhaus_drop("; comment\n203.0.113.0/24 ; SBL\n# comment\n")[0],
            reputation_record("cidr", "203.0.113.0/24", 95, "spamhaus-drop", "drop")
        );
        assert_eq!(
            parse_firehol_level1("0.0.0.0/8\n198.51.100.7\n203.0.113.0/24 # note\n"),
            vec![
                reputation_record("ip", "198.51.100.7", 90, "firehol-level1", "firehol"),
                reputation_record("cidr", "203.0.113.0/24", 90, "firehol-level1", "firehol"),
            ]
        );
        assert_eq!(
            parse_cins("# comment\n192.0.2.10\nnot-an-ip\n")[0],
            reputation_record("ip", "192.0.2.10", 85, "cins-army", "ci-badguys")
        );
        assert_eq!(
            parse_blocklist_de("198.51.100.8\n")[0],
            reputation_record("ip", "198.51.100.8", 80, "blocklist.de", "blocklist.de")
        );
    }

    #[test]
    fn converts_and_sorts_iptoasn_ranges_without_network_access() {
        let ranges = parse_iptoasn_v4(
            "198.51.100.0\t198.51.100.255\t64501\tUS\tExample Two\n192.0.2.0\t192.0.2.255\t0\tUS\tUnassigned\n192.0.3.0\t192.0.3.255\t64500\tUS\tExample One\n",
        );
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, "192.0.3.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ranges[0].asn, 64_500);
        assert_eq!(ranges[1].org, "Example Two");
    }

    #[test]
    fn writes_deterministic_local_jsonl_and_tsv_outputs() {
        let directory = tempdir().unwrap();
        let reputation = directory.path().join("reputation.jsonl");
        let ranges = directory.path().join("asn-ranges.tsv");
        write_reputation_jsonl(
            &reputation,
            &[
                reputation_record("ip", "198.51.100.9", 80, "blocklist.de", "blocklist.de"),
                reputation_record("cidr", "203.0.113.0/24", 95, "spamhaus-drop", "drop"),
            ],
        )
        .unwrap();
        write_asn_ranges(
            &ranges,
            &[
                AsnRangeRecord {
                    start: "198.51.100.0".parse().unwrap(),
                    end: "198.51.100.255".parse().unwrap(),
                    asn: 64_501,
                    org: "Second\tOrg".to_owned(),
                },
                AsnRangeRecord {
                    start: "192.0.2.0".parse().unwrap(),
                    end: "192.0.2.255".parse().unwrap(),
                    asn: 64_500,
                    org: "First Org".to_owned(),
                },
            ],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(reputation).unwrap(),
            concat!(
                "{\"scope\":\"cidr\",\"value\":\"203.0.113.0/24\",\"score\":95,\"source\":\"spamhaus-drop\",\"categories\":[\"drop\"]}\n",
                "{\"scope\":\"ip\",\"value\":\"198.51.100.9\",\"score\":80,\"source\":\"blocklist.de\",\"categories\":[\"blocklist.de\"]}\n"
            )
        );
        assert_eq!(
            std::fs::read_to_string(ranges).unwrap(),
            "192.0.2.0\t192.0.2.255\t64500\tFirst Org\n198.51.100.0\t198.51.100.255\t64501\tSecond Org\n"
        );
    }
}
