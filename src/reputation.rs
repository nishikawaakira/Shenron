//! Offline IP/ASN reputation enrichment for private analyst output.
//!
//! This module reads only analyst-supplied, frozen local datasets. Reputation
//! is a third-party opinion, not a determination of an attack, exploitation,
//! compromise, vulnerable product, or attacker attribution.

use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Read},
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::triage::{AsnResolver, ResolvedAsn, ScoreTier};

/// ASN information resolved from an analyst-supplied local CSV dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: u32,
    pub org: String,
}

/// Reproducibility metadata for a local enrichment dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetProvenance {
    pub path: String,
    pub sha256: String,
    pub records: usize,
}

/// A local ASN lookup database backed by either GeoLite-compatible networks or
/// non-overlapping IPv4 ranges. Both forms are loaded from local files only.
pub struct AsnDatabase {
    entries: AsnEntries,
    provenance: DatasetProvenance,
}

enum AsnEntries {
    Networks(Vec<(IpNet, AsnInfo)>),
    Ranges(Vec<AsnRange>),
}

struct AsnRange {
    start: u32,
    end: u32,
    info: AsnInfo,
}

impl AsnDatabase {
    /// Return the most-specific ASN record that contains `ip`.
    pub fn lookup(&self, ip: IpAddr) -> Option<&AsnInfo> {
        match &self.entries {
            AsnEntries::Networks(entries) => entries
                .iter()
                .filter(|(network, _)| network.contains(&ip))
                .max_by_key(|(network, _)| network.prefix_len())
                .map(|(_, asn)| asn),
            AsnEntries::Ranges(entries) => {
                let IpAddr::V4(ip) = ip else {
                    return None;
                };
                let value = u32::from(ip);
                let index = entries.partition_point(|range| range.start <= value);
                entries
                    .get(index.checked_sub(1)?)
                    .filter(|range| value <= range.end)
                    .map(|range| &range.info)
            }
        }
    }

    /// Return the immutable provenance for the local CSV file.
    pub fn provenance(&self) -> &DatasetProvenance {
        &self.provenance
    }
}

impl AsnResolver for AsnDatabase {
    fn resolve(&self, ip: IpAddr) -> Option<ResolvedAsn> {
        self.lookup(ip).map(|info| ResolvedAsn {
            asn: info.asn,
            org: info.org.clone(),
        })
    }
}

/// Load a local ASN dataset without contacting any network.
///
/// `.tsv` files use Shenron's `start_ip<TAB>end_ip<TAB>asn<TAB>org` range
/// format; every other extension keeps GeoLite2-ASN-compatible CSV support.
pub fn load_asn_database(path: &Path) -> Result<AsnDatabase> {
    if path.extension().is_some_and(|extension| extension == "tsv") {
        return load_asn_ranges(path);
    }
    let mut reader = csv::Reader::from_path(path)
        .with_context(|| format!("opening ASN dataset {}", path.display()))?;
    let headers = reader
        .headers()
        .with_context(|| format!("reading ASN dataset header {}", path.display()))?
        .clone();
    let network_index = required_header(&headers, &["network"], path)?;
    let asn_index = required_header(&headers, &["autonomous_system_number", "asn"], path)?;
    let org_index = required_header(
        &headers,
        &["autonomous_system_organization", "as_org", "as_name"],
        path,
    )?;

    let mut entries = Vec::new();
    for (row, record) in reader.records().enumerate() {
        let record = record.with_context(|| {
            format!("reading ASN dataset {} at row {}", path.display(), row + 2)
        })?;
        let network = record
            .get(network_index)
            .unwrap_or_default()
            .trim()
            .parse::<IpNet>()
            .with_context(|| {
                format!(
                    "invalid ASN network in {} at row {}",
                    path.display(),
                    row + 2
                )
            })?;
        let asn = record
            .get(asn_index)
            .unwrap_or_default()
            .trim()
            .parse::<u32>()
            .with_context(|| {
                format!(
                    "invalid ASN number in {} at row {}",
                    path.display(),
                    row + 2
                )
            })?;
        let org = record.get(org_index).unwrap_or_default().trim().to_owned();
        entries.push((network, AsnInfo { asn, org }));
    }
    let provenance = provenance(path, entries.len())?;
    Ok(AsnDatabase {
        entries: AsnEntries::Networks(entries),
        provenance,
    })
}

/// Load sorted, non-overlapping IPv4 ASN ranges and resolve them in O(log n).
pub fn load_asn_ranges(path: &Path) -> Result<AsnDatabase> {
    let reader = BufReader::new(
        File::open(path)
            .with_context(|| format!("opening ASN range dataset {}", path.display()))?,
    );
    let mut entries = Vec::new();
    for (line_number, line) in reader.lines().enumerate() {
        let line = line.with_context(|| {
            format!(
                "reading ASN range dataset {} at line {}",
                path.display(),
                line_number + 1
            )
        })?;
        if line.trim().is_empty() || line.starts_with('#') || line.starts_with("start_ip\t") {
            continue;
        }
        let fields = line.splitn(4, '\t').collect::<Vec<_>>();
        if fields.len() != 4 {
            bail!(
                "invalid ASN range in {} at line {} (expected start_ip<TAB>end_ip<TAB>asn<TAB>org)",
                path.display(),
                line_number + 1
            );
        }
        let start = fields[0].trim().parse::<Ipv4Addr>().with_context(|| {
            format!(
                "invalid ASN range start in {} at line {}",
                path.display(),
                line_number + 1
            )
        })?;
        let end = fields[1].trim().parse::<Ipv4Addr>().with_context(|| {
            format!(
                "invalid ASN range end in {} at line {}",
                path.display(),
                line_number + 1
            )
        })?;
        let start = u32::from(start);
        let end = u32::from(end);
        if start > end {
            bail!(
                "invalid descending ASN range in {} at line {}",
                path.display(),
                line_number + 1
            );
        }
        let asn = fields[2].trim().parse::<u32>().with_context(|| {
            format!(
                "invalid ASN number in {} at line {}",
                path.display(),
                line_number + 1
            )
        })?;
        entries.push(AsnRange {
            start,
            end,
            info: AsnInfo {
                asn,
                org: fields[3].trim().to_owned(),
            },
        });
    }
    entries.sort_by_key(|range| range.start);
    for pair in entries.windows(2) {
        if pair[0].end >= pair[1].start {
            bail!("overlapping ASN ranges in {}", path.display());
        }
    }
    let provenance = provenance(path, entries.len())?;
    Ok(AsnDatabase {
        entries: AsnEntries::Ranges(entries),
        provenance,
    })
}

fn required_header(headers: &csv::StringRecord, aliases: &[&str], path: &Path) -> Result<usize> {
    headers
        .iter()
        .position(|header| {
            let header = header.trim().to_ascii_lowercase();
            aliases.iter().any(|alias| header == *alias)
        })
        .ok_or_else(|| {
            anyhow!(
                "ASN dataset {} is missing required header ({})",
                path.display(),
                aliases.join(" or ")
            )
        })
}

/// One third-party reputation opinion from an analyst-supplied JSONL file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReputationHit {
    pub scope: &'static str,
    pub value: String,
    pub score: u32,
    pub source: String,
    pub categories: Vec<String>,
    pub as_of: Option<String>,
}

/// A fully local reputation database indexed by IP address, CIDR, and ASN.
pub struct ReputationDatabase {
    ip: HashMap<IpAddr, Vec<ReputationHit>>,
    cidr: Vec<(IpNet, ReputationHit)>,
    asn: HashMap<u32, Vec<ReputationHit>>,
    provenance: DatasetProvenance,
}

impl ReputationDatabase {
    /// Look up every applicable local reputation opinion for an entity.
    ///
    /// The headline score uses most-specific precedence (IP, then CIDR, then
    /// ASN), while `hits` retains all opinions in that same scope order.
    pub fn lookup(&self, ip: IpAddr, asn: Option<u32>) -> EntityReputation {
        let ip_hits = self.ip.get(&ip).cloned().unwrap_or_default();
        let cidr_hits = self
            .cidr
            .iter()
            .filter(|(network, _)| network.contains(&ip))
            .map(|(_, hit)| hit.clone())
            .collect::<Vec<_>>();
        let asn_hits = asn
            .and_then(|number| self.asn.get(&number))
            .cloned()
            .unwrap_or_default();

        let (score, score_scope) = if !ip_hits.is_empty() {
            (ip_hits.iter().map(|hit| hit.score).max(), Some("ip"))
        } else if !cidr_hits.is_empty() {
            (cidr_hits.iter().map(|hit| hit.score).max(), Some("cidr"))
        } else if !asn_hits.is_empty() {
            (asn_hits.iter().map(|hit| hit.score).max(), Some("asn"))
        } else {
            (None, None)
        };

        let mut hits = ip_hits;
        hits.extend(cidr_hits);
        hits.extend(asn_hits);
        hits.sort_by(|left, right| {
            scope_rank(left.scope)
                .cmp(&scope_rank(right.scope))
                .then_with(|| right.score.cmp(&left.score))
                .then_with(|| left.value.cmp(&right.value))
                .then_with(|| left.source.cmp(&right.source))
        });
        EntityReputation {
            hits,
            score,
            tier: score.map(score_tier),
            score_scope,
        }
    }

    /// Look up only ASN-scoped third-party opinions for a resolved ASN.
    pub fn lookup_asn(&self, asn: u32) -> EntityReputation {
        let mut hits = self.asn.get(&asn).cloned().unwrap_or_default();
        hits.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.value.cmp(&right.value))
                .then_with(|| left.source.cmp(&right.source))
        });
        let score = hits.iter().map(|hit| hit.score).max();
        EntityReputation {
            hits,
            score,
            tier: score.map(score_tier),
            score_scope: score.map(|_| "asn"),
        }
    }

    /// Return immutable provenance for the local JSONL file.
    pub fn provenance(&self) -> &DatasetProvenance {
        &self.provenance
    }
}

/// The complete local reputation lookup result for one IP entity.
#[derive(Debug, Clone)]
pub struct EntityReputation {
    pub hits: Vec<ReputationHit>,
    pub score: Option<u32>,
    pub tier: Option<ScoreTier>,
    pub score_scope: Option<&'static str>,
}

#[derive(Deserialize)]
struct RawReputationRecord {
    scope: String,
    value: serde_json::Value,
    score: serde_json::Value,
    source: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    as_of: Option<String>,
}

/// Load a frozen JSONL reputation dataset without executing it or using a network.
pub fn load_reputation_database(path: &Path) -> Result<ReputationDatabase> {
    let reader = BufReader::new(
        File::open(path)
            .with_context(|| format!("opening reputation dataset {}", path.display()))?,
    );
    let mut database = ReputationDatabase {
        ip: HashMap::new(),
        cidr: Vec::new(),
        asn: HashMap::new(),
        provenance: DatasetProvenance {
            path: path.display().to_string(),
            sha256: String::new(),
            records: 0,
        },
    };
    for (line_number, line) in reader.lines().enumerate() {
        let line = line.with_context(|| {
            format!(
                "reading reputation dataset {} at line {}",
                path.display(),
                line_number + 1
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let raw: RawReputationRecord = serde_json::from_str(&line).with_context(|| {
            format!(
                "parsing reputation dataset {} at line {}",
                path.display(),
                line_number + 1
            )
        })?;
        let scope = parse_scope(&raw.scope, path, line_number + 1)?;
        let score = parse_score(&raw.score, path, line_number + 1)?;
        let value = value_string(&raw.value, path, line_number + 1)?;
        let hit = ReputationHit {
            scope,
            value: value.clone(),
            score,
            source: raw.source,
            categories: raw.categories,
            as_of: raw.as_of,
        };
        match scope {
            "ip" => {
                let ip = value.parse::<IpAddr>().with_context(|| {
                    format!(
                        "invalid reputation IP in {} at line {}",
                        path.display(),
                        line_number + 1
                    )
                })?;
                database.ip.entry(ip).or_default().push(hit);
            }
            "cidr" => {
                let network = value.parse::<IpNet>().with_context(|| {
                    format!(
                        "invalid reputation CIDR in {} at line {}",
                        path.display(),
                        line_number + 1
                    )
                })?;
                database.cidr.push((network, hit));
            }
            "asn" => {
                let asn = value.parse::<u32>().with_context(|| {
                    format!(
                        "invalid reputation ASN in {} at line {}",
                        path.display(),
                        line_number + 1
                    )
                })?;
                database.asn.entry(asn).or_default().push(hit);
            }
            _ => unreachable!("scope was validated"),
        }
        database.provenance.records += 1;
    }
    database.provenance = provenance(path, database.provenance.records)?;
    Ok(database)
}

fn parse_scope(value: &str, path: &Path, line_number: usize) -> Result<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ip" => Ok("ip"),
        "cidr" => Ok("cidr"),
        "asn" => Ok("asn"),
        _ => bail!(
            "invalid reputation scope in {} at line {} (expected ip, cidr, or asn)",
            path.display(),
            line_number
        ),
    }
}

fn value_string(value: &serde_json::Value, path: &Path, line_number: usize) -> Result<String> {
    match value {
        serde_json::Value::String(value) => Ok(value.trim().to_owned()),
        serde_json::Value::Number(value) => Ok(value.to_string()),
        _ => bail!(
            "invalid reputation value in {} at line {} (expected string or number)",
            path.display(),
            line_number
        ),
    }
}

fn parse_score(value: &serde_json::Value, path: &Path, line_number: usize) -> Result<u32> {
    let score = value.as_u64().ok_or_else(|| {
        anyhow!(
            "invalid reputation score in {} at line {} (expected integer 0..=100)",
            path.display(),
            line_number
        )
    })?;
    u32::try_from(score)
        .ok()
        .filter(|score| *score <= 100)
        .ok_or_else(|| {
            anyhow!(
                "invalid reputation score in {} at line {} (expected integer 0..=100)",
                path.display(),
                line_number
            )
        })
}

fn scope_rank(scope: &str) -> u8 {
    match scope {
        "ip" => 0,
        "cidr" => 1,
        "asn" => 2,
        _ => u8::MAX,
    }
}

fn score_tier(score: u32) -> ScoreTier {
    match score {
        75..=100 => ScoreTier::High,
        50..=74 => ScoreTier::Medium,
        25..=49 => ScoreTier::Low,
        _ => ScoreTier::Info,
    }
}

fn provenance(path: &Path, records: usize) -> Result<DatasetProvenance> {
    Ok(DatasetProvenance {
        path: path.display().to_string(),
        sha256: sha256_file(path)?,
        records,
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("hashing dataset {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::{fs, net::IpAddr, path::Path};

    use super::{load_asn_database, load_reputation_database};
    use tempfile::tempdir;

    const ASN_FIXTURE: &str = "tests/fixtures/reputation/asn.csv";
    const REPUTATION_FIXTURE: &str = "tests/fixtures/reputation/reputation.jsonl";

    #[test]
    fn resolves_the_most_specific_asn_network() {
        let database = load_asn_database(Path::new(ASN_FIXTURE)).unwrap();
        let ip = "203.0.113.7".parse::<IpAddr>().unwrap();
        assert_eq!(database.lookup(ip).unwrap().asn, 64_501);
        assert_eq!(database.lookup(ip).unwrap().org, "EXAMPLE-NARROW");
    }

    #[test]
    fn resolves_generated_asn_ranges_with_binary_search() {
        let directory = tempdir().unwrap();
        let ranges = directory.path().join("asn-ranges.tsv");
        fs::write(
            &ranges,
            "192.0.2.0\t192.0.2.10\t64500\tFIRST\n198.51.100.0\t198.51.100.255\t64501\tSECOND\n",
        )
        .unwrap();
        let database = load_asn_database(&ranges).unwrap();
        assert_eq!(
            database.lookup("192.0.2.0".parse().unwrap()).unwrap().asn,
            64_500
        );
        assert_eq!(
            database.lookup("192.0.2.10".parse().unwrap()).unwrap().org,
            "FIRST"
        );
        assert_eq!(
            database
                .lookup("198.51.100.255".parse().unwrap())
                .unwrap()
                .asn,
            64_501
        );
        assert!(database.lookup("192.0.2.11".parse().unwrap()).is_none());
        assert!(database.lookup("2001:db8::1".parse().unwrap()).is_none());
    }

    #[test]
    fn applies_ip_precedence_but_retains_every_matching_opinion() {
        let database = load_reputation_database(Path::new(REPUTATION_FIXTURE)).unwrap();
        let result = database.lookup("203.0.113.7".parse().unwrap(), Some(64_501));
        assert_eq!(result.score, Some(90));
        assert_eq!(result.score_scope, Some("ip"));
        assert_eq!(result.hits.len(), 3);
        assert_eq!(result.hits[0].scope, "ip");
        assert_eq!(result.hits[1].scope, "cidr");
        assert_eq!(result.hits[2].scope, "asn");
    }

    #[test]
    fn leaves_unknown_addresses_without_an_opinion() {
        let database = load_reputation_database(Path::new(REPUTATION_FIXTURE)).unwrap();
        let result = database.lookup("192.0.2.99".parse().unwrap(), None);
        assert!(result.hits.is_empty());
        assert_eq!(result.score, None);
    }

    #[test]
    fn accepts_optional_fields_and_string_or_numeric_asn_values() {
        let database = load_reputation_database(Path::new(REPUTATION_FIXTURE)).unwrap();
        let numeric = database.lookup("192.0.2.1".parse().unwrap(), Some(64_502));
        assert_eq!(numeric.hits[0].categories, Vec::<String>::new());
        assert_eq!(numeric.hits[0].as_of, None);
        let string = database.lookup("192.0.2.1".parse().unwrap(), Some(64_503));
        assert_eq!(string.hits[0].value, "64503");
    }

    #[test]
    fn looks_up_asn_scoped_reputation_without_ip_or_cidr_opinions() {
        let database = load_reputation_database(Path::new(REPUTATION_FIXTURE)).unwrap();
        let result = database.lookup_asn(64_501);
        assert_eq!(result.score, Some(70));
        assert_eq!(result.score_scope, Some("asn"));
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].scope, "asn");
    }
}
