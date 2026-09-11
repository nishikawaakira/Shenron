//! Opt-in, append-only memory of recurring private address-space observations.
//!
//! The store records network prefixes and optional locally resolved ASNs, never
//! individual IP addresses. Recurrence is not attribution: address space can be
//! reassigned, shared by tenants, or observed through intermediaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    net::IpAddr,
    path::Path,
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    concentration::{FocusPrefixLengths, PrivateRequestConcentrationReport},
    reputation::AsnDatabase,
};

pub const DEFAULT_MAX_STORE_ENTITIES: usize = 1_000_000;
pub const DEFAULT_MAX_STORE_ENTRY_SNAPSHOTS: usize = 10_000_000;
pub const DEFAULT_MAX_STORE_RUNS: usize = 100_000;

const SAFETY_NOTE: &str = "PRIVATE append-only observation memory: contains network prefixes and optional ASNs derived from local run artifacts. Analyst corpus labels may contain private information and are annotations, not Shenron determinations. A prefix observed across several runs is recurring address-space observation, not evidence that one operator, owner, or other entity is responsible. Address space is reassigned, shared across tenants, and reused. This is not attribution or a determination of coordinated activity, probing, scanning, attack, or abuse.";

#[derive(Debug, Clone, Copy)]
pub struct ObservationStoreLimits {
    pub max_entities: usize,
    pub max_entry_snapshots: usize,
    pub max_runs: usize,
}

impl Default for ObservationStoreLimits {
    fn default() -> Self {
        Self {
            max_entities: DEFAULT_MAX_STORE_ENTITIES,
            max_entry_snapshots: DEFAULT_MAX_STORE_ENTRY_SNAPSHOTS,
            max_runs: DEFAULT_MAX_STORE_RUNS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationMemoryEntry {
    pub entity_kind: String,
    pub value: String,
    pub first_observed_epoch_minute: Option<i64>,
    pub last_observed_epoch_minute: Option<i64>,
    pub first_observed_run_id: String,
    pub last_observed_run_id: String,
    pub runs_observed: usize,
    pub run_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record_kind", rename_all = "SCREAMING_SNAKE_CASE")]
enum StoreRecord {
    Header {
        safety_note: String,
        max_entities: usize,
        max_entry_snapshots: usize,
        max_runs: usize,
    },
    Entry {
        #[serde(flatten)]
        entry: ObservationMemoryEntry,
    },
    Run {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        corpus_label: Option<String>,
        run_id: String,
        run_index: usize,
        retained_entity_observations: usize,
        entity_observations_beyond_cap: usize,
        invalid_source_ips_excluded: usize,
    },
}

#[derive(Debug, Serialize)]
pub struct ObservationStoreUpdate {
    pub safety_note: &'static str,
    pub run_id: String,
    pub already_recorded: bool,
    pub runs_recorded: usize,
    pub retained_entities: usize,
    pub retained_entity_observations: usize,
    pub entity_observations_beyond_cap: usize,
    pub invalid_source_ips_excluded: usize,
    pub entries: Vec<ObservationMemoryEntry>,
}

/// Update one explicitly selected private store from a completed local run.
/// The run ID is the SHA-256 of its immutable run manifest; ingesting the same
/// run directory twice is therefore idempotent.
pub fn update_observation_store(
    store_path: &Path,
    run_dir: &Path,
    prefixes: FocusPrefixLengths,
    asn_database: Option<&AsnDatabase>,
    limits: ObservationStoreLimits,
) -> Result<ObservationStoreUpdate> {
    let manifest_path = run_dir.join("run-manifest.json");
    let manifest = fs::read(&manifest_path)
        .with_context(|| format!("reading run manifest {}", manifest_path.display()))?;
    let run_id = format!("sha256:{}", hex_digest(&manifest));
    let metadata: serde_json::Value =
        serde_json::from_slice(&manifest).context("parsing private run manifest")?;
    let corpus_label = metadata
        .get("corpus_label")
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    let concentration_path = run_dir.join("request-concentration.json");
    let concentration: PrivateRequestConcentrationReport = serde_json::from_reader(BufReader::new(
        File::open(&concentration_path)
            .with_context(|| format!("opening {}", concentration_path.display()))?,
    ))
    .with_context(|| format!("reading {}", concentration_path.display()))?;
    let observed_from = concentration
        .requests_per_minute_series
        .first()
        .map(|point| point.minute_epoch);
    let observed_to = concentration
        .requests_per_minute_series
        .last()
        .map(|point| point.minute_epoch);

    let loaded = load_store(store_path)?;
    if loaded.run_ids.contains(&run_id) {
        return Ok(update_report(
            run_id,
            true,
            loaded.run_ids.len(),
            0,
            0,
            0,
            loaded.entries,
        ));
    }
    if loaded.run_ids.len() >= limits.max_runs {
        let candidates = candidate_entities(&concentration, prefixes, asn_database);
        return Ok(update_report(
            run_id,
            false,
            loaded.run_ids.len(),
            0,
            candidates.entities.len(),
            candidates.invalid_source_ips,
            loaded.entries,
        ));
    }

    let candidates = candidate_entities(&concentration, prefixes, asn_database);
    let mut entries = loaded.entries;
    let mut snapshots = Vec::new();
    let mut beyond_cap = 0usize;
    let mut snapshot_count = loaded.entry_snapshot_count;
    for key in candidates.entities {
        if snapshot_count >= limits.max_entry_snapshots {
            beyond_cap += 1;
            continue;
        }
        if !entries.contains_key(&key) && entries.len() >= limits.max_entities {
            beyond_cap += 1;
            continue;
        }
        let entry = entries
            .entry(key.clone())
            .or_insert_with(|| ObservationMemoryEntry {
                entity_kind: key.0.clone(),
                value: key.1.clone(),
                first_observed_epoch_minute: observed_from,
                last_observed_epoch_minute: observed_to,
                first_observed_run_id: run_id.clone(),
                last_observed_run_id: run_id.clone(),
                runs_observed: 0,
                run_ids: Vec::new(),
            });
        if !entry.run_ids.contains(&run_id) {
            entry.last_observed_epoch_minute = observed_to;
            entry.last_observed_run_id = run_id.clone();
            entry.run_ids.push(run_id.clone());
            entry.runs_observed = entry.run_ids.len();
        }
        snapshots.push(entry.clone());
        snapshot_count += 1;
    }

    append_update(
        store_path,
        &snapshots,
        &run_id,
        loaded.run_ids.len() + 1,
        beyond_cap,
        candidates.invalid_source_ips,
        limits,
        loaded.has_header,
        corpus_label,
    )?;
    Ok(update_report(
        run_id,
        false,
        loaded.run_ids.len() + 1,
        snapshots.len(),
        beyond_cap,
        candidates.invalid_source_ips,
        entries,
    ))
}

struct LoadedStore {
    header: Option<StoreRecord>,
    runs: BTreeMap<String, StoreRecord>,
    records_read: usize,
    has_header: bool,
    run_ids: BTreeSet<String>,
    entries: BTreeMap<(String, String), ObservationMemoryEntry>,
    entry_snapshot_count: usize,
}

fn load_store(path: &Path) -> Result<LoadedStore> {
    let mut loaded = LoadedStore {
        header: None,
        runs: BTreeMap::new(),
        records_read: 0,
        has_header: false,
        run_ids: BTreeSet::new(),
        entries: BTreeMap::new(),
        entry_snapshot_count: 0,
    };
    if !path.is_file() {
        return Ok(loaded);
    }
    let reader =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    for (index, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("reading {} line {}", path.display(), index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let record: StoreRecord = serde_json::from_str(&line)
            .with_context(|| format!("parsing {} line {}", path.display(), index + 1))?;
        loaded.records_read += 1;
        match record {
            header @ StoreRecord::Header { .. } => {
                loaded.has_header = true;
                loaded.header = Some(header);
            }
            StoreRecord::Entry { entry } => {
                loaded.entry_snapshot_count += 1;
                loaded
                    .entries
                    .insert((entry.entity_kind.clone(), entry.value.clone()), entry);
            }
            ref run @ StoreRecord::Run { ref run_id, .. } => {
                loaded.run_ids.insert(run_id.clone());
                loaded.runs.insert(run_id.clone(), run.clone());
            }
        }
    }
    Ok(loaded)
}

struct CandidateEntities {
    entities: BTreeSet<(String, String)>,
    invalid_source_ips: usize,
}

fn candidate_entities(
    concentration: &PrivateRequestConcentrationReport,
    prefixes: FocusPrefixLengths,
    asn_database: Option<&AsnDatabase>,
) -> CandidateEntities {
    let mut entities = BTreeSet::new();
    let mut invalid_source_ips = 0usize;
    for source in &concentration.source_ips {
        let Ok(address) = source.source_ip.parse::<IpAddr>() else {
            invalid_source_ips += 1;
            continue;
        };
        let prefix = match address {
            IpAddr::V4(_) => prefixes.ipv4,
            IpAddr::V6(_) => prefixes.ipv6,
        };
        if let Ok(network) = IpNet::new(address, prefix) {
            entities.insert((
                "network-prefix".to_owned(),
                format!("{}/{}", network.network(), prefix),
            ));
        }
        if let Some(asn) = asn_database.and_then(|database| database.lookup(address)) {
            entities.insert(("asn".to_owned(), format!("AS{}", asn.asn)));
        }
    }
    CandidateEntities {
        entities,
        invalid_source_ips,
    }
}

#[allow(clippy::too_many_arguments)]
fn append_update(
    path: &Path,
    entries: &[ObservationMemoryEntry],
    run_id: &str,
    run_index: usize,
    beyond_cap: usize,
    invalid_source_ips: usize,
    limits: ObservationStoreLimits,
    has_header: bool,
    corpus_label: Option<String>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("creating observation-store directory {}", parent.display())
        })?;
    }
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening append-only observation store {}", path.display()))?;
    if !has_header {
        write_record(
            &mut output,
            &StoreRecord::Header {
                safety_note: SAFETY_NOTE.to_owned(),
                max_entities: limits.max_entities,
                max_entry_snapshots: limits.max_entry_snapshots,
                max_runs: limits.max_runs,
            },
        )?;
    }
    for entry in entries {
        write_record(
            &mut output,
            &StoreRecord::Entry {
                entry: entry.clone(),
            },
        )?;
    }
    write_record(
        &mut output,
        &StoreRecord::Run {
            corpus_label,
            run_id: run_id.to_owned(),
            run_index,
            retained_entity_observations: entries.len(),
            entity_observations_beyond_cap: beyond_cap,
            invalid_source_ips_excluded: invalid_source_ips,
        },
    )?;
    Ok(())
}

fn write_record(output: &mut impl Write, record: &StoreRecord) -> Result<()> {
    serde_json::to_writer(&mut *output, record)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn update_report(
    run_id: String,
    already_recorded: bool,
    runs_recorded: usize,
    retained_entity_observations: usize,
    entity_observations_beyond_cap: usize,
    invalid_source_ips_excluded: usize,
    entries: BTreeMap<(String, String), ObservationMemoryEntry>,
) -> ObservationStoreUpdate {
    ObservationStoreUpdate {
        safety_note: SAFETY_NOTE,
        run_id,
        already_recorded,
        runs_recorded,
        retained_entities: entries.len(),
        retained_entity_observations,
        entity_observations_beyond_cap,
        invalid_source_ips_excluded,
        entries: entries.into_values().collect(),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Serialize)]
pub struct ObservationReadEntry {
    #[serde(flatten)]
    pub entry: ObservationMemoryEntry,
    /// Verbatim analyst annotations keyed by opaque run ID, never inferred.
    pub corpus_labels: BTreeMap<String, String>,
    pub runs_without_corpus_label: usize,
}

#[derive(Debug, Serialize)]
pub struct ObservationStoreRead {
    pub report_kind: &'static str,
    pub safety_note: &'static str,
    pub runs_recorded: usize,
    pub retained_entities: usize,
    pub entries_omitted_by_limit: usize,
    pub entity_observations_beyond_cap: usize,
    pub invalid_source_ips_excluded: usize,
    pub entries: Vec<ObservationReadEntry>,
}

/// Read completed observations only. No logs, writes, external lookup or
/// classification. Zero limit means all entries; ties use kind then value.
pub fn read_observation_store(path: &Path, limit: usize) -> Result<ObservationStoreRead> {
    anyhow::ensure!(
        path.is_file(),
        "observation store does not exist: {}",
        path.display()
    );
    let loaded = load_store(path)?;
    let mut entries = loaded.entries.into_values().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .runs_observed
            .cmp(&left.runs_observed)
            .then_with(|| left.entity_kind.cmp(&right.entity_kind))
            .then_with(|| left.value.cmp(&right.value))
    });
    let retained_entities = entries.len();
    let shown = if limit == 0 {
        retained_entities
    } else {
        limit.min(retained_entities)
    };
    let mut excluded = 0;
    let mut invalid = 0;
    for run in loaded.runs.values() {
        if let StoreRecord::Run {
            entity_observations_beyond_cap,
            invalid_source_ips_excluded,
            ..
        } = run
        {
            excluded += entity_observations_beyond_cap;
            invalid += invalid_source_ips_excluded;
        }
    }
    Ok(ObservationStoreRead {
        report_kind: "PRIVATE_OBSERVATION_STORE_READ",
        safety_note: SAFETY_NOTE,
        runs_recorded: loaded.run_ids.len(),
        retained_entities,
        entries_omitted_by_limit: retained_entities - shown,
        entity_observations_beyond_cap: excluded,
        invalid_source_ips_excluded: invalid,
        entries: entries
            .into_iter()
            .take(shown)
            .map(|entry| {
                let corpus_labels = entry
                    .run_ids
                    .iter()
                    .filter_map(|id| match loaded.runs.get(id) {
                        Some(StoreRecord::Run {
                            corpus_label: Some(label),
                            ..
                        }) => Some((id.clone(), label.clone())),
                        _ => None,
                    })
                    .collect::<BTreeMap<_, _>>();
                ObservationReadEntry {
                    runs_without_corpus_label: entry.run_ids.len() - corpus_labels.len(),
                    entry,
                    corpus_labels,
                }
            })
            .collect(),
    })
}

#[derive(Debug, Serialize)]
pub struct ObservationCompaction {
    pub report_kind: &'static str,
    pub safety_note: &'static str,
    pub records_before: usize,
    pub records_after: usize,
    pub entry_snapshots_before: usize,
    pub entry_snapshots_after: usize,
}

/// Explicit deterministic compaction into a new file. The source is untouched;
/// existing destinations (including symlinks/hardlinks) are never overwritten.
/// Each entity's last appended snapshot preserves its complete run-ID history.
pub fn compact_observation_store(input: &Path, output: &Path) -> Result<ObservationCompaction> {
    anyhow::ensure!(
        input.is_file(),
        "observation store does not exist: {}",
        input.display()
    );
    let loaded = load_store(input)?;
    let header = loaded
        .header
        .context("observation store has no header; refusing compaction")?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .with_context(|| {
            format!(
                "creating new private compacted store {} (must not already exist)",
                output.display()
            )
        })?;
    let mut destination = BufWriter::new(destination);
    write_record(&mut destination, &header)?;
    for entry in loaded.entries.values() {
        write_record(
            &mut destination,
            &StoreRecord::Entry {
                entry: entry.clone(),
            },
        )?;
    }
    let mut runs = loaded.runs.values().collect::<Vec<_>>();
    runs.sort_by_key(|run| match run {
        StoreRecord::Run {
            run_index, run_id, ..
        } => (*run_index, run_id.as_str()),
        _ => unreachable!("run map only retains RUN records"),
    });
    for run in runs {
        write_record(&mut destination, run)?;
    }
    destination.flush()?;
    destination.get_ref().sync_all()?;
    Ok(ObservationCompaction {
        report_kind: "PRIVATE_OBSERVATION_STORE_COMPACTION",
        safety_note: SAFETY_NOTE,
        records_before: loaded.records_read,
        records_after: 1 + loaded.entries.len() + loaded.runs.len(),
        entry_snapshots_before: loaded.entry_snapshot_count,
        entry_snapshots_after: loaded.entries.len(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::concentration::{
        PrivateRequestConcentrationReport, PrivateSourceConcentration, RequestConcentrationSummary,
        RequestRateSummary,
    };

    fn write_run(path: &Path, marker: &str, ips: &[&str], minute: i64) {
        fs::create_dir_all(path).unwrap();
        fs::write(
            path.join("run-manifest.json"),
            format!("{{\"run\":\"{marker}\"}}"),
        )
        .unwrap();
        let report = PrivateRequestConcentrationReport {
            waf: None,
            ja4_sources: None,
            report_kind: "REQUEST_CONCENTRATION_PRIVATE".to_owned(),
            safety_note: "private".to_owned(),
            summary: RequestConcentrationSummary {
                waf: None,
                source_segment_diversity: None,
                response_status_codes: None,
                total_requests: ips.len() as u64,
                distinct_uri_paths: 0,
                distinct_source_ips: ips.len(),
                requests_without_uri_path: 0,
                requests_without_source_ip: 0,
                paths_beyond_tracking_cap: 0,
                source_ips_beyond_tracking_cap: 0,
                source_path_pairs_beyond_tracking_cap: 0,
                top_path: None,
                top_ten_paths_request_share: 0.0,
                top_ten_source_ips_request_share: 0.0,
                requests_per_minute: RequestRateSummary {
                    peak_requests_per_minute: None,
                    median_requests_per_minute: None,
                    peak_to_median_ratio: None,
                    observations_without_timestamp: 0,
                },
                request_rates: Vec::new(),
                response_outcomes: None,
                response_outcome_windows: None,
                focus: None,
            },
            paths: Vec::new(),
            source_ips: ips
                .iter()
                .map(|ip| PrivateSourceConcentration {
                    waf: None,
                    path_segment_diversity: None,
                    response_status_codes: None,
                    response_outcomes: None,
                    source_ip: (*ip).to_owned(),
                    requests: 1,
                    most_requested_uri_path: None,
                    response_status_classes: Default::default(),
                })
                .collect(),
            focus: None,
            requests_per_minute_series: vec![crate::concentration::MinuteRequestCount {
                minute_epoch: minute,
                requests: ips.len() as u64,
            }],
            status_class_requests_per_minute_series: Vec::new(),
            minute_buckets_beyond_cap: 0,
        };
        serde_json::to_writer_pretty(
            File::create(path.join("request-concentration.json")).unwrap(),
            &report,
        )
        .unwrap();
    }

    #[test]
    fn remembers_recurring_prefixes_across_three_runs_and_is_idempotent() {
        let directory = tempdir().unwrap();
        let store = directory.path().join("memory.jsonl");
        let run1 = directory.path().join("run1");
        let run2 = directory.path().join("run2");
        let run3 = directory.path().join("run3");
        write_run(&run1, "one", &["198.51.100.1"], 10);
        write_run(&run2, "two", &["203.0.113.1"], 20);
        write_run(&run3, "three", &["198.51.100.2", "192.0.2.1"], 30);
        let limits = ObservationStoreLimits::default();
        update_observation_store(&store, &run1, FocusPrefixLengths::default(), None, limits)
            .unwrap();
        update_observation_store(&store, &run2, FocusPrefixLengths::default(), None, limits)
            .unwrap();
        let third =
            update_observation_store(&store, &run3, FocusPrefixLengths::default(), None, limits)
                .unwrap();
        let recurring = third
            .entries
            .iter()
            .find(|entry| entry.value == "198.51.100.0/24")
            .unwrap();
        assert_eq!(recurring.runs_observed, 2);
        assert_eq!(recurring.first_observed_epoch_minute, Some(10));
        assert_eq!(recurring.last_observed_epoch_minute, Some(30));
        let new = third
            .entries
            .iter()
            .find(|entry| entry.value == "192.0.2.0/24")
            .unwrap();
        assert_eq!(new.runs_observed, 1);
        assert_eq!(new.first_observed_epoch_minute, Some(30));

        let before = fs::read(&store).unwrap();
        let duplicate =
            update_observation_store(&store, &run3, FocusPrefixLengths::default(), None, limits)
                .unwrap();
        assert!(duplicate.already_recorded);
        assert_eq!(before, fs::read(&store).unwrap());
        assert_eq!(
            duplicate
                .entries
                .iter()
                .find(|entry| entry.value == "198.51.100.0/24")
                .unwrap()
                .runs_observed,
            2
        );
    }

    #[test]
    fn discloses_entity_growth_caps_without_approximating() {
        let directory = tempdir().unwrap();
        let store = directory.path().join("memory.jsonl");
        let run = directory.path().join("run");
        write_run(&run, "one", &["198.51.100.1", "203.0.113.1"], 10);
        let update = update_observation_store(
            &store,
            &run,
            FocusPrefixLengths::default(),
            None,
            ObservationStoreLimits {
                max_entities: 1,
                max_entry_snapshots: 1,
                max_runs: 1,
            },
        )
        .unwrap();
        assert_eq!(update.retained_entities, 1);
        assert_eq!(update.entity_observations_beyond_cap, 1);
        assert!(fs::read_to_string(store).unwrap().contains("safety_note"));
    }

    #[test]
    fn read_and_compact_preserve_recurrence_labels_and_the_original_store() {
        let directory = tempdir().unwrap();
        let store = directory.path().join("memory.jsonl");
        for (index, label, ips) in [
            (1, None, vec!["198.51.100.1"]),
            (
                2,
                Some("  Analyst Label A  "),
                vec!["198.51.100.2", "203.0.113.1"],
            ),
            (3, Some("Label B"), vec!["198.51.100.3", "192.0.2.1"]),
        ] {
            let run = directory.path().join(format!("run-{index}"));
            write_run(&run, &index.to_string(), &ips, index);
            if let Some(label) = label {
                fs::write(
                    run.join("run-manifest.json"),
                    serde_json::to_vec(&serde_json::json!({"run":index,"corpus_label":label}))
                        .unwrap(),
                )
                .unwrap();
            }
            update_observation_store(
                &store,
                &run,
                FocusPrefixLengths::default(),
                None,
                ObservationStoreLimits::default(),
            )
            .unwrap();
        }
        let original = fs::read(&store).unwrap();
        let report = read_observation_store(&store, 0).unwrap();
        assert_eq!(report.entries[0].entry.runs_observed, 3);
        assert_eq!(report.entries[0].entry.run_ids.len(), 3);
        assert_eq!(report.entries[0].corpus_labels.len(), 2);
        assert!(report.entries[0]
            .corpus_labels
            .values()
            .any(|label| label == "  Analyst Label A  "));
        assert_eq!(report.entries[0].runs_without_corpus_label, 1); // Historical unlabeled RUN.
        assert_eq!(report.entries[1].entry.value, "192.0.2.0/24"); // Tie sorted by kind/value.
        assert_eq!(
            read_observation_store(&store, 1)
                .unwrap()
                .entries_omitted_by_limit,
            2
        );
        assert_eq!(fs::read(&store).unwrap(), original);

        let first = directory.path().join("compact-a.jsonl");
        let second = directory.path().join("compact-b.jsonl");
        let summary = compact_observation_store(&store, &first).unwrap();
        compact_observation_store(&store, &second).unwrap();
        assert!(summary.records_before > summary.records_after);
        assert_eq!(summary.entry_snapshots_before, 5);
        assert_eq!(summary.entry_snapshots_after, 3);
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::to_value(read_observation_store(&first, 0).unwrap()).unwrap()
        );
        assert_eq!(fs::read(&store).unwrap(), original);
        assert!(compact_observation_store(&store, &store).is_err());
        assert!(compact_observation_store(&store, &first).is_err());
        assert_eq!(fs::read(&store).unwrap(), original);
        let run = directory.path().join("run-4");
        write_run(&run, "four", &["198.51.100.4"], 4);
        let update = update_observation_store(
            &first,
            &run,
            FocusPrefixLengths::default(),
            None,
            ObservationStoreLimits::default(),
        )
        .unwrap();
        assert_eq!(
            update
                .entries
                .iter()
                .find(|entry| entry.value == "198.51.100.0/24")
                .unwrap()
                .runs_observed,
            4
        );
    }
}
