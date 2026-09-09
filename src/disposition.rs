//! Private, append-only analyst dispositions for recurring finding patterns.
//!
//! Dispositions are analyst opinions, not Shenron determinations. The store
//! contains raw request paths and optional query strings and must remain private.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
};

use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};

pub const DISPOSITION_SAFETY_NOTE: &str = "PRIVATE: contains analyst-authored opinions and raw request patterns. A disposition is not a Shenron determination of attack, exploitation, compromise, or benignness. Do not share without review.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalystDisposition {
    Reviewed,
    Expected,
    NeedsReview,
}

impl AnalystDisposition {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reviewed => "reviewed",
            Self::Expected => "expected",
            Self::NeedsReview => "needs-review",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct DispositionKey {
    pub source: String,
    pub template_id: String,
    pub method: String,
    pub uri_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_query: Option<String>,
}

impl DispositionKey {
    pub fn new(
        source: &str,
        template_id: &str,
        method: &str,
        uri_path: &str,
        uri_query: Option<&str>,
    ) -> Self {
        Self {
            source: source.trim().to_ascii_lowercase(),
            template_id: template_id.to_owned(),
            method: method.trim().to_ascii_uppercase(),
            uri_path: uri_path.to_owned(),
            uri_query: uri_query.map(str::to_owned),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DispositionEntry {
    pub safety_note: String,
    pub key: DispositionKey,
    pub disposition: AnalystDisposition,
    pub recorded_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DispositionStore {
    entries: BTreeMap<DispositionKey, DispositionEntry>,
}

impl DispositionStore {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let reader = BufReader::new(
            File::open(path).with_context(|| format!("opening {}", path.display()))?,
        );
        let mut entries = BTreeMap::new();
        for (index, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("reading {}", path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: DispositionEntry = serde_json::from_str(&line)
                .with_context(|| format!("parsing {} line {}", path.display(), index + 1))?;
            entries.insert(entry.key.clone(), entry);
        }
        Ok(Self { entries })
    }

    pub fn get(&self, key: &DispositionKey) -> Option<AnalystDisposition> {
        self.entries.get(key).map(|entry| entry.disposition)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordDispositionResult {
    pub already_recorded: bool,
    pub effective_entries: usize,
}

pub fn record_disposition(
    path: &Path,
    key: DispositionKey,
    disposition: AnalystDisposition,
    comment: Option<String>,
) -> anyhow::Result<RecordDispositionResult> {
    let store = DispositionStore::load(path)?;
    let normalized_comment = comment.filter(|value| !value.is_empty());
    if store.entries.get(&key).is_some_and(|entry| {
        entry.disposition == disposition && entry.comment == normalized_comment
    }) {
        return Ok(RecordDispositionResult {
            already_recorded: true,
            effective_entries: store.len(),
        });
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating disposition directory {}", parent.display()))?;
    }
    let entry = DispositionEntry {
        safety_note: DISPOSITION_SAFETY_NOTE.to_owned(),
        key,
        disposition,
        recorded_at: Utc::now().to_rfc3339(),
        comment: normalized_comment,
    };
    let mut writer = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {} for append", path.display()))?;
    serde_json::to_writer(&mut writer, &entry)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(RecordDispositionResult {
        already_recorded: false,
        effective_entries: store.len() + usize::from(!store.entries.contains_key(&entry.key)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_identical_record_is_idempotent_and_latest_changed_opinion_wins() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dispositions.jsonl");
        let key = DispositionKey::new("nuclei", "template", "get", "/robots.txt", None);
        let first = record_disposition(
            &path,
            key.clone(),
            AnalystDisposition::Expected,
            Some("reviewed crawler traffic".to_owned()),
        )
        .unwrap();
        assert!(!first.already_recorded);
        let duplicate = record_disposition(
            &path,
            key.clone(),
            AnalystDisposition::Expected,
            Some("reviewed crawler traffic".to_owned()),
        )
        .unwrap();
        assert!(duplicate.already_recorded);
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);

        record_disposition(&path, key.clone(), AnalystDisposition::NeedsReview, None).unwrap();
        let store = DispositionStore::load(&path).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&key), Some(AnalystDisposition::NeedsReview));
        assert_eq!(fs::read_to_string(path).unwrap().lines().count(), 2);
    }
}
