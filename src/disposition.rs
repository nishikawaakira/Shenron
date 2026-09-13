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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// Exact analyst-defined corpus scope. No hostname inference or fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_scope: Option<String>,
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
            corpus_scope: None,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<DispositionReview>,
}

/// Private analyst metadata, not automatically verified evidence or ground truth.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DispositionReview {
    pub reviewer: Option<String>,
    pub evidence_run: Option<String>,
    pub nuclei_revision: Option<String>,
    pub review_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct DispositionReviewSummary {
    pub selected_entries: usize,
    pub entries_excluded_by_scope: usize,
    pub entries_with_review_deadline: usize,
    /// None when no explicit evaluation time was provided. Never reads the clock.
    pub entries_due_for_review: Option<usize>,
    pub as_of: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DispositionContext {
    pub corpus_scope: Option<String>,
    pub as_of: Option<DateTime<Utc>>,
    pub store_sha256: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DispositionStore {
    entries: BTreeMap<DispositionKey, DispositionEntry>,
    scope: Option<String>,
    as_of: Option<DateTime<Utc>>,
    store_sha256: Option<String>,
}

impl DispositionStore {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let mut reader = BufReader::new(
            File::open(path).with_context(|| format!("opening {}", path.display()))?,
        );
        let mut entries = BTreeMap::new();
        let mut hash = Sha256::new();
        let mut line = String::new();
        let mut index = 0;
        loop {
            line.clear();
            if reader
                .read_line(&mut line)
                .with_context(|| format!("reading {}", path.display()))?
                == 0
            {
                break;
            }
            hash.update(line.as_bytes());
            index += 1;
            if line.trim().is_empty() {
                continue;
            }
            let entry: DispositionEntry = serde_json::from_str(&line)
                .with_context(|| format!("parsing {} line {}", path.display(), index))?;
            entries.insert(entry.key.clone(), entry);
        }
        Ok(Self {
            entries,
            store_sha256: Some(format!("{:x}", hash.finalize())),
            ..Default::default()
        })
    }

    pub fn get(&self, key: &DispositionKey) -> Option<AnalystDisposition> {
        let mut selected = key.clone();
        selected.corpus_scope = self.scope.clone();
        self.entries.get(&selected).map(|entry| entry.disposition)
    }

    pub fn select(mut self, scope: Option<String>, as_of: Option<DateTime<Utc>>) -> Self {
        self.scope = scope;
        self.as_of = as_of;
        self
    }

    pub fn review_evaluation_requested(&self) -> bool {
        self.as_of.is_some()
    }

    pub fn review_due(&self, key: &DispositionKey) -> Option<bool> {
        let mut selected = key.clone();
        selected.corpus_scope = self.scope.clone();
        let deadline = self.entries.get(&selected)?.review.as_ref()?.review_after?;
        Some(deadline <= self.as_of?)
    }

    /// Opt-in reproducibility metadata is private; legacy unscoped stores add nothing.
    pub fn review_context(&self) -> Option<DispositionContext> {
        (self.scope.is_some()
            || self.as_of.is_some()
            || self
                .entries
                .values()
                .any(|entry| entry.review.is_some() || entry.key.corpus_scope.is_some()))
        .then(|| DispositionContext {
            corpus_scope: self.scope.clone(),
            as_of: self.as_of,
            store_sha256: self.store_sha256.clone(),
        })
    }

    pub fn selected_entries(&self) -> Vec<&DispositionEntry> {
        self.entries
            .values()
            .filter(|entry| entry.key.corpus_scope == self.scope)
            .collect()
    }

    /// Due entries retain their original opinion; metadata never reclassifies a finding.
    pub fn review_summary(&self) -> DispositionReviewSummary {
        let selected = self.selected_entries();
        let deadlines: Vec<_> = selected
            .iter()
            .filter_map(|entry| entry.review.as_ref()?.review_after)
            .collect();
        DispositionReviewSummary {
            selected_entries: selected.len(),
            entries_excluded_by_scope: self.entries.len() - selected.len(),
            entries_with_review_deadline: deadlines.len(),
            entries_due_for_review: self
                .as_of
                .map(|now| deadlines.iter().filter(|time| **time <= now).count()),
            as_of: self.as_of,
        }
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
    record_disposition_with_review(path, key, disposition, comment, None)
}

pub fn record_disposition_with_review(
    path: &Path,
    key: DispositionKey,
    disposition: AnalystDisposition,
    comment: Option<String>,
    review: Option<DispositionReview>,
) -> anyhow::Result<RecordDispositionResult> {
    let store = DispositionStore::load(path)?;
    let normalized_comment = comment.filter(|value| !value.is_empty());
    if store.entries.get(&key).is_some_and(|entry| {
        entry.disposition == disposition
            && entry.comment == normalized_comment
            && entry.review == review
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
        review,
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
    fn scope_is_exact_and_deadlines_require_explicit_time_without_reclassification() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private.jsonl");
        let key = DispositionKey::new("nuclei", "template", "GET", "/private", None);
        record_disposition(&path, key.clone(), AnalystDisposition::Reviewed, None).unwrap();
        let mut scoped = key.clone();
        scoped.corpus_scope = Some("site-a".into());
        let review = DispositionReview {
            reviewer: Some("analyst".into()),
            evidence_run: Some("private/run".into()),
            nuclei_revision: Some("frozen".into()),
            review_after: Some("2026-09-01T00:00:00Z".parse().unwrap()),
        };
        record_disposition_with_review(
            &path,
            scoped.clone(),
            AnalystDisposition::Expected,
            None,
            Some(review.clone()),
        )
        .unwrap();
        assert!(
            record_disposition_with_review(
                &path,
                scoped,
                AnalystDisposition::Expected,
                None,
                Some(review)
            )
            .unwrap()
            .already_recorded
        );
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
        let store = DispositionStore::load(&path).unwrap();
        assert_eq!(store.get(&key), Some(AnalystDisposition::Reviewed));
        let a = store.clone().select(Some("site-a".into()), None);
        assert_eq!(a.get(&key), Some(AnalystDisposition::Expected));
        assert_eq!(a.review_summary().entries_due_for_review, None);
        assert_eq!(a.review_summary().entries_excluded_by_scope, 1);
        let due = a.select(
            Some("site-a".into()),
            Some("2026-09-01T00:00:00Z".parse().unwrap()),
        );
        assert_eq!(due.review_summary().entries_due_for_review, Some(1));
        assert_eq!(due.get(&key), Some(AnalystDisposition::Expected));
        let other = store.select(Some("site-b".into()), None);
        assert_eq!(other.get(&key), None);
        assert_eq!(other.review_summary().entries_excluded_by_scope, 2);
    }

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
