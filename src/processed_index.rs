//! Explicit, private file-level processing index for recurring local runs.
//!
//! The index never changes matching or aggregation within a selected file. It
//! only omits whole files whose recorded path, size, modification time, and
//! SHA-256 fingerprint still identify the same prior input. Skips are always
//! disclosed. The index contains local file paths and is therefore private.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ProcessedFileRecord {
    path: String,
    byte_length: u64,
    modified_unix_seconds: u64,
    modified_subsec_nanos: u32,
    sha256: String,
    execution_id: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct ProcessedFileIndex {
    report_kind: String,
    safety_note: String,
    files: BTreeMap<String, ProcessedFileRecord>,
}

/// A deterministic selection of files for one run. Committing it updates the
/// explicit private index only after the caller has processed every selected
/// file successfully.
pub struct ProcessedFilePlan {
    pub files: Vec<PathBuf>,
    pub skipped_files: usize,
    index_path: Option<PathBuf>,
    index: ProcessedFileIndex,
    processed_records: Vec<ProcessedFileRecord>,
}

impl ProcessedFilePlan {
    pub fn commit(mut self) -> Result<()> {
        let Some(path) = self.index_path else {
            return Ok(());
        };
        for record in self.processed_records {
            self.index.files.insert(record.path.clone(), record);
        }
        self.index.report_kind = "PROCESSED_FILE_INDEX".to_owned();
        self.index.safety_note = "Private local processing state: contains input file paths and fingerprints. Skipped files are excluded from the current run's aggregates; this is not a cumulative report.".to_owned();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| {
                format!("creating processed-index directory {}", parent.display())
            })?;
        }
        let temporary = path.with_extension("tmp");
        let mut file = File::create(&temporary)
            .with_context(|| format!("creating processed index {}", temporary.display()))?;
        serde_json::to_writer_pretty(&mut file, &self.index)?;
        file.write_all(b"\n")?;
        file.flush()?;
        fs::rename(&temporary, &path)
            .with_context(|| format!("replacing processed index {}", path.display()))?;
        Ok(())
    }
}

/// Select files not already represented by an unchanged index entry. Every
/// candidate is hashed so same-size content changes cannot be mistaken for an
/// unchanged file. The caller may ignore all prior entries with
/// `reprocess_all`.
pub fn prepare_processed_files(
    mut files: Vec<PathBuf>,
    index_path: Option<&Path>,
    reprocess_all: bool,
) -> Result<ProcessedFilePlan> {
    files.sort();
    let Some(index_path) = index_path else {
        return Ok(ProcessedFilePlan {
            files,
            skipped_files: 0,
            index_path: None,
            index: ProcessedFileIndex::default(),
            processed_records: Vec::new(),
        });
    };

    let normalized_index = normalize_path(index_path)?;
    files.retain(|path| normalize_path(path).ok().as_ref() != Some(&normalized_index));
    let index = if index_path.exists() {
        serde_json::from_reader(
            File::open(index_path)
                .with_context(|| format!("opening processed index {}", index_path.display()))?,
        )
        .with_context(|| format!("reading processed index {}", index_path.display()))?
    } else {
        ProcessedFileIndex::default()
    };

    let mut selected = Vec::new();
    let mut skipped_files = 0;
    let mut processed_records = Vec::new();
    for path in files {
        let normalized = normalize_path(&path)?;
        let key = normalized.display().to_string();
        let metadata = fs::metadata(&path)
            .with_context(|| format!("reading input metadata {}", path.display()))?;
        let modified = metadata
            .modified()
            .with_context(|| format!("reading input modification time {}", path.display()))?
            .duration_since(UNIX_EPOCH)
            .with_context(|| {
                format!(
                    "input modification time precedes Unix epoch: {}",
                    path.display()
                )
            })?;
        let sha256 = sha256_file(&path)?;
        let unchanged = index.files.get(&key).is_some_and(|record| {
            record.byte_length == metadata.len()
                && record.modified_unix_seconds == modified.as_secs()
                && record.modified_subsec_nanos == modified.subsec_nanos()
                && record.sha256 == sha256
        });
        if !reprocess_all && unchanged {
            skipped_files += 1;
            continue;
        }
        processed_records.push(ProcessedFileRecord {
            path: key,
            byte_length: metadata.len(),
            modified_unix_seconds: modified.as_secs(),
            modified_subsec_nanos: modified.subsec_nanos(),
            sha256,
            execution_id: String::new(),
        });
        selected.push(path);
    }
    let execution_id = execution_id(&processed_records);
    for record in &mut processed_records {
        record.execution_id.clone_from(&execution_id);
    }
    Ok(ProcessedFilePlan {
        files: selected,
        skipped_files,
        index_path: Some(index_path.to_owned()),
        index,
        processed_records,
    })
}

fn normalize_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))
    } else if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn execution_id(records: &[ProcessedFileRecord]) -> String {
    let mut hasher = Sha256::new();
    for record in records {
        hasher.update(record.path.as_bytes());
        hasher.update([0]);
        hasher.update(record.byte_length.to_le_bytes());
        hasher.update(record.modified_unix_seconds.to_le_bytes());
        hasher.update(record.modified_subsec_nanos.to_le_bytes());
        hasher.update(record.sha256.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}
