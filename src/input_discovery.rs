//! Deterministic local corpus discovery and explicit exclusion accounting.
use crate::event::TelemetryProfile;
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedInputFile {
    pub path: PathBuf,
    pub reason: String,
}

/// Only the count is serialized into aggregate reports. Paths and reasons are
/// carried in memory for private manifests and value-free CLI disclosures.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InputDiscoverySummary {
    /// Skipped files plus pruned hidden directories, each counted once without
    /// enumerating its contents. The field name is retained for compatibility.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub files_skipped: usize,
    #[serde(skip)]
    pub skipped: Vec<SkippedInputFile>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

impl InputDiscoverySummary {
    pub fn from_skipped(skipped: Vec<SkippedInputFile>) -> Self {
        Self {
            files_skipped: skipped.len(),
            skipped,
        }
    }

    pub fn disclosure(&self) -> Option<String> {
        if self.files_skipped == 0 {
            return None;
        }
        let mut counts = BTreeMap::new();
        for file in &self.skipped {
            *counts.entry(file.reason.as_str()).or_insert(0usize) += 1;
        }
        Some(format!(
            "Files skipped: {} ({})",
            self.files_skipped,
            counts
                .into_iter()
                .map(|(reason, count)| format!("{reason}: {count}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    pub fn reject_symlinks(&self) -> anyhow::Result<()> {
        if self.skipped.iter().any(|file| file.reason == "symlink") {
            bail!("symbolic links inside a corpus must be resolved explicitly");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct InputDiscovery {
    pub files: Vec<PathBuf>,
    pub summary: InputDiscoverySummary,
}

/// `None` selects the union of supported extensions for format autodetection.
/// An explicit regular file (including an explicit link to one) is always read.
/// Directory links are never followed; traversal errors are propagated.
/// Hidden descendant directories are pruned, but the explicitly selected root
/// is always traversed, even when hidden or named `.` or `..`.
pub fn discover_input_files(
    input: &Path,
    profile: Option<TelemetryProfile>,
) -> anyhow::Result<InputDiscovery> {
    if input.is_file() {
        return Ok(InputDiscovery {
            files: vec![input.to_owned()],
            summary: InputDiscoverySummary::default(),
        });
    }
    if !input.is_dir() {
        bail!(
            "input {} is neither a file nor a directory",
            input.display()
        );
    }
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut hidden_directories = Vec::new();
    let entries = walkdir::WalkDir::new(input)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            // Symlinks are not directories here and retain their existing policy.
            let hidden_directory = entry.depth() > 0
                && entry.file_type().is_dir()
                && entry.file_name().to_string_lossy().starts_with('.');
            if hidden_directory {
                hidden_directories.push(SkippedInputFile {
                    path: entry.path().to_owned(),
                    reason: "hidden-directory".to_owned(),
                });
            }
            !hidden_directory
        });
    for entry in entries {
        let entry = entry.with_context(|| format!("walking input corpus {}", input.display()))?;
        let reason = if entry.file_type().is_symlink() {
            Some("symlink")
        } else if !entry.file_type().is_file() {
            continue;
        } else if entry.file_name().to_string_lossy().starts_with('.') {
            Some("hidden")
        } else if !supported_extension(entry.path(), profile) {
            Some("unsupported-extension")
        } else {
            None
        };
        if let Some(reason) = reason {
            skipped.push(SkippedInputFile {
                path: entry.into_path(),
                reason: reason.to_owned(),
            });
        } else {
            files.push(entry.into_path());
        }
    }
    skipped.extend(hidden_directories);
    files.sort();
    skipped.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(InputDiscovery {
        files,
        summary: InputDiscoverySummary::from_skipped(skipped),
    })
}

fn supported_extension(path: &Path, profile: Option<TelemetryProfile>) -> bool {
    let Some(extension) = path.extension() else {
        return true;
    };
    let Some(extension) = extension.to_str() else {
        return false;
    };
    if extension.eq_ignore_ascii_case("gz")
        || (!extension.is_empty() && extension.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return true;
    }
    match profile {
        Some(TelemetryProfile::AwsWaf) => matches!(extension, "json" | "jsonl"),
        Some(_) => matches!(extension, "log" | "txt"),
        None => matches!(extension, "json" | "jsonl" | "log" | "txt"),
    }
}

/// File-output commands keep exclusion paths in a private companion manifest,
/// never in their aggregate JSON. Runs without exclusions create nothing extra.
pub fn write_discovery_manifest(
    output: &Path,
    summary: &InputDiscoverySummary,
) -> anyhow::Result<()> {
    if summary.skipped.is_empty() {
        return Ok(());
    }
    let name = output.file_name().context("output requires a file name")?;
    let mut name = name.to_os_string();
    name.push(".run-manifest.json");
    crate::output::write_json_pretty(
        output.with_file_name(name),
        &serde_json::json!({
            "report_kind": "RUN_MANIFEST",
            "safety_note": "PRIVATE input discovery provenance: skipped input paths may contain private information. Not sanitized; do not share without review.",
            "skipped_input_files": summary.skipped,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn hidden_directories_are_pruned_and_counted_once_without_enumerating_contents() {
        let directory = tempfile::tempdir().unwrap();
        for name in [
            "access.log",
            ".git/HEAD",
            ".git/objects/abcdef",
            ".cache/access.log",
            "nested/access_log_20260102",
            "nested/.hidden-dir/access.log",
        ] {
            let path = directory.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"synthetic data").unwrap();
        }
        let result =
            discover_input_files(directory.path(), Some(TelemetryProfile::NginxCombined)).unwrap();
        assert_eq!(
            result.files,
            ["access.log", "nested/access_log_20260102"].map(|name| directory.path().join(name))
        );
        assert_eq!(
            result.summary.skipped,
            [".cache", ".git", "nested/.hidden-dir"].map(|name| SkippedInputFile {
                path: directory.path().join(name),
                reason: "hidden-directory".into(),
            })
        );
        assert_eq!(
            result.summary.disclosure().as_deref(),
            Some("Files skipped: 3 (hidden-directory: 3)")
        );
        assert_eq!(
            serde_json::to_string(&result.summary).unwrap(),
            "{\"files_skipped\":3}"
        );
    }

    #[test]
    fn explicitly_selected_hidden_directory_is_traversed() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join(".logs");
        fs::create_dir(&input).unwrap();
        fs::write(input.join("access.log"), b"").unwrap();
        let result = discover_input_files(&input, None).unwrap();
        assert_eq!(result.files, vec![input.join("access.log")]);
        assert_eq!(result.summary.files_skipped, 0);
    }

    #[test]
    fn relative_dot_and_parent_directory_roots_are_not_pruned() {
        // Use a relative temporary root without changing the process directory.
        let directory = tempfile::tempdir_in(".").unwrap();
        let relative = Path::new(".").join(directory.path().file_name().unwrap());
        fs::write(directory.path().join("access.log"), b"").unwrap();
        fs::create_dir(directory.path().join("nested")).unwrap();
        for input in [relative.join("."), relative.join("nested/..")] {
            assert!(input.is_relative());
            let result = discover_input_files(&input, None).unwrap();
            assert_eq!(result.files.len(), 1);
            assert_eq!(
                result.files[0].canonicalize().unwrap(),
                directory.path().join("access.log").canonicalize().unwrap()
            );
            assert_eq!(result.summary.files_skipped, 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn hidden_directory_symlinks_keep_symlink_disclosure_and_context_rejection() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("logs");
        let target = directory.path().join(".cache");
        fs::create_dir(&input).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(target.join("access.log"), b"").unwrap();
        std::os::unix::fs::symlink(&target, input.join(".hidden-link")).unwrap();
        let result = discover_input_files(&input, None).unwrap();
        assert!(result.files.is_empty());
        assert_eq!(
            result.summary.skipped,
            vec![SkippedInputFile {
                path: input.join(".hidden-link"),
                reason: "symlink".into(),
            }]
        );
        assert_eq!(
            result.summary.disclosure().as_deref(),
            Some("Files skipped: 1 (symlink: 1)")
        );
        assert!(result.summary.reject_symlinks().is_err());
    }

    #[test]
    fn discovery_includes_rotations_and_discloses_sorted_profile_exclusions() {
        let directory = tempfile::tempdir().unwrap();
        let names = [
            "access.log",
            "access.log.1",
            "access.log.2.gz",
            "access_log_20260102",
            "access_log_20260101",
            ".DS_Store",
            "notes.md",
            "waf.json",
            "waf.jsonl",
            "access.txt",
        ];
        for name in names.iter().rev() {
            fs::write(directory.path().join(name), b"").unwrap();
        }
        for profile in [
            TelemetryProfile::AwsWaf,
            TelemetryProfile::ApacheCombined,
            TelemetryProfile::NginxCombined,
            TelemetryProfile::ApacheVhostCombined,
            TelemetryProfile::NginxCombinedHost,
            TelemetryProfile::NginxSecurity,
        ] {
            let discovery = discover_input_files(directory.path(), Some(profile)).unwrap();
            let mut expected = vec![
                "access.log.1",
                "access.log.2.gz",
                "access_log_20260101",
                "access_log_20260102",
            ];
            if profile == TelemetryProfile::AwsWaf {
                expected.extend(["waf.json", "waf.jsonl"]);
            } else {
                expected.extend(["access.log", "access.txt"]);
            }
            expected.sort();
            assert_eq!(
                discovery.files,
                expected
                    .iter()
                    .map(|name| directory.path().join(name))
                    .collect::<Vec<_>>()
            );
            let skipped: Vec<_> = discovery
                .summary
                .skipped
                .iter()
                .map(|file| {
                    (
                        file.path.file_name().unwrap().to_str().unwrap(),
                        file.reason.as_str(),
                    )
                })
                .collect();
            let mut expected_skips = vec![
                (".DS_Store", "hidden"),
                ("notes.md", "unsupported-extension"),
            ];
            if profile == TelemetryProfile::AwsWaf {
                expected_skips.extend([
                    ("access.log", "unsupported-extension"),
                    ("access.txt", "unsupported-extension"),
                ]);
            } else {
                expected_skips.extend([
                    ("waf.json", "unsupported-extension"),
                    ("waf.jsonl", "unsupported-extension"),
                ]);
            }
            expected_skips.sort();
            assert_eq!(skipped, expected_skips);
            assert_eq!(
                discovery.summary.disclosure().unwrap(),
                "Files skipped: 4 (hidden: 1, unsupported-extension: 3)"
            );
            assert_eq!(
                serde_json::to_string(&discovery.summary).unwrap(),
                "{\"files_skipped\":4}"
            );
        }
        assert_eq!(
            serde_json::to_string(&InputDiscoverySummary::default()).unwrap(),
            "{}"
        );
        // Recreate in the opposite order: discovery depends only on path order.
        let before = discover_input_files(directory.path(), None).unwrap().files;
        for name in names {
            fs::remove_file(directory.path().join(name)).unwrap();
        }
        for name in names {
            fs::write(directory.path().join(name), b"").unwrap();
        }
        assert_eq!(
            before,
            discover_input_files(directory.path(), None).unwrap().files
        );
    }

    #[test]
    fn explicitly_selected_files_bypass_hidden_and_extension_filters() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["access_log", "notes.md", ".hidden", "log.json"] {
            let path = directory.path().join(name);
            fs::write(&path, b"").unwrap();
            let result =
                discover_input_files(&path, Some(TelemetryProfile::NginxCombined)).unwrap();
            assert_eq!(result.files, vec![path]);
            assert_eq!(result.summary.files_skipped, 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn directory_symlinks_are_disclosed_without_following_and_context_can_reject_them() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("access.log"), b"").unwrap();
        std::os::unix::fs::symlink("access.log", directory.path().join("alias.log")).unwrap();
        std::os::unix::fs::symlink(".", directory.path().join("loop")).unwrap();
        let result = discover_input_files(directory.path(), None).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.summary.files_skipped, 2);
        assert!(result
            .summary
            .skipped
            .iter()
            .all(|file| file.reason == "symlink"));
        assert!(result
            .summary
            .reject_symlinks()
            .unwrap_err()
            .to_string()
            .contains("symbolic links"));
    }
}
