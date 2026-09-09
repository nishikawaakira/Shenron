//! Read-only extraction of one private URI path across existing concentration
//! artifacts. Raw logs are never opened or reprocessed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{concentration::StatusClassCounts, production::load_private_concentration};

#[derive(Debug, Serialize)]
pub struct PathTrendReport {
    pub report_kind: &'static str,
    pub safety_note: &'static str,
    /// Private analyst-supplied request path. This report is not sanitized.
    pub uri_path: String,
    pub runs: Vec<PathTrendRun>,
}

#[derive(Debug, Serialize)]
pub struct PathTrendRun {
    /// Private local artifact location; no file content is transmitted.
    pub results_dir: String,
    pub total_requests_in_run: u64,
    pub paths_beyond_tracking_cap: u64,
    /// `None` means the path has no retained record in this artifact. This is
    /// deliberately distinct from an observed record with a zero count.
    pub observation: Option<PathTrendObservation>,
}

#[derive(Debug, Serialize)]
pub struct PathTrendObservation {
    pub requests: u64,
    pub request_share: f64,
    pub distinct_source_ips: usize,
    pub requests_per_source_ip: f64,
    pub response_status_classes: StatusClassCounts,
    pub rank: usize,
}

/// Build a deterministic private trend from existing run artifacts only.
/// Result directories are sorted and deduplicated before they are read.
pub fn path_trend(results_dirs: &[PathBuf], path: &str) -> Result<PathTrendReport> {
    let mut directories = results_dirs.to_vec();
    directories.sort();
    directories.dedup();
    let runs = directories
        .into_iter()
        .map(|directory| path_trend_run(&directory, path))
        .collect::<Result<Vec<_>>>()?;
    Ok(PathTrendReport {
        report_kind: "PRIVATE_PATH_TREND",
        safety_note: "Private local artifact: contains an analyst-selected URI path and local result-directory names. Counts describe observed request volume only, not a determination of denial of service, attack, abuse, compromise, or attacker identity. Source IP counts may represent CDN, load-balancer, NAT, or proxy peers.",
        uri_path: path.to_owned(),
        runs,
    })
}

fn path_trend_run(directory: &Path, path: &str) -> Result<PathTrendRun> {
    let artifact = directory.join("request-concentration.json");
    let report = load_private_concentration(&artifact)
        .with_context(|| format!("loading trend input {}", artifact.display()))?;
    let observation = report
        .paths
        .iter()
        .find(|item| item.uri_path == path)
        .map(|item| PathTrendObservation {
            requests: item.summary.requests,
            request_share: item.summary.request_share,
            distinct_source_ips: item.summary.distinct_source_ips,
            requests_per_source_ip: requests_per_source(
                item.summary.requests,
                item.summary.distinct_source_ips,
            ),
            response_status_classes: item.summary.response_status_classes.clone(),
            rank: 1 + report
                .paths
                .iter()
                .filter(|candidate| {
                    candidate.summary.requests > item.summary.requests
                        || (candidate.summary.requests == item.summary.requests
                            && candidate.uri_path < item.uri_path)
                })
                .count(),
        });
    Ok(PathTrendRun {
        results_dir: directory.display().to_string(),
        total_requests_in_run: report.summary.total_requests,
        paths_beyond_tracking_cap: report.summary.paths_beyond_tracking_cap,
        observation,
    })
}

fn requests_per_source(requests: u64, sources: usize) -> f64 {
    if sources == 0 {
        0.0
    } else {
        requests as f64 / sources as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_is_finite_without_retained_sources() {
        assert_eq!(requests_per_source(10, 2), 5.0);
        assert_eq!(requests_per_source(10, 0), 0.0);
        assert!(requests_per_source(10, 0).is_finite());
    }
}
