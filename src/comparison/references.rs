//! Deterministic distributions over explicit frozen reference runs, never logs.
use super::{
    conditions::{read_conditions, RunConditions},
    daily::DailyMetric,
};
use crate::concentration::RequestConcentrationSummary;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub const NOTE: &str = "Explicit reference-run measurements, not normal ranges, classifications or forecasts. Select comparable periods (for example the same weekday) yourself and review recorded conditions, missing values and caps. Median gives each available run equal weight; even counts use the arithmetic mean of the two central values. Ratios to a zero median are unavailable. No logs are reprocessed.";

#[derive(Debug, Serialize)]
pub struct ReferenceProvenance {
    pub artifacts_sha256: BTreeMap<&'static str, Option<String>>,
    pub conditions: RunConditions,
}

#[derive(Debug, Serialize)]
pub struct MetricDistribution {
    pub available_runs: usize,
    pub unavailable_runs: usize,
    pub unavailable_reasons: BTreeMap<String, usize>,
    pub minimum: Option<f64>,
    pub median: Option<f64>,
    pub maximum: Option<f64>,
    pub current: Option<f64>,
    pub current_unavailable_reason: Option<String>,
    pub delta_from_median: Option<f64>,
    pub ratio_to_median: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct ReferenceDistribution {
    pub note: &'static str,
    pub requested_reference_runs: usize,
    pub duplicate_directory_references_excluded: usize,
    pub reference_runs: Vec<ReferenceProvenance>,
    pub current_run: ReferenceProvenance,
    pub metrics: BTreeMap<DailyMetric, MetricDistribution>,
}

fn provenance(dir: &Path) -> anyhow::Result<ReferenceProvenance> {
    let mut artifacts_sha256 = BTreeMap::new();
    for name in [
        "run-manifest.json",
        "sanitized-research.json",
        "request-concentration.json",
    ] {
        let path = dir.join(name);
        artifacts_sha256.insert(
            name,
            path.exists()
                .then(|| super::sha256_file(&path))
                .transpose()?,
        );
    }
    Ok(ReferenceProvenance {
        artifacts_sha256,
        conditions: read_conditions(dir)?,
    })
}

fn summary(dir: &Path) -> anyhow::Result<Option<RequestConcentrationSummary>> {
    if let Some(summary) = super::daily_summary(dir, None)? {
        return Ok(Some(summary));
    }
    let path = dir.join("request-concentration.json");
    path.exists()
        .then(|| crate::production::load_private_concentration(&path).map(|v| v.summary))
        .transpose()
}

/// The primary baseline and explicit additional references form one equal-weight set.
/// Canonical directory duplicates are excluded and disclosed; no date is inferred from names.
pub fn compare_reference_runs(
    baseline: &Path,
    additional: &[PathBuf],
    current: &Path,
) -> anyhow::Result<ReferenceDistribution> {
    let current = current.canonicalize()?;
    if !current.is_dir() {
        anyhow::bail!("current must be an existing run directory");
    }
    let mut references = BTreeSet::new();
    for path in std::iter::once(baseline).chain(additional.iter().map(PathBuf::as_path)) {
        let path = path.canonicalize()?;
        if !path.is_dir() {
            anyhow::bail!("reference must be an existing run directory");
        }
        if path == current {
            anyhow::bail!("the current run cannot be included in its reference set");
        }
        references.insert(path);
    }
    let requested = additional.len() + 1;
    let duplicates = requested - references.len();
    let summaries: Vec<_> = references
        .iter()
        .map(|dir| summary(dir))
        .collect::<anyhow::Result<_>>()?;
    let current_summary = summary(&current)?;
    let mut metrics = BTreeMap::new();
    for metric in DailyMetric::ALL {
        let mut values = Vec::new();
        let mut reasons = BTreeMap::new();
        for summary in &summaries {
            match metric.measurement(summary.as_ref()) {
                Ok(value) => values.push(value),
                Err(reason) => *reasons.entry(reason.to_owned()).or_insert(0) += 1,
            }
        }
        let result = metric.measurement(current_summary.as_ref());
        metrics.insert(metric, distribution(values, reasons, result));
    }
    Ok(ReferenceDistribution {
        note: NOTE,
        requested_reference_runs: requested,
        duplicate_directory_references_excluded: duplicates,
        reference_runs: references
            .iter()
            .map(|dir| provenance(dir))
            .collect::<anyhow::Result<_>>()?,
        current_run: provenance(&current)?,
        metrics,
    })
}

fn distribution(
    mut values: Vec<f64>,
    reasons: BTreeMap<String, usize>,
    current: Result<f64, &'static str>,
) -> MetricDistribution {
    values.sort_by(f64::total_cmp);
    let median = if values.is_empty() {
        None
    } else {
        let mid = values.len() / 2;
        Some(if values.len().is_multiple_of(2) {
            values[mid - 1] / 2.0 + values[mid] / 2.0
        } else {
            values[mid]
        })
    };
    let current_value = current.ok();
    MetricDistribution {
        available_runs: values.len(),
        unavailable_runs: reasons.values().sum(),
        unavailable_reasons: reasons,
        minimum: values.first().copied(),
        median,
        maximum: values.last().copied(),
        current: current_value,
        current_unavailable_reason: current.err().map(str::to_owned),
        delta_from_median: current_value.zip(median).map(|(c, b)| c - b),
        ratio_to_median: current_value
            .zip(median)
            .filter(|(_, b)| *b != 0.0)
            .map(|(c, b)| c / b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn median_has_explicit_even_empty_and_zero_semantics() {
        let result = distribution(
            vec![8.0, 2.0, 4.0, 6.0],
            [("missing".into(), 1)].into(),
            Ok(10.0),
        );
        assert_eq!(result.median, Some(5.0));
        assert_eq!(result.ratio_to_median, Some(2.0));
        assert_eq!(result.unavailable_runs, 1);
        assert_eq!(
            distribution(vec![0.0], BTreeMap::new(), Ok(3.0)).ratio_to_median,
            None
        );
        let missing = distribution(vec![], [("missing".into(), 2)].into(), Err("missing"));
        assert_eq!(missing.median, None);
        assert_eq!(missing.current, None);
    }
    #[test]
    fn explicit_run_set_is_order_independent_deduplicated_and_never_reads_logs() {
        let temp = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for name in ["a", "b", "current"] {
            let dir = temp.path().join(name);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("run-manifest.json"), r#"{"corpus":[{"path":"/nonexistent/private/log"}],"corpus_label":"private-label"}"#).unwrap();
            paths.push(dir);
        }
        let result =
            compare_reference_runs(&paths[0], &[paths[1].clone(), paths[0].clone()], &paths[2])
                .unwrap();
        assert_eq!(result.duplicate_directory_references_excluded, 1);
        assert_eq!(
            result.metrics[&DailyMetric::TotalRequests].unavailable_runs,
            2
        );
        let reverse =
            compare_reference_runs(&paths[1], &[paths[0].clone(), paths[1].clone()], &paths[2])
                .unwrap();
        assert_eq!(
            serde_json::to_string(&result).unwrap(),
            serde_json::to_string(&reverse).unwrap()
        );
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("private-label") && !json.contains("/nonexistent"));
    }
}
