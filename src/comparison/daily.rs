//! Opt-in descriptive comparisons of frozen aggregate measurements.
//! No raw entity values, classifications, clocks, or network access are used.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{NumericDelta, OptionalRatioDelta};
use crate::concentration::RequestConcentrationSummary;

pub const COMPARISON_POINT_NOTE: &str = "A comparison point is a value the operator chose, not a finding. Crossing one means the measurement moved by at least that much between two runs of the same corpus. Traffic changes for many reasons: a campaign, a release, a holiday, a crawler arriving or leaving, an upstream change in how client addresses are presented. None of this is a determination of an outage, degraded availability, an attack, or abuse.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DailyMetric {
    TotalRequests,
    DistinctSourceIps,
    TopPathShare,
    TopPathRequestsPerSourceIp,
    CorpusRequestsPerSourceIp,
    SuccessShare,
    ClientClosedRequest499Share,
    ServerErrorShare,
}

impl DailyMetric {
    pub const ALL: [Self; 8] = [
        Self::TotalRequests,
        Self::DistinctSourceIps,
        Self::TopPathShare,
        Self::TopPathRequestsPerSourceIp,
        Self::CorpusRequestsPerSourceIp,
        Self::SuccessShare,
        Self::ClientClosedRequest499Share,
        Self::ServerErrorShare,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::TotalRequests => "Total requests",
            Self::DistinctSourceIps => "Retained distinct source IPs",
            Self::TopPathShare => "Top path share",
            Self::TopPathRequestsPerSourceIp => "Top path requests per source IP",
            Self::CorpusRequestsPerSourceIp => "Corpus requests per source IP",
            Self::SuccessShare => "2xx share",
            Self::ClientClosedRequest499Share => "499 share",
            Self::ServerErrorShare => "5xx share",
        }
    }

    pub fn is_share(self) -> bool {
        matches!(
            self,
            Self::TopPathShare
                | Self::SuccessShare
                | Self::ClientClosedRequest499Share
                | Self::ServerErrorShare
        )
    }

    fn count(self, summary: &RequestConcentrationSummary) -> Option<u64> {
        match self {
            Self::TotalRequests => Some(summary.total_requests),
            Self::DistinctSourceIps => Some(summary.distinct_source_ips as u64),
            _ => None,
        }
    }

    fn measurement(
        self,
        summary: Option<&RequestConcentrationSummary>,
    ) -> Result<f64, &'static str> {
        let summary = summary.ok_or("concentration summary unavailable")?;
        match self {
            Self::TotalRequests => Ok(summary.total_requests as f64),
            Self::DistinctSourceIps => Ok(summary.distinct_source_ips as f64),
            Self::TopPathShare => {
                let path = summary.top_path.as_ref().ok_or("no retained top path")?;
                if summary.total_requests == 0 {
                    return Err("no observed requests");
                }
                Ok(path.request_share)
            }
            Self::TopPathRequestsPerSourceIp => {
                let path = summary.top_path.as_ref().ok_or("no retained top path")?;
                ratio(path.requests as f64, path.distinct_source_ips as f64)
                    .ok_or("no observed sources on retained top path")
            }
            Self::CorpusRequestsPerSourceIp => ratio(
                summary.total_requests as f64,
                summary.distinct_source_ips as f64,
            )
            .ok_or("no retained observed sources"),
            Self::SuccessShare | Self::ClientClosedRequest499Share | Self::ServerErrorShare => {
                let outcomes = summary
                    .response_outcomes
                    .as_ref()
                    .ok_or("response status unavailable in profile or artifact")?;
                let total = outcomes.counts.total_observations();
                if total == 0 || total == outcomes.counts.unavailable {
                    return Err("no recorded response status");
                }
                // Preserve all-observation denominators, including unavailable.
                Ok(match self {
                    Self::SuccessShare => outcomes.success_share,
                    Self::ClientClosedRequest499Share => outcomes.client_closed_request_499_share,
                    _ => outcomes.server_error_share,
                })
            }
        }
        .and_then(|value| {
            value
                .is_finite()
                .then_some(value)
                .ok_or("non-finite measurement")
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonBasis {
    Delta,
    Ratio,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonRelation {
    AtLeast,
    AtMost,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonPoint {
    pub basis: ComparisonBasis,
    pub relation: ComparisonRelation,
    pub value: f64,
}

/// A supplied `points` map replaces the defaults, not merges with them.
/// An empty map requests measurements without any comparison points.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DailyComparisonPoints {
    pub points: BTreeMap<DailyMetric, ComparisonPoint>,
}

impl Default for DailyComparisonPoints {
    fn default() -> Self {
        use ComparisonBasis::{Delta, Ratio};
        use ComparisonRelation::{AtLeast, AtMost};
        Self {
            points: [
                (
                    DailyMetric::TopPathRequestsPerSourceIp,
                    Ratio,
                    AtLeast,
                    10.0,
                ),
                (DailyMetric::TopPathShare, Delta, AtLeast, 0.20),
                (DailyMetric::SuccessShare, Delta, AtMost, -0.25),
                (
                    DailyMetric::ClientClosedRequest499Share,
                    Delta,
                    AtLeast,
                    0.10,
                ),
            ]
            .into_iter()
            .map(|(metric, basis, relation, value)| {
                (
                    metric,
                    ComparisonPoint {
                        basis,
                        relation,
                        value,
                    },
                )
            })
            .collect(),
        }
    }
}

impl DailyComparisonPoints {
    pub fn validate(&self) -> anyhow::Result<()> {
        for point in self.points.values() {
            if !point.value.is_finite()
                || (matches!(point.basis, ComparisonBasis::Ratio) && point.value < 0.0)
            {
                anyhow::bail!(
                    "comparison points must be finite; ratio comparison points must be nonnegative"
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DailyMetricDelta {
    pub values: OptionalRatioDelta,
    /// Integer counts and signed change remain exact, independently of f64 ratios.
    pub counts: Option<NumericDelta>,
    /// Current / baseline in either direction. A zero baseline is unavailable.
    pub current_to_baseline_ratio: Option<f64>,
    pub unavailable_reasons: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PointEvaluation {
    pub crossed: Option<bool>,
    pub unavailable_reason: Option<String>,
}

/// Only count-based coverage information; never copy paths or source values.
#[derive(Debug, Deserialize, Serialize)]
pub struct DailyMeasurementCoverage {
    pub requests_without_uri_path: u64,
    pub requests_without_source_ip: u64,
    pub paths_beyond_tracking_cap: u64,
    pub source_ips_beyond_tracking_cap: u64,
    pub source_path_pairs_beyond_tracking_cap: u64,
    pub top_path_requests: Option<u64>,
    pub top_path_distinct_source_ips: Option<usize>,
    pub response_observations: Option<u64>,
    pub response_status_unavailable: Option<u64>,
}

impl From<&RequestConcentrationSummary> for DailyMeasurementCoverage {
    fn from(s: &RequestConcentrationSummary) -> Self {
        Self {
            requests_without_uri_path: s.requests_without_uri_path,
            requests_without_source_ip: s.requests_without_source_ip,
            paths_beyond_tracking_cap: s.paths_beyond_tracking_cap,
            source_ips_beyond_tracking_cap: s.source_ips_beyond_tracking_cap,
            source_path_pairs_beyond_tracking_cap: s.source_path_pairs_beyond_tracking_cap,
            top_path_requests: s.top_path.as_ref().map(|p| p.requests),
            top_path_distinct_source_ips: s.top_path.as_ref().map(|p| p.distinct_source_ips),
            response_observations: s
                .response_outcomes
                .as_ref()
                .map(|o| o.counts.total_observations()),
            response_status_unavailable: s.response_outcomes.as_ref().map(|o| o.counts.unavailable),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DailyComparison {
    pub safety_note: String,
    pub measurement_note: String,
    pub comparison_points: DailyComparisonPoints,
    pub measurements: BTreeMap<DailyMetric, DailyMetricDelta>,
    pub baseline_coverage: Option<DailyMeasurementCoverage>,
    pub current_coverage: Option<DailyMeasurementCoverage>,
    pub evaluations: BTreeMap<DailyMetric, PointEvaluation>,
    pub configured_points: usize,
    pub evaluated_points: usize,
    pub unavailable_points: usize,
    pub crossed_points: Vec<DailyMetric>,
    pub crossed_point_count: usize,
}

fn ratio(current: f64, baseline: f64) -> Option<f64> {
    (baseline != 0.0)
        .then(|| current / baseline)
        .filter(|value| value.is_finite())
}

pub fn compare_daily_metrics(
    baseline: Option<&RequestConcentrationSummary>,
    current: Option<&RequestConcentrationSummary>,
    points: DailyComparisonPoints,
) -> anyhow::Result<DailyComparison> {
    points.validate()?;
    let mut measurements = BTreeMap::new();
    for metric in DailyMetric::ALL {
        let b = metric.measurement(baseline);
        let c = metric.measurement(current);
        let mut reasons = Vec::new();
        for (side, result) in [("baseline", &b), ("current", &c)] {
            if let Err(reason) = result {
                reasons.push(format!("{side}: {reason}"));
            }
        }
        let (b, c) = (b.ok(), c.ok());
        let ratio = b.zip(c).and_then(|(b, c)| ratio(c, b));
        if b == Some(0.0) {
            reasons.push("current/baseline ratio unavailable: baseline is zero".to_owned());
        }
        // NumericDelta uses i64 for change. Reject out-of-range changes rather
        // than silently wrapping or saturating an exact count difference.
        let counts = baseline
            .and_then(|s| metric.count(s))
            .zip(current.and_then(|s| metric.count(s)))
            .map(|(baseline, current)| -> anyhow::Result<NumericDelta> {
                let delta =
                    i64::try_from(i128::from(current) - i128::from(baseline)).map_err(|_| {
                        anyhow::anyhow!("daily count delta exceeds signed 64-bit range")
                    })?;
                Ok(NumericDelta {
                    baseline,
                    current,
                    delta,
                })
            })
            .transpose()?;
        measurements.insert(
            metric,
            DailyMetricDelta {
                values: OptionalRatioDelta {
                    baseline: b,
                    current: c,
                    delta: b.zip(c).map(|(b, c)| c - b),
                },
                counts,
                current_to_baseline_ratio: ratio,
                unavailable_reasons: reasons,
            },
        );
    }
    let evaluations: BTreeMap<_, _> = points
        .points
        .iter()
        .map(|(&metric, point)| {
            let measurement = &measurements[&metric];
            let value = match point.basis {
                ComparisonBasis::Delta => measurement.values.delta,
                ComparisonBasis::Ratio => measurement.current_to_baseline_ratio,
            };
            let crossed = value.map(|value| match point.relation {
                ComparisonRelation::AtLeast => value >= point.value,
                ComparisonRelation::AtMost => value <= point.value,
            });
            (
                metric,
                PointEvaluation {
                    crossed,
                    unavailable_reason: crossed
                        .is_none()
                        .then(|| measurement.unavailable_reasons.join("; ")),
                },
            )
        })
        .collect();
    let crossed_points: Vec<_> = evaluations
        .iter()
        .filter_map(|(&metric, result)| (result.crossed == Some(true)).then_some(metric))
        .collect();
    let unavailable_points = evaluations
        .values()
        .filter(|result| result.crossed.is_none())
        .count();
    Ok(DailyComparison {
        safety_note: COMPARISON_POINT_NOTE.to_owned(),
        measurement_note: "Delta = current - baseline; ratio = current / baseline. Share deltas use fractions (multiply by 100 for percentage points). Each run selects its own retained top path; these need not be the same path. Corpus requests/source uses total requests divided by retained distinct sources, not top-path counts. Retention omissions can affect the selected top path and denominators; counts are not cumulative across runs. Status shares retain all observations, including missing status, in the denominator. Select two windows of the same corpus; Shenron does not infer shared host identity.".to_owned(),
        configured_points: evaluations.len(),
        evaluated_points: evaluations.len() - unavailable_points,
        unavailable_points,
        crossed_point_count: crossed_points.len(),
        crossed_points,
        evaluations,
        measurements,
        baseline_coverage: baseline.map(Into::into),
        current_coverage: current.map(Into::into),
        comparison_points: points,
    })
}

/// Aggregate-only human-readable lines, with unavailable values and cap
/// denominators disclosed. Display precision never controls evaluation.
impl DailyComparison {
    pub fn display_lines(&self) -> Vec<String> {
        let mut lines = vec!["Daily metric comparison (descriptive counts only):".to_owned()];
        let number = |value: Option<f64>| {
            value
                .map(|n| format!("{n:.6}"))
                .unwrap_or_else(|| "unavailable".to_owned())
        };
        for (&metric, measurement) in &self.measurements {
            let (baseline, current, delta) = if let Some(counts) = &measurement.counts {
                (
                    counts.baseline.to_string(),
                    counts.current.to_string(),
                    counts.delta.to_string(),
                )
            } else if metric.is_share() {
                (
                    number(measurement.values.baseline.map(|v| v * 100.0)),
                    number(measurement.values.current.map(|v| v * 100.0)),
                    number(measurement.values.delta.map(|v| v * 100.0)),
                )
            } else {
                (
                    number(measurement.values.baseline),
                    number(measurement.values.current),
                    number(measurement.values.delta),
                )
            };
            let unit = if metric.is_share() {
                " (shares %, delta percentage points)"
            } else {
                ""
            };
            lines.push(format!("  {} baseline / current / delta: {baseline} / {current} / {delta}{unit}; current/baseline ratio: {}", metric.label(), number(measurement.current_to_baseline_ratio)));
            for reason in &measurement.unavailable_reasons {
                lines.push(format!("    Unavailable: {reason}"));
            }
        }
        for (side, coverage) in [
            ("Baseline", &self.baseline_coverage),
            ("Current", &self.current_coverage),
        ] {
            if let Some(c) = coverage {
                lines.push(format!("  {side} coverage: missing path/source {} / {}; cap omissions paths/sources/pairs {} / {} / {}; retained top-path requests/sources {} / {}; response observations/unavailable {} / {}",
                    c.requests_without_uri_path, c.requests_without_source_ip, c.paths_beyond_tracking_cap, c.source_ips_beyond_tracking_cap, c.source_path_pairs_beyond_tracking_cap,
                    c.top_path_requests.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned()), c.top_path_distinct_source_ips.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned()),
                    c.response_observations.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned()), c.response_status_unavailable.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned())));
            } else {
                lines.push(format!(
                    "  {side} coverage: unavailable (concentration summary missing)"
                ));
            }
        }
        for (&metric, point) in &self.comparison_points.points {
            let evaluation = &self.evaluations[&metric];
            lines.push(format!(
                "  Comparison point {}: {:?} {:?} {}; crossed: {}",
                metric.label(),
                point.basis,
                point.relation,
                point.value,
                evaluation
                    .crossed
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| format!(
                        "unavailable ({})",
                        evaluation
                            .unavailable_reason
                            .as_deref()
                            .unwrap_or("measurement missing")
                    ))
            ));
        }
        lines.push(format!(
            "  Comparison points crossed: {} (configured: {}; evaluated: {}; unavailable: {})",
            self.crossed_point_count,
            self.configured_points,
            self.evaluated_points,
            self.unavailable_points
        ));
        lines.push(format!(
            "  Crossed comparison points: {}",
            if self.crossed_points.is_empty() {
                "none".to_owned()
            } else {
                self.crossed_points
                    .iter()
                    .map(|m| m.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        lines.push(self.measurement_note.clone());
        lines.push(self.safety_note.clone());
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concentration::{RequestConcentration, ResponseOutcomeSummary, StatusClassCounts};

    fn summary(
        total: u64,
        sources: usize,
        top_requests: u64,
        top_sources: usize,
    ) -> RequestConcentrationSummary {
        let mut summary = RequestConcentration::with_capabilities(true, true).summary();
        summary.total_requests = total;
        summary.distinct_source_ips = sources;
        // Deliberately omit requests_per_source_ip to exercise legacy artifacts.
        summary.top_path = Some(serde_json::from_value(serde_json::json!({
            "requests": top_requests, "request_share": if total == 0 { 0.0 } else { top_requests as f64 / total as f64 },
            "distinct_source_ips": top_sources,
            "response_status_classes": StatusClassCounts::default(), "response_bytes": null
        })).unwrap());
        summary
    }

    fn outcomes(
        success: u64,
        closed: u64,
        server_error: u64,
        unavailable: u64,
    ) -> ResponseOutcomeSummary {
        let counts = StatusClassCounts {
            success,
            client_error: closed,
            client_closed_request_499: closed,
            server_error,
            unavailable,
            ..Default::default()
        };
        let total = counts.total_observations() as f64;
        ResponseOutcomeSummary {
            success_share: success as f64 / total,
            redirection_share: 0.0,
            ordinary_client_error_share: 0.0,
            client_closed_request_499_share: closed as f64 / total,
            server_error_share: server_error as f64 / total,
            counts,
        }
    }

    fn close(actual: Option<f64>, expected: f64) {
        assert!(
            (actual.unwrap() - expected).abs() < 1e-10,
            "{actual:?} != {expected}"
        );
    }

    #[test]
    fn daily_deltas_preserve_independent_denominators_and_all_measurements() {
        let mut b = summary(1_000_000, 10_000, 200, 100);
        let mut c = summary(2_000_000, 2_000, 400, 200);
        b.response_outcomes = Some(outcomes(900_000, 10_000, 90_000, 0));
        c.response_outcomes = Some(outcomes(1_000_000, 600_000, 200_000, 200_000));
        let result =
            compare_daily_metrics(Some(&b), Some(&c), DailyComparisonPoints::default()).unwrap();
        let m = &result.measurements;
        let counts = m[&DailyMetric::TotalRequests].counts.as_ref().unwrap();
        assert_eq!(
            (counts.baseline, counts.current, counts.delta),
            (1_000_000, 2_000_000, 1_000_000)
        );
        assert_eq!(
            m[&DailyMetric::DistinctSourceIps]
                .counts
                .as_ref()
                .unwrap()
                .delta,
            -8_000
        );
        close(
            m[&DailyMetric::TotalRequests].current_to_baseline_ratio,
            2.0,
        );
        close(
            m[&DailyMetric::DistinctSourceIps].current_to_baseline_ratio,
            0.2,
        );
        close(m[&DailyMetric::TopPathShare].values.delta, 0.0);
        close(
            m[&DailyMetric::TopPathRequestsPerSourceIp].values.current,
            2.0,
        );
        close(
            m[&DailyMetric::TopPathRequestsPerSourceIp].current_to_baseline_ratio,
            1.0,
        );
        close(
            m[&DailyMetric::CorpusRequestsPerSourceIp].values.baseline,
            100.0,
        );
        close(
            m[&DailyMetric::CorpusRequestsPerSourceIp].values.current,
            1_000.0,
        );
        close(
            m[&DailyMetric::CorpusRequestsPerSourceIp].values.delta,
            900.0,
        );
        close(
            m[&DailyMetric::CorpusRequestsPerSourceIp].current_to_baseline_ratio,
            10.0,
        );
        close(m[&DailyMetric::SuccessShare].values.delta, -0.4);
        close(
            m[&DailyMetric::ClientClosedRequest499Share].values.delta,
            0.29,
        );
        close(m[&DailyMetric::ServerErrorShare].values.delta, 0.01);
        assert_eq!(
            result.current_coverage.unwrap().response_status_unavailable,
            Some(200_000)
        );
        assert_eq!(
            result.crossed_points,
            [
                DailyMetric::SuccessShare,
                DailyMetric::ClientClosedRequest499Share
            ]
        );
        assert_eq!(result.crossed_point_count, 2);
    }

    #[test]
    fn decreasing_counts_and_reverse_ratios_do_not_need_direction_flags() {
        let b = summary(1_245, 10, 100, 10);
        let c = summary(7, 6, 2, 2);
        let points: DailyComparisonPoints = serde_json::from_value(serde_json::json!({"points": {
            "total_requests": {"basis":"ratio", "relation":"at_most", "value":0.01},
            "distinct_source_ips": {"basis":"ratio", "relation":"at_most", "value":0.7}
        }}))
        .unwrap();
        let result = compare_daily_metrics(Some(&b), Some(&c), points.clone()).unwrap();
        close(
            result.measurements[&DailyMetric::TotalRequests].current_to_baseline_ratio,
            7.0 / 1245.0,
        );
        close(
            result.measurements[&DailyMetric::DistinctSourceIps].current_to_baseline_ratio,
            0.6,
        );
        assert_eq!(
            result.measurements[&DailyMetric::TotalRequests]
                .counts
                .as_ref()
                .unwrap()
                .delta,
            -1238
        );
        assert_eq!(result.crossed_point_count, 2);
        let reverse = compare_daily_metrics(Some(&c), Some(&b), points).unwrap();
        close(
            reverse.measurements[&DailyMetric::TotalRequests].current_to_baseline_ratio,
            1245.0 / 7.0,
        );
        close(
            reverse.measurements[&DailyMetric::DistinctSourceIps].current_to_baseline_ratio,
            10.0 / 6.0,
        );
        assert_eq!(reverse.crossed_point_count, 0);
    }

    #[test]
    fn points_use_inclusive_boundaries_and_are_recorded_in_stable_order() {
        let mut b = summary(100, 10, 10, 10);
        let mut c = summary(100, 10, 50, 5);
        b.response_outcomes = Some(outcomes(100, 0, 0, 0));
        c.response_outcomes = Some(outcomes(50, 25, 25, 0));
        let result =
            compare_daily_metrics(Some(&b), Some(&c), DailyComparisonPoints::default()).unwrap();
        assert_eq!(
            result.crossed_points,
            [
                DailyMetric::TopPathShare,
                DailyMetric::TopPathRequestsPerSourceIp,
                DailyMetric::SuccessShare,
                DailyMetric::ClientClosedRequest499Share
            ]
        );
        assert_eq!(result.configured_points, 4);
        assert_eq!(result.evaluated_points, 4);
        assert_eq!(result.unavailable_points, 0);
        close(
            Some(result.comparison_points.points[&DailyMetric::TopPathRequestsPerSourceIp].value),
            10.0,
        );
        assert_eq!(
            serde_json::to_vec(&result).unwrap(),
            serde_json::to_vec(
                &compare_daily_metrics(Some(&b), Some(&c), DailyComparisonPoints::default())
                    .unwrap()
            )
            .unwrap()
        );
        for metric in DailyMetric::ALL {
            let points = DailyComparisonPoints {
                points: BTreeMap::from([(
                    metric,
                    ComparisonPoint {
                        basis: ComparisonBasis::Delta,
                        relation: ComparisonRelation::AtLeast,
                        value: 0.0,
                    },
                )]),
            };
            let same = compare_daily_metrics(Some(&b), Some(&b), points).unwrap();
            assert_eq!(same.evaluations[&metric].crossed, Some(true));
        }
    }

    #[test]
    fn missing_status_and_zero_denominators_are_unavailable_not_zero() {
        let b = summary(10, 2, 5, 1);
        let mut c = b.clone();
        for outcome in [None, Some(outcomes(0, 0, 0, 10))] {
            c.response_outcomes = outcome;
            let result =
                compare_daily_metrics(Some(&c), Some(&c), DailyComparisonPoints::default())
                    .unwrap();
            for metric in [
                DailyMetric::SuccessShare,
                DailyMetric::ClientClosedRequest499Share,
                DailyMetric::ServerErrorShare,
            ] {
                assert!(result.measurements[&metric].values.baseline.is_none());
                assert!(result.measurements[&metric].values.current.is_none());
                assert!(result.measurements[&metric].values.delta.is_none());
                assert!(!result.measurements[&metric].unavailable_reasons.is_empty());
            }
            assert_eq!(result.unavailable_points, 2);
            assert_eq!(result.evaluations[&DailyMetric::SuccessShare].crossed, None);
            assert!(result.display_lines().join("\n").contains(
                "2xx share baseline / current / delta: unavailable / unavailable / unavailable"
            ));
        }
        let empty = summary(0, 0, 0, 0);
        let result =
            compare_daily_metrics(Some(&empty), Some(&b), DailyComparisonPoints::default())
                .unwrap();
        assert!(result.measurements[&DailyMetric::TotalRequests]
            .current_to_baseline_ratio
            .is_none());
        assert_eq!(
            result.measurements[&DailyMetric::TotalRequests]
                .counts
                .as_ref()
                .unwrap()
                .delta,
            10
        );
        assert!(result.measurements[&DailyMetric::CorpusRequestsPerSourceIp]
            .values
            .delta
            .is_none());
        let missing =
            compare_daily_metrics(None, Some(&b), DailyComparisonPoints::default()).unwrap();
        assert_eq!(missing.unavailable_points, 4);
        assert!(missing.measurements[&DailyMetric::TotalRequests]
            .counts
            .is_none());
        close(
            missing.measurements[&DailyMetric::TotalRequests]
                .values
                .current,
            10.0,
        );
    }

    #[test]
    fn configuration_rejects_mistakes_and_caps_are_disclosed_as_counts() {
        for json in [
            r#"{"point":{}}"#,
            r#"{"points":{"misspelled":{}}}"#,
            r#"{"points":{"total_requests":{"basis":"ratio","relation":"above","value":2}}}"#,
        ] {
            assert!(serde_json::from_str::<DailyComparisonPoints>(json).is_err());
        }
        for value in [-1.0, f64::NAN, f64::INFINITY] {
            let points = DailyComparisonPoints {
                points: BTreeMap::from([(
                    DailyMetric::TotalRequests,
                    ComparisonPoint {
                        basis: ComparisonBasis::Ratio,
                        relation: ComparisonRelation::AtLeast,
                        value,
                    },
                )]),
            };
            assert!(points.validate().is_err());
        }
        let mut b = summary(10, 1, 5, 1);
        b.paths_beyond_tracking_cap = 3;
        b.source_ips_beyond_tracking_cap = 4;
        b.source_path_pairs_beyond_tracking_cap = 5;
        b.requests_without_source_ip = 6;
        let result =
            compare_daily_metrics(Some(&b), Some(&b), DailyComparisonPoints::default()).unwrap();
        let text = result.display_lines().join("\n");
        assert!(text.contains("cap omissions paths/sources/pairs 3 / 4 / 5"));
        assert!(text.contains("missing path/source 0 / 6"));
        assert!(text.contains(COMPARISON_POINT_NOTE));
    }
}
