//! Opt-in, allowlisted measurement context. Missing metadata is never inferred.
use chrono::{DateTime, Datelike, Timelike};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

pub const NOTE: &str = "Recorded measurement conditions, not a claim that runs describe the same service or that a change is a finding. Review coverage, exclusions, caps, field availability and frozen inputs before interpreting deltas. Missing facts remain unavailable; equal facts do not prove comparable populations.";

#[derive(Debug, Serialize)]
pub struct RunConditions {
    pub numeric: BTreeMap<&'static str, Option<f64>>,
    /// Hashes compare recorded settings without exposing their private values.
    pub signatures: BTreeMap<&'static str, Option<String>>,
}

#[derive(Debug, Serialize)]
pub struct ConditionsComparison {
    pub note: &'static str,
    pub baseline: RunConditions,
    pub current: RunConditions,
    pub changed_recorded_facts: Vec<String>,
    pub unavailable_facts: Vec<String>,
}

pub fn read_conditions(dir: &Path) -> anyhow::Result<RunConditions> {
    let manifest =
        super::read_json_optional(&dir.join("run-manifest.json"))?.unwrap_or(Value::Null);
    let sanitized =
        super::read_json_optional(&dir.join("sanitized-research.json"))?.unwrap_or(Value::Null);
    let metrics = sanitized.get("metrics").unwrap_or(&sanitized);
    let summary = metrics.get("request_concentration").unwrap_or(&Value::Null);
    let mut numeric = BTreeMap::new();
    for (label, pointer) in [
        ("analyzed_requests", "/total_requests_analyzed"),
        ("parse_errors", "/parse_errors"),
        ("outside_window", "/requests_outside_time_range"),
        ("undated_excluded", "/requests_without_timestamp_excluded"),
        ("files_analyzed", "/files_analyzed"),
        ("files_skipped_as_processed", "/files_skipped_as_processed"),
        ("populated_client_ip", "/fields_available/client_ip"),
        ("populated_query", "/fields_available/query"),
        ("populated_headers", "/fields_available/headers"),
    ] {
        numeric.insert(label, metrics.pointer(pointer).and_then(Value::as_f64));
    }
    for (label, pointer) in [
        (
            "undated_observations",
            "/requests_per_minute/observations_without_timestamp",
        ),
        ("path_cap_omissions", "/paths_beyond_tracking_cap"),
        ("source_cap_omissions", "/source_ips_beyond_tracking_cap"),
        (
            "pair_cap_omissions",
            "/source_path_pairs_beyond_tracking_cap",
        ),
        (
            "status_unavailable",
            "/response_outcomes/counts/unavailable",
        ),
        ("response_observations", "/total_requests"),
    ] {
        numeric.insert(label, summary.pointer(pointer).and_then(Value::as_f64));
    }
    let outcomes = summary.pointer("/response_outcomes/counts");
    numeric.insert(
        "minute_cap_omissions",
        summary
            .get("request_rates")
            .and_then(Value::as_array)
            .and_then(|rates| {
                rates.iter().find(|rate| {
                    rate.get("bucket_width_seconds").and_then(Value::as_u64) == Some(60)
                })
            })
            .and_then(|rate| rate.get("observations_beyond_bucket_cap"))
            .and_then(Value::as_f64),
    );
    let status_total = outcomes.and_then(|v| {
        [
            "informational",
            "success",
            "redirection",
            "client_error",
            "server_error",
            "other",
            "unavailable",
        ]
        .into_iter()
        .try_fold(0.0, |sum, k| Some(sum + v.get(k)?.as_f64()?))
    });
    numeric.insert(
        "recorded_status_share",
        status_total
            .filter(|n| *n > 0.0)
            .zip(outcomes.and_then(|v| v.get("unavailable")?.as_f64()))
            .map(|(total, missing)| (total - missing) / total),
    );
    for key in [
        "max_paths",
        "max_source_ips",
        "max_source_path_pairs",
        "max_source_segments",
    ] {
        numeric.insert(
            key,
            manifest
                .get("tracking_limits")
                .and_then(|v| v.get(key))
                .and_then(Value::as_f64),
        );
    }
    numeric.insert(
        "approved_templates",
        manifest
            .pointer("/inputs/approved_validated_template_count")
            .and_then(Value::as_f64),
    );
    numeric.insert(
        "sigma_rules_evaluated",
        manifest
            .get("sigma_rules_evaluated")
            .and_then(Value::as_f64),
    );
    let time = |key: &str| {
        manifest
            .get("hunt_parameters")
            .and_then(|v| v.get(key))
            .filter(|v| !v.is_null())
            .or_else(|| metrics.get(key))
            .or_else(|| sanitized.get(key))
            .and_then(Value::as_str)
            .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
    };
    let from = time("filter_from");
    let to = time("filter_to");
    numeric.insert(
        "window_seconds",
        from.zip(to).map(|(a, b)| (b - a).num_seconds() as f64),
    );
    numeric.insert(
        "window_start_weekday_utc",
        from.map(|t| f64::from(t.weekday().num_days_from_monday())),
    );
    numeric.insert(
        "window_start_second_of_day_utc",
        from.map(|t| f64::from(t.num_seconds_from_midnight())),
    );
    let observed = |key: &str| {
        metrics
            .get(key)
            .and_then(Value::as_str)
            .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
    };
    numeric.insert(
        "observed_span_seconds",
        observed("earliest_timestamp")
            .zip(observed("latest_timestamp"))
            .map(|(a, b)| (b - a).num_seconds() as f64),
    );
    let mut signatures = BTreeMap::new();
    for (label, pointer) in [
        ("telemetry_profile", "/telemetry_profile"),
        ("shenron_version", "/shenron_version"),
        ("nuclei_revision", "/nuclei_revision"),
        ("nuclei_report", "/inputs/nuclei_report/sha256"),
        ("kev_report", "/inputs/kev_report/sha256"),
        (
            "trusted_proxy_configuration",
            "/hunt_parameters/trusted_proxy_networks",
        ),
        ("triage_policy", "/hunt_parameters/triage_policy"),
        ("corpus_scope_annotation", "/corpus_label"),
        ("template_selection", "/inputs/template_filter"),
    ] {
        signatures.insert(
            label,
            manifest
                .pointer(pointer)
                .filter(|v| !v.is_null())
                .map(|v| format!("{:x}", Sha256::digest(v.to_string().as_bytes()))),
        );
    }
    Ok(RunConditions {
        numeric,
        signatures,
    })
}

pub fn compare_conditions(baseline: &Path, current: &Path) -> anyhow::Result<ConditionsComparison> {
    let baseline = read_conditions(baseline)?;
    let current = read_conditions(current)?;
    let mut changed = Vec::new();
    let mut unavailable = Vec::new();
    for (key, b) in &baseline.numeric {
        match (b, current.numeric[key]) {
            (Some(a), Some(b)) if *a != b => changed.push((*key).to_owned()),
            (None, _) | (_, None) => unavailable.push((*key).to_owned()),
            _ => {}
        }
    }
    for (key, b) in &baseline.signatures {
        match (b, &current.signatures[key]) {
            (Some(a), Some(b)) if a != b => changed.push((*key).to_owned()),
            (None, _) | (_, None) => unavailable.push((*key).to_owned()),
            _ => {}
        }
    }
    changed.sort();
    unavailable.sort();
    Ok(ConditionsComparison {
        note: NOTE,
        baseline,
        current,
        changed_recorded_facts: changed,
        unavailable_facts: unavailable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn minute_cap_omissions_comes_only_from_the_sixty_second_rate_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sanitized-research.json");
        let mut report = serde_json::json!({"request_concentration": {
            "requests_per_minute": {"observations_beyond_bucket_cap": 999},
            "request_rates": [
                {"bucket_width_seconds": 600, "observations_beyond_bucket_cap": 44},
                {"bucket_width_seconds": 60, "observations_beyond_bucket_cap": 7}
            ]
        }});
        fs::write(&path, report.to_string()).unwrap();
        let conditions = read_conditions(dir.path()).unwrap();
        assert_eq!(conditions.numeric["minute_cap_omissions"], Some(7.0));
        assert_eq!(
            serde_json::to_string(&conditions)
                .unwrap()
                .matches("\"minute_cap_omissions\"")
                .count(),
            1
        );

        report["request_concentration"]["request_rates"]
            .as_array_mut()
            .unwrap()
            .pop();
        fs::write(&path, report.to_string()).unwrap();
        assert_eq!(
            read_conditions(dir.path()).unwrap().numeric["minute_cap_omissions"],
            None
        );
    }

    #[test]
    fn differences_and_missing_facts_are_disclosed_without_private_values() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        for (path, cap) in [(&a, 5), (&b, 9)] {
            fs::create_dir(path).unwrap();
            fs::write(path.join("run-manifest.json"), serde_json::json!({"tracking_limits":{"max_paths":cap},"corpus_label":"private-site", "hunt_parameters":{"trusted_proxy_networks":["198.51.100.1"]}}).to_string()).unwrap();
        }
        let result = compare_conditions(&a, &b).unwrap();
        assert!(result.changed_recorded_facts.contains(&"max_paths".into()));
        assert!(result
            .unavailable_facts
            .contains(&"recorded_status_share".into()));
        assert_eq!(result.baseline.numeric["max_paths"], Some(5.0));
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("private-site") && !json.contains("198.51.100.1"));
        assert!(compare_conditions(&a, &a)
            .unwrap()
            .changed_recorded_facts
            .is_empty());
    }
}
