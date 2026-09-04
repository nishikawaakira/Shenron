//! Optional best-effort Slack notification for completed hunts.
//!
//! This module accepts aggregate sanitized counters only. Its types have no
//! fields for requests, IP addresses, hosts, headers, or other customer
//! telemetry, so the notification path cannot serialize private findings.

use std::{
    env::{self, VarError},
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{bail, Context};
use serde_json::Value;

use crate::{
    comparison::SanitizedTemporalComparison,
    nuclei::CatalogSeverity,
    production::{CatalogSeverityCounts, HuntMetrics},
};

const SLACK_WEBHOOK_ENV: &str = "SHENRON_SLACK_WEBHOOK";
const SLACK_MIN_SEVERITY_ENV: &str = "SHENRON_SLACK_MIN_SEVERITY";
const CURL_MAX_TIME_SECONDS: &str = "30";

/// Environment-only notification configuration. The webhook remains private
/// and is never included in error messages or notification content.
pub struct SlackNotificationConfig {
    webhook: Option<String>,
    pub min_severity: Option<CatalogSeverity>,
}

impl SlackNotificationConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let webhook = optional_unicode_env(SLACK_WEBHOOK_ENV)?;
        let min_severity = optional_unicode_env(SLACK_MIN_SEVERITY_ENV)?;
        Self::from_values(webhook, min_severity)
    }

    fn from_values(webhook: Option<String>, min_severity: Option<String>) -> anyhow::Result<Self> {
        let webhook = webhook.and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        });
        let min_severity = min_severity
            .map(|value| parse_min_severity(&value))
            .transpose()?;
        Ok(Self {
            webhook,
            min_severity,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.webhook.is_some()
    }
}

fn optional_unicode_env(name: &str) -> anyhow::Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => bail!("{name} must contain valid Unicode"),
    }
}

fn parse_min_severity(value: &str) -> anyhow::Result<CatalogSeverity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" => Ok(CatalogSeverity::Info),
        "low" => Ok(CatalogSeverity::Low),
        "medium" => Ok(CatalogSeverity::Medium),
        "high" => Ok(CatalogSeverity::High),
        "critical" => Ok(CatalogSeverity::Critical),
        _ => bail!("{SLACK_MIN_SEVERITY_ENV} must be one of info, low, medium, high, or critical"),
    }
}

/// Sanitized scalar inputs accepted by the Slack formatter and policy gate.
/// The absence of private-value fields is a structural privacy boundary.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SlackNotificationMetrics {
    pub cve_findings_by_severity: CatalogSeverityCounts,
    pub sigma_matches_by_severity: CatalogSeverityCounts,
    pub unique_cves_observed: usize,
    pub unique_cisa_kevs_observed: usize,
    pub sigma_matched_requests: usize,
    pub sensitive_config_probe_matches: usize,
    pub sensitive_config_probe_success_responses: usize,
    pub concentration_peak_per_minute: Option<u64>,
    pub top_ten_paths_request_share: Option<f64>,
}

impl SlackNotificationMetrics {
    pub fn from_hunt(metrics: &HuntMetrics) -> Self {
        Self {
            cve_findings_by_severity: metrics.cve_findings_by_severity.clone(),
            sigma_matches_by_severity: metrics.sigma_matches_by_severity.clone(),
            unique_cves_observed: metrics.unique_cves_observed,
            unique_cisa_kevs_observed: metrics.unique_cisa_kevs_observed,
            sigma_matched_requests: metrics.sigma_matched_requests,
            sensitive_config_probe_matches: metrics.sensitive_config_probe_matches,
            sensitive_config_probe_success_responses: metrics
                .sensitive_config_probe_success_responses,
            concentration_peak_per_minute: metrics
                .request_concentration
                .as_ref()
                .and_then(|summary| summary.requests_per_minute.peak_requests_per_minute),
            top_ten_paths_request_share: metrics
                .request_concentration
                .as_ref()
                .map(|summary| summary.top_ten_paths_request_share),
        }
    }

    /// Load the same aggregate fields from an existing sanitized run. Missing
    /// additive fields from an older artifact remain zero or unavailable.
    pub fn from_sanitized_value(report: &Value) -> anyhow::Result<Self> {
        let metrics = report.get("metrics").unwrap_or(report);
        if !metrics.is_object() {
            bail!("sanitized-research.json does not contain an aggregate metrics object");
        }
        Ok(Self {
            cve_findings_by_severity: severity_counts(metrics.get("cve_findings_by_severity")),
            sigma_matches_by_severity: severity_counts(metrics.get("sigma_matches_by_severity")),
            unique_cves_observed: usize_field(metrics, "unique_cves_observed"),
            unique_cisa_kevs_observed: usize_field(metrics, "unique_cisa_kevs_observed"),
            sigma_matched_requests: usize_field(metrics, "sigma_matched_requests"),
            sensitive_config_probe_matches: usize_field(metrics, "sensitive_config_probe_matches"),
            sensitive_config_probe_success_responses: usize_field(
                metrics,
                "sensitive_config_probe_success_responses",
            ),
            concentration_peak_per_minute: metrics
                .pointer("/request_concentration/requests_per_minute/peak_requests_per_minute")
                .and_then(Value::as_u64),
            top_ten_paths_request_share: metrics
                .pointer("/request_concentration/top_ten_paths_request_share")
                .and_then(Value::as_f64),
        })
    }
}

fn usize_field(value: &Value, field: &str) -> usize {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or_default()
}

fn severity_counts(value: Option<&Value>) -> CatalogSeverityCounts {
    let count = |field: &str| {
        value
            .and_then(|value| value.get(field))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or_default()
    };
    CatalogSeverityCounts {
        unknown: count("unknown"),
        info: count("info"),
        low: count("low"),
        medium: count("medium"),
        high: count("high"),
        critical: count("critical"),
    }
}

/// Sanitized baseline delta used in the notification message.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SlackComparisonSummary {
    pub newly_observed_cves: usize,
    pub first_seen_entities: usize,
    pub elevated_paths: usize,
}

impl SlackComparisonSummary {
    pub fn from_comparison(comparison: &SanitizedTemporalComparison) -> Self {
        Self {
            newly_observed_cves: comparison.cve_diff.newly_observed_cves.len(),
            first_seen_entities: comparison.first_seen_counts.source_ips
                + comparison.first_seen_counts.hosts
                + comparison.first_seen_counts.uri_paths
                + comparison.first_seen_counts.ja4_fingerprints
                + comparison.first_seen_counts.client_ips.unwrap_or_default(),
            elevated_paths: comparison.concentration_delta.elevated_paths,
        }
    }

    pub fn from_sanitized_value(value: &Value) -> anyhow::Result<Self> {
        if !value.is_object() {
            bail!("comparison-summary.json does not contain an aggregate object");
        }
        let first_seen = value.get("first_seen_counts");
        Ok(Self {
            newly_observed_cves: value
                .pointer("/cve_diff/newly_observed_cves")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            first_seen_entities: [
                "source_ips",
                "hosts",
                "uri_paths",
                "ja4_fingerprints",
                "client_ips",
            ]
            .into_iter()
            .map(|field| first_seen.map_or(0, |counts| usize_field(counts, field)))
            .sum(),
            elevated_paths: value
                .pointer("/concentration_delta/elevated_paths")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or_default(),
        })
    }
}

/// Return whether a configured notification passes its catalog-severity gate.
/// KEV observations and sensitive/config-file 2xx responses always pass an
/// enabled threshold because they are independent review-priority signals.
pub fn should_notify(
    metrics: &SlackNotificationMetrics,
    min_severity: Option<CatalogSeverity>,
) -> bool {
    let Some(min_severity) = min_severity else {
        return true;
    };
    metrics.unique_cisa_kevs_observed != 0
        || metrics.sensitive_config_probe_success_responses != 0
        || severity_at_or_above(&metrics.cve_findings_by_severity, min_severity)
        || severity_at_or_above(&metrics.sigma_matches_by_severity, min_severity)
}

fn severity_at_or_above(counts: &CatalogSeverityCounts, minimum: CatalogSeverity) -> bool {
    [
        (CatalogSeverity::Info, counts.info),
        (CatalogSeverity::Low, counts.low),
        (CatalogSeverity::Medium, counts.medium),
        (CatalogSeverity::High, counts.high),
        (CatalogSeverity::Critical, counts.critical),
    ]
    .into_iter()
    .any(|(severity, count)| severity >= minimum && count != 0)
}

/// Build a Slack message from aggregate values only. The only strings accepted
/// are analyst-local artifact paths, never telemetry values.
pub fn build_notification_message(
    metrics: &SlackNotificationMetrics,
    comparison: Option<SlackComparisonSummary>,
    run_dir: &Path,
    report_path: Option<&Path>,
) -> String {
    let mut lines = vec![
        "Shenron daily review summary (sanitized aggregates only)".to_owned(),
        format_severity_line("CVE catalog severity", &metrics.cve_findings_by_severity),
        format_severity_line("Sigma catalog severity", &metrics.sigma_matches_by_severity),
        format!("Observed CVEs (unique): {}", metrics.unique_cves_observed),
        format!("Observed CISA KEVs: {}", metrics.unique_cisa_kevs_observed),
        format!("Sigma-matched requests: {}", metrics.sigma_matched_requests),
        format!(
            "Sensitive file/config probe matches / 2xx response status: {} / {}",
            metrics.sensitive_config_probe_matches,
            metrics.sensitive_config_probe_success_responses
        ),
    ];
    if metrics.sensitive_config_probe_success_responses != 0 {
        lines.push(format!(
            "HIGHEST REVIEW PRIORITY: {} sensitive file/config probe matches returned a 2xx response; this status alone does not confirm disclosure or compromise.",
            metrics.sensitive_config_probe_success_responses
        ));
    }
    let peak = metrics
        .concentration_peak_per_minute
        .map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
    let share = metrics.top_ten_paths_request_share.map_or_else(
        || "unavailable".to_owned(),
        |value| format!("{:.1}%", value * 100.0),
    );
    lines.push(format!(
        "Request concentration peak/minute / top-10 path share: {peak} / {share}"
    ));
    if let Some(comparison) = comparison {
        lines.push(format!(
            "Baseline delta — newly observed CVEs / first-seen entities / elevated paths: {} / {} / {}",
            comparison.newly_observed_cves,
            comparison.first_seen_entities,
            comparison.elevated_paths
        ));
    }
    lines.push(format!(
        "Local run directory: {}",
        single_line_path(run_dir)
    ));
    match report_path {
        Some(path) => lines.push(format!("Local HTML report: {}", single_line_path(path))),
        None => lines.push(format!(
            "Local HTML report: {} (not generated; use --report)",
            single_line_path(&run_dir.join("report.html"))
        )),
    }
    lines.push("Aggregate review signals, not a determination of attack, exploitation, compromise, or attacker identity. Severity is the source catalog's declared value.".to_owned());
    lines.join("\n")
}

fn format_severity_line(label: &str, counts: &CatalogSeverityCounts) -> String {
    format!(
        "{label}: critical={}, high={}, medium={}, low={}, info={}, unknown={}",
        counts.critical, counts.high, counts.medium, counts.low, counts.info, counts.unknown
    )
}

fn single_line_path(path: &Path) -> String {
    path.display()
        .to_string()
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

/// Send one notification when explicitly configured. Transfer failures are
/// reported without the secret webhook URL and never fail the completed hunt.
pub fn notify_best_effort(
    config: &SlackNotificationConfig,
    metrics: &SlackNotificationMetrics,
    comparison: Option<SlackComparisonSummary>,
    run_dir: &Path,
    report_path: Option<&Path>,
) {
    let Some(webhook) = config.webhook.as_deref() else {
        return;
    };
    if !should_notify(metrics, config.min_severity) {
        eprintln!("Slack notification skipped (below SHENRON_SLACK_MIN_SEVERITY)");
        return;
    }
    let message = build_notification_message(metrics, comparison, run_dir, report_path);
    match post_to_slack(webhook, &message) {
        Ok(()) => eprintln!("Slack notification sent"),
        Err(error) => eprintln!("Slack notification failed: {error}"),
    }
}

fn post_to_slack(webhook: &str, message: &str) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(&serde_json::json!({ "text": message }))?;
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--max-time",
            CURL_MAX_TIME_SECONDS,
            "--data-binary",
            "@-",
            "--write-out",
            "\n%{http_code}",
        ])
        .arg(webhook)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("curl executable was not found")
            } else {
                anyhow::anyhow!("could not start curl")
            }
        })?;
    child
        .stdin
        .take()
        .context("curl stdin was unavailable")?
        .write_all(&payload)
        .context("could not write the sanitized Slack payload to curl")?;
    let output = child
        .wait_with_output()
        .context("could not wait for curl")?;
    if !output.status.success() {
        let status = output.status.code().map_or_else(
            || "terminated by signal".to_owned(),
            |code| code.to_string(),
        );
        bail!("curl exited unsuccessfully ({status})");
    }
    let response = String::from_utf8_lossy(&output.stdout);
    let status = response
        .trim_end()
        .rsplit_once('\n')
        .map_or(response.trim(), |(_, status)| status)
        .parse::<u16>()
        .context("curl did not return a valid HTTP status")?;
    if !(200..=299).contains(&status) {
        bail!("Slack endpoint returned HTTP status {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> SlackNotificationMetrics {
        SlackNotificationMetrics {
            cve_findings_by_severity: CatalogSeverityCounts {
                medium: 2,
                high: 1,
                ..CatalogSeverityCounts::default()
            },
            sigma_matches_by_severity: CatalogSeverityCounts {
                low: 3,
                critical: 1,
                ..CatalogSeverityCounts::default()
            },
            unique_cves_observed: 3,
            unique_cisa_kevs_observed: 1,
            sigma_matched_requests: 4,
            sensitive_config_probe_matches: 5,
            sensitive_config_probe_success_responses: 1,
            concentration_peak_per_minute: Some(120),
            top_ten_paths_request_share: Some(0.75),
        }
    }

    #[test]
    fn severity_gate_accepts_catalog_threshold_or_independent_review_signals() {
        let mut value = SlackNotificationMetrics::default();
        assert!(should_notify(&value, None));
        assert!(!should_notify(&value, Some(CatalogSeverity::Medium)));

        value.cve_findings_by_severity.medium = 1;
        assert!(should_notify(&value, Some(CatalogSeverity::Medium)));
        value.cve_findings_by_severity.medium = 0;
        value.sigma_matches_by_severity.high = 1;
        assert!(should_notify(&value, Some(CatalogSeverity::Medium)));
        value.sigma_matches_by_severity.high = 0;
        value.cve_findings_by_severity.low = 1;
        assert!(!should_notify(&value, Some(CatalogSeverity::Medium)));

        value.unique_cisa_kevs_observed = 1;
        assert!(should_notify(&value, Some(CatalogSeverity::Critical)));
        value.unique_cisa_kevs_observed = 0;
        value.sensitive_config_probe_success_responses = 1;
        assert!(should_notify(&value, Some(CatalogSeverity::Critical)));
    }

    #[test]
    fn message_contains_only_aggregate_review_context_and_local_paths() {
        let message = build_notification_message(
            &metrics(),
            Some(SlackComparisonSummary {
                newly_observed_cves: 2,
                first_seen_entities: 3,
                elevated_paths: 4,
            }),
            Path::new("/tmp/shenron-run"),
            Some(Path::new("/tmp/shenron-run/report.html")),
        );
        for expected in [
            "CVE catalog severity: critical=0, high=1, medium=2",
            "Sigma catalog severity: critical=1, high=0, medium=0, low=3",
            "Observed CVEs (unique): 3",
            "Observed CISA KEVs: 1",
            "Sensitive file/config probe matches / 2xx response status: 5 / 1",
            "Request concentration peak/minute / top-10 path share: 120 / 75.0%",
            "Baseline delta — newly observed CVEs / first-seen entities / elevated paths: 2 / 3 / 4",
            "Aggregate review signals, not a determination of attack",
            "Severity is the source catalog's declared value",
        ] {
            assert!(message.contains(expected), "missing {expected}");
        }
        for private_value in ["198.51.100.1", "/vulnerable/execute"] {
            assert!(!message.contains(private_value));
        }
    }

    #[test]
    fn rejects_invalid_minimum_severity_and_treats_an_empty_webhook_as_disabled() {
        assert!(SlackNotificationConfig::from_values(
            Some(String::new()),
            Some("urgent".to_owned())
        )
        .is_err());
        let config = SlackNotificationConfig::from_values(Some("  ".to_owned()), None).unwrap();
        assert!(!config.is_enabled());
    }
}
