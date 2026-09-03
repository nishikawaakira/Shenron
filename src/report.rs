//! Pure, deterministic rendering of private Shenron run artifacts as a
//! self-contained HTML document.
//!
//! The renderer performs no I/O and emits no JavaScript or external resource
//! references. Every artifact-derived string is HTML-escaped before it enters
//! HTML or inline SVG. The result is private analyst output, not a sanitized
//! artifact and not a determination of attack, abuse, compromise, or identity.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::concentration::{
    MinuteRequestCount, PrivateFocusPrefixGroup, PrivateFocusSource,
    PrivateRequestConcentrationReport, PrivateSourceConcentration, StatusClassCounts,
};

pub const PRIVATE_REPORT_WARNING: &str =
    "PRIVATE — contains raw IP addresses and request paths. Do not share.";

/// Existing local run artifacts accepted by [`render_report`]. Missing
/// artifacts remain `None` and are rendered as unavailable rather than guessed.
#[derive(Debug, Default)]
pub struct ReportArtifacts {
    pub sanitized: Option<Value>,
    pub manifest: Option<Value>,
    pub concentration: Option<PrivateRequestConcentrationReport>,
    pub triage: Option<ReportTriageView>,
}

/// Deserialization view of `triage-view.json`. It remains separate from the
/// writer's static-string fields so historical JSON can be loaded as owned data.
#[derive(Debug, Default, Deserialize)]
pub struct ReportTriageView {
    #[serde(default)]
    pub entities: Vec<ReportTriageEntity>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ReportTriageEntity {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub behavior_score: ReportBehaviorScore,
    #[serde(default)]
    pub triage_basis: Option<String>,
    #[serde(default)]
    pub distinct_templates: usize,
    #[serde(default)]
    pub distinct_cves: usize,
    #[serde(default)]
    pub distinct_observations: usize,
    #[serde(default)]
    pub matching_records: usize,
    #[serde(default)]
    pub resolved_asn: Option<ReportAsn>,
    #[serde(default)]
    pub reputation: Option<ReportReputation>,
    #[serde(default)]
    pub first_seen: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct ReportBehaviorScore {
    #[serde(default)]
    pub total: u32,
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub reachable_max: u32,
}

#[derive(Debug, Deserialize)]
pub struct ReportAsn {
    pub asn: u32,
    #[serde(default)]
    pub org: String,
}

#[derive(Debug, Deserialize)]
pub struct ReportReputation {
    pub score: u32,
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub scope: String,
}

/// Escape text for either HTML or inline SVG text nodes. Attribute values in
/// this renderer are static or numeric; artifact-derived strings are emitted
/// only after passing through this function.
pub fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Render one completely self-contained private HTML report. The output is
/// deterministic for identical artifacts and parameters.
pub fn render_report(artifacts: &ReportArtifacts, limit: usize, timeline_points: usize) -> String {
    let profile = first_string(
        artifacts,
        &[
            (ArtifactKind::Manifest, "/telemetry_profile"),
            (ArtifactKind::Sanitized, "/telemetry_profile"),
        ],
    )
    .unwrap_or_else(|| "unavailable".to_owned());
    let from = first_string(
        artifacts,
        &[
            (ArtifactKind::Manifest, "/hunt_parameters/filter_from"),
            (ArtifactKind::Sanitized, "/filter_from"),
            (ArtifactKind::Sanitized, "/metrics/filter_from"),
            (ArtifactKind::Sanitized, "/metrics/earliest_timestamp"),
        ],
    )
    .unwrap_or_else(|| "unavailable".to_owned());
    let to = first_string(
        artifacts,
        &[
            (ArtifactKind::Manifest, "/hunt_parameters/filter_to"),
            (ArtifactKind::Sanitized, "/filter_to"),
            (ArtifactKind::Sanitized, "/metrics/filter_to"),
            (ArtifactKind::Sanitized, "/metrics/latest_timestamp"),
        ],
    )
    .unwrap_or_else(|| "unavailable".to_owned());
    let version = first_string(artifacts, &[(ArtifactKind::Manifest, "/shenron_version")])
        .unwrap_or_else(|| "unavailable".to_owned());
    let revision = first_string(artifacts, &[(ArtifactKind::Manifest, "/nuclei_revision")])
        .unwrap_or_else(|| "unavailable".to_owned());
    let generated_at = first_string(artifacts, &[(ArtifactKind::Manifest, "/generated_at")])
        .unwrap_or_else(|| "unavailable".to_owned());

    let mut html = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Shenron private run report</title><style>\
        :root{color-scheme:dark;--bg:#0b1020;--panel:#151d31;--muted:#a8b3c7;--text:#f4f7fb;--accent:#66d9c2;--warn:#ffcf66;--danger:#ff6b78;--line:#33415f}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}main{max-width:1240px;margin:auto;padding:24px}.private{background:#6b1320;border:2px solid var(--danger);padding:16px;font-size:18px;font-weight:800}.note,.unavailable,.cap{color:var(--muted)}.note{border-left:3px solid var(--warn);padding-left:12px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.card,section{background:var(--panel);border:1px solid var(--line);border-radius:10px}.card{padding:14px}.card b{display:block;font-size:24px}section{margin-top:18px;padding:18px}h1,h2,h3{margin-top:0}svg{width:100%;height:auto;background:#10172a;border-radius:8px}.bar{fill:var(--accent)}.axis{stroke:var(--line);stroke-width:1}.timeline{fill:none;stroke:var(--accent);stroke-width:3}.timeline-area{fill:#66d9c226;stroke:none}svg text{fill:var(--text);font:12px system-ui,sans-serif}table{width:100%;border-collapse:collapse;display:block;overflow-x:auto}th,td{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;white-space:nowrap}.score{width:120px;background:#26334f;border-radius:9px;overflow:hidden}.score span{display:block;height:10px;background:var(--accent)}code{color:#b9f4e8}.small{font-size:12px;color:var(--muted)}</style></head><body><main>",
    );
    html.push_str(&format!(
        "<div class=\"private\">{}</div><h1>Shenron private run report</h1>\
         <p class=\"note\">This report visualizes observed access volume and triage context. It is not a determination of a denial-of-service attempt, attack, exploitation, abuse, compromise, or attacker identity. First-seen means review, not malicious.</p>\
         <section><h2>Provenance</h2><div class=\"grid\">{}{}{}{}{}{}</div></section>",
        PRIVATE_REPORT_WARNING,
        card("Telemetry profile", &profile),
        card("Time range start (UTC)", &from),
        card("Time range end (UTC)", &to),
        card("Shenron version", &version),
        card("Nuclei revision", &revision),
        card("Run generated at", &generated_at),
    ));

    render_summary(&mut html, artifacts);
    render_concentration(
        &mut html,
        artifacts.concentration.as_ref(),
        limit,
        timeline_points,
    );
    render_triage(&mut html, artifacts.triage.as_ref(), limit);
    html.push_str("</main></body></html>");
    html
}

fn render_summary(html: &mut String, artifacts: &ReportArtifacts) {
    html.push_str("<section><h2>Aggregate summary</h2>");
    if artifacts.sanitized.is_none() && artifacts.concentration.is_none() {
        html.push_str("<p class=\"unavailable\">Aggregate summary unavailable: sanitized-research.json and request-concentration.json were not found.</p></section>");
        return;
    }
    let total = artifacts
        .concentration
        .as_ref()
        .map(|value| value.summary.total_requests)
        .or_else(|| {
            first_u64(
                artifacts,
                &[
                    "/total_requests_analyzed",
                    "/metrics/total_requests_analyzed",
                ],
            )
        });
    let paths = artifacts
        .concentration
        .as_ref()
        .map(|value| value.summary.distinct_uri_paths as u64);
    let source_ips = artifacts
        .concentration
        .as_ref()
        .map(|value| value.summary.distinct_source_ips as u64);
    let cves = first_u64(artifacts, &["/metrics/unique_cves_observed"]).or_else(|| {
        artifacts
            .sanitized
            .as_ref()
            .and_then(|value| value.pointer("/cve_findings"))
            .and_then(Value::as_array)
            .map(|values| values.len() as u64)
    });
    let triage_entities = artifacts
        .triage
        .as_ref()
        .map(|view| view.entities.len() as u64);
    html.push_str("<div class=\"grid\">");
    for (label, value) in [
        ("Requests", optional_number(total)),
        ("Distinct paths", optional_number(paths)),
        ("Distinct observed peers", optional_number(source_ips)),
        ("Observed CVEs", optional_number(cves)),
        ("Triage entities", optional_number(triage_entities)),
    ] {
        html.push_str(&card(label, &value));
    }
    html.push_str("</div>");
    if let Some(view) = &artifacts.triage {
        let mut tiers = BTreeMap::<&str, usize>::new();
        for entity in &view.entities {
            *tiers
                .entry(entity.behavior_score.tier.as_str())
                .or_default() += 1;
        }
        html.push_str(&format!(
            "<p class=\"small\">Behavior-priority tiers (not threat severity): info={}, low={}, medium={}, high={}.</p>",
            tiers.get("info").copied().unwrap_or_default(),
            tiers.get("low").copied().unwrap_or_default(),
            tiers.get("medium").copied().unwrap_or_default(),
            tiers.get("high").copied().unwrap_or_default(),
        ));
    }
    html.push_str("</section>");
}

fn render_concentration(
    html: &mut String,
    concentration: Option<&PrivateRequestConcentrationReport>,
    limit: usize,
    timeline_points: usize,
) {
    html.push_str("<section><h2>Request concentration</h2><p class=\"note\">These are observed access counts and concentration only, not a denial-of-service, attack, exploitation, abuse, compromise, or attribution determination. Source IPs are observed connection peers and may be a CDN, load balancer, NAT, or proxy; they are not attacker attribution.</p>");
    let Some(concentration) = concentration else {
        html.push_str("<p class=\"unavailable\">Concentration unavailable: request-concentration.json was not found.</p></section>");
        return;
    };

    html.push_str("<h3>Top paths</h3>");
    let path_rows = limited(&concentration.paths, limit)
        .iter()
        .map(|path| BarRow {
            label: path.uri_path.as_str(),
            value: path.summary.requests,
            details: format!(
                "{:.1}% · {} peers · {}",
                path.summary.request_share * 100.0,
                path.summary.distinct_source_ips,
                status_details(&path.summary.response_status_classes),
            ),
        })
        .collect::<Vec<_>>();
    html.push_str(&bar_chart("Top request paths", &path_rows));
    omitted(html, concentration.paths.len(), path_rows.len(), "paths");

    html.push_str("<h3>Top observed connection peers</h3>");
    let source_rows = source_rows(&concentration.source_ips, limit);
    html.push_str(&bar_chart("Top observed connection peers", &source_rows));
    omitted(
        html,
        concentration.source_ips.len(),
        source_rows.len(),
        "peer addresses",
    );

    html.push_str("<h3>Requests per minute</h3>");
    html.push_str(&timeline_chart(
        "Global request timeline",
        &concentration.requests_per_minute_series,
        timeline_points,
    ));
    cap_note(
        html,
        concentration.minute_buckets_beyond_cap,
        "global records in new minute buckets",
    );
    render_general_caps(html, concentration);

    if let Some(focus) = &concentration.focus {
        html.push_str(&format!(
            "<h2>Focused path</h2><p><code>{}</code> — {} requests from {} retained observed peers.</p>",
            html_escape(&focus.uri_path),
            focus.total_requests,
            focus.distinct_source_ips,
        ));
        html.push_str("<h3>Focused-path peers</h3>");
        let rows = focus_source_rows(&focus.sources, limit);
        html.push_str(&bar_chart("Focused-path observed peers", &rows));
        omitted(
            html,
            focus.sources.len(),
            rows.len(),
            "focused peer addresses",
        );

        html.push_str("<h3>Focused-path network prefixes</h3><p class=\"note\">Addresses are grouped by network prefix only. A shared prefix is not evidence of a shared operator, owner, or actor: allocations can be split across tenants and one operator can span many prefixes.</p>");
        let prefix_rows = prefix_rows(&focus.network_prefix_groups, limit);
        html.push_str(&bar_chart("Focused-path network prefixes", &prefix_rows));
        omitted(
            html,
            focus.network_prefix_groups.len(),
            prefix_rows.len(),
            "network prefixes",
        );

        html.push_str("<h3>Focused-path requests per minute</h3>");
        html.push_str(&timeline_chart(
            "Focused-path request timeline",
            &focus.requests_per_minute_series,
            timeline_points,
        ));
        cap_note(
            html,
            focus.minute_buckets_beyond_cap,
            "focused-path records in new minute buckets",
        );
        cap_note(
            html,
            focus.source_ips_beyond_cap,
            "focused-path requests from new peer addresses",
        );
    }
    html.push_str("</section>");
}

fn render_triage(html: &mut String, triage: Option<&ReportTriageView>, limit: usize) {
    html.push_str("<section><h2>Hunt triage view</h2><p class=\"note\">Behavior score is a human-review priority, not threat severity or a probability of malice. First-seen means review, not malicious. Entity keys can be observed peers rather than end clients and do not establish an attacker identity.</p>");
    let Some(triage) = triage else {
        html.push_str("<p class=\"unavailable\">Triage unavailable: triage-view.json was not found.</p></section>");
        return;
    };
    let entities = limited(&triage.entities, limit);
    if entities.is_empty() {
        html.push_str("<p class=\"unavailable\">No triage entities were recorded.</p></section>");
        return;
    }
    html.push_str("<table><thead><tr><th>Entity</th><th>Identity</th><th>Behavior priority</th><th>Basis</th><th>Observed breadth</th><th>Reputation opinion</th><th>Resolved ASN</th><th>First-seen</th></tr></thead><tbody>");
    for entity in entities {
        let score = entity.behavior_score.total.min(100);
        let basis = entity.triage_basis.as_deref().unwrap_or("none");
        let reputation = entity.reputation.as_ref().map_or_else(
            || "unavailable".to_owned(),
            |value| format!("{}/100 {} ({})", value.score, value.tier, value.scope),
        );
        let asn = entity.resolved_asn.as_ref().map_or_else(
            || "unavailable".to_owned(),
            |value| format!("AS{} {}", value.asn, value.org),
        );
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}/100 {}<div class=\"score\"><span style=\"width:{}%\"></span></div><span class=\"small\">reachable max {}</span></td><td>{}</td><td>{} observations / {} templates / {} CVEs<br><span class=\"small\">{} matching records</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&entity.key),
            html_escape(&entity.identity),
            entity.behavior_score.total,
            html_escape(&entity.behavior_score.tier),
            score,
            entity.behavior_score.reachable_max,
            html_escape(basis),
            entity.distinct_observations,
            entity.distinct_templates,
            entity.distinct_cves,
            entity.matching_records,
            html_escape(&reputation),
            html_escape(&asn),
            if entity.first_seen { "yes — review" } else { "no" },
        ));
    }
    html.push_str("</tbody></table>");
    omitted(
        html,
        triage.entities.len(),
        entities.len(),
        "triage entities",
    );
    html.push_str("</section>");
}

struct BarRow<'a> {
    label: &'a str,
    value: u64,
    details: String,
}

fn bar_chart(title: &str, rows: &[BarRow<'_>]) -> String {
    if rows.is_empty() {
        return "<p class=\"unavailable\">unavailable</p>".to_owned();
    }
    let maximum = rows.iter().map(|row| row.value).max().unwrap_or(1).max(1);
    let height = rows.len() * 42 + 16;
    let mut svg = format!(
        "<svg viewBox=\"0 0 1000 {height}\" role=\"img\" aria-label=\"{}\">",
        html_escape(title)
    );
    for (index, row) in rows.iter().enumerate() {
        let y = index * 42 + 8;
        let width = row.value as f64 / maximum as f64 * 500.0;
        svg.push_str(&format!(
            "<text x=\"8\" y=\"{}\">{}</text><rect class=\"bar\" x=\"300\" y=\"{}\" width=\"{:.2}\" height=\"14\"></rect><text x=\"{}\" y=\"{}\">{} · {}</text>",
            y + 12,
            html_escape(row.label),
            y,
            width,
            310.0 + width,
            y + 12,
            row.value,
            html_escape(&row.details),
        ));
    }
    svg.push_str("</svg>");
    svg
}

fn timeline_chart(title: &str, series: &[MinuteRequestCount], maximum_points: usize) -> String {
    let points = downsample_timeline(series, maximum_points.max(1));
    if points.is_empty() {
        return "<p class=\"unavailable\">Timeline unavailable: no retained timestamped minute buckets.</p>".to_owned();
    }
    let first = points
        .first()
        .expect("checked non-empty timeline")
        .minute_epoch;
    let last = points
        .last()
        .expect("checked non-empty timeline")
        .minute_epoch;
    let peak = points
        .iter()
        .map(|point| point.requests)
        .max()
        .unwrap_or(1)
        .max(1);
    let span = (last as i128 - first as i128).max(1) as f64;
    let coordinates = points
        .iter()
        .map(|point| {
            let x = 60.0 + (point.minute_epoch as i128 - first as i128) as f64 / span * 880.0;
            let y = 180.0 - point.requests as f64 / peak as f64 * 145.0;
            format!("{x:.2},{y:.2}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    let area = format!("60,180 {coordinates} 940,180");
    format!(
        "<svg viewBox=\"0 0 1000 220\" role=\"img\" aria-label=\"{}\"><line class=\"axis\" x1=\"60\" y1=\"180\" x2=\"940\" y2=\"180\"></line><line class=\"axis\" x1=\"60\" y1=\"35\" x2=\"60\" y2=\"180\"></line><polygon class=\"timeline-area\" points=\"{}\"></polygon><polyline class=\"timeline\" points=\"{}\"></polyline><text x=\"60\" y=\"205\">{}</text><text x=\"760\" y=\"205\">{}</text><text x=\"65\" y=\"30\">peak {}</text></svg><p class=\"small\">{} retained/downsampled points; UTC. Downsampling sums deterministic equal-width minute spans.</p>",
        html_escape(title),
        area,
        coordinates,
        html_escape(&minute_label(first)),
        html_escape(&minute_label(last)),
        peak,
        points.len(),
    )
}

fn downsample_timeline(
    series: &[MinuteRequestCount],
    maximum_points: usize,
) -> Vec<MinuteRequestCount> {
    let mut minutes = BTreeMap::<i64, u64>::new();
    for point in series {
        let requests = minutes.entry(point.minute_epoch).or_default();
        *requests = requests.saturating_add(point.requests);
    }
    let Some((&first, _)) = minutes.first_key_value() else {
        return Vec::new();
    };
    let last = *minutes
        .last_key_value()
        .expect("checked non-empty series")
        .0;
    let span = last as i128 - first as i128 + 1;
    let maximum_points = maximum_points.max(1) as i128;
    let width = ((span + maximum_points - 1) / maximum_points).max(1);
    let mut buckets = BTreeMap::<i128, u64>::new();
    for (minute, requests) in minutes {
        let index = (minute as i128 - first as i128) / width;
        let value = buckets.entry(index).or_default();
        *value = value.saturating_add(requests);
    }
    buckets
        .into_iter()
        .map(|(index, requests)| {
            let minute = first as i128 + index * width;
            MinuteRequestCount {
                minute_epoch: minute.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
                requests,
            }
        })
        .collect()
}

fn minute_label(minute_epoch: i64) -> String {
    minute_epoch
        .checked_mul(60)
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| format!("epoch minute {minute_epoch}"))
}

fn source_rows<'a>(sources: &'a [PrivateSourceConcentration], limit: usize) -> Vec<BarRow<'a>> {
    limited(sources, limit)
        .iter()
        .map(|source| BarRow {
            label: source.source_ip.as_str(),
            value: source.requests,
            details: "requests".to_owned(),
        })
        .collect()
}

fn focus_source_rows<'a>(sources: &'a [PrivateFocusSource], limit: usize) -> Vec<BarRow<'a>> {
    limited(sources, limit)
        .iter()
        .map(|source| BarRow {
            label: source.source_ip.as_str(),
            value: source.requests,
            details: "requests".to_owned(),
        })
        .collect()
}

fn prefix_rows<'a>(groups: &'a [PrivateFocusPrefixGroup], limit: usize) -> Vec<BarRow<'a>> {
    limited(groups, limit)
        .iter()
        .map(|group| BarRow {
            label: group.network_prefix.as_str(),
            value: group.requests,
            details: format!(
                "{:.1}% · {} retained peers",
                group.request_share * 100.0,
                group.distinct_source_ips
            ),
        })
        .collect()
}

fn render_general_caps(html: &mut String, report: &PrivateRequestConcentrationReport) {
    for (count, label) in [
        (
            report.summary.paths_beyond_tracking_cap,
            "requests on new paths",
        ),
        (
            report.summary.source_ips_beyond_tracking_cap,
            "requests from new peer addresses",
        ),
        (
            report.summary.source_path_pairs_beyond_tracking_cap,
            "new peer/path associations",
        ),
    ] {
        cap_note(html, count, label);
    }
}

fn cap_note(html: &mut String, count: u64, label: &str) {
    if count != 0 {
        html.push_str(&format!(
            "<p class=\"cap\">Tracking cap disclosure: {} {} were not admitted.</p>",
            count,
            html_escape(label),
        ));
    }
}

fn status_details(counts: &StatusClassCounts) -> String {
    format!(
        "status 1xx:{} 2xx:{} 3xx:{} 4xx:{} 5xx:{} other:{} unavailable:{}",
        counts.informational,
        counts.success,
        counts.redirection,
        counts.client_error,
        counts.server_error,
        counts.other,
        counts.unavailable,
    )
}

fn card(label: &str, value: &str) -> String {
    format!(
        "<div class=\"card\"><span>{}</span><b>{}</b></div>",
        html_escape(label),
        html_escape(value),
    )
}

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn limited<T>(values: &[T], limit: usize) -> &[T] {
    if limit == 0 {
        values
    } else {
        &values[..values.len().min(limit)]
    }
}

fn omitted(html: &mut String, total: usize, displayed: usize, label: &str) {
    if total > displayed {
        html.push_str(&format!(
            "<p class=\"small\">{} additional {} omitted by the report limit.</p>",
            total - displayed,
            html_escape(label),
        ));
    }
}

#[derive(Clone, Copy)]
enum ArtifactKind {
    Sanitized,
    Manifest,
}

fn first_string(artifacts: &ReportArtifacts, paths: &[(ArtifactKind, &str)]) -> Option<String> {
    paths.iter().find_map(|(kind, path)| {
        artifact_value(artifacts, *kind)
            .and_then(|value| value.pointer(path))
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
}

fn first_u64(artifacts: &ReportArtifacts, paths: &[&str]) -> Option<u64> {
    paths.iter().find_map(|path| {
        artifacts
            .sanitized
            .as_ref()
            .and_then(|value| value.pointer(path))
            .and_then(Value::as_u64)
    })
}

fn artifact_value(artifacts: &ReportArtifacts, kind: ArtifactKind) -> Option<&Value> {
    match kind {
        ArtifactKind::Sanitized => artifacts.sanitized.as_ref(),
        ArtifactKind::Manifest => artifacts.manifest.as_ref(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concentration::{
        PathConcentrationSummary, PrivateFocusSummary, PrivatePathConcentration,
        PrivateRequestConcentrationReport, RequestConcentrationSummary, RequestRateSummary,
        SanitizedFocusSummary,
    };

    fn synthetic_concentration(path: &str) -> PrivateRequestConcentrationReport {
        let status = StatusClassCounts {
            success: 2,
            client_error: 1,
            ..StatusClassCounts::default()
        };
        PrivateRequestConcentrationReport {
            report_kind: "REQUEST_CONCENTRATION_PRIVATE".to_owned(),
            safety_note: String::new(),
            summary: RequestConcentrationSummary {
                total_requests: 3,
                distinct_uri_paths: 1,
                distinct_source_ips: 1,
                requests_without_uri_path: 0,
                requests_without_source_ip: 0,
                paths_beyond_tracking_cap: 0,
                source_ips_beyond_tracking_cap: 0,
                source_path_pairs_beyond_tracking_cap: 0,
                top_path: None,
                top_ten_paths_request_share: 1.0,
                top_ten_source_ips_request_share: 1.0,
                requests_per_minute: RequestRateSummary {
                    peak_requests_per_minute: Some(2),
                    median_requests_per_minute: Some(1.5),
                    peak_to_median_ratio: Some(4.0 / 3.0),
                    observations_without_timestamp: 0,
                },
                focus: Some(SanitizedFocusSummary {
                    total_requests: 3,
                    distinct_source_ips: 1,
                    source_ips_beyond_cap: 0,
                    peak_requests_per_minute: Some(2),
                    median_requests_per_minute: Some(1.5),
                }),
            },
            paths: vec![PrivatePathConcentration {
                uri_path: path.to_owned(),
                summary: PathConcentrationSummary {
                    requests: 3,
                    request_share: 1.0,
                    distinct_source_ips: 1,
                    response_status_classes: status.clone(),
                    response_bytes: Some(30),
                },
            }],
            source_ips: vec![PrivateSourceConcentration {
                source_ip: "198.51.100.1".to_owned(),
                requests: 3,
                most_requested_uri_path: Some(path.to_owned()),
            }],
            focus: Some(PrivateFocusSummary {
                uri_path: path.to_owned(),
                total_requests: 3,
                distinct_source_ips: 1,
                source_ips_beyond_cap: 0,
                peak_requests_per_minute: Some(2),
                median_requests_per_minute: Some(1.5),
                response_status_classes: status,
                sources: vec![PrivateFocusSource {
                    source_ip: "198.51.100.1".to_owned(),
                    requests: 3,
                }],
                network_prefix_groups: vec![PrivateFocusPrefixGroup {
                    network_prefix: "198.51.100.0/24".to_owned(),
                    requests: 3,
                    request_share: 1.0,
                    distinct_source_ips: 1,
                }],
                requests_per_minute_series: vec![
                    MinuteRequestCount {
                        minute_epoch: 0,
                        requests: 1,
                    },
                    MinuteRequestCount {
                        minute_epoch: 1,
                        requests: 2,
                    },
                ],
                minute_buckets_beyond_cap: 0,
            }),
            requests_per_minute_series: vec![
                MinuteRequestCount {
                    minute_epoch: 0,
                    requests: 1,
                },
                MinuteRequestCount {
                    minute_epoch: 1,
                    requests: 2,
                },
            ],
            minute_buckets_beyond_cap: 0,
        }
    }

    #[test]
    fn renders_expected_private_sections_and_escapes_artifact_values() {
        let artifacts = ReportArtifacts {
            sanitized: Some(serde_json::json!({
                "metrics": {"total_requests_analyzed": 3, "unique_cves_observed": 1}
            })),
            manifest: Some(serde_json::json!({
                "shenron_version": "0.1.0",
                "telemetry_profile": "aws-waf",
                "nuclei_revision": "fixture"
            })),
            concentration: Some(synthetic_concentration("/x?<script>alert(1)</script>&\"'")),
            triage: Some(ReportTriageView {
                entities: vec![ReportTriageEntity {
                    key: "198.51.100.1".to_owned(),
                    identity: "observed-peer".to_owned(),
                    behavior_score: ReportBehaviorScore {
                        total: 50,
                        tier: "medium".to_owned(),
                        reachable_max: 100,
                    },
                    distinct_templates: 2,
                    distinct_cves: 1,
                    distinct_observations: 3,
                    matching_records: 3,
                    ..ReportTriageEntity::default()
                }],
            }),
        };
        let html = render_report(&artifacts, 20, 240);
        for section in [
            "Top paths",
            "Top observed connection peers",
            "Requests per minute",
            "Hunt triage view",
        ] {
            assert!(html.contains(section));
        }
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;&quot;&#39;"));
        for forbidden in ["http://", "https://", "src=", "<script src"] {
            assert!(
                !html.contains(forbidden),
                "found external reference marker {forbidden}"
            );
        }
    }

    #[test]
    fn renders_missing_artifacts_as_unavailable_without_panicking() {
        let html = render_report(&ReportArtifacts::default(), 20, 240);
        assert!(html.contains(PRIVATE_REPORT_WARNING));
        assert!(html.contains("Aggregate summary unavailable"));
        assert!(html.contains("Concentration unavailable"));
        assert!(html.contains("Triage unavailable"));
    }

    #[test]
    fn downsampling_is_bounded_and_sums_equal_width_minute_spans() {
        let series = (0..10)
            .map(|minute_epoch| MinuteRequestCount {
                minute_epoch,
                requests: 1,
            })
            .collect::<Vec<_>>();
        let sampled = downsample_timeline(&series, 3);
        assert_eq!(sampled.len(), 3);
        assert_eq!(sampled.iter().map(|point| point.requests).sum::<u64>(), 10);
        assert_eq!(sampled[0].minute_epoch, 0);
        assert_eq!(sampled[1].minute_epoch, 4);
        assert_eq!(sampled[2].minute_epoch, 8);
    }

    #[test]
    fn status_details_is_numeric_and_deterministic() {
        assert!(status_details(&StatusClassCounts::default()).contains("status 1xx:0"));
    }
}
