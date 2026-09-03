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
    MinuteRequestCount, PrivateFocusPath, PrivateFocusPrefixGroup, PrivateFocusSource,
    PrivateRequestConcentrationReport, PrivateSourceConcentration, StatusClassCounts,
    StatusClassMinuteCount,
};

pub const PRIVATE_REPORT_WARNING: &str =
    "PRIVATE — contains raw IP addresses and request paths. Do not share.";

/// Human-readable language used by the private HTML report. Artifact values
/// are never translated and remain escaped verbatim.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportLanguage {
    #[default]
    En,
    Ja,
}

impl ReportLanguage {
    pub const fn html_lang(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ja => "ja",
        }
    }

    pub const fn private_warning(self) -> &'static str {
        match self {
            Self::En => PRIVATE_REPORT_WARNING,
            Self::Ja => {
                "PRIVATE — 生の IP アドレスとリクエストパスを含みます。共有しないでください。"
            }
        }
    }

    const fn labels(self) -> &'static Labels {
        match self {
            Self::En => &EN_LABELS,
            Self::Ja => &JA_LABELS,
        }
    }
}

struct Labels {
    title: &'static str,
    overall_note: &'static str,
    provenance: &'static str,
    telemetry_profile: &'static str,
    time_start: &'static str,
    time_end: &'static str,
    shenron_version: &'static str,
    nuclei_revision: &'static str,
    run_generated_at: &'static str,
    aggregate_summary: &'static str,
    aggregate_unavailable: &'static str,
    requests: &'static str,
    distinct_paths: &'static str,
    distinct_peers: &'static str,
    observed_cves: &'static str,
    sensitive_success_heading: &'static str,
    sensitive_success_note: &'static str,
    sensitive_path: &'static str,
    sensitive_observed_peer: &'static str,
    sensitive_response_status: &'static str,
    sensitive_timestamp: &'static str,
    sensitive_records: &'static str,
    cve_list_heading: &'static str,
    cve_list_note: &'static str,
    cve_id: &'static str,
    cve_templates: &'static str,
    kev_membership: &'static str,
    kev_badge: &'static str,
    detectability: &'static str,
    distinctive_matches: &'static str,
    generic_matches: &'static str,
    cve_first_seen: &'static str,
    last_seen: &'static str,
    protection_gap_rate: &'static str,
    triage_entities: &'static str,
    tier_summary: &'static str,
    concentration: &'static str,
    concentration_note: &'static str,
    concentration_unavailable: &'static str,
    top_paths: &'static str,
    top_request_paths: &'static str,
    top_peers: &'static str,
    top_observed_peers: &'static str,
    requests_per_minute: &'static str,
    global_timeline: &'static str,
    status_requests_per_minute: &'static str,
    status_timeline: &'static str,
    status_timeline_note: &'static str,
    status_informational: &'static str,
    status_success: &'static str,
    status_redirection: &'static str,
    status_client_error: &'static str,
    status_server_error: &'static str,
    focused_path: &'static str,
    focused_source_ip: &'static str,
    focused_paths_chart: &'static str,
    focused_paths_label: &'static str,
    focused_peers: &'static str,
    focused_peer_chart: &'static str,
    focused_prefixes: &'static str,
    prefix_note: &'static str,
    focused_prefix_chart: &'static str,
    focused_requests_per_minute: &'static str,
    focused_timeline: &'static str,
    triage: &'static str,
    triage_note: &'static str,
    triage_unavailable: &'static str,
    no_triage: &'static str,
    entity: &'static str,
    identity: &'static str,
    behavior_priority: &'static str,
    basis: &'static str,
    observed_breadth: &'static str,
    reputation: &'static str,
    resolved_asn: &'static str,
    first_seen: &'static str,
    unavailable: &'static str,
    not_applicable: &'static str,
    time_range_observed: &'static str,
    none: &'static str,
    reachable_max: &'static str,
    observations: &'static str,
    templates: &'static str,
    cves: &'static str,
    matching_records: &'static str,
    yes_review: &'static str,
    no: &'static str,
    timeline_unavailable: &'static str,
    epoch_minute: &'static str,
    peak: &'static str,
    timeline_footer: &'static str,
    request_count_label: &'static str,
    retained_peers: &'static str,
    status: &'static str,
    other: &'static str,
    status_unavailable: &'static str,
    cap_disclosure: &'static str,
    cap_not_admitted: &'static str,
    paths: &'static str,
    peer_addresses: &'static str,
    focused_peer_addresses: &'static str,
    network_prefixes: &'static str,
    global_minute_records: &'static str,
    focused_minute_records: &'static str,
    focused_new_peer_requests: &'static str,
    new_path_requests: &'static str,
    new_peer_requests: &'static str,
    new_peer_path_pairs: &'static str,
    omitted_suffix: &'static str,
}

const EN_LABELS: Labels = Labels {
    title: "Shenron private run report",
    overall_note: "This report visualizes observed access volume and triage context. It is not a determination of a denial-of-service attempt, attack, exploitation, abuse, compromise, malicious probability, or attacker identity. First-seen means review, not malicious.",
    provenance: "Provenance",
    telemetry_profile: "Telemetry profile",
    time_start: "Time range start (UTC)",
    time_end: "Time range end (UTC)",
    shenron_version: "Shenron version",
    nuclei_revision: "Nuclei revision",
    run_generated_at: "Run generated at",
    aggregate_summary: "Aggregate summary",
    aggregate_unavailable: "Aggregate summary unavailable: sanitized-research.json and request-concentration.json were not found.",
    requests: "Requests",
    distinct_paths: "Distinct paths",
    distinct_peers: "Distinct observed peers",
    observed_cves: "Observed CVEs",
    sensitive_success_heading: "Sensitive file/config access with a success response",
    sensitive_success_note: "A 2xx is the response status only; it does not confirm that file contents were disclosed or that attack, exploitation, or compromise occurred. Review these records with highest priority. An observed peer may be a CDN, load balancer, NAT, or proxy and is not attacker attribution.",
    sensitive_path: "Request path",
    sensitive_observed_peer: "Observed connection peer",
    sensitive_response_status: "Response status",
    sensitive_timestamp: "Timestamp",
    sensitive_records: "sensitive file/config 2xx records",
    cve_list_heading: "Observed CVEs",
    cve_list_note: "Nuclei template IDs are public CTI metadata. Template IDs, KEV membership, and detectability are catalog facts, not an exploitation, compromise, or attacker-identity determination. Request counts are observed matcher volume, not proof of exploitation.",
    cve_id: "CVE ID",
    cve_templates: "Templates",
    kev_membership: "CISA KEV",
    kev_badge: "KEV",
    detectability: "Detectability",
    distinctive_matches: "Distinctive-path matches",
    generic_matches: "Generic-path matches",
    cve_first_seen: "First-seen",
    last_seen: "Last-seen",
    protection_gap_rate: "Protection-gap rate",
    triage_entities: "Triage entities",
    tier_summary: "Behavior-priority tiers (not threat severity)",
    concentration: "Request concentration",
    concentration_note: "These are observed access counts and concentration only, not a denial-of-service, attack, exploitation, abuse, compromise, or attribution determination. Source IPs are observed connection peers and may be a CDN, load balancer, NAT, or proxy; they are not attacker attribution.",
    concentration_unavailable: "Concentration unavailable: request-concentration.json was not found.",
    top_paths: "Top paths",
    top_request_paths: "Top request paths",
    top_peers: "Top observed connection peers",
    top_observed_peers: "Top observed connection peers",
    requests_per_minute: "Requests per minute",
    global_timeline: "Global request timeline",
    status_requests_per_minute: "Requests per minute by HTTP status class",
    status_timeline: "HTTP status-class request timeline",
    status_timeline_note: "HTTP status classes are response outcomes, not a determination of attack, exploitation, or compromise. Other or unavailable status values are not plotted.",
    status_informational: "Informational",
    status_success: "Success",
    status_redirection: "Redirection",
    status_client_error: "Client error",
    status_server_error: "Server error",
    focused_path: "Focused path",
    focused_source_ip: "Focused source IP",
    focused_paths_chart: "URI paths in focus",
    focused_paths_label: "focused URI paths",
    focused_peers: "Focused-path peers",
    focused_peer_chart: "Focused-path observed peers",
    focused_prefixes: "Focused-path network prefixes",
    prefix_note: "Addresses are grouped by network prefix only. A shared prefix is not evidence of a shared operator, owner, or actor: allocations can be split across tenants and one operator can span many prefixes.",
    focused_prefix_chart: "Focused-path network prefixes",
    focused_requests_per_minute: "Focused-path requests per minute",
    focused_timeline: "Focused-path request timeline",
    triage: "Hunt triage view",
    triage_note: "Behavior score is a human-review priority, not threat severity or a probability of malice. First-seen means review, not malicious. Entity keys can be observed peers rather than end clients and do not establish an attacker identity.",
    triage_unavailable: "Triage unavailable: triage-view.json was not found.",
    no_triage: "No triage entities were recorded.",
    entity: "Entity",
    identity: "Identity",
    behavior_priority: "Behavior priority",
    basis: "Basis",
    observed_breadth: "Observed breadth",
    reputation: "Reputation opinion",
    resolved_asn: "Resolved ASN",
    first_seen: "First-seen",
    unavailable: "unavailable",
    not_applicable: "not applicable (no CVE pass)",
    time_range_observed: "Time range is the observed span of retained minute buckets, not a requested filter.",
    none: "none",
    reachable_max: "reachable max",
    observations: "observations",
    templates: "templates",
    cves: "CVEs",
    matching_records: "matching records",
    yes_review: "yes — review",
    no: "no",
    timeline_unavailable: "Timeline unavailable: no retained timestamped minute buckets. Re-run hunt or concentration with the current build to generate the timeline series.",
    epoch_minute: "epoch minute",
    peak: "peak",
    timeline_footer: "retained/downsampled points; UTC. Downsampling sums deterministic equal-width minute spans.",
    request_count_label: "requests",
    retained_peers: "retained peers",
    status: "status",
    other: "other",
    status_unavailable: "unavailable",
    cap_disclosure: "Tracking cap disclosure",
    cap_not_admitted: "were not admitted.",
    paths: "paths",
    peer_addresses: "peer addresses",
    focused_peer_addresses: "focused peer addresses",
    network_prefixes: "network prefixes",
    global_minute_records: "global records in new minute buckets",
    focused_minute_records: "focused-path records in new minute buckets",
    focused_new_peer_requests: "focused-path requests from new peer addresses",
    new_path_requests: "requests on new paths",
    new_peer_requests: "requests from new peer addresses",
    new_peer_path_pairs: "new peer/path associations",
    omitted_suffix: "omitted by the report limit.",
};

const JA_LABELS: Labels = Labels {
    title: "Shenron プライベート実行レポート",
    overall_note: "これはアクセス量とトリアージ状況の可視化であり、DoS・攻撃・悪用・侵害・悪性確率・攻撃者特定の判定ではありません。first-seen は要確認を意味し、悪性を意味しません。",
    provenance: "出自情報",
    telemetry_profile: "テレメトリプロファイル",
    time_start: "期間開始 (UTC)",
    time_end: "期間終了 (UTC)",
    shenron_version: "Shenron バージョン",
    nuclei_revision: "Nuclei リビジョン",
    run_generated_at: "実行成果物の生成日時",
    aggregate_summary: "集計サマリ",
    aggregate_unavailable: "集計サマリを利用できません。sanitized-research.json と request-concentration.json が見つかりません。",
    requests: "リクエスト数",
    distinct_paths: "異なるパス数",
    distinct_peers: "異なる観測接続ピア数",
    observed_cves: "観測された CVE 数",
    sensitive_success_heading: "成功応答を返した秘密・設定ファイルアクセス",
    sensitive_success_note: "2xx は応答ステータスのみを示し、ファイル内容の開示や攻撃・悪用・侵害を断定するものではありません。最優先で人手確認してください。観測接続ピアは CDN・ロードバランサ・NAT・プロキシの場合があり、攻撃者帰属ではありません。",
    sensitive_path: "リクエストパス",
    sensitive_observed_peer: "観測接続ピア",
    sensitive_response_status: "応答ステータス",
    sensitive_timestamp: "時刻",
    sensitive_records: "秘密・設定ファイルの 2xx レコード",
    cve_list_heading: "観測された CVE",
    cve_list_note: "Nuclei テンプレート ID は公開 CTI メタデータです。テンプレート ID・KEV 該否・detectability はカタログ上の情報であり、悪用・侵害・攻撃者特定の判定ではありません。リクエスト件数は観測されたマッチ量であり、悪用の証明ではありません。",
    cve_id: "CVE ID",
    cve_templates: "テンプレート",
    kev_membership: "CISA KEV",
    kev_badge: "KEV",
    detectability: "検知可能性",
    distinctive_matches: "distinctive-path 一致数",
    generic_matches: "generic-path 一致数",
    cve_first_seen: "初回観測",
    last_seen: "最終観測",
    protection_gap_rate: "保護ギャップ率",
    triage_entities: "トリアージ対象数",
    tier_summary: "挙動優先度 tier（脅威の深刻度ではありません）",
    concentration: "リクエスト集中度",
    concentration_note: "これは観測されたアクセス件数と集中度の表示であり、DoS・攻撃・悪用・侵害・攻撃者特定の判定ではありません。送信元 IP は観測された接続ピアであり、CDN・ロードバランサ・NAT・プロキシの場合があります。攻撃者帰属を示しません。",
    concentration_unavailable: "集中度を利用できません。request-concentration.json が見つかりません。",
    top_paths: "上位パス",
    top_request_paths: "上位リクエストパス",
    top_peers: "上位の観測接続ピア",
    top_observed_peers: "上位の観測接続ピア",
    requests_per_minute: "1分ごとのリクエスト数",
    global_timeline: "全体リクエスト時系列",
    status_requests_per_minute: "HTTP ステータスクラス別 1分ごとのリクエスト数",
    status_timeline: "HTTP ステータスクラス別リクエスト時系列",
    status_timeline_note: "HTTP ステータスクラスはレスポンス結果であり、攻撃・悪用・侵害の判定ではありません。その他または利用不可のステータス値は描画しません。",
    status_informational: "情報",
    status_success: "成功",
    status_redirection: "リダイレクト",
    status_client_error: "クライアントエラー",
    status_server_error: "サーバーエラー",
    focused_path: "フォーカスパス",
    focused_source_ip: "フォーカス送信元 IP",
    focused_paths_chart: "フォーカス内の URI パス",
    focused_paths_label: "フォーカス URI パス",
    focused_peers: "フォーカスパスの接続ピア",
    focused_peer_chart: "フォーカスパスの観測接続ピア",
    focused_prefixes: "フォーカスパスのネットワークプレフィックス",
    prefix_note: "アドレスはネットワークプレフィックスだけで集約しています。同じプレフィックスであることは、同じ運用者・所有者・主体の証拠ではありません。割り当ては複数テナントに分かれることがあり、1つの運用者が複数プレフィックスを使用することもあります。",
    focused_prefix_chart: "フォーカスパスのネットワークプレフィックス",
    focused_requests_per_minute: "フォーカスパスの1分ごとのリクエスト数",
    focused_timeline: "フォーカスパスのリクエスト時系列",
    triage: "hunt トリアージビュー",
    triage_note: "behavior score は人手確認の優先順位であり、脅威度や悪性確率ではありません。first-seen は要確認を意味し、悪性を意味しません。エンティティキーは末端クライアントではなく観測接続ピアの場合があり、攻撃者特定を示しません。",
    triage_unavailable: "トリアージを利用できません。triage-view.json が見つかりません。",
    no_triage: "トリアージ対象は記録されていません。",
    entity: "エンティティ",
    identity: "識別種別",
    behavior_priority: "挙動優先度",
    basis: "トリアージ根拠",
    observed_breadth: "観測された広がり",
    reputation: "レピュテーション意見",
    resolved_asn: "解決された ASN",
    first_seen: "first-seen",
    unavailable: "利用不可",
    not_applicable: "対象外（Nuclei 未実行）",
    time_range_observed: "期間は保持された分バケットの観測範囲であり、指定したフィルタ範囲ではありません。",
    none: "なし",
    reachable_max: "到達可能な最大値",
    observations: "観測",
    templates: "テンプレート",
    cves: "CVE",
    matching_records: "一致レコード",
    yes_review: "はい — 要確認",
    no: "いいえ",
    timeline_unavailable: "時系列を利用できません。保持されたタイムスタンプ付き分バケットがありません。現在のビルドで hunt または concentration を再実行すると時系列が生成されます。",
    epoch_minute: "エポック分",
    peak: "ピーク",
    timeline_footer: "保持またはダウンサンプルされた点。時刻は UTC。ダウンサンプリングは決定論的な等幅の分区間を合算します。",
    request_count_label: "リクエスト",
    retained_peers: "保持された接続ピア",
    status: "ステータス",
    other: "その他",
    status_unavailable: "利用不可",
    cap_disclosure: "追跡上限の開示",
    cap_not_admitted: "は保持対象に追加されませんでした。",
    paths: "パス",
    peer_addresses: "接続ピアアドレス",
    focused_peer_addresses: "フォーカスパスの接続ピアアドレス",
    network_prefixes: "ネットワークプレフィックス",
    global_minute_records: "新しい分バケットに属する全体レコード",
    focused_minute_records: "新しい分バケットに属するフォーカスパスのレコード",
    focused_new_peer_requests: "新しい接続ピアアドレスからのフォーカスパスへのリクエスト",
    new_path_requests: "新しいパスへのリクエスト",
    new_peer_requests: "新しい接続ピアアドレスからのリクエスト",
    new_peer_path_pairs: "新しい接続ピアとパスの組み合わせ",
    omitted_suffix: "がレポート上限により省略されました。",
};

/// Existing local run artifacts accepted by [`render_report`]. Missing
/// artifacts remain `None` and are rendered as unavailable rather than guessed.
#[derive(Debug, Default)]
pub struct ReportArtifacts {
    pub sanitized: Option<Value>,
    pub manifest: Option<Value>,
    pub concentration: Option<PrivateRequestConcentrationReport>,
    pub triage: Option<ReportTriageView>,
    /// Private 2xx findings for the bundled sensitive/config-file Sigma rule.
    /// These are selected while streaming the JSONL artifact and remain review
    /// context rather than evidence of disclosure or compromise.
    pub sensitive_success_findings: Vec<SensitiveSuccessFinding>,
}

/// Minimal private view retained for the highest-priority response-status
/// review section. Every string is escaped by the renderer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SensitiveSuccessFinding {
    pub uri_path: Option<String>,
    pub source_ip: Option<String>,
    pub response_status: u16,
    pub timestamp: Option<String>,
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
pub fn render_report(
    artifacts: &ReportArtifacts,
    limit: usize,
    timeline_points: usize,
    language: ReportLanguage,
) -> String {
    let labels = language.labels();
    let profile = first_string(
        artifacts,
        &[
            (ArtifactKind::Manifest, "/telemetry_profile"),
            (ArtifactKind::Sanitized, "/telemetry_profile"),
        ],
    )
    .unwrap_or_else(|| labels.unavailable.to_owned());
    // A concentration run performs no Nuclei pass and does not set explicit
    // filter bounds. Recognize it so provenance reads as "not applicable"
    // rather than "unavailable", and so the observed minute span can stand in
    // for the time range.
    let is_concentration_run =
        first_string(artifacts, &[(ArtifactKind::Sanitized, "/report_kind")])
            .is_some_and(|kind| kind == "SANITIZED_REQUEST_CONCENTRATION");
    let observed_range = artifacts
        .concentration
        .as_ref()
        .and_then(observed_time_range);
    let from = first_string(
        artifacts,
        &[
            (ArtifactKind::Manifest, "/hunt_parameters/filter_from"),
            (ArtifactKind::Sanitized, "/filter_from"),
            (ArtifactKind::Sanitized, "/metrics/filter_from"),
            (ArtifactKind::Sanitized, "/metrics/earliest_timestamp"),
        ],
    )
    .or_else(|| observed_range.as_ref().map(|(from, _)| from.clone()))
    .unwrap_or_else(|| labels.unavailable.to_owned());
    let to = first_string(
        artifacts,
        &[
            (ArtifactKind::Manifest, "/hunt_parameters/filter_to"),
            (ArtifactKind::Sanitized, "/filter_to"),
            (ArtifactKind::Sanitized, "/metrics/filter_to"),
            (ArtifactKind::Sanitized, "/metrics/latest_timestamp"),
        ],
    )
    .or_else(|| observed_range.as_ref().map(|(_, to)| to.clone()))
    .unwrap_or_else(|| labels.unavailable.to_owned());
    // The time range was derived from the observed series only when no explicit
    // filter/manifest bound supplied it.
    let time_range_from_series = observed_range.is_some()
        && first_string(
            artifacts,
            &[
                (ArtifactKind::Manifest, "/hunt_parameters/filter_from"),
                (ArtifactKind::Sanitized, "/filter_from"),
            ],
        )
        .is_none();
    let version = first_string(artifacts, &[(ArtifactKind::Manifest, "/shenron_version")])
        .unwrap_or_else(|| labels.unavailable.to_owned());
    let revision = first_string(artifacts, &[(ArtifactKind::Manifest, "/nuclei_revision")])
        .unwrap_or_else(|| {
            if is_concentration_run {
                labels.not_applicable
            } else {
                labels.unavailable
            }
            .to_owned()
        });
    let generated_at = first_string(artifacts, &[(ArtifactKind::Manifest, "/generated_at")])
        .unwrap_or_else(|| labels.unavailable.to_owned());

    let mut html = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><style>\
        :root{{color-scheme:dark;--bg:#0b1020;--panel:#151d31;--muted:#a8b3c7;--text:#f4f7fb;--accent:#66d9c2;--warn:#ffcf66;--danger:#ff6b78;--line:#33415f}}*{{box-sizing:border-box}}body{{margin:0;overflow-x:hidden;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}}main{{max-width:1240px;margin:auto;padding:24px;min-width:0}}a{{color:var(--accent)}}.private{{background:#6b1320;border:2px solid var(--danger);padding:16px;font-size:18px;font-weight:800;overflow-wrap:anywhere;word-break:break-word}}.note,.unavailable,.cap{{color:var(--muted)}}.note{{border-left:3px solid var(--warn);padding-left:12px}}.priority{{border:2px solid var(--danger);box-shadow:0 0 0 2px #ff6b7826}}.priority h2{{color:#ff9aa4}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;min-width:0}}.card,section{{background:var(--panel);border:1px solid var(--line);border-radius:10px;min-width:0}}.card{{padding:14px;overflow:hidden}}.card span,.card b{{overflow-wrap:anywhere;word-break:break-word}}.card b{{display:block;font-size:24px}}.badge{{display:inline-block;padding:1px 7px;border:1px solid var(--warn);border-radius:999px;color:var(--warn);font-weight:700}}section{{margin-top:18px;padding:18px;overflow:hidden}}h1,h2,h3{{margin-top:0;overflow-wrap:anywhere;word-break:break-word}}.chart-scroll,.table-scroll{{max-width:100%;overflow:auto;max-height:70vh}}svg{{width:100%;height:auto;background:#10172a;border-radius:8px}}.chart-scroll svg{{display:block;min-width:1000px}}.bar{{fill:var(--accent)}}.axis{{stroke:var(--line);stroke-width:1}}.timeline{{fill:none;stroke:var(--accent);stroke-width:3}}.timeline-area{{fill:#66d9c226;stroke:none}}.timeline-dot{{fill:var(--accent)}}.status-line{{fill:none;stroke-width:2.5}}.status-line.s1xx{{stroke:#c084fc}}.status-line.s2xx{{stroke:#4ade80}}.status-line.s3xx{{stroke:#38bdf8}}.status-line.s4xx{{stroke:#facc15}}.status-line.s5xx{{stroke:#fb7185}}.status-key.s1xx{{fill:#c084fc}}.status-key.s2xx{{fill:#4ade80}}.status-key.s3xx{{fill:#38bdf8}}.status-key.s4xx{{fill:#facc15}}.status-key.s5xx{{fill:#fb7185}}.col{{cursor:crosshair}}.hit{{fill:transparent;pointer-events:all}}.col:hover .hit{{fill:#66d9c22e}}.tip{{visibility:hidden;pointer-events:none}}.col:hover .tip{{visibility:visible}}.tip-bg{{fill:#070b14;stroke:var(--accent);stroke-width:1}}.tip-label{{fill:#fff;font-weight:700}}svg text{{fill:var(--text);font:12px system-ui,sans-serif}}table{{width:100%;min-width:1000px;border-collapse:collapse}}th,td{{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;white-space:nowrap}}.score{{width:120px;background:#26334f;border-radius:9px;overflow:hidden}}.score span{{display:block;height:10px;background:var(--accent)}}code{{color:#b9f4e8;overflow-wrap:anywhere;word-break:break-word}}.small{{font-size:12px;color:var(--muted)}}</style></head><body><main>",
        language.html_lang(),
        html_escape(labels.title),
    );
    let time_range_note = if time_range_from_series {
        format!(
            "<p class=\"small\">{}</p>",
            html_escape(labels.time_range_observed)
        )
    } else {
        String::new()
    };
    html.push_str(&format!(
        "<div class=\"private\">{}</div><h1>{}</h1><p class=\"note\">{}</p>\
         <section><h2>{}</h2><div class=\"grid\">{}{}{}{}{}{}</div>{}</section>",
        html_escape(language.private_warning()),
        html_escape(labels.title),
        html_escape(labels.overall_note),
        html_escape(labels.provenance),
        card(labels.telemetry_profile, &profile),
        card(labels.time_start, &from),
        card(labels.time_end, &to),
        card(labels.shenron_version, &version),
        card(labels.nuclei_revision, &revision),
        card(labels.run_generated_at, &generated_at),
        time_range_note,
    ));

    render_summary(&mut html, artifacts, language);
    render_sensitive_success_findings(&mut html, artifacts, limit, language);
    render_concentration(
        &mut html,
        artifacts.concentration.as_ref(),
        limit,
        timeline_points,
        language,
    );
    render_triage(&mut html, artifacts.triage.as_ref(), limit, language);
    render_cve_list(&mut html, artifacts, language);
    html.push_str("</main></body></html>");
    html
}

fn render_summary(html: &mut String, artifacts: &ReportArtifacts, language: ReportLanguage) {
    let labels = language.labels();
    html.push_str(&format!(
        "<section><h2>{}</h2>",
        html_escape(labels.aggregate_summary)
    ));
    if artifacts.sanitized.is_none() && artifacts.concentration.is_none() {
        html.push_str(&format!(
            "<p class=\"unavailable\">{}</p></section>",
            html_escape(labels.aggregate_unavailable)
        ));
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
        (labels.requests, optional_number(total, language)),
        (labels.distinct_paths, optional_number(paths, language)),
        (labels.distinct_peers, optional_number(source_ips, language)),
    ] {
        html.push_str(&card(label, &value));
    }
    let cve_count = optional_number(cves, language);
    if observed_cve_findings(artifacts).is_some() {
        html.push_str(&anchor_card(
            labels.observed_cves,
            &cve_count,
            "observed-cves",
        ));
    } else {
        html.push_str(&card(labels.observed_cves, &cve_count));
    }
    html.push_str(&card(
        labels.triage_entities,
        &optional_number(triage_entities, language),
    ));
    html.push_str("</div>");
    if let Some(view) = &artifacts.triage {
        let mut tiers = BTreeMap::<&str, usize>::new();
        for entity in &view.entities {
            *tiers
                .entry(entity.behavior_score.tier.as_str())
                .or_default() += 1;
        }
        html.push_str(&format!(
            "<p class=\"small\">{}: info={}, low={}, medium={}, high={}.</p>",
            html_escape(labels.tier_summary),
            group_thousands(tiers.get("info").copied().unwrap_or_default() as u64),
            group_thousands(tiers.get("low").copied().unwrap_or_default() as u64),
            group_thousands(tiers.get("medium").copied().unwrap_or_default() as u64),
            group_thousands(tiers.get("high").copied().unwrap_or_default() as u64),
        ));
    }
    html.push_str("</section>");
}

fn render_sensitive_success_findings(
    html: &mut String,
    artifacts: &ReportArtifacts,
    limit: usize,
    language: ReportLanguage,
) {
    let findings = &artifacts.sensitive_success_findings;
    if findings.is_empty() {
        return;
    }

    let labels = language.labels();
    let visible = limited(findings, limit);
    html.push_str(&format!(
        "<section class=\"priority\"><h2>{}</h2><p class=\"note\">{}</p><div class=\"table-scroll\"><table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>",
        html_escape(labels.sensitive_success_heading),
        html_escape(labels.sensitive_success_note),
        html_escape(labels.sensitive_path),
        html_escape(labels.sensitive_observed_peer),
        html_escape(labels.sensitive_response_status),
        html_escape(labels.sensitive_timestamp),
    ));
    for finding in visible {
        let path = finding.uri_path.as_deref().unwrap_or(labels.unavailable);
        let source_ip = finding.source_ip.as_deref().unwrap_or(labels.unavailable);
        let timestamp = finding.timestamp.as_deref().unwrap_or(labels.unavailable);
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            html_escape(path),
            html_escape(source_ip),
            group_thousands(u64::from(finding.response_status)),
            html_escape(timestamp),
        ));
    }
    html.push_str("</tbody></table></div>");
    omitted(
        html,
        findings.len(),
        visible.len(),
        labels.sensitive_records,
        language,
    );
    html.push_str("</section>");
}

fn render_concentration(
    html: &mut String,
    concentration: Option<&PrivateRequestConcentrationReport>,
    limit: usize,
    timeline_points: usize,
    language: ReportLanguage,
) {
    let labels = language.labels();
    html.push_str(&format!(
        "<section><h2>{}</h2><p class=\"note\">{}</p>",
        html_escape(labels.concentration),
        html_escape(labels.concentration_note),
    ));
    let Some(concentration) = concentration else {
        html.push_str(&format!(
            "<p class=\"unavailable\">{}</p></section>",
            html_escape(labels.concentration_unavailable),
        ));
        return;
    };

    html.push_str(&format!("<h3>{}</h3>", html_escape(labels.top_paths)));
    let path_rows = limited(&concentration.paths, limit)
        .iter()
        .map(|path| BarRow {
            label: path.uri_path.as_str(),
            value: path.summary.requests,
            details: format!(
                "{:.1}% · {} {} · {}",
                path.summary.request_share * 100.0,
                group_thousands(path.summary.distinct_source_ips as u64),
                labels.retained_peers,
                status_details(&path.summary.response_status_classes, language),
            ),
        })
        .collect::<Vec<_>>();
    html.push_str(&bar_chart(labels.top_request_paths, &path_rows, language));
    omitted(
        html,
        concentration.paths.len(),
        path_rows.len(),
        labels.paths,
        language,
    );

    html.push_str(&format!("<h3>{}</h3>", html_escape(labels.top_peers)));
    let source_rows = source_rows(&concentration.source_ips, limit, language);
    html.push_str(&bar_chart(
        labels.top_observed_peers,
        &source_rows,
        language,
    ));
    omitted(
        html,
        concentration.source_ips.len(),
        source_rows.len(),
        labels.peer_addresses,
        language,
    );

    html.push_str(&format!(
        "<h3>{}</h3>",
        html_escape(labels.requests_per_minute)
    ));
    html.push_str(&timeline_chart(
        labels.global_timeline,
        &concentration.requests_per_minute_series,
        timeline_points,
        language,
    ));
    if concentration
        .status_class_requests_per_minute_series
        .iter()
        .any(|point| status_class_total(point) != 0)
    {
        html.push_str(&format!(
            "<h3>{}</h3>",
            html_escape(labels.status_requests_per_minute)
        ));
        html.push_str(&status_class_timeline_chart(
            labels.status_timeline,
            &concentration.status_class_requests_per_minute_series,
            timeline_points,
            language,
        ));
        html.push_str(&format!(
            "<p class=\"note\">{}</p>",
            html_escape(labels.status_timeline_note)
        ));
    }
    cap_note(
        html,
        concentration.minute_buckets_beyond_cap,
        labels.global_minute_records,
        language,
    );
    render_general_caps(html, concentration, language);

    if let Some(focus) = &concentration.focus {
        let is_source_ip_focus = focus.focus_kind == "source-ip";
        let heading = if is_source_ip_focus {
            labels.focused_source_ip
        } else {
            labels.focused_path
        };
        html.push_str(&format!(
            "<h2>{}</h2><p><code>{}</code> — {}</p>",
            html_escape(heading),
            html_escape(&focus.uri_path),
            html_escape(&focus_summary(
                language,
                focus.total_requests,
                focus.distinct_source_ips as u64,
            )),
        ));

        // Sub-paths of a prefix focus, or the paths one source IP requested.
        if !focus.paths.is_empty() {
            html.push_str(&format!(
                "<h3>{}</h3>",
                html_escape(labels.focused_paths_chart)
            ));
            let path_rows = focus_path_rows(&focus.paths, limit, language);
            html.push_str(&bar_chart(labels.focused_paths_chart, &path_rows, language));
            omitted(
                html,
                focus.paths.len(),
                path_rows.len(),
                labels.focused_paths_label,
                language,
            );
            cap_note(
                html,
                focus.paths_beyond_cap,
                labels.focused_paths_label,
                language,
            );
        }

        // A multi-source-IP focus retains a useful per-peer breakdown. A
        // single-source focus omits that redundant chart, as before.
        let has_multiple_selected_source_ips = is_source_ip_focus
            && focus
                .selector
                .split(',')
                .filter(|value| !value.trim().is_empty())
                .nth(1)
                .is_some();
        if !is_source_ip_focus || has_multiple_selected_source_ips {
            let (peer_heading, peer_chart, peer_label) = if is_source_ip_focus {
                (
                    labels.top_peers,
                    labels.top_observed_peers,
                    labels.peer_addresses,
                )
            } else {
                (
                    labels.focused_peers,
                    labels.focused_peer_chart,
                    labels.focused_peer_addresses,
                )
            };
            html.push_str(&format!("<h3>{}</h3>", html_escape(peer_heading)));
            let rows = focus_source_rows(&focus.sources, limit, language);
            html.push_str(&bar_chart(peer_chart, &rows, language));
            omitted(html, focus.sources.len(), rows.len(), peer_label, language);
        }

        // Network-prefix groups apply only to a path or path-prefix focus.
        if !is_source_ip_focus {
            html.push_str(&format!(
                "<h3>{}</h3><p class=\"note\">{}</p>",
                html_escape(labels.focused_prefixes),
                html_escape(labels.prefix_note),
            ));
            let prefix_rows = prefix_rows(&focus.network_prefix_groups, limit, language);
            html.push_str(&bar_chart(
                labels.focused_prefix_chart,
                &prefix_rows,
                language,
            ));
            omitted(
                html,
                focus.network_prefix_groups.len(),
                prefix_rows.len(),
                labels.network_prefixes,
                language,
            );
        }

        html.push_str(&format!(
            "<h3>{}</h3>",
            html_escape(labels.focused_requests_per_minute)
        ));
        html.push_str(&timeline_chart(
            labels.focused_timeline,
            &focus.requests_per_minute_series,
            timeline_points,
            language,
        ));
        cap_note(
            html,
            focus.minute_buckets_beyond_cap,
            labels.focused_minute_records,
            language,
        );
        cap_note(
            html,
            focus.source_ips_beyond_cap,
            labels.focused_new_peer_requests,
            language,
        );
    }
    html.push_str("</section>");
}

fn render_triage(
    html: &mut String,
    triage: Option<&ReportTriageView>,
    limit: usize,
    language: ReportLanguage,
) {
    let labels = language.labels();
    html.push_str(&format!(
        "<section><h2>{}</h2><p class=\"note\">{}</p>",
        html_escape(labels.triage),
        html_escape(labels.triage_note),
    ));
    let Some(triage) = triage else {
        html.push_str(&format!(
            "<p class=\"unavailable\">{}</p></section>",
            html_escape(labels.triage_unavailable),
        ));
        return;
    };
    let entities = limited(&triage.entities, limit);
    if entities.is_empty() {
        html.push_str(&format!(
            "<p class=\"unavailable\">{}</p></section>",
            html_escape(labels.no_triage),
        ));
        return;
    }
    let show_reputation = triage
        .entities
        .iter()
        .any(|entity| entity.reputation.is_some());
    let show_resolved_asn = triage
        .entities
        .iter()
        .any(|entity| entity.resolved_asn.is_some());
    html.push_str("<div class=\"table-scroll\"><table><thead><tr>");
    for heading in [
        labels.entity,
        labels.identity,
        labels.behavior_priority,
        labels.basis,
        labels.observed_breadth,
    ] {
        html.push_str(&format!("<th>{}</th>", html_escape(heading)));
    }
    if show_reputation {
        html.push_str(&format!("<th>{}</th>", html_escape(labels.reputation)));
    }
    if show_resolved_asn {
        html.push_str(&format!("<th>{}</th>", html_escape(labels.resolved_asn)));
    }
    html.push_str(&format!(
        "<th>{}</th></tr></thead><tbody>",
        html_escape(labels.first_seen)
    ));
    for entity in entities {
        let score = entity.behavior_score.total.min(100);
        let basis = entity.triage_basis.as_deref().unwrap_or(labels.none);
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}/100 {}<div class=\"score\"><span style=\"width:{}%\"></span></div><span class=\"small\">{} {}</span></td><td>{}</td><td>{} {} / {} {} / {} {}<br><span class=\"small\">{} {}</span></td>",
            html_escape(&entity.key),
            html_escape(&entity.identity),
            group_thousands(entity.behavior_score.total as u64),
            html_escape(&entity.behavior_score.tier),
            score,
            html_escape(labels.reachable_max),
            group_thousands(entity.behavior_score.reachable_max as u64),
            html_escape(basis),
            group_thousands(entity.distinct_observations as u64),
            html_escape(labels.observations),
            group_thousands(entity.distinct_templates as u64),
            html_escape(labels.templates),
            group_thousands(entity.distinct_cves as u64),
            html_escape(labels.cves),
            group_thousands(entity.matching_records as u64),
            html_escape(labels.matching_records),
        ));
        if show_reputation {
            let reputation = entity.reputation.as_ref().map_or_else(
                || labels.unavailable.to_owned(),
                |value| {
                    format!(
                        "{}/100 {} ({})",
                        group_thousands(value.score as u64),
                        value.tier,
                        value.scope
                    )
                },
            );
            html.push_str(&format!("<td>{}</td>", html_escape(&reputation)));
        }
        if show_resolved_asn {
            let asn = entity.resolved_asn.as_ref().map_or_else(
                || labels.unavailable.to_owned(),
                |value| format!("AS{} {}", group_thousands(value.asn as u64), value.org),
            );
            html.push_str(&format!("<td>{}</td>", html_escape(&asn)));
        }
        html.push_str(&format!(
            "<td>{}</td></tr>",
            html_escape(if entity.first_seen {
                labels.yes_review
            } else {
                labels.no
            }),
        ));
    }
    html.push_str("</tbody></table></div>");
    omitted(
        html,
        triage.entities.len(),
        entities.len(),
        labels.triage_entities,
        language,
    );
    html.push_str("</section>");
}

fn render_cve_list(html: &mut String, artifacts: &ReportArtifacts, language: ReportLanguage) {
    let Some(findings) = observed_cve_findings(artifacts) else {
        return;
    };
    let labels = language.labels();
    html.push_str(&format!(
        "<section id=\"observed-cves\"><h2>{}</h2><p class=\"note\">{}</p>\
         <div class=\"table-scroll\"><table><thead><tr>\
         <th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th>\
         <th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>",
        html_escape(labels.cve_list_heading),
        html_escape(labels.cve_list_note),
        html_escape(labels.cve_id),
        html_escape(labels.cve_templates),
        html_escape(labels.kev_membership),
        html_escape(labels.detectability),
        html_escape(labels.requests),
        html_escape(labels.distinctive_matches),
        html_escape(labels.generic_matches),
        html_escape(labels.cve_first_seen),
        html_escape(labels.last_seen),
        html_escape(labels.protection_gap_rate),
    ));
    for finding in findings {
        let cve = finding
            .get("cve")
            .and_then(Value::as_str)
            .unwrap_or(labels.unavailable);
        let kev = if finding
            .get("cisa_kev")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            format!(
                "<span class=\"badge\">{}</span>",
                html_escape(labels.kev_badge)
            )
        } else {
            "—".to_owned()
        };
        let detectability = finding
            .get("detectability")
            .and_then(Value::as_str)
            .unwrap_or(labels.unavailable);
        let first_seen = finding
            .get("first_seen")
            .and_then(Value::as_str)
            .unwrap_or(labels.unavailable);
        let last_seen = finding
            .get("last_seen")
            .and_then(Value::as_str)
            .unwrap_or(labels.unavailable);
        let protection_gap_rate = finding
            .get("protection_gap_rate")
            .and_then(Value::as_f64)
            .map_or_else(|| "—".to_owned(), |rate| format!("{:.1}%", rate * 100.0));
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(cve),
            cve_template_ids(finding),
            kev,
            html_escape(detectability),
            cve_count(finding, "request_count", language),
            cve_count(finding, "distinctive_path_matches", language),
            cve_count(finding, "generic_path_matches", language),
            html_escape(first_seen),
            html_escape(last_seen),
            html_escape(&protection_gap_rate),
        ));
    }
    html.push_str("</tbody></table></div></section>");
}

fn cve_count(finding: &Value, field: &str, language: ReportLanguage) -> String {
    finding.get(field).and_then(Value::as_u64).map_or_else(
        || html_escape(language.labels().unavailable),
        group_thousands,
    )
}

fn cve_template_ids(finding: &Value) -> String {
    let template_ids = finding
        .get("template_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(html_escape)
        .collect::<Vec<_>>();
    if template_ids.is_empty() {
        "—".to_owned()
    } else {
        template_ids.join(", ")
    }
}

fn observed_cve_findings(artifacts: &ReportArtifacts) -> Option<&[Value]> {
    artifacts
        .sanitized
        .as_ref()?
        .pointer("/cve_findings")?
        .as_array()
        .filter(|findings| !findings.is_empty())
        .map(Vec::as_slice)
}

struct BarRow<'a> {
    label: &'a str,
    value: u64,
    details: String,
}

fn bar_chart(title: &str, rows: &[BarRow<'_>], language: ReportLanguage) -> String {
    if rows.is_empty() {
        return format!(
            "<p class=\"unavailable\">{}</p>",
            html_escape(language.labels().unavailable)
        );
    }
    let maximum = rows.iter().map(|row| row.value).max().unwrap_or(1).max(1);
    let height = rows.len() * 42 + 16;
    // Preserve room for ordinary long paths instead of clipping them at the
    // fixed label column. The enclosing scroll container exposes any width
    // beyond the viewport; an extreme value still has its complete SVG title.
    let label_column = rows
        .iter()
        .map(|row| {
            row.label
                .chars()
                .count()
                .saturating_mul(7)
                .saturating_add(16)
        })
        .max()
        .unwrap_or(300)
        .clamp(300, 4_000);
    let chart_width = label_column + 700;
    let mut svg = format!(
        "<div class=\"chart-scroll\"><svg width=\"{chart_width}\" height=\"{height}\" viewBox=\"0 0 {chart_width} {height}\" role=\"img\" aria-label=\"{}\">",
        html_escape(title)
    );
    for (index, row) in rows.iter().enumerate() {
        let y = index * 42 + 8;
        let width = row.value as f64 / maximum as f64 * 500.0;
        // A native SVG <title> gives the full label and count on hover even when
        // the on-chart label is visually truncated.
        let tip = format!(
            "{} · {} {}",
            row.label,
            group_thousands(row.value),
            row.details
        );
        svg.push_str(&format!(
            "<text x=\"8\" y=\"{}\">{}</text><rect class=\"bar\" x=\"{label_column}\" y=\"{}\" width=\"{:.2}\" height=\"14\"><title>{}</title></rect><text x=\"{}\" y=\"{}\">{} · {}</text>",
            y + 12,
            html_escape(row.label),
            y,
            width,
            html_escape(&tip),
            label_column as f64 + 10.0 + width,
            y + 12,
            group_thousands(row.value),
            html_escape(&row.details),
        ));
    }
    svg.push_str("</svg></div>");
    svg
}

fn timeline_chart(
    title: &str,
    series: &[MinuteRequestCount],
    maximum_points: usize,
    language: ReportLanguage,
) -> String {
    let labels = language.labels();
    let points = downsample_timeline(series, maximum_points.max(1));
    if points.is_empty() {
        return format!(
            "<p class=\"unavailable\">{}</p>",
            html_escape(labels.timeline_unavailable)
        );
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
    // Per-point x for a point i minutes into the span. Shared by the polyline,
    // the visible dots, and the invisible hover targets so they stay aligned.
    let point_x =
        |minute_epoch: i64| 60.0 + (minute_epoch as i128 - first as i128) as f64 / span * 880.0;
    let point_y = |requests: u64| 180.0 - requests as f64 / peak as f64 * 145.0;
    let mut coordinate_values = points
        .iter()
        .map(|point| {
            format!(
                "{:.2},{:.2}",
                point_x(point.minute_epoch),
                point_y(point.requests)
            )
        })
        .collect::<Vec<_>>();
    if coordinate_values.len() == 1 {
        coordinate_values.push(format!("940.00,{:.2}", point_y(points[0].requests)));
    }
    let coordinates = coordinate_values.join(" ");
    let area = format!("60,180 {coordinates} 940,180");
    // Each point owns the non-overlapping column bounded by the midpoints to
    // its neighbors. Hovering the column reveals an explicit CSS-only readout;
    // the native SVG title remains as a fallback and requires no JavaScript.
    let mut markers = String::new();
    for (index, point) in points.iter().enumerate() {
        let x = point_x(point.minute_epoch);
        let y = point_y(point.requests);
        let hit_x = if index == 0 {
            60.0
        } else {
            (point_x(points[index - 1].minute_epoch) + x) / 2.0
        };
        let hit_right = if index + 1 == points.len() {
            940.0
        } else {
            (x + point_x(points[index + 1].minute_epoch)) / 2.0
        };
        let hit_width = (hit_right - hit_x).max(0.5);
        let tip_x = (x - 180.0).clamp(62.0, 578.0);
        let tip = format!(
            "{} · {} {}",
            minute_label(point.minute_epoch, language),
            group_thousands(point.requests),
            labels.request_count_label,
        );
        markers.push_str(&format!(
            "<g class=\"col\"><rect class=\"hit\" x=\"{hit_x:.2}\" y=\"35\" width=\"{hit_width:.2}\" height=\"145\"><title>{}</title></rect><circle class=\"timeline-dot\" cx=\"{x:.2}\" cy=\"{y:.2}\" r=\"2.5\"></circle><g class=\"tip\"><rect class=\"tip-bg\" x=\"{tip_x:.2}\" y=\"40\" width=\"360\" height=\"26\" rx=\"4\"></rect><text class=\"tip-label\" x=\"{:.2}\" y=\"58\">{}</text></g></g>",
            html_escape(&tip),
            tip_x + 8.0,
            html_escape(&tip),
        ));
    }
    format!(
        "<div class=\"chart-scroll\"><svg width=\"1000\" height=\"220\" viewBox=\"0 0 1000 220\" role=\"img\" aria-label=\"{}\"><line class=\"axis\" x1=\"60\" y1=\"180\" x2=\"940\" y2=\"180\"></line><line class=\"axis\" x1=\"60\" y1=\"35\" x2=\"60\" y2=\"180\"></line><polygon class=\"timeline-area\" points=\"{}\"></polygon><polyline class=\"timeline\" points=\"{}\"></polyline>{}<text x=\"60\" y=\"205\">{}</text><text x=\"760\" y=\"205\">{}</text><text x=\"65\" y=\"30\">{} {}</text></svg></div><p class=\"small\">{} {}</p>",
        html_escape(title),
        area,
        coordinates,
        markers,
        html_escape(&minute_label(first, language)),
        html_escape(&minute_label(last, language)),
        html_escape(labels.peak),
        group_thousands(peak),
        group_thousands(points.len() as u64),
        html_escape(labels.timeline_footer),
    )
}

fn status_class_timeline_chart(
    title: &str,
    series: &[StatusClassMinuteCount],
    maximum_points: usize,
    language: ReportLanguage,
) -> String {
    let labels = language.labels();
    let points = downsample_status_timeline(series, maximum_points.max(1));
    let Some(first_point) = points.first() else {
        return String::new();
    };
    let first = first_point.minute_epoch;
    let last = points
        .last()
        .expect("checked non-empty status timeline")
        .minute_epoch;
    let peak = points
        .iter()
        .flat_map(|point| {
            [
                point.informational,
                point.success,
                point.redirection,
                point.client_error,
                point.server_error,
            ]
        })
        .max()
        .unwrap_or(1)
        .max(1);
    let span = (last as i128 - first as i128).max(1) as f64;
    let point_x =
        |minute_epoch: i64| 60.0 + (minute_epoch as i128 - first as i128) as f64 / span * 880.0;
    let point_y = |requests: u64| 180.0 - requests as f64 / peak as f64 * 145.0;
    let classes = [
        ("s1xx", "1xx", labels.status_informational),
        ("s2xx", "2xx", labels.status_success),
        ("s3xx", "3xx", labels.status_redirection),
        ("s4xx", "4xx", labels.status_client_error),
        ("s5xx", "5xx", labels.status_server_error),
    ];
    let mut polylines = String::new();
    let mut legend = String::new();
    for (index, (class, code, class_label)) in classes.iter().enumerate() {
        let mut coordinates = points
            .iter()
            .map(|point| {
                format!(
                    "{:.2},{:.2}",
                    point_x(point.minute_epoch),
                    point_y(status_class_value(point, index))
                )
            })
            .collect::<Vec<_>>();
        if coordinates.len() == 1 {
            coordinates.push(format!(
                "940.00,{:.2}",
                point_y(status_class_value(&points[0], index))
            ));
        }
        polylines.push_str(&format!(
            "<polyline class=\"status-line {class}\" points=\"{}\"></polyline>",
            coordinates.join(" ")
        ));
        let legend_x = 70 + index * 176;
        legend.push_str(&format!(
            "<rect class=\"status-key {class}\" x=\"{legend_x}\" y=\"9\" width=\"12\" height=\"12\"></rect><text x=\"{}\" y=\"19\">{} {}</text>",
            legend_x + 18,
            html_escape(code),
            html_escape(class_label),
        ));
    }
    format!(
        "<div class=\"chart-scroll\"><svg width=\"1000\" height=\"220\" viewBox=\"0 0 1000 220\" role=\"img\" aria-label=\"{}\">{}<line class=\"axis\" x1=\"60\" y1=\"180\" x2=\"940\" y2=\"180\"></line><line class=\"axis\" x1=\"60\" y1=\"35\" x2=\"60\" y2=\"180\"></line>{}<text x=\"60\" y=\"205\">{}</text><text x=\"760\" y=\"205\">{}</text></svg></div><p class=\"small\">{} {} · {} {}.</p>",
        html_escape(title),
        legend,
        polylines,
        html_escape(&minute_label(first, language)),
        html_escape(&minute_label(last, language)),
        group_thousands(points.len() as u64),
        html_escape(labels.timeline_footer),
        html_escape(labels.peak),
        group_thousands(peak),
    )
}

fn status_class_value(point: &StatusClassMinuteCount, index: usize) -> u64 {
    match index {
        0 => point.informational,
        1 => point.success,
        2 => point.redirection,
        3 => point.client_error,
        4 => point.server_error,
        _ => 0,
    }
}

fn status_class_total(point: &StatusClassMinuteCount) -> u64 {
    point
        .informational
        .saturating_add(point.success)
        .saturating_add(point.redirection)
        .saturating_add(point.client_error)
        .saturating_add(point.server_error)
}

fn downsample_status_timeline(
    series: &[StatusClassMinuteCount],
    maximum_points: usize,
) -> Vec<StatusClassMinuteCount> {
    let mut minutes = BTreeMap::<i64, StatusClassMinuteCount>::new();
    for point in series {
        let aggregate =
            minutes
                .entry(point.minute_epoch)
                .or_insert_with(|| StatusClassMinuteCount {
                    minute_epoch: point.minute_epoch,
                    ..StatusClassMinuteCount::default()
                });
        add_status_point(aggregate, point);
    }
    let Some((&first, _)) = minutes.first_key_value() else {
        return Vec::new();
    };
    let last = *minutes
        .last_key_value()
        .expect("checked non-empty status series")
        .0;
    let span = last as i128 - first as i128 + 1;
    let maximum_points = maximum_points.max(1) as i128;
    let width = ((span + maximum_points - 1) / maximum_points).max(1);
    let mut buckets = BTreeMap::<i128, StatusClassMinuteCount>::new();
    for (minute, point) in minutes {
        let index = (minute as i128 - first as i128) / width;
        let bucket = buckets.entry(index).or_default();
        add_status_point(bucket, &point);
    }
    buckets
        .into_iter()
        .map(|(index, mut point)| {
            let minute = first as i128 + index * width;
            point.minute_epoch = minute.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
            point
        })
        .collect()
}

fn add_status_point(target: &mut StatusClassMinuteCount, point: &StatusClassMinuteCount) {
    target.informational = target.informational.saturating_add(point.informational);
    target.success = target.success.saturating_add(point.success);
    target.redirection = target.redirection.saturating_add(point.redirection);
    target.client_error = target.client_error.saturating_add(point.client_error);
    target.server_error = target.server_error.saturating_add(point.server_error);
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

fn minute_label(minute_epoch: i64, language: ReportLanguage) -> String {
    minute_epoch
        .checked_mul(60)
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| {
            format!(
                "{} {}",
                language.labels().epoch_minute,
                group_signed_thousands(minute_epoch)
            )
        })
}

/// Observed UTC span (first, last) of the retained minute series as RFC 3339
/// strings, or `None` when no timestamped minute buckets were retained. This is
/// the span of the data actually observed, not a requested filter window.
fn observed_time_range(
    concentration: &PrivateRequestConcentrationReport,
) -> Option<(String, String)> {
    let series = &concentration.requests_per_minute_series;
    let first = series.iter().map(|point| point.minute_epoch).min()?;
    let last = series.iter().map(|point| point.minute_epoch).max()?;
    Some((minute_timestamp(first)?, minute_timestamp(last)?))
}

fn minute_timestamp(minute_epoch: i64) -> Option<String> {
    minute_epoch
        .checked_mul(60)
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|timestamp| timestamp.to_rfc3339())
}

fn source_rows<'a>(
    sources: &'a [PrivateSourceConcentration],
    limit: usize,
    language: ReportLanguage,
) -> Vec<BarRow<'a>> {
    limited(sources, limit)
        .iter()
        .map(|source| BarRow {
            label: source.source_ip.as_str(),
            value: source.requests,
            details: language.labels().request_count_label.to_owned(),
        })
        .collect()
}

fn focus_source_rows<'a>(
    sources: &'a [PrivateFocusSource],
    limit: usize,
    language: ReportLanguage,
) -> Vec<BarRow<'a>> {
    limited(sources, limit)
        .iter()
        .map(|source| BarRow {
            label: source.source_ip.as_str(),
            value: source.requests,
            details: language.labels().request_count_label.to_owned(),
        })
        .collect()
}

fn focus_path_rows<'a>(
    paths: &'a [PrivateFocusPath],
    limit: usize,
    language: ReportLanguage,
) -> Vec<BarRow<'a>> {
    limited(paths, limit)
        .iter()
        .map(|path| BarRow {
            label: path.uri_path.as_str(),
            value: path.requests,
            details: language.labels().request_count_label.to_owned(),
        })
        .collect()
}

fn prefix_rows<'a>(
    groups: &'a [PrivateFocusPrefixGroup],
    limit: usize,
    language: ReportLanguage,
) -> Vec<BarRow<'a>> {
    limited(groups, limit)
        .iter()
        .map(|group| BarRow {
            label: group.network_prefix.as_str(),
            value: group.requests,
            details: format!(
                "{:.1}% · {} {}",
                group.request_share * 100.0,
                group_thousands(group.distinct_source_ips as u64),
                language.labels().retained_peers,
            ),
        })
        .collect()
}

fn render_general_caps(
    html: &mut String,
    report: &PrivateRequestConcentrationReport,
    language: ReportLanguage,
) {
    let labels = language.labels();
    for (count, label) in [
        (
            report.summary.paths_beyond_tracking_cap,
            labels.new_path_requests,
        ),
        (
            report.summary.source_ips_beyond_tracking_cap,
            labels.new_peer_requests,
        ),
        (
            report.summary.source_path_pairs_beyond_tracking_cap,
            labels.new_peer_path_pairs,
        ),
    ] {
        cap_note(html, count, label, language);
    }
}

fn cap_note(html: &mut String, count: u64, label: &str, language: ReportLanguage) {
    if count != 0 {
        let labels = language.labels();
        html.push_str(&format!(
            "<p class=\"cap\">{}: {} {} {}</p>",
            html_escape(labels.cap_disclosure),
            group_thousands(count),
            html_escape(label),
            html_escape(labels.cap_not_admitted),
        ));
    }
}

fn status_details(counts: &StatusClassCounts, language: ReportLanguage) -> String {
    let labels = language.labels();
    format!(
        "{} 1xx:{} 2xx:{} 3xx:{} 4xx:{} 5xx:{} {}:{} {}:{}",
        labels.status,
        group_thousands(counts.informational),
        group_thousands(counts.success),
        group_thousands(counts.redirection),
        group_thousands(counts.client_error),
        group_thousands(counts.server_error),
        labels.other,
        group_thousands(counts.other),
        labels.status_unavailable,
        group_thousands(counts.unavailable),
    )
}

fn focus_summary(language: ReportLanguage, requests: u64, peers: u64) -> String {
    match language {
        ReportLanguage::En => format!(
            "{} requests from {} retained observed peers.",
            group_thousands(requests),
            group_thousands(peers),
        ),
        ReportLanguage::Ja => format!(
            "{} リクエスト（保持された観測接続ピア {} 件）。",
            group_thousands(requests),
            group_thousands(peers),
        ),
    }
}

fn group_thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(character);
    }
    grouped
}

fn group_signed_thousands(value: i64) -> String {
    if value < 0 {
        format!("-{}", group_thousands(value.unsigned_abs()))
    } else {
        group_thousands(value as u64)
    }
}

fn card(label: &str, value: &str) -> String {
    format!(
        "<div class=\"card\"><span>{}</span><b>{}</b></div>",
        html_escape(label),
        html_escape(value),
    )
}

fn anchor_card(label: &str, value: &str, target: &str) -> String {
    format!(
        "<div class=\"card\"><span>{}</span><b><a href=\"#{}\">{}</a></b></div>",
        html_escape(label),
        html_escape(target),
        html_escape(value),
    )
}

fn optional_number(value: Option<u64>, language: ReportLanguage) -> String {
    value.map_or_else(|| language.labels().unavailable.to_owned(), group_thousands)
}

fn limited<T>(values: &[T], limit: usize) -> &[T] {
    if limit == 0 {
        values
    } else {
        &values[..values.len().min(limit)]
    }
}

fn omitted(
    html: &mut String,
    total: usize,
    displayed: usize,
    label: &str,
    language: ReportLanguage,
) {
    if total > displayed {
        html.push_str(&format!(
            "<p class=\"small\">{} {} {}</p>",
            group_thousands((total - displayed) as u64),
            html_escape(label),
            html_escape(language.labels().omitted_suffix),
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
                    focus_kind: "exact-path".to_owned(),
                    total_requests: 3,
                    distinct_source_ips: 1,
                    source_ips_beyond_cap: 0,
                    distinct_uri_paths: 0,
                    paths_beyond_cap: 0,
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
                focus_kind: "exact-path".to_owned(),
                selector: path.to_owned(),
                uri_path: path.to_owned(),
                total_requests: 3,
                distinct_source_ips: 1,
                source_ips_beyond_cap: 0,
                paths: Vec::new(),
                paths_beyond_cap: 0,
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
            status_class_requests_per_minute_series: vec![
                StatusClassMinuteCount {
                    minute_epoch: 0,
                    success: 1,
                    ..StatusClassMinuteCount::default()
                },
                StatusClassMinuteCount {
                    minute_epoch: 1,
                    success: 1,
                    client_error: 1,
                    ..StatusClassMinuteCount::default()
                },
            ],
            minute_buckets_beyond_cap: 0,
        }
    }

    #[test]
    fn renders_expected_private_sections_and_escapes_artifact_values() {
        let mut concentration = synthetic_concentration("/x?<script>alert(1)</script>&\"'");
        concentration.summary.total_requests = 1_234;
        concentration.paths[0].summary.requests = 1_234;
        concentration.source_ips[0].requests = 1_234;
        let artifacts = ReportArtifacts {
            sanitized: Some(serde_json::json!({
                "metrics": {"total_requests_analyzed": 3, "unique_cves_observed": 1}
            })),
            manifest: Some(serde_json::json!({
                "shenron_version": "0.1.0",
                "telemetry_profile": "aws-waf",
                "nuclei_revision": "fixture",
                "generated_at": "2026-09-03T07:51:07.442436+00:00"
            })),
            concentration: Some(concentration),
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
            sensitive_success_findings: Vec::new(),
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::En);
        for section in [
            "Top paths",
            "Top observed connection peers",
            "Requests per minute",
            "Requests per minute by HTTP status class",
            "Hunt triage view",
        ] {
            assert!(html.contains(section));
        }
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;&quot;&#39;"));
        assert!(html.contains("1,234"));
        assert!(html.contains("<svg width=\"1000\" height=\"58\" viewBox=\"0 0 1000 58\""));
        assert!(html.contains("overflow-wrap:anywhere;word-break:break-word"));
        assert!(html.contains("body{margin:0;overflow-x:hidden"));
        assert!(html.contains("<div class=\"chart-scroll\"><svg"));
        assert!(html.contains("<div class=\"table-scroll\"><table"));
        for forbidden in ["http://", "https://", "src=", "<script src"] {
            assert!(
                !html.contains(forbidden),
                "found external reference marker {forbidden}"
            );
        }
    }

    #[test]
    fn renders_missing_artifacts_as_unavailable_without_panicking() {
        let html = render_report(&ReportArtifacts::default(), 20, 240, ReportLanguage::En);
        assert!(html.contains(PRIVATE_REPORT_WARNING));
        assert!(html.contains("Aggregate summary unavailable"));
        assert!(html.contains("Concentration unavailable"));
        assert!(html.contains("Triage unavailable"));
    }

    #[test]
    fn triage_omits_globally_unavailable_optional_columns() {
        let mut triage = ReportTriageView {
            entities: vec![ReportTriageEntity {
                key: "198.51.100.1".to_owned(),
                identity: "observed-peer".to_owned(),
                ..ReportTriageEntity::default()
            }],
        };
        let mut html = String::new();
        render_triage(&mut html, Some(&triage), 20, ReportLanguage::En);
        assert!(!html.contains("Reputation opinion"));
        assert!(!html.contains("Resolved ASN"));
        assert_eq!(html.matches("<th>").count(), 6);
        assert_eq!(html.matches("<td>").count(), 6);

        let mut japanese = String::new();
        render_triage(&mut japanese, Some(&triage), 20, ReportLanguage::Ja);
        assert!(!japanese.contains("レピュテーション意見"));
        assert!(!japanese.contains("解決された ASN"));

        triage.entities[0].reputation = Some(ReportReputation {
            score: 85,
            tier: "high".to_owned(),
            scope: "ip".to_owned(),
        });
        let mut enriched = String::new();
        render_triage(&mut enriched, Some(&triage), 20, ReportLanguage::En);
        assert!(enriched.contains("Reputation opinion"));
        assert!(!enriched.contains("Resolved ASN"));
        assert_eq!(enriched.matches("<th>").count(), 7);
        assert_eq!(enriched.matches("<td>").count(), 7);
    }

    #[test]
    fn observed_cve_card_links_to_the_sanitized_cve_table() {
        let artifacts = ReportArtifacts {
            sanitized: Some(serde_json::json!({
                "cve_findings": [
                    {
                        "cve": "CVE-2026-10001",
                        "template_ids": ["nuclei-template-a", "nuclei-template-b", "nuclei-template-<escaped>"],
                        "cisa_kev": true,
                        "detectability": "HIGH",
                        "request_count": 1234,
                        "distinctive_path_matches": 1200,
                        "generic_path_matches": 34,
                        "first_seen": "2026-09-01T00:00:00+00:00",
                        "last_seen": "2026-09-02T00:00:00+00:00",
                        "protection_gap_rate": 0.5
                    },
                    {
                        "cve": "CVE-&<escaped>",
                        "template_ids": [],
                        "cisa_kev": false,
                        "detectability": "MEDIUM",
                        "request_count": 2,
                        "distinctive_path_matches": 0,
                        "generic_path_matches": 2,
                        "first_seen": null,
                        "last_seen": null,
                        "protection_gap_rate": null
                    }
                ]
            })),
            ..ReportArtifacts::default()
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::En);
        for expected in [
            "<a href=\"#observed-cves\">2</a>",
            "<section id=\"observed-cves\">",
            "CVE-2026-10001",
            "Templates",
            "nuclei-template-a, nuclei-template-b, nuclei-template-&lt;escaped&gt;",
            "<span class=\"badge\">KEV</span>",
            "Distinctive-path matches",
            "Generic-path matches",
            "1,234",
            "50.0%",
            "CVE-&amp;&lt;escaped&gt;",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        assert!(!html.contains("CVE-&<escaped>"));
        assert!(!html.contains("nuclei-template-<escaped>"));
        assert_eq!(html.matches("<th>").count(), 10);
        assert_eq!(html.matches("<td>").count(), 20);
        assert_eq!(
            cve_template_ids(&serde_json::json!({"template_ids": []})),
            "—"
        );
        for forbidden in ["http://", "https://", "src=", "<script"] {
            assert!(!html.contains(forbidden));
        }

        let japanese = render_report(&artifacts, 20, 240, ReportLanguage::Ja);
        assert!(japanese.contains("観測された CVE 数"));
        assert!(japanese.contains("テンプレート"));
        assert!(japanese.contains("検知可能性"));
        assert!(japanese.contains("保護ギャップ率"));

        let empty = ReportArtifacts {
            sanitized: Some(serde_json::json!({"cve_findings": []})),
            ..ReportArtifacts::default()
        };
        let empty_html = render_report(&empty, 20, 240, ReportLanguage::En);
        assert!(!empty_html.contains("href=\"#observed-cves\""));
        assert!(!empty_html.contains("<section id=\"observed-cves\">"));
    }

    #[test]
    fn sensitive_success_findings_render_as_an_escaped_priority_review_section() {
        let artifacts = ReportArtifacts {
            sensitive_success_findings: vec![SensitiveSuccessFinding {
                uri_path: Some("/.env?<script>alert(1)</script>".to_owned()),
                source_ip: Some("198.51.100.1<&".to_owned()),
                response_status: 200,
                timestamp: Some("2026-09-04T00:00:00+00:00".to_owned()),
            }],
            ..ReportArtifacts::default()
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::En);
        for expected in [
            "Sensitive file/config access with a success response",
            "/.env?&lt;script&gt;alert(1)&lt;/script&gt;",
            "198.51.100.1&lt;&amp;",
            ">200<",
            "Review these records with highest priority",
            "does not confirm that file contents were disclosed",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        assert!(!html.contains("<script>alert(1)</script>"));
        for forbidden in ["http://", "https://", "src=", "<script src"] {
            assert!(!html.contains(forbidden));
        }

        let japanese = render_report(&artifacts, 20, 240, ReportLanguage::Ja);
        assert!(japanese.contains("成功応答を返した秘密・設定ファイルアクセス"));
        assert!(
            japanese.contains("ファイル内容の開示や攻撃・悪用・侵害を断定するものではありません")
        );

        let empty = render_report(&ReportArtifacts::default(), 20, 240, ReportLanguage::En);
        assert!(!empty.contains("Sensitive file/config access with a success response"));
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
        assert!(
            status_details(&StatusClassCounts::default(), ReportLanguage::En)
                .contains("status 1xx:0")
        );
    }

    #[test]
    fn groups_integer_display_values_by_thousands() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1_000), "1,000");
        assert_eq!(group_thousands(1_234_567), "1,234,567");
        assert_eq!(group_thousands(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn timeline_has_intrinsic_dimensions_and_non_degenerate_polyline() {
        let series = vec![MinuteRequestCount {
            minute_epoch: 0,
            requests: 1,
        }];
        let html = timeline_chart("Timeline", &series, 240, ReportLanguage::En);
        assert!(html.contains("<svg width=\"1000\" height=\"220\""));
        assert!(html.contains("<polyline"));
        let points = html
            .split_once("<polyline class=\"timeline\" points=\"")
            .and_then(|(_, rest)| rest.split_once('\"'))
            .map(|(value, _)| value)
            .expect("timeline polyline points");
        assert!(points.split_whitespace().count() >= 2);
    }

    #[test]
    fn empty_timeline_explains_how_to_regenerate_the_series() {
        let html = timeline_chart("Timeline", &[], 240, ReportLanguage::En);
        assert!(html.contains("Re-run hunt or concentration with the current build"));
    }

    #[test]
    fn status_class_timeline_renders_five_lines_and_a_legend_without_external_refs() {
        let series = vec![
            StatusClassMinuteCount {
                minute_epoch: 0,
                informational: 1,
                success: 1_234,
                redirection: 2,
                client_error: 3,
                server_error: 4,
            },
            StatusClassMinuteCount {
                minute_epoch: 1,
                informational: 2,
                success: 5,
                redirection: 6,
                client_error: 7,
                server_error: 8,
            },
        ];
        let html = status_class_timeline_chart("Status timeline", &series, 240, ReportLanguage::En);
        assert_eq!(html.matches("<polyline class=\"status-line s").count(), 5);
        for expected in [
            "1xx Informational",
            "2xx Success",
            "3xx Redirection",
            "4xx Client error",
            "5xx Server error",
            "1,234",
        ] {
            assert!(html.contains(expected));
        }
        assert!(html.contains("width=\"1000\" height=\"220\""));
        for forbidden in ["http://", "https://", "src=", "<script"] {
            assert!(!html.contains(forbidden));
        }
    }

    #[test]
    fn empty_status_class_series_omits_its_report_section() {
        let mut concentration = synthetic_concentration("/a");
        concentration
            .status_class_requests_per_minute_series
            .clear();
        let artifacts = ReportArtifacts {
            sanitized: None,
            manifest: None,
            concentration: Some(concentration),
            triage: None,
            sensitive_success_findings: Vec::new(),
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::En);
        assert!(!html.contains("Requests per minute by HTTP status class"));

        let mut unavailable_only = synthetic_concentration("/a");
        unavailable_only.status_class_requests_per_minute_series = vec![StatusClassMinuteCount {
            minute_epoch: 0,
            ..StatusClassMinuteCount::default()
        }];
        let artifacts = ReportArtifacts {
            sanitized: None,
            manifest: None,
            concentration: Some(unavailable_only),
            triage: None,
            sensitive_success_findings: Vec::new(),
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::En);
        assert!(!html.contains("Requests per minute by HTTP status class"));
    }

    #[test]
    fn japanese_report_translates_human_labels_and_remains_self_contained() {
        let artifacts = ReportArtifacts {
            concentration: Some(synthetic_concentration("/a")),
            ..ReportArtifacts::default()
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::Ja);
        assert!(html.contains("<html lang=\"ja\">"));
        assert!(html.contains("集計サマリ"));
        assert!(html.contains("HTTP ステータスクラス別 1分ごとのリクエスト数"));
        assert!(html.contains("1xx 情報"));
        assert!(html.contains("DoS・攻撃・悪用・侵害・悪性確率・攻撃者特定の判定ではありません"));
        for forbidden in ["http://", "https://", "src=", "<script src"] {
            assert!(!html.contains(forbidden));
        }
    }

    #[test]
    fn concentration_provenance_derives_range_and_marks_nuclei_not_applicable() {
        // A concentration run has no Nuclei pass and no explicit filter bounds.
        let artifacts = ReportArtifacts {
            sanitized: Some(serde_json::json!({
                "report_kind": "SANITIZED_REQUEST_CONCENTRATION",
                "telemetry_profile": "apache-combined"
            })),
            manifest: None,
            concentration: Some(synthetic_concentration("/a")),
            triage: None,
            sensitive_success_findings: Vec::new(),
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::En);
        // Time range is derived from the observed minute series (epoch minutes 0..1).
        assert!(html.contains("1970-01-01T00:00:00+00:00"));
        assert!(html.contains("1970-01-01T00:01:00+00:00"));
        assert!(html.contains("Time range is the observed span"));
        // Nuclei revision reads as not applicable, not a bare "unavailable".
        assert!(html.contains("not applicable (no CVE pass)"));
    }

    #[test]
    fn timeline_columns_have_visible_css_readouts_and_native_title_fallbacks() {
        let series = vec![
            MinuteRequestCount {
                minute_epoch: 100,
                requests: 3,
            },
            MinuteRequestCount {
                minute_epoch: 101,
                requests: 7,
            },
        ];
        let html = timeline_chart("t", &series, 240, ReportLanguage::Ja);
        assert!(html.contains("<g class=\"col\">"));
        assert!(html.contains("<g class=\"tip\">"));
        assert!(html.contains("<text class=\"tip-label\""));
        assert!(html.contains("1970-01-01 01:40 · 3 リクエスト"));
        assert!(html.contains("<title>"));
        assert!(html.contains("class=\"timeline-dot\""));
        assert!(html.contains("<svg width=\"1000\" height=\"220\""));
        for forbidden in ["http://", "https://", "src=", "<script"] {
            assert!(!html.contains(forbidden));
        }
    }

    #[test]
    fn bar_rows_carry_native_hover_titles() {
        let rows = [BarRow {
            label: "/x",
            value: 1234,
            details: "d".to_owned(),
        }];
        let html = bar_chart("Top", &rows, ReportLanguage::En);
        assert!(html.contains("<rect class=\"bar\""));
        assert!(html.contains("<title>/x · 1,234 d</title>"));
    }

    #[test]
    fn long_bar_labels_expand_inside_the_scroll_container() {
        let label = format!("/{}", "segment".repeat(40));
        let rows = [BarRow {
            label: &label,
            value: 1,
            details: "d".to_owned(),
        }];
        let html = bar_chart("Top", &rows, ReportLanguage::En);
        assert!(html.contains("<div class=\"chart-scroll\">"));
        assert!(!html.contains("<svg width=\"1000\""));
        assert!(html.contains(&html_escape(&label)));
    }

    #[test]
    fn source_ip_focus_renders_ip_heading_and_path_breakdown() {
        let mut concentration = synthetic_concentration("/a");
        let focus = concentration.focus.as_mut().unwrap();
        focus.focus_kind = "source-ip".to_owned();
        focus.selector = "198.51.100.7".to_owned();
        focus.uri_path = "198.51.100.7".to_owned();
        focus.paths = vec![
            PrivateFocusPath {
                uri_path: "/a".to_owned(),
                requests: 5,
            },
            PrivateFocusPath {
                uri_path: "/b".to_owned(),
                requests: 2,
            },
        ];
        let artifacts = ReportArtifacts {
            sanitized: None,
            manifest: None,
            concentration: Some(concentration),
            triage: None,
            sensitive_success_findings: Vec::new(),
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::En);
        assert!(html.contains("Focused source IP"));
        assert!(html.contains("URI paths in focus"));
        assert!(html.contains("198.51.100.7"));
        assert!(html.contains("/a"));
        assert!(!html.contains("Focused-path observed peers"));
    }

    #[test]
    fn multiple_source_ip_focus_renders_the_per_ip_breakdown() {
        let mut concentration = synthetic_concentration("/a");
        let focus = concentration.focus.as_mut().unwrap();
        focus.focus_kind = "source-ip".to_owned();
        focus.selector = "198.51.100.1, 198.51.100.2".to_owned();
        focus.uri_path = focus.selector.clone();
        focus.sources = vec![
            PrivateFocusSource {
                source_ip: "198.51.100.1".to_owned(),
                requests: 5,
            },
            PrivateFocusSource {
                source_ip: "198.51.100.2".to_owned(),
                requests: 3,
            },
        ];
        let artifacts = ReportArtifacts {
            sanitized: None,
            manifest: None,
            concentration: Some(concentration),
            triage: None,
            sensitive_success_findings: Vec::new(),
        };
        let html = render_report(&artifacts, 20, 240, ReportLanguage::En);
        assert!(html.contains("Focused source IP"));
        assert!(html.contains("198.51.100.1, 198.51.100.2"));
        assert!(html.contains("Top observed connection peers"));
        assert!(html.contains("198.51.100.1"));
        assert!(html.contains("198.51.100.2"));
    }
}
