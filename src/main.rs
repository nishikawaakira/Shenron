mod commands;

use commands::hunt::{run_hunt, HuntArgs};

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, BufRead, BufReader},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use shenron::input_discovery::{discover_input_files, InputDiscoverySummary};

use shenron::{
    access_log::{parse_combined_line, AccessLogFormat},
    candidate::{
        build_batch_from_findings_with_sigma, compatibility as candidate_compatibility,
        export as export_candidate, load as load_candidate, replay as replay_candidate,
        save as save_candidate, save_batch, Backend,
    },
    comparison::{
        compare_runs_with_points, daily::DailyComparisonPoints, write_comparison,
        PrivateTemporalComparison, SanitizedTemporalComparison,
    },
    concentration::{
        FocusPrefixLengths, FocusSelector, PrivateRequestConcentrationReport,
        ResponseOutcomeSummary, WindowedResponseOutcomeSummary, DEFAULT_RATE_WINDOW_SECONDS,
        DEFAULT_RESPONSE_BUCKET_MINIMUM_REQUESTS, DEFAULT_RESPONSE_SUCCESS_SHARE_THRESHOLD_PERCENT,
    },
    cti_export::{export_run as export_cti_run, CtiExportFormat, TlpLevel},
    disposition::{
        record_disposition_with_review, AnalystDisposition, DispositionKey, DispositionReview,
        DispositionStore, DISPOSITION_SAFETY_NOTE,
    },
    event::{canonical_ip, TelemetryCapabilities, TelemetryProfile, TrustedProxy, TrustedProxySet},
    lab_cli::{run as run_lab_command, LabCommand},
    nuclei::{path_distinctiveness, PathDistinctiveness},
    output::{write_json_pretty, write_json_pretty_new},
    paths::{
        default_asn_dataset, default_kev_report, default_nuclei_report, default_reputation_dataset,
        default_templates_dir,
    },
    production::{
        ablation_with_optional_kev_and_filter as production_ablation,
        concentration_with_optional_output_and_source_prefixes as production_daily_concentration,
        concentration_with_optional_output_and_source_prefixes_detailed as production_daily_concentration_detailed,
        count_hypotheses_with_optional_kev_and_filter as production_count_hypotheses,
        explain_private_findings,
        historical_replay_with_optional_kev_and_filter as production_historical_replay,
        load_private_concentration, terminal_safe, AblationReport, ConcentrationTrackingLimits,
        CountHypothesisReport, HistoricalReplayReport, HuntFindingFormat, HuntTimeRange,
        SanitizedConcentrationReport, TemplateFilterOptions,
    },
    report::ReportLanguage,
    reputation::{load_asn_database, load_reputation_database, AsnDatabase, ReputationDatabase},
    sigma::load_explicit_rules,
    trend::{path_trend, PathTrendReport},
    triage::{
        asn_entity_groups, entity_groups, EntityDimension, TriagePolicy,
        DEFAULT_MAX_SEQUENCE_OBSERVATIONS, DEFAULT_SEQUENCE_WINDOW_SECONDS,
    },
    waf::sniff_gzip_reader,
};

#[derive(Debug, Parser)]
#[command(
    name = "shenron",
    version,
    about = "Passive historical web threat hunting"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
// CLI variants intentionally keep their typed arguments together. Boxing the
// entire production command would add dispatch indirection solely for enum size.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Read or explicitly compact private observation memory; never parses logs or contacts a service.
    ObservationStore {
        #[command(subcommand)]
        command: ObservationStoreCommand,
    },
    /// Prepare, inventory, generate, and validate public or synthetic inputs.
    /// Network access occurs only in explicitly invoked update/setup commands.
    #[command(flatten)]
    Lab(LabCommand),
    /// Report which user-provided rules are in the intentionally small MVP subset.
    ValidateRules {
        #[arg(long)]
        rules: PathBuf,
    },
    /// Record private analyst-authored dispositions for stable finding patterns.
    Disposition {
        #[command(subcommand)]
        command: DispositionCommand,
    },
    /// Read-only local hunting and aggregate analysis of historical web logs.
    /// These subcommands are flattened to the top level (for example
    /// `shenron hunt`); the separate `production` namespace exposes response-sizes only.
    #[command(flatten)]
    Production(ProductionCommand),
    /// Namespaced entry point for response-size measurements.
    #[command(name = "production")]
    ProductionNamespace {
        #[command(subcommand)]
        command: ResponseSizesCommand,
    },
    /// Build, review, and export defensive candidates. Never deploys controls.
    Candidate {
        #[command(subcommand)]
        command: CandidateCommand,
    },
    /// Convert an existing run into a local STIX 2.1 or MISP JSON file.
    /// Sanitized aggregates are the default; nothing is transmitted.
    Export {
        /// Existing hunt run directory. Source logs are not reprocessed.
        #[arg(long)]
        results_dir: PathBuf,
        #[arg(long, value_enum, default_value_t = CtiExportFormat::Stix)]
        format: CtiExportFormat,
        #[arg(long)]
        output: PathBuf,
        /// Include private observed connection-peer IPs and URI paths. Without
        /// this explicit opt-in, private findings are not read.
        #[arg(long)]
        include_observables: bool,
        /// Override the default marking (AMBER sanitized; RED with observables).
        #[arg(long, value_enum)]
        tlp: Option<TlpLevel>,
    },
}

#[derive(Debug, Subcommand)]
// Keep the infrequently constructed, typed CLI arguments together.
#[allow(clippy::large_enum_variant)]
enum DispositionCommand {
    /// Read private selected opinions and review metadata; never modifies the store.
    Read {
        #[arg(long)]
        store: PathBuf,
        #[command(flatten)]
        selection: DispositionSelectionArgs,
    },
    /// Append or update one analyst opinion. Repeating an identical opinion is idempotent.
    Set {
        #[arg(long)]
        store: PathBuf,
        #[arg(long, default_value = "nuclei")]
        source: String,
        #[arg(long)]
        template_id: String,
        #[arg(long)]
        method: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        query: Option<String>,
        #[arg(long, value_enum)]
        disposition: DispositionValue,
        #[arg(long)]
        comment: Option<String>,
        /// Exact private corpus scope. Unscoped opinions are never inherited by a scope.
        #[arg(long)]
        corpus_scope: Option<String>,
        #[arg(long)]
        reviewer: Option<String>,
        /// Private analyst-provided evidence run reference, not automatically verified.
        #[arg(long)]
        evidence_run: Option<String>,
        #[arg(long)]
        nuclei_revision: Option<String>,
        /// Explicit UTC review deadline. Does not automatically change the opinion.
        #[arg(long, value_parser = parse_rfc3339_utc)]
        review_after: Option<DateTime<Utc>>,
    },
}

#[derive(Debug, Default, Args)]
struct DispositionSelectionArgs {
    /// Exact analyst-defined scope; no cross-scope or unscoped fallback.
    #[arg(long)]
    disposition_scope: Option<String>,
    /// Evaluate review deadlines at this explicit UTC time, never the system clock.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    disposition_as_of: Option<DateTime<Utc>>,
}

impl DispositionSelectionArgs {
    fn load(self, path: Option<&Path>) -> Result<Option<DispositionStore>> {
        let active = self.disposition_scope.is_some() || self.disposition_as_of.is_some();
        let Some(path) = path else {
            if active {
                anyhow::bail!("disposition scope/as-of requires --disposition-store");
            }
            return Ok(None);
        };
        let store =
            DispositionStore::load(path)?.select(self.disposition_scope, self.disposition_as_of);
        let summary = store.review_summary();
        if active
            || summary.entries_excluded_by_scope > 0
            || summary.entries_with_review_deadline > 0
        {
            eprintln!(
                "Analyst opinion selection (store entries, not matching requests): {}",
                serde_json::to_string(&summary)?
            );
            eprintln!("Exact scope only; excluded opinions are not applied. Review deadlines do not change analyst opinions or finding counts; no deadline evaluation without explicit --disposition-as-of.");
        }
        Ok(Some(store))
    }
}

#[derive(Debug, Subcommand)]
enum ObservationStoreCommand {
    /// Print PRIVATE prefix/ASN recurrence and analyst labels as JSON. Does not modify the store.
    Read {
        #[arg(long)]
        store: PathBuf,
        /// Maximum entities, ordered by runs observed; 0 displays all.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Keep each entity's latest cumulative snapshot in a NEW private store; never overwrites either file.
    Compact {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DispositionValue {
    Reviewed,
    Expected,
    NeedsReview,
}

impl From<DispositionValue> for AnalystDisposition {
    fn from(value: DispositionValue) -> Self {
        match value {
            DispositionValue::Reviewed => Self::Reviewed,
            DispositionValue::Expected => Self::Expected,
            DispositionValue::NeedsReview => Self::NeedsReview,
        }
    }
}

#[derive(Debug, Subcommand)]
enum CandidateCommand {
    /// Evaluate one frozen candidate across explicitly selected corpora; does not authorize export.
    Evaluate {
        #[arg(long)]
        candidate: PathBuf,
        /// Private JSON cohort plan; relative input paths resolve against its parent directory.
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Maximum displayed matching paths/peers per cohort. Caps and omissions are disclosed.
        #[arg(long, default_value = "20", value_parser = parse_positive_usize)]
        limit: usize,
    },
    /// Build narrow candidates from private hunt findings. AWS WAF BLOCK and URI-only findings are excluded by default.
    Build {
        #[arg(long)]
        from_findings: PathBuf,
        /// Narrow candidates by frozen observed-peer IP/CIDR membership. Private local input.
        #[arg(long)]
        source_address_set: Option<PathBuf>,
        /// Existing operator-maintained IPv4 WAF IP set reference. No set is created.
        #[arg(long, requires = "source_address_set")]
        source_ip_set_v4_arn: Option<String>,
        /// Existing operator-maintained IPv6 WAF IP set reference. No set is created.
        #[arg(long, requires = "source_address_set")]
        source_ip_set_v6_arn: Option<String>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        telemetry: InputFormat,
        /// Include URI-only response-unverified findings. Use only after human review or with additional evidence.
        #[arg(long)]
        include_response_unverified: bool,
        /// Build a separate Sigma TTP candidate class from faithfully translatable literal rules.
        #[arg(long)]
        include_sigma_ttp: bool,
        /// Sigma rules used to interpret matched Sigma finding IDs. Required with --include-sigma-ttp.
        #[arg(long, requires = "include_sigma_ttp")]
        rules: Option<PathBuf>,
    },
    /// Evaluate a candidate against local historical telemetry and write a new candidate file.
    Replay {
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
        format: InputFormat,
        #[arg(long)]
        output: PathBuf,
    },
    /// Explain backend compatibility without writing any configuration.
    Compatibility {
        #[arg(long)]
        candidate: PathBuf,
        /// Override the candidate's recorded telemetry profile.
        #[arg(long, value_enum)]
        telemetry: Option<InputFormat>,
    },
    /// Display candidate evidence and conditions for human review.
    Explain {
        #[arg(long)]
        candidate: PathBuf,
        /// Override the candidate's recorded telemetry profile.
        #[arg(long, value_enum)]
        telemetry: Option<InputFormat>,
    },
    /// Export a review-only configuration and sanitized evidence sidecar. Never deploys it.
    Export {
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long, value_enum)]
        backend: CandidateBackend,
        #[arg(long)]
        output: PathBuf,
        /// Override the candidate's recorded telemetry profile.
        #[arg(long, value_enum)]
        telemetry: Option<InputFormat>,
        /// Required for AWS WAF/Terraform because Shenron cannot infer WebACL priority.
        #[arg(long)]
        priority: Option<u32>,
        #[arg(long, default_value_t = 99_001)]
        ossec_rule_id: u32,
    },
}

#[derive(Debug, Clone, Default, Args)]
struct ConcentrationLimitArgs {
    /// Maximum retained URI paths (default: 100000). Higher caps use more memory.
    #[arg(long, value_parser = parse_positive_usize)]
    max_paths: Option<usize>,
    /// Maximum retained observed sources (default: 1000000).
    #[arg(long, value_parser = parse_positive_usize)]
    max_source_ips: Option<usize>,
    /// Maximum retained source/path pairs (default: 2000000).
    #[arg(long, value_parser = parse_positive_usize)]
    max_source_path_pairs: Option<usize>,
    /// Maximum retained first path segments per source and set (default: 256).
    /// Higher caps use more memory; only segment counts enter artifacts.
    #[arg(long, value_parser = parse_positive_usize)]
    max_source_segments: Option<usize>,
}

#[derive(Debug, Clone, Default, Args)]
struct SourcePrefixArgs {
    /// Enable private corpus-wide peer-prefix aggregation, using this IPv4
    /// length (0..=32). If only IPv6 is specified, IPv4 defaults to 24.
    #[arg(long, value_parser = parse_ipv4_prefix_length, requires = "output")]
    source_prefix_bits: Option<u8>,
    /// Enable private corpus-wide peer-prefix aggregation, using this IPv6
    /// length (0..=128). If only IPv4 is specified, IPv6 defaults to 48.
    #[arg(long, value_parser = parse_ipv6_prefix_length, requires = "output")]
    source_prefix_bits_v6: Option<u8>,
    /// Maximum distinct paths per source prefix (default: 5000). Requires
    /// source-prefix aggregation; higher caps use more memory.
    #[arg(long, value_parser = parse_positive_usize)]
    max_paths_per_source_prefix: Option<usize>,
    /// Maximum retained prefix/path pairs overall (default: 10000000).
    /// Requires source-prefix aggregation; zero never means unlimited.
    #[arg(long, value_parser = parse_positive_usize)]
    max_source_prefix_path_pairs: Option<usize>,
    /// Maximum distinct names in the shared prefix path table (default: 10000000).
    /// Independent of --max-paths; requires source-prefix aggregation.
    #[arg(long, value_parser = parse_positive_usize)]
    max_source_prefix_paths: Option<usize>,
}

impl SourcePrefixArgs {
    fn tracking_limits(
        &self,
        tracking: Option<ConcentrationTrackingLimits>,
    ) -> anyhow::Result<Option<ConcentrationTrackingLimits>> {
        if self.max_paths_per_source_prefix.is_none()
            && self.max_source_prefix_path_pairs.is_none()
            && self.max_source_prefix_paths.is_none()
        {
            return Ok(tracking);
        }
        if self.resolve().is_none() {
            anyhow::bail!(
                "prefix path limits require --source-prefix-bits or --source-prefix-bits-v6"
            );
        }
        let mut tracking = tracking.unwrap_or_default();
        tracking.max_paths_per_source_prefix = self.max_paths_per_source_prefix;
        tracking.max_source_prefix_path_pairs = self.max_source_prefix_path_pairs;
        tracking.max_source_prefix_paths = self.max_source_prefix_paths;
        Ok(Some(tracking))
    }

    fn resolve(&self) -> Option<FocusPrefixLengths> {
        if self.source_prefix_bits.is_none() && self.source_prefix_bits_v6.is_none() {
            return None;
        }
        let defaults = FocusPrefixLengths::default();
        Some(FocusPrefixLengths {
            ipv4: self.source_prefix_bits.unwrap_or(defaults.ipv4),
            ipv6: self.source_prefix_bits_v6.unwrap_or(defaults.ipv6),
        })
    }
}

impl ConcentrationLimitArgs {
    fn resolve(&self) -> Option<ConcentrationTrackingLimits> {
        if self.max_paths.is_none()
            && self.max_source_ips.is_none()
            && self.max_source_path_pairs.is_none()
            && self.max_source_segments.is_none()
        {
            return None;
        }
        let defaults = ConcentrationTrackingLimits::default();
        Some(ConcentrationTrackingLimits {
            max_paths: self.max_paths.unwrap_or(defaults.max_paths),
            max_source_ips: self.max_source_ips.unwrap_or(defaults.max_source_ips),
            max_source_path_pairs: self
                .max_source_path_pairs
                .unwrap_or(defaults.max_source_path_pairs),
            max_source_segments: self
                .max_source_segments
                .unwrap_or(defaults.max_source_segments),
            ..defaults
        })
    }
}

#[derive(Debug, Clone, Default, Args)]
struct TemplateFilterArgs {
    /// JSON allowlist with `vendors`, `products`, and/or `tags` arrays. Known
    /// template metadata must match at least one listed value.
    #[arg(long, value_name = "PATH")]
    template_allowlist: Option<PathBuf>,
    /// JSON denylist with `vendors`, `products`, and/or `tags` arrays. A match
    /// excludes the template and takes precedence over an allowlist match.
    #[arg(long, value_name = "PATH")]
    template_denylist: Option<PathBuf>,
    /// Exclude templates whose frozen report declares no vendor, product, or
    /// tag metadata. Unknown metadata is included by default.
    #[arg(long)]
    exclude_unknown_template_metadata: bool,
}

impl TemplateFilterArgs {
    fn into_options(self) -> TemplateFilterOptions {
        TemplateFilterOptions {
            allowlist: self.template_allowlist,
            denylist: self.template_denylist,
            exclude_unknown_metadata: self.exclude_unknown_template_metadata,
        }
    }

    fn is_active(&self) -> bool {
        self.template_allowlist.is_some()
            || self.template_denylist.is_some()
            || self.exclude_unknown_template_metadata
    }
}

#[derive(Debug, Subcommand)]
// Hunt intentionally keeps its typed options together; boxing the filter
// arguments would add indirection solely to reduce the enum's stack size.
#[allow(clippy::large_enum_variant)]
enum ProductionCommand {
    /// Match operator-provided indicators against local history without inferring compromise.
    Ioc(IocArgs),
    /// Measure request spellings and command-local parse recovery, without inferring intent.
    RequestAnomalies(RequestAnomaliesArgs),
    /// Observe paths with few successful sources and prior probe-shaped activity.
    RareSuccess(RareSuccessArgs),
    /// Count bounded field-value frequencies without inferring intent or automation.
    Stack(StackArgs),
    /// Compare request-adjusted response sizes without inferring content or disclosure.
    ResponseSizes(ResponseSizesArgs),
    /// Count bounded identifier variations without inferring authorization or intent.
    IdentifierAccess(IdentifierAccessArgs),
    /// Describe bounded per-source request shapes, not attack or blocking decisions.
    ProbeSources(ProbeSourcesArgs),
    /// Review all requests (including non-matches) by observed peers, optionally within UTC bounds.
    Context(ContextArgs),
    /// Hunt web logs with Nuclei and/or Sigma. Without --output, private findings are written only to stdout.
    Hunt(HuntArgs),
    /// Compare two existing local run-artifact directories without re-streaming logs.
    Compare(CompareArgs),
    /// Measure bounded request-volume distribution without CTI inputs or detector matching.
    Concentration(ConcentrationArgs),
    /// Print a lightweight aggregate-only daily volume summary. No artifacts
    /// are written unless --output is explicitly supplied.
    Daily(DailyArgs),
    /// Read one private URI path across existing concentration run artifacts.
    /// Raw logs are not opened or reprocessed.
    Trend {
        /// Existing run directory. Repeat to compare multiple artifacts; input
        /// order is normalized for deterministic output.
        #[arg(long, required = true)]
        results_dir: Vec<PathBuf>,
        /// Private URI path to extract. Supplying this value is the explicit
        /// opt-in to print the path and its retained per-run measurements.
        #[arg(long)]
        path: String,
        #[arg(long, value_enum, default_value_t = TrendOutputFormat::Text)]
        output_format: TrendOutputFormat,
    },
    /// Compare aggregate match volume across predicates derived from one validated Nuclei IR. Never writes private findings.
    Ablation(AblationArgs),
    /// Compare broad-to-narrow validated Nuclei conditions as local COUNT-mode simulations. Never deploys a control.
    CountHypotheses(CountHypothesesArgs),
    /// Measure validated Nuclei matcher coverage and other aggregate historical matches. Never writes private findings.
    Replay(ReplayArgs),
    /// Show CVE/template mappings from a locally stored private findings file.
    Explain(ExplainArgs),
}

#[derive(Debug, clap::Args)]
struct ExplainArgs {
    #[command(flatten)]
    disposition_selection: DispositionSelectionArgs,
    #[arg(long)]
    findings: PathBuf,
    /// Restrict results to a WAF enforcement outcome. nginx/Apache findings have an unknown outcome.
    #[arg(long, value_enum)]
    waf_outcome: Option<WafOutcomeFilter>,
    /// Include URI-only matches on generic paths such as /robots.txt.
    #[arg(long)]
    include_generic: bool,
    /// Display matched method, path, and query. This may expose sensitive request values.
    #[arg(long)]
    show_request: bool,
    /// Display all private evidence captured by hunt, including IP, host,
    /// headers, JA3/JA4, WAF labels/rule IDs, and request ID. Implies --show-request.
    #[arg(long)]
    show_evidence: bool,
    /// Summarize source IP addresses from the selected private findings.
    #[arg(long)]
    show_source_ips: bool,
    /// Summarize selected findings by locally resolved ASN. Uses a prepared default dataset when available.
    #[arg(long)]
    show_asn: bool,
    /// Local ASN CSV or Shenron range TSV used only to enrich displayed IP groups.
    #[arg(long)]
    asn_dataset: Option<PathBuf>,
    /// Local JSONL third-party reputation opinions used only to enrich displayed IP groups.
    #[arg(long)]
    reputation_dataset: Option<PathBuf>,
    /// Private append-only analyst disposition store used only to group
    /// retained findings by analyst-authored review state.
    #[arg(long)]
    disposition_store: Option<PathBuf>,
    /// Summarize JA4 TLS client fingerprints from the selected private findings.
    #[arg(long)]
    show_fingerprints: bool,
    /// Matching observations required for breadth-based triage (default: 3).
    #[arg(long, value_parser = parse_positive_usize)]
    triage_breadth_observations: Option<usize>,
    /// Distinct templates required for breadth-based triage (default: 2).
    #[arg(long, value_parser = parse_positive_usize)]
    triage_breadth_templates: Option<usize>,
    /// Matching observations required for depth-based triage (default: 10).
    #[arg(long, value_parser = parse_positive_usize)]
    triage_depth_observations: Option<usize>,
    /// Evaluate repeated behavior within this sliding duration (for example 10m, 1h, or 2d).
    #[arg(long, value_parser = parse_triage_duration)]
    #[arg(value_delimiter = ',')]
    triage_window: Vec<Duration>,
    /// Window for ordered request-sequence context (default: 10s).
    #[arg(long, value_parser = parse_triage_duration)]
    sequence_window: Option<Duration>,
    /// Maximum individual findings to display. Use 0 to display all findings.
    #[arg(long, default_value_t = 20)]
    limit: usize,
    /// Write the report to a file instead of stdout. Private analyst output.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Output format. `json` emits the same content the text mode was asked
    /// to show, honoring the same --show-* gates.
    #[arg(long, value_enum, default_value_t = ExplainOutputFormat::Text)]
    output_format: ExplainOutputFormat,
}

#[derive(Debug, clap::Args)]
struct ConcentrationArgs {
    #[command(flatten)]
    source_prefixes: SourcePrefixArgs,
    #[command(flatten)]
    tracking_limits: ConcentrationLimitArgs,
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    /// Directory for the private detail and sanitized aggregate artifacts.
    #[arg(long)]
    output: PathBuf,
    /// Verbatim analyst annotation stored only in the private run manifest.
    #[arg(long)]
    corpus_label: Option<String>,
    /// Focus the private source-IP breakdown on this exact URI path.
    #[arg(long, conflicts_with_all = ["path_prefix", "source_ip"])]
    path: Option<String>,
    /// Focus on this path and everything under it (`/api` covers `/api` and
    /// `/api/...`), listing the sub-paths and observed connection peers.
    #[arg(long, conflicts_with_all = ["path", "source_ip"])]
    path_prefix: Option<String>,
    /// Focus on one or more observed connection-peer IPs, listing the union
    /// of URI paths they requested. Repeat the flag or separate IPs by commas.
    /// This is volume context, not attacker attribution.
    #[arg(long, value_delimiter = ',', conflicts_with_all = ["path", "path_prefix"])]
    source_ip: Vec<String>,
    /// IPv4 prefix length for private focus-path address-block aggregation (default: 24).
    #[arg(long, value_parser = parse_ipv4_prefix_length)]
    ipv4_group_prefix: Option<u8>,
    /// IPv6 prefix length for private focus-path address-block aggregation (default: 48).
    #[arg(long, value_parser = parse_ipv6_prefix_length)]
    ipv6_group_prefix: Option<u8>,
    /// Local GeoLite2-ASN-compatible CSV or Shenron ASN range TSV for private
    /// focus/prefix grouping. Prefix groups also use an existing default dataset.
    /// The default TSV covers IPv4 only; use CSV with IPv6 networks for IPv6.
    /// No network lookup is performed.
    #[arg(long)]
    asn_dataset: Option<PathBuf>,
    /// UTC bucket widths evaluated simultaneously for request-rate shape.
    /// Repeat or comma-separate durations such as 1m,10m,1h,1d.
    #[arg(long, value_delimiter = ',', value_parser = parse_triage_duration)]
    rate_window: Vec<Duration>,
    /// Minimum requests required before a rate bucket contributes response
    /// outcome minima/maxima. This is an inclusion floor, not an alert.
    #[arg(long, default_value_t = DEFAULT_RESPONSE_BUCKET_MINIMUM_REQUESTS, value_parser = clap::value_parser!(u64).range(1..))]
    response_bucket_min_requests: u64,
    /// Count eligible buckets strictly below this success-share percentage.
    /// This is a descriptive count, not a classification or alert.
    #[arg(long, default_value_t = DEFAULT_RESPONSE_SUCCESS_SHARE_THRESHOLD_PERCENT, value_parser = clap::value_parser!(u8).range(0..=100))]
    response_success_share_threshold_percent: u8,
    /// Inclusive UTC start time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    /// Inclusive UTC end time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    /// Private file-level index used to skip unchanged, previously
    /// processed files. The current report covers only files processed now.
    #[arg(long)]
    processed_index: Option<PathBuf>,
    /// Ignore --processed-index entries and process every discovered file.
    #[arg(long, requires = "processed_index")]
    reprocess_all: bool,
    /// Display raw URI paths from the private artifact.
    #[arg(long)]
    show_paths: bool,
    /// Display observed connection-peer IPs from the private artifact.
    #[arg(long)]
    show_source_ips: bool,
    /// Maximum private path/IP entries to display. Use 0 to display all.
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Debug, clap::Args)]
struct ContextArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long, required = true, value_delimiter = ',')]
    source_ip: Vec<IpAddr>,
    /// Inclusive lower UTC bound; omit for no lower time limit.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    /// Inclusive upper UTC bound; omit for no upper time limit.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    #[arg(long, default_value = "10000", value_parser = parse_positive_usize)]
    max_records: usize,
    /// Opt in to private request records on stdout; default stdout is counts only.
    #[arg(long)]
    show_request: bool,
    /// Include sensitive query and Referer values in private output. Requires --show-request.
    #[arg(long, requires = "show_request")]
    show_query: bool,
    /// Write a private context artifact, never a sanitized report.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct CompareArgs {
    /// Add explicit frozen reference runs to the baseline set; repeat for multiple runs.
    /// Reports equal-weight median/min/max, not an inferred normal range.
    #[arg(long)]
    reference_run: Vec<PathBuf>,
    /// Disclose recorded coverage/settings differences without inferring comparability.
    #[arg(long)]
    compare_conditions: bool,
    /// Opt in to daily measurement deltas and descriptive comparison points,
    /// not classifications or alerts. No PATH uses four documented defaults;
    /// a JSON file supplies explicit points. Omit for the legacy comparison.
    #[arg(long, num_args = 0..=1, value_name = "PATH")]
    comparison_points: Option<Option<PathBuf>>,
    #[arg(long)]
    baseline: PathBuf,
    #[arg(long)]
    current: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    show_entities: bool,
    #[arg(long)]
    show_paths: bool,
    #[arg(long)]
    show_source_ips: bool,
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Debug, clap::Args)]
struct DailyArgs {
    #[command(flatten)]
    source_prefixes: SourcePrefixArgs,
    #[command(flatten)]
    tracking_limits: ConcentrationLimitArgs,
    /// Local ASN dataset for explicitly enabled private source-prefix groups.
    /// The default TSV covers IPv4 only; use CSV with IPv6 networks for IPv6.
    #[arg(long, requires = "output")]
    asn_dataset: Option<PathBuf>,
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    /// Write the normal private and sanitized concentration artifacts.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Verbatim analyst annotation stored only in the private run manifest.
    #[arg(long, requires = "output")]
    corpus_label: Option<String>,
    /// Machine-readable aggregate-only output.
    #[arg(long, value_enum, default_value_t = DailyOutputFormat::Text)]
    output_format: DailyOutputFormat,
    /// UTC bucket widths evaluated simultaneously. Repeat or comma-separate
    /// durations such as 1m,10m,1h,1d.
    #[arg(long, value_delimiter = ',', value_parser = parse_triage_duration)]
    rate_window: Vec<Duration>,
    /// Minimum requests required before a rate bucket contributes response
    /// outcome minima/maxima. This is an inclusion floor, not an alert.
    #[arg(long, default_value_t = DEFAULT_RESPONSE_BUCKET_MINIMUM_REQUESTS, value_parser = clap::value_parser!(u64).range(1..))]
    response_bucket_min_requests: u64,
    /// Count eligible buckets strictly below this success-share percentage.
    /// This is a descriptive count, not a classification or alert.
    #[arg(long, default_value_t = DEFAULT_RESPONSE_SUCCESS_SHARE_THRESHOLD_PERCENT, value_parser = clap::value_parser!(u8).range(0..=100))]
    response_success_share_threshold_percent: u8,
    /// Inclusive UTC start time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    /// Inclusive UTC end time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    /// Private file-level index used to skip unchanged, previously
    /// processed files. The current summary covers only files processed now.
    #[arg(long)]
    processed_index: Option<PathBuf>,
    /// Ignore --processed-index entries and process every discovered file.
    #[arg(long, requires = "processed_index")]
    reprocess_all: bool,
}

#[derive(Debug, clap::Args)]
struct ProbeSourcesArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    /// Write private source detail/provenance and a separate counts-only report.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Inclusive lower UTC bound; undated rows are disclosed and excluded.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    /// Inclusive upper UTC bound.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    /// Verify forwarded clients only behind these peers; keep identities separate.
    #[arg(long, value_name = "IP_OR_CIDR")]
    trusted_proxy: Vec<TrustedProxy>,
    /// Opt in to private address values and per-source evidence on stdout.
    #[arg(long)]
    show_source_ips: bool,
    /// Also show bounded private example paths; never show query values.
    #[arg(long, requires = "show_source_ips")]
    show_paths: bool,
    #[arg(long, default_value = "20", value_parser = parse_positive_usize)]
    limit: usize,
    #[arg(long, value_enum, default_value_t = DailyOutputFormat::Text)]
    output_format: DailyOutputFormat,
    #[command(flatten)]
    options: shenron::probe_sources::Options,
}

#[derive(Debug, clap::Args)]
struct StackArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    /// Also count verified clients without merging them with observed peers.
    #[arg(long, value_name = "IP_OR_CIDR")]
    trusted_proxy: Vec<TrustedProxy>,
    /// Opt in to private values; stdout truncation never changes the artifact.
    #[arg(long)]
    show_values: bool,
    #[arg(long, value_enum, default_value_t = DailyOutputFormat::Text)]
    output_format: DailyOutputFormat,
    #[command(flatten)]
    options: shenron::stack::Options,
}

#[derive(Debug, clap::Args)]
struct RareSuccessArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    /// Verify forwarded clients only behind explicitly trusted peers.
    #[arg(long, value_name = "IP_OR_CIDR")]
    trusted_proxy: Vec<TrustedProxy>,
    #[arg(long)]
    show_paths: bool,
    #[arg(long)]
    show_source_ips: bool,
    #[arg(long, value_enum, default_value_t = DailyOutputFormat::Text)]
    output_format: DailyOutputFormat,
    #[command(flatten)]
    options: shenron::rare_success::Options,
}

#[derive(Debug, clap::Args)]
struct RequestAnomaliesArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    #[arg(long)]
    show_examples: bool,
    #[arg(long)]
    show_source_ips: bool,
    #[arg(long, value_enum, default_value_t = DailyOutputFormat::Text)]
    output_format: DailyOutputFormat,
    #[command(flatten)]
    options: shenron::request_anomalies::Options,
}

#[derive(Debug, clap::Args)]
struct IocArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    /// Local TSV or STIX bundle; repeat to combine files. Values stay private.
    #[arg(long, required = true)]
    indicators: Vec<PathBuf>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    /// Include only forwarded clients verified against these connection peers.
    #[arg(long, value_name = "IP_OR_CIDR")]
    trusted_proxy: Vec<TrustedProxy>,
    /// Opt in to private indicator values and bounded request evidence on stdout.
    #[arg(long)]
    show_matches: bool,
    /// Maximum retained match records to display; zero displays all retained records.
    #[arg(long, default_value_t = 20)]
    limit: usize,
    #[command(flatten)]
    options: shenron::ioc::Options,
}

#[derive(Debug, clap::Args)]
struct IdentifierAccessArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    /// Private analyst annotation, recorded verbatim in the manifest.
    #[arg(long)]
    corpus_label: Option<String>,
    #[arg(long, value_name = "IP_OR_CIDR")]
    trusted_proxy: Vec<TrustedProxy>,
    #[arg(long)]
    show_paths: bool,
    #[arg(long)]
    show_source_ips: bool,
    /// Number of entries to display; zero displays all retained report entries.
    #[arg(long, default_value_t = 20)]
    limit: usize,
    #[command(flatten)]
    options: shenron::identifier_access::Options,
}

#[derive(Debug, clap::Args)]
struct ReplayArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long)]
    nuclei_templates: Option<PathBuf>,
    #[arg(long)]
    nuclei_report: Option<PathBuf>,
    #[command(flatten)]
    template_filter: TemplateFilterArgs,
    #[arg(long)]
    kev_report: Option<PathBuf>,
    /// Local private findings from a prior hunt; read only to establish conservative coverage.
    #[arg(long)]
    findings: PathBuf,
    /// Optional aggregate-only JSON report destination.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Inclusive UTC start time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    /// Inclusive UTC end time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
}

#[derive(Debug, clap::Args)]
struct CountHypothesesArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long)]
    nuclei_templates: Option<PathBuf>,
    #[arg(long)]
    nuclei_report: Option<PathBuf>,
    #[command(flatten)]
    template_filter: TemplateFilterArgs,
    #[arg(long)]
    kev_report: Option<PathBuf>,
    /// Local private findings from a prior hunt; read only for conservative coverage.
    #[arg(long)]
    findings: PathBuf,
    /// Optional aggregate-only JSON report destination.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Inclusive UTC start time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    /// Inclusive UTC end time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    /// Maximum CVE ladders to display. Use 0 to display all.
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Debug, clap::Args)]
struct AblationArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    format: InputFormat,
    #[arg(long)]
    nuclei_templates: Option<PathBuf>,
    #[arg(long)]
    nuclei_report: Option<PathBuf>,
    #[command(flatten)]
    template_filter: TemplateFilterArgs,
    #[arg(long)]
    kev_report: Option<PathBuf>,
    /// Optional aggregate-only JSON report destination.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Inclusive UTC start time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    /// Inclusive UTC end time in RFC 3339 format.
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
}

/// The rendering format for `production explain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExplainOutputFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum ResponseSizesCommand {
    /// Compare request-adjusted sizes and character positions from a local corpus.
    ResponseSizes(ResponseSizesArgs),
}

#[derive(Debug, clap::Args)]
struct ResponseSizesArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = InputFormat::NginxPostdata)]
    format: InputFormat,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    from: Option<DateTime<Utc>>,
    #[arg(long, value_parser = parse_rfc3339_utc)]
    to: Option<DateTime<Utc>>,
    #[arg(long, value_name = "IP_OR_CIDR")]
    trusted_proxy: Vec<TrustedProxy>,
    #[arg(long)]
    show_source_ips: bool,
    #[arg(long)]
    show_expressions: bool,
    /// Maximum expression rows to display; zero displays all.
    #[arg(long, default_value_t = 20)]
    limit: usize,
    #[command(flatten)]
    options: shenron::response_sizes::Options,
}

fn run_response_sizes(args: ResponseSizesArgs) -> Result<()> {
    let report = shenron::response_sizes::run(
        &args.input,
        args.format.telemetry_profile_for_input(&args.input)?,
        &HuntTimeRange {
            from: args.from,
            to: args.to,
        },
        &TrustedProxySet::new(args.trusted_proxy),
        &args.options,
        &args.output,
    )?;
    shenron::response_sizes::write_text(
        io::stdout().lock(),
        &report,
        args.show_source_ips,
        args.show_expressions,
        args.limit,
    )
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InputFormat {
    /// Detect AWS WAF, ALB, headered CloudFront or vhost-prefixed Apache logs; ambiguous Combined logs require an explicit format.
    Auto,
    /// AWS WAF JSON logs.
    AwsWaf,
    /// Application Load Balancer access logs.
    Alb,
    /// Legacy CloudFront standard TSV logs, with optional #Fields headers.
    Cloudfront,
    /// Standard nginx Combined Log Format.
    Nginx,
    /// Explicit nginx Combined plus content type, TLS, request time and postdata body.
    NginxPostdata,
    /// Apache standard Combined or vhost-prefixed Combined, detected per line.
    Apache,
    /// Apache vhost-prefixed Combined only; a leading vhost is required.
    ApacheVhost,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CandidateBackend {
    AwsWafJson,
    TerraformAwsWaf,
    Ossec,
}
impl CandidateBackend {
    fn backend(self) -> Backend {
        match self {
            Self::AwsWafJson => Backend::AwsWafJson,
            Self::TerraformAwsWaf => Backend::TerraformAwsWaf,
            Self::Ossec => Backend::Ossec,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WafOutcomeFilter {
    /// The WAF recorded BLOCK for the matching request.
    Block,
    /// The WAF recorded an action other than BLOCK, such as ALLOW or COUNT.
    NotBlocked,
    /// No WAF action was recorded by the telemetry source.
    Unknown,
}

impl WafOutcomeFilter {
    fn matches(self, finding: &shenron::production::FindingExplanation) -> bool {
        match (self, finding.waf_action.as_deref()) {
            (Self::Block, Some(action)) => action.eq_ignore_ascii_case("BLOCK"),
            (Self::NotBlocked, Some(action)) => !action.eq_ignore_ascii_case("BLOCK"),
            (Self::Unknown, None) => true,
            _ => false,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::NotBlocked => "not-blocked",
            Self::Unknown => "unknown",
        }
    }
}

impl InputFormat {
    fn explicit_telemetry_profile(self) -> Result<TelemetryProfile> {
        match self {
            Self::Auto => anyhow::bail!(
                "auto format selection requires an input log path; pass an explicit telemetry format"
            ),
            Self::AwsWaf => Ok(TelemetryProfile::AwsWaf),
            Self::Alb => Ok(TelemetryProfile::Alb),
            Self::Cloudfront => Ok(TelemetryProfile::CloudFront),
            Self::Nginx => Ok(TelemetryProfile::NginxCombined),
            Self::NginxPostdata => Ok(TelemetryProfile::NginxPostdata),
            Self::Apache => Ok(TelemetryProfile::ApacheCombined),
            Self::ApacheVhost => Ok(TelemetryProfile::ApacheVhostCombined),
        }
    }

    fn telemetry_profile_for_input(self, input: &Path) -> Result<TelemetryProfile> {
        resolve_input_format(input, self)?.explicit_telemetry_profile()
    }
}

const AUTO_DETECTION_RECORD_LIMIT_PER_FILE: usize = 1_000;
const AUTO_DETECTION_ERROR: &str = "Could not determine the input format safely.\nPass --format aws-waf, nginx, apache, or apache-vhost.";

#[derive(Debug, Default)]
struct DetectedInputFormats {
    aws_waf: bool,
    alb: bool,
    cloudfront: bool,
    standard_combined: bool,
    apache_vhost: bool,
}

fn resolve_input_format(input: &Path, requested: InputFormat) -> Result<InputFormat> {
    if !matches!(requested, InputFormat::Auto) {
        return Ok(requested);
    }

    let detected = detect_input_formats(input)?;
    if detected.alb || detected.cloudfront {
        if detected.aws_waf
            || detected.standard_combined
            || detected.apache_vhost
            || (detected.alb && detected.cloudfront)
        {
            anyhow::bail!(AUTO_DETECTION_ERROR);
        }
        return Ok(if detected.alb {
            InputFormat::Alb
        } else {
            InputFormat::Cloudfront
        });
    }
    match (
        detected.aws_waf,
        detected.standard_combined,
        detected.apache_vhost,
    ) {
        (true, false, false) => Ok(InputFormat::AwsWaf),
        (false, _, true) => Ok(InputFormat::Apache),
        _ => anyhow::bail!(AUTO_DETECTION_ERROR),
    }
}

fn detect_input_formats(input: &Path) -> Result<DetectedInputFormats> {
    let discovery = discover_input_files(input, None)?;
    let mut detected = DetectedInputFormats::default();
    for path in discovery.files {
        let mut records_examined = 0;
        let reader = sniff_gzip_reader(
            File::open(&path).with_context(|| format!("opening {}", path.display()))?,
        )?;
        let mut cloudfront_version = false;
        for (line_index, line) in BufReader::new(reader).lines().enumerate() {
            let line = line.with_context(|| format!("reading {}", path.display()))?;
            let line = line.trim();
            if line_index == 0 && line == "#Version: 1.0" {
                cloudfront_version = true;
            }
            if line_index == 1 && cloudfront_version && line.starts_with("#Fields:") {
                detected.cloudfront = true;
            }
            if line.is_empty() {
                continue;
            }
            records_examined += 1;
            if line.split_once(' ').is_some_and(|(kind, rest)| {
                matches!(kind, "http" | "https" | "h2" | "grpcs" | "ws" | "wss")
                    && rest.split_once(' ').is_some_and(|(time, _)| {
                        time.ends_with('Z') && DateTime::parse_from_rfc3339(time).is_ok()
                    })
            }) {
                detected.alb = true;
            } else if is_aws_waf_record(line) {
                detected.aws_waf = true;
            } else if parse_combined_line(line, AccessLogFormat::ApacheVhostCombined).is_ok() {
                detected.apache_vhost = true;
            } else if parse_combined_line(line, AccessLogFormat::NginxCombined).is_ok() {
                // Standard nginx and Apache Combined Log Format have the same
                // shape. Do not assign a source identity without user input.
                detected.standard_combined = true;
            }
            if records_examined >= AUTO_DETECTION_RECORD_LIMIT_PER_FILE {
                break;
            }
        }
    }
    Ok(detected)
}

fn is_aws_waf_record(raw: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.get("httpRequest").cloned())
        .is_some_and(|request| request.is_object())
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Jsonl,
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DailyOutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TrendOutputFormat {
    Text,
    Json,
}

#[derive(Debug, Serialize)]
struct DailyVolumeSummary {
    waf: Option<shenron::waf_summary::WafSummary>,
    source_segment_diversity: Option<shenron::concentration::SourceSegmentDiversitySummary>,
    report_kind: &'static str,
    safety_note: &'static str,
    telemetry_profile: TelemetryProfile,
    files_analyzed: usize,
    #[serde(flatten)]
    input_discovery: InputDiscoverySummary,
    total_requests: usize,
    distinct_source_ips: usize,
    top_path_request_share: Option<f64>,
    top_path_distinct_source_ips: Option<usize>,
    top_path_requests_per_source_ip: Option<f64>,
    request_rates: Vec<shenron::concentration::WindowedRequestRateSummary>,
    parse_errors: usize,
    requests_outside_time_range: usize,
    requests_without_timestamp_excluded: usize,
    paths_beyond_tracking_cap: u64,
    source_ips_beyond_tracking_cap: u64,
    source_path_pairs_beyond_tracking_cap: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_prefix_path_pairs_beyond_tracking_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_prefix_path_tracking: Option<shenron::concentration::SourcePrefixPathTracking>,
    processed_index_enabled: bool,
    files_skipped_as_processed: usize,
    response_outcomes: Option<ResponseOutcomeSummary>,
    response_outcome_windows: Option<Vec<WindowedResponseOutcomeSummary>>,
    response_status_codes: Option<shenron::concentration::StatusCodeCounts>,
}

impl DailyVolumeSummary {
    fn from_report(report: &SanitizedConcentrationReport, processed_index_enabled: bool) -> Self {
        let concentration = &report.request_concentration;
        Self {
            report_kind: "DAILY_REQUEST_VOLUME_SUMMARY",
            waf: concentration.waf.clone(),
            source_segment_diversity: concentration.source_segment_diversity.clone(),
            safety_note: "Aggregate request-volume and response-outcome measurements only. Response shares are counts of what the log recorded: low success can also result from redirects, authentication, health checks, early client disconnects, a slow backend, or an unavailable origin. These values are not thresholds, alerts, or determinations of outage, degraded availability, automation, denial of service, attack, abuse, compromise, or attacker identity. Source IP counts describe observed connection peers and may include CDN, load-balancer, NAT, or proxy addresses.",
            telemetry_profile: report.telemetry_profile,
            files_analyzed: report.files_analyzed,
            input_discovery: report.input_discovery.clone(),
            total_requests: report.total_requests_analyzed,
            distinct_source_ips: concentration.distinct_source_ips,
            top_path_request_share: concentration.top_path.as_ref().map(|item| item.request_share),
            top_path_distinct_source_ips: concentration
                .top_path
                .as_ref()
                .map(|item| item.distinct_source_ips),
            top_path_requests_per_source_ip: concentration
                .top_path
                .as_ref()
                .map(|item| item.requests_per_source_ip),
            request_rates: concentration.request_rates.clone(),
            parse_errors: report.parse_errors,
            requests_outside_time_range: report.requests_outside_time_range,
            requests_without_timestamp_excluded: report.requests_without_timestamp_excluded,
            paths_beyond_tracking_cap: concentration.paths_beyond_tracking_cap,
            source_ips_beyond_tracking_cap: concentration.source_ips_beyond_tracking_cap,
            source_path_pairs_beyond_tracking_cap: concentration
                .source_path_pairs_beyond_tracking_cap,
            source_prefix_path_pairs_beyond_tracking_cap: None,
            source_prefix_path_tracking: None,
            processed_index_enabled,
            files_skipped_as_processed: report.files_skipped_as_processed,
            response_outcomes: concentration.response_outcomes.clone(),
            response_outcome_windows: concentration.response_outcome_windows.clone(),
            response_status_codes: concentration.response_status_codes.clone(),
        }
    }
}

impl OutputFormat {
    fn hunt_format(self) -> HuntFindingFormat {
        match self {
            Self::Jsonl => HuntFindingFormat::Jsonl,
            Self::Csv => HuntFindingFormat::Csv,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ObservationStore { command } => run_observation_store(command),
        Command::Lab(command) => run_lab_command(command),
        Command::ValidateRules { rules } => validate(&rules),
        Command::Disposition { command } => run_disposition(command),
        Command::ProductionNamespace {
            command: ResponseSizesCommand::ResponseSizes(args),
        } => run_response_sizes(args),
        Command::Production(command) => match command {
            ProductionCommand::Ioc(args) => run_ioc(args),
            ProductionCommand::RequestAnomalies(args) => run_request_anomalies(args),
            ProductionCommand::RareSuccess(args) => run_rare_success(args),
            ProductionCommand::Stack(args) => run_stack(args),
            ProductionCommand::ResponseSizes(args) => run_response_sizes(args),
            ProductionCommand::IdentifierAccess(args) => run_identifier_access(args),
            ProductionCommand::ProbeSources(args) => run_probe_sources(args),
            ProductionCommand::Context(args) => run_context(args),
            ProductionCommand::Hunt(args) => run_hunt(args),
            ProductionCommand::Compare(args) => run_compare(args),
            ProductionCommand::Concentration(args) => run_concentration(args),
            ProductionCommand::Daily(args) => run_daily(args),
            ProductionCommand::Trend {
                results_dir,
                path,
                output_format,
            } => run_trend(results_dir, path, output_format),
            ProductionCommand::Ablation(args) => run_ablation(args),
            ProductionCommand::Replay(args) => run_replay(args),
            ProductionCommand::CountHypotheses(args) => run_count_hypotheses(args),
            ProductionCommand::Explain(args) => run_explain(args),
        },
        Command::Export {
            results_dir,
            format,
            output,
            include_observables,
            tlp,
        } => run_export(results_dir, format, output, include_observables, tlp),
        Command::Candidate { command } => run_candidate(command),
    }
}

fn run_explain(args: ExplainArgs) -> Result<()> {
    let ExplainArgs {
        disposition_selection,
        findings,
        waf_outcome,
        include_generic,
        show_request,
        show_evidence,
        show_source_ips,
        show_asn,
        asn_dataset,
        reputation_dataset,
        disposition_store,
        show_fingerprints,
        triage_breadth_observations,
        triage_breadth_templates,
        triage_depth_observations,
        triage_window,
        sequence_window,
        limit,
        output,
        output_format,
    } = args;
    let asn_dataset = resolve_optional_local_dataset(asn_dataset, default_asn_dataset);
    let reputation_dataset =
        resolve_optional_local_dataset(reputation_dataset, default_reputation_dataset);
    let asn_database = asn_dataset.as_deref().map(load_asn_database).transpose()?;
    let reputation_database = reputation_dataset
        .as_deref()
        .map(load_reputation_database)
        .transpose()?;
    let findings = explain_private_findings(&findings)?;
    let disposition_store = disposition_selection.load(disposition_store.as_deref())?;
    // Bound the reachable behavior-score maximum by what the source
    // profiles can express. Union across recorded sources; legacy
    // findings without a source fall back to the full-capability
    // default so they are never penalized.
    let capabilities = findings
        .iter()
        .filter_map(|finding| {
            finding
                .log_source
                .map(|source| source.telemetry_profile().capabilities())
        })
        .reduce(TelemetryCapabilities::union)
        .unwrap_or_default();
    // The --waf-outcome filter is an explicit analyst selection, so
    // it bounds everything downstream. The full waf-filtered set is
    // what triage grouping and scoring see.
    let grouped: Vec<_> = match waf_outcome {
        Some(filter) => findings
            .into_iter()
            .filter(|finding| filter.matches(finding))
            .collect(),
        None => findings,
    };
    // The low-confidence generic filter is display-only: it changes
    // what is listed, never what is grouped or scored. `hidden` is
    // disclosed; `listed` drives the per-finding rows and the path
    // summary; `grouped` drives entity grouping and scoring.
    let hidden: Vec<_> = if include_generic {
        Vec::new()
    } else {
        grouped
            .iter()
            .filter(|finding| is_low_confidence_generic_match(finding))
            .cloned()
            .collect()
    };
    let listed: Vec<_> = if include_generic {
        grouped.clone()
    } else {
        grouped
            .iter()
            .filter(|finding| !is_low_confidence_generic_match(finding))
            .cloned()
            .collect()
    };
    let analyst_dispositions = disposition_store
        .as_ref()
        .map(|store| disposition_counts(&grouped, store));
    let display = ExplainDisplay {
        show_request: show_request || show_evidence,
        show_evidence,
        show_source_ips,
        show_asn,
        show_fingerprints,
    };
    let triage = TriageContext {
        policy: TriagePolicy::with_windows(
            triage_breadth_observations,
            triage_breadth_templates,
            triage_depth_observations,
            triage_window,
        )
        .with_sequence_settings(
            sequence_window.unwrap_or_else(|| Duration::from_secs(DEFAULT_SEQUENCE_WINDOW_SECONDS)),
            DEFAULT_MAX_SEQUENCE_OBSERVATIONS,
        ),
        capabilities,
    };
    match output_format {
        ExplainOutputFormat::Json => {
            let report = build_explain_report(
                &listed,
                &grouped,
                &hidden,
                &display,
                waf_outcome.map(WafOutcomeFilter::label),
                limit,
                triage,
                asn_database.as_ref(),
                reputation_database.as_ref(),
                analyst_dispositions.clone(),
            );
            let json = serde_json::to_string_pretty(&report)?;
            match output {
                Some(path) => {
                    std::fs::write(&path, json)
                        .with_context(|| format!("writing explain report {}", path.display()))?;
                    eprintln!("Explain report (JSON) written to: {}", path.display());
                }
                None => println!("{json}"),
            }
        }
        ExplainOutputFormat::Text => {
            if output.is_some() {
                anyhow::bail!(
                    "--output writes a file only for --output-format json; the human-readable text report is written to stdout. Redirect it with `>`, or pass --output-format json to write --output."
                );
            }
            if !hidden.is_empty() {
                let hidden_cves = hidden
                    .iter()
                    .flat_map(|finding| finding.cves.iter())
                    .collect::<BTreeSet<_>>();
                println!(
                    "Hidden {} low-confidence matches (response-unverified on generic paths such as /robots.txt), spanning {} CVEs. Pass --include-generic to show them.",
                    hidden.len(),
                    hidden_cves.len()
                );
            }
            print_analyst_dispositions(analyst_dispositions.as_ref());
            print_explanations(
                &listed,
                &grouped,
                !hidden.is_empty(),
                display,
                waf_outcome.map(WafOutcomeFilter::label),
                limit,
                triage,
                asn_database.as_ref(),
                reputation_database.as_ref(),
            );
        }
    }
    Ok(())
}

fn run_concentration(args: ConcentrationArgs) -> Result<()> {
    let ConcentrationArgs {
        source_prefixes,
        tracking_limits,
        input,
        format,
        output,
        corpus_label,
        path,
        path_prefix,
        source_ip,
        ipv4_group_prefix,
        ipv6_group_prefix,
        asn_dataset,
        rate_window,
        response_bucket_min_requests,
        response_success_share_threshold_percent,
        from,
        to,
        processed_index,
        reprocess_all,
        show_paths,
        show_source_ips,
        limit,
    } = args;
    // clap enforces that at most one focus selector kind is set.
    // Normalize repeated and comma-delimited source values into one
    // deterministic set; empty elements do not create a focus.
    let source_ips = source_ip
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    let focus = if let Some(path) = path {
        Some(FocusSelector::ExactPath(path))
    } else if let Some(prefix) = path_prefix {
        Some(FocusSelector::PathPrefix(prefix))
    } else if source_ips.is_empty() {
        None
    } else {
        Some(FocusSelector::SourceIp(source_ips))
    };
    // Address-block grouping applies to a path or path-prefix focus,
    // which aggregate connection peers; source-IP focuses already
    // have an analyst-selected peer set.
    let groups_path_focus = matches!(
        focus,
        Some(FocusSelector::ExactPath(_) | FocusSelector::PathPrefix(_))
    );
    if !groups_path_focus && (ipv4_group_prefix.is_some() || ipv6_group_prefix.is_some()) {
        anyhow::bail!(
            "--ipv4-group-prefix and --ipv6-group-prefix require --path or --path-prefix"
        );
    }
    let default_prefixes = FocusPrefixLengths::default();
    let focus_prefix_lengths = FocusPrefixLengths {
        ipv4: ipv4_group_prefix.unwrap_or(default_prefixes.ipv4),
        ipv6: ipv6_group_prefix.unwrap_or(default_prefixes.ipv6),
    };
    let asn_database = asn_dataset.as_deref().map(load_asn_database).transpose()?;
    let rate_window_seconds = normalized_rate_windows(rate_window);
    let report = production_daily_concentration(
        &input,
        Some(&output),
        format.telemetry_profile_for_input(&input)?,
        HuntTimeRange { from, to },
        focus.clone(),
        focus_prefix_lengths,
        asn_database.as_ref(),
        &rate_window_seconds,
        show_paths,
        processed_index.as_deref(),
        reprocess_all,
        response_bucket_min_requests,
        response_success_share_threshold_percent,
        corpus_label,
        source_prefixes.tracking_limits(tracking_limits.resolve())?,
        source_prefixes.resolve(),
    )?;
    let private_path = output.join("request-concentration.json");
    let private =
        (show_paths || show_source_ips || focus.is_some() || source_prefixes.resolve().is_some())
            .then(|| load_private_concentration(&private_path))
            .transpose()?;
    print_concentration(
        &report,
        &output.join("sanitized-research.json"),
        private.as_ref(),
        show_paths,
        show_source_ips,
        limit,
        focus.as_ref(),
    );
    print_processed_index_scope(processed_index.is_some(), report.files_skipped_as_processed);
    Ok(())
}

fn run_context(args: ContextArgs) -> Result<()> {
    let ContextArgs {
        input,
        format,
        source_ip,
        from,
        to,
        max_records,
        show_request,
        show_query,
        output,
    } = args;
    if let Some(path) = &output {
        shenron::production::ensure_separate_output(&input, path)?;
    }
    let result = shenron::investigation::request_context(
        &input,
        format.telemetry_profile_for_input(&input)?,
        &shenron::investigation::ContextOptions {
            source_ips: source_ip.into_iter().collect(),
            from,
            to,
            maximum_records: max_records,
            include_query: show_query,
        },
    )?;
    if let Some(path) = output {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        write_json_pretty(&path, &result)?;
        shenron::input_discovery::write_discovery_manifest(&path, &result.counts.input_discovery)?;
        eprintln!("{}", shenron::investigation::SAFETY_NOTE);
    }
    print_input_discovery(&result.counts.input_discovery, true);
    if show_request {
        eprintln!("{}", shenron::investigation::SAFETY_NOTE);
        serde_json::to_writer_pretty(io::stdout().lock(), &result)?;
    } else {
        serde_json::to_writer_pretty(io::stdout().lock(), &result.counts)?;
    }
    println!();
    eprintln!("{}", result.retention_note);
    if result.counts.records_beyond_cap > 0 {
        eprintln!(
            "{} record(s) beyond the cap were omitted; narrow the window or raise --max-records.",
            result.counts.records_beyond_cap
        );
    }
    Ok(())
}

fn run_compare(args: CompareArgs) -> Result<()> {
    let CompareArgs {
        reference_run,
        compare_conditions,
        comparison_points,
        baseline,
        current,
        output,
        show_entities,
        show_paths,
        show_source_ips,
        limit,
    } = args;
    shenron::production::ensure_separate_output(&baseline, &output)?;
    shenron::production::ensure_separate_output(&current, &output)?;
    for reference in &reference_run {
        shenron::production::ensure_separate_output(reference, &output)?;
    }
    let points = comparison_points
        .map(|path| -> Result<DailyComparisonPoints> {
            match path {
                None => Ok(DailyComparisonPoints::default()),
                Some(path) => serde_json::from_reader(File::open(&path)?)
                    .with_context(|| format!("reading comparison points {}", path.display())),
            }
        })
        .transpose()?;
    let mut comparison = compare_runs_with_points(&baseline, &current, points)?;
    if !reference_run.is_empty() {
        comparison.sanitized.reference_distribution =
            Some(shenron::comparison::references::compare_reference_runs(
                &baseline,
                &reference_run,
                &current,
            )?);
    }
    if compare_conditions {
        comparison.sanitized.measurement_conditions = Some(
            shenron::comparison::conditions::compare_conditions(&baseline, &current)?,
        );
    }
    write_comparison(&output, &comparison)?;
    print_temporal_comparison(
        &comparison.sanitized,
        &comparison.private,
        show_entities,
        show_paths,
        show_source_ips,
        limit,
    );
    Ok(())
}

fn run_daily(args: DailyArgs) -> Result<()> {
    let DailyArgs {
        source_prefixes,
        tracking_limits,
        asn_dataset,
        input,
        format,
        output,
        corpus_label,
        output_format,
        rate_window,
        response_bucket_min_requests,
        response_success_share_threshold_percent,
        from,
        to,
        processed_index,
        reprocess_all,
    } = args;
    if asn_dataset.is_some() && source_prefixes.resolve().is_none() {
        anyhow::bail!(
            "--asn-dataset requires --source-prefix-bits or --source-prefix-bits-v6 for daily"
        );
    }
    let asn_database = asn_dataset.as_deref().map(load_asn_database).transpose()?;
    let rate_window_seconds = normalized_rate_windows(rate_window);
    let telemetry_profile = format.telemetry_profile_for_input(&input)?;
    let outcome = production_daily_concentration_detailed(
        &input,
        output.as_deref(),
        telemetry_profile,
        HuntTimeRange { from, to },
        None,
        FocusPrefixLengths::default(),
        asn_database.as_ref(),
        &rate_window_seconds,
        false,
        processed_index.as_deref(),
        reprocess_all,
        response_bucket_min_requests,
        response_success_share_threshold_percent,
        corpus_label,
        source_prefixes.tracking_limits(tracking_limits.resolve())?,
        source_prefixes.resolve(),
    )?;
    let mut summary =
        DailyVolumeSummary::from_report(&outcome.sanitized, processed_index.is_some());
    summary.source_prefix_path_pairs_beyond_tracking_cap = outcome
        .prefix_path_pairs_beyond_cap
        .filter(|count| *count > 0);
    summary.source_prefix_path_tracking = outcome.prefix_path_tracking;
    match output_format {
        DailyOutputFormat::Text => print_daily_volume_summary(&summary, output.as_deref()),
        DailyOutputFormat::Json => {
            print_input_discovery(&summary.input_discovery, true);
            serde_json::to_writer_pretty(io::stdout().lock(), &summary)?;
            println!();
        }
    }
    Ok(())
}

fn run_stack(args: StackArgs) -> Result<()> {
    let report = shenron::stack::run(
        &args.input,
        args.format.telemetry_profile_for_input(&args.input)?,
        &HuntTimeRange {
            from: args.from,
            to: args.to,
        },
        &TrustedProxySet::new(args.trusted_proxy),
        &args.options,
        args.output.as_deref(),
    )?;
    match args.output_format {
        DailyOutputFormat::Text => shenron::stack::write_text(
            io::stdout().lock(),
            &report,
            args.show_values,
            &args.options,
        ),
        DailyOutputFormat::Json => {
            serde_json::to_writer_pretty(
                io::stdout().lock(),
                &shenron::stack::display(&report, args.show_values, &args.options),
            )?;
            println!();
            Ok(())
        }
    }
}

fn run_rare_success(args: RareSuccessArgs) -> Result<()> {
    let report = shenron::rare_success::run(
        &args.input,
        args.format.telemetry_profile_for_input(&args.input)?,
        &HuntTimeRange {
            from: args.from,
            to: args.to,
        },
        &TrustedProxySet::new(args.trusted_proxy),
        &args.options,
        args.output.as_deref(),
    )?;
    match args.output_format {
        DailyOutputFormat::Text => shenron::rare_success::write_text(
            io::stdout().lock(),
            &report,
            args.show_paths,
            args.show_source_ips,
            args.options.limit,
        ),
        DailyOutputFormat::Json => {
            serde_json::to_writer_pretty(
                io::stdout().lock(),
                &shenron::rare_success::display(
                    &report,
                    args.show_paths,
                    args.show_source_ips,
                    args.options.limit,
                ),
            )?;
            println!();
            Ok(())
        }
    }
}

fn run_request_anomalies(args: RequestAnomaliesArgs) -> Result<()> {
    let report = shenron::request_anomalies::run(
        &args.input,
        args.format.telemetry_profile_for_input(&args.input)?,
        &HuntTimeRange {
            from: args.from,
            to: args.to,
        },
        &args.options,
        args.output.as_deref(),
    )?;
    match args.output_format {
        DailyOutputFormat::Text => shenron::request_anomalies::write_text(
            io::stdout().lock(),
            &report,
            args.show_examples,
            args.show_source_ips,
        ),
        DailyOutputFormat::Json => {
            serde_json::to_writer_pretty(
                io::stdout().lock(),
                &shenron::request_anomalies::display(
                    &report,
                    args.show_examples,
                    args.show_source_ips,
                ),
            )?;
            println!();
            Ok(())
        }
    }
}

fn run_ioc(args: IocArgs) -> Result<()> {
    let report = shenron::ioc::run(
        &args.input,
        args.format.telemetry_profile_for_input(&args.input)?,
        &HuntTimeRange {
            from: args.from,
            to: args.to,
        },
        &TrustedProxySet::new(args.trusted_proxy),
        &args.indicators,
        &args.options,
        args.output.as_deref(),
    )?;
    shenron::ioc::write_text(io::stdout().lock(), &report, args.show_matches, args.limit)
}

fn run_probe_sources(args: ProbeSourcesArgs) -> Result<()> {
    let ProbeSourcesArgs {
        input,
        format,
        output,
        from,
        to,
        trusted_proxy,
        show_source_ips,
        show_paths,
        limit,
        output_format,
        options,
    } = args;
    let report = shenron::probe_sources::run(
        &input,
        format.telemetry_profile_for_input(&input)?,
        &HuntTimeRange { from, to },
        &TrustedProxySet::new(trusted_proxy),
        &options,
        output.as_deref(),
    )?;
    let json = matches!(output_format, DailyOutputFormat::Json);
    if json {
        print_input_discovery(&report.summary.input_discovery, true);
        let view = shenron::probe_sources::display(&report, show_source_ips, show_paths, limit);
        serde_json::to_writer_pretty(io::stdout().lock(), &view)?;
        println!();
    } else {
        shenron::probe_sources::write_text(
            io::stdout().lock(),
            &report,
            show_source_ips,
            show_paths,
            limit,
        )?;
    }
    Ok(())
}

fn run_identifier_access(args: IdentifierAccessArgs) -> Result<()> {
    let IdentifierAccessArgs {
        input,
        format,
        output,
        from,
        to,
        corpus_label,
        trusted_proxy,
        show_paths,
        show_source_ips,
        limit,
        options,
    } = args;
    let report = shenron::identifier_access::run(
        &input,
        format.telemetry_profile_for_input(&input)?,
        &HuntTimeRange { from, to },
        &options,
        &output,
        corpus_label.as_deref(),
        &TrustedProxySet::new(trusted_proxy),
    )?;
    shenron::identifier_access::write_text(
        io::stdout().lock(),
        &report,
        show_paths,
        show_source_ips,
        limit,
    )
}

fn run_replay(args: ReplayArgs) -> Result<()> {
    let ReplayArgs {
        input,
        format,
        nuclei_templates,
        nuclei_report,
        template_filter,
        kev_report,
        findings,
        output,
        from,
        to,
    } = args;
    let (nuclei_templates, nuclei_report) = resolve_nuclei_inputs(nuclei_templates, nuclei_report)?;
    let kev_report = resolve_optional_local_dataset(kev_report, default_kev_report);
    if let Some(path) = output.as_deref() {
        shenron::production::ensure_separate_output(&input, path)?;
    }
    let report = production_historical_replay(
        &input,
        &nuclei_templates,
        &nuclei_report,
        kev_report.as_deref(),
        &findings,
        format.telemetry_profile_for_input(&input)?,
        HuntTimeRange { from, to },
        &template_filter.into_options(),
    )?;
    if let Some(path) = output.as_deref() {
        write_json_pretty(path, &report)?;
        shenron::input_discovery::write_discovery_manifest(path, &report.input_discovery)?;
    }
    print_historical_replay(&report, output.as_deref());
    Ok(())
}

fn run_count_hypotheses(args: CountHypothesesArgs) -> Result<()> {
    let CountHypothesesArgs {
        input,
        format,
        nuclei_templates,
        nuclei_report,
        template_filter,
        kev_report,
        findings,
        output,
        from,
        to,
        limit,
    } = args;
    let (nuclei_templates, nuclei_report) = resolve_nuclei_inputs(nuclei_templates, nuclei_report)?;
    let kev_report = resolve_optional_local_dataset(kev_report, default_kev_report);
    if let Some(path) = output.as_deref() {
        shenron::production::ensure_separate_output(&input, path)?;
    }
    let report = production_count_hypotheses(
        &input,
        &nuclei_templates,
        &nuclei_report,
        kev_report.as_deref(),
        &findings,
        format.telemetry_profile_for_input(&input)?,
        HuntTimeRange { from, to },
        &template_filter.into_options(),
    )?;
    if let Some(path) = output.as_deref() {
        write_json_pretty(path, &report)?;
        shenron::input_discovery::write_discovery_manifest(path, &report.input_discovery)?;
    }
    print_count_hypotheses(&report, output.as_deref(), limit);
    Ok(())
}

fn run_ablation(args: AblationArgs) -> Result<()> {
    let AblationArgs {
        input,
        format,
        nuclei_templates,
        nuclei_report,
        template_filter,
        kev_report,
        output,
        from,
        to,
    } = args;
    let (nuclei_templates, nuclei_report) = resolve_nuclei_inputs(nuclei_templates, nuclei_report)?;
    let kev_report = resolve_optional_local_dataset(kev_report, default_kev_report);
    let report = production_ablation(
        &input,
        &nuclei_templates,
        &nuclei_report,
        kev_report.as_deref(),
        format.telemetry_profile_for_input(&input)?,
        HuntTimeRange { from, to },
        &template_filter.into_options(),
    )?;
    if let Some(path) = output.as_deref() {
        write_json_pretty(path, &report)?;
        shenron::input_discovery::write_discovery_manifest(path, &report.input_discovery)?;
    }
    print_ablation(&report, output.as_deref());
    Ok(())
}

fn run_observation_store(command: ObservationStoreCommand) -> Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    match command {
        ObservationStoreCommand::Read { store, limit } => serde_json::to_writer_pretty(
            &mut stdout,
            &shenron::observation_store::read_observation_store(&store, limit)?,
        )?,
        ObservationStoreCommand::Compact { store, output } => serde_json::to_writer_pretty(
            &mut stdout,
            &shenron::observation_store::compact_observation_store(&store, &output)?,
        )?,
    }
    io::Write::write_all(&mut stdout, b"\n")?;
    Ok(())
}

fn run_disposition(command: DispositionCommand) -> Result<()> {
    match command {
        DispositionCommand::Read { store, selection } => {
            let store = selection.load(Some(&store))?.expect("explicit store");
            eprintln!("{DISPOSITION_SAFETY_NOTE}");
            serde_json::to_writer_pretty(io::stdout().lock(), &store.selected_entries())?;
            println!();
            Ok(())
        }
        DispositionCommand::Set {
            store,
            source,
            template_id,
            method,
            path,
            query,
            disposition,
            comment,
            corpus_scope,
            reviewer,
            evidence_run,
            nuclei_revision,
            review_after,
        } => {
            let mut key =
                DispositionKey::new(&source, &template_id, &method, &path, query.as_deref());
            key.corpus_scope = corpus_scope;
            let review = (reviewer.is_some()
                || evidence_run.is_some()
                || nuclei_revision.is_some()
                || review_after.is_some())
            .then_some(DispositionReview {
                reviewer,
                evidence_run,
                nuclei_revision,
                review_after,
            });
            let result =
                record_disposition_with_review(&store, key, disposition.into(), comment, review)?;
            println!(
                "Private analyst disposition store: {}\n  Already recorded: {}\n  Effective pattern dispositions: {}",
                store.display(),
                result.already_recorded,
                result.effective_entries,
            );
            println!("{DISPOSITION_SAFETY_NOTE}");
            Ok(())
        }
    }
}

fn run_candidate(command: CandidateCommand) -> Result<()> {
    match command {
        CandidateCommand::Build {
            from_findings,
            source_address_set,
            source_ip_set_v4_arn,
            source_ip_set_v6_arn,
            output,
            telemetry,
            include_response_unverified,
            include_sigma_ttp,
            rules,
        } => {
            let findings = explain_private_findings(&from_findings)?;
            let sigma_rules = if include_sigma_ttp {
                let rules = rules
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("--include-sigma-ttp requires --rules <DIR>"))?;
                let ruleset = load_explicit_rules(rules)?;
                if ruleset.supported.is_empty() {
                    anyhow::bail!(
                        "no supported Sigma rules were found under {}",
                        rules.display()
                    );
                }
                Some(ruleset)
            } else {
                None
            };
            let (mut candidates, stats) = build_batch_from_findings_with_sigma(
                &findings,
                telemetry.explicit_telemetry_profile()?,
                include_response_unverified,
                sigma_rules
                    .as_ref()
                    .map(|ruleset| ruleset.supported.as_slice()),
            );
            if candidates.is_empty() {
                anyhow::bail!(
                    "no candidate patterns could be built from the supplied findings; response-unverified and Sigma findings are excluded by default, and Sigma rules must be faithfully translatable"
                );
            }
            if let Some(path) = source_address_set {
                shenron::production::ensure_separate_output(&path, &output)?;
                let set = shenron::address_set::FrozenAddressSet::load(
                    &path,
                    source_ip_set_v4_arn,
                    source_ip_set_v6_arn,
                )?;
                println!("Frozen source-address set: {} retained networks; {} invalid records excluded; {} duplicate records; {} comment/empty records skipped.\n{}", set.networks.len(), set.invalid_records, set.duplicate_records, set.comment_or_empty_records, shenron::address_set::ADDRESS_SET_NOTE);
                for candidate in &mut candidates {
                    shenron::candidate::with_source_address_set(candidate, set.clone());
                }
            }
            save_batch(&candidates, &output)?;
            println!("Candidates written: {}\nSigma TTP candidates (separate evidence class): {}\nOutput directory: {}\nSigma findings excluded without explicit opt-in: {}\nSigma findings skipped because the source rule was missing or not faithfully translatable: {}\nAWS WAF BLOCK findings excluded: {}\nResponse-unverified findings excluded: {}\nFindings skipped for missing method/path: {}\nRecommended initial action: COUNT\nHistorical replay: required before preventive export.\nSigma TTP candidates represent literal rule matches, not CVE evidence or a determination of attack, exploitation, or compromise.", stats.candidates, stats.sigma_candidates, output.display(), stats.excluded_sigma_findings, stats.skipped_sigma_findings_untranslatable, stats.excluded_blocked_findings, stats.excluded_response_unverified_findings, stats.skipped_incomplete_findings);
            Ok(())
        }
        CandidateCommand::Replay {
            candidate,
            input,
            format,
            output,
        } => {
            let candidate = replay_candidate(
                load_candidate(&candidate)?,
                &input,
                format.telemetry_profile_for_input(&input)?,
                &output,
            )?;
            save_candidate(&candidate, &output)?;
            let discovery =
                InputDiscoverySummary::from_skipped(candidate.evidence.skipped_input_files.clone());
            print_input_discovery(&discovery, false);
            shenron::input_discovery::write_discovery_manifest(&output, &discovery)?;
            if candidate.evidence.source_address_unavailable > 0
                || candidate.evidence.source_address_invalid > 0
            {
                println!("Source-address evaluation excluded: {} missing peer addresses; {} invalid peer addresses. These observations cannot establish membership.", candidate.evidence.source_address_unavailable, candidate.evidence.source_address_invalid);
            }
            println!("Historical replay complete. Candidate written: {}\nRequests evaluated: {}\nOther historical matches: {}\nPreventive export remains COUNT-only.", output.display(), candidate.evidence.historical_requests_evaluated, candidate.evidence.other_historical_matches);
            Ok(())
        }
        CandidateCommand::Evaluate {
            candidate,
            plan,
            output,
            limit,
        } => {
            for input in [&candidate, &plan] {
                shenron::production::ensure_separate_output(input, &output)?;
            }
            let inputs: shenron::candidate::evaluation::EvaluationPlan =
                serde_json::from_reader(File::open(&plan)?)?;
            for corpus in inputs.corpora {
                let input = if corpus.input.is_absolute() {
                    corpus.input
                } else {
                    plan.parent().unwrap_or(Path::new(".")).join(corpus.input)
                };
                shenron::production::ensure_separate_output(&input, &output)?;
            }
            let result = shenron::candidate::evaluation::evaluate(&candidate, &plan, limit)?;
            if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            write_json_pretty_new(&output, &result)?;
            eprintln!("{}", result.safety_note);
            let discovery = InputDiscoverySummary::from_skipped(
                result
                    .corpora
                    .iter()
                    .flat_map(|row| row.skipped_input_files.clone())
                    .collect(),
            );
            print_input_discovery(&discovery, false);
            shenron::input_discovery::write_discovery_manifest(&output, &discovery)?;
            for (index, row) in result.corpora.iter().enumerate() {
                println!("Cohort {}: parsed {} / malformed {} / matched {} / match share {} (source missing/invalid exclusions: {}/{}; absent condition fields: {}; overlapping whole files: {}; displayed path/peer omissions: {}/{})", index + 1, row.parseable_records, row.parse_errors, row.matching_records, row.match_share.map(|v| format!("{:.2}%", v*100.0)).unwrap_or_else(|| "unavailable".into()), row.source_address_unavailable, row.source_address_invalid, row.records_with_absent_condition_fields, row.files_with_identical_bytes_in_another_cohort, row.retained_paths_omitted_from_display, row.retained_peers_omitted_from_display);
                println!(
                    "  Tracking-cap omissions (paths / sources / pairs): {} / {} / {}",
                    row.matches.paths_beyond_tracking_cap,
                    row.matches.source_ips_beyond_tracking_cap,
                    row.matches.source_path_pairs_beyond_tracking_cap
                );
            }
            println!("COUNT evaluation only; candidate and replay/export evidence unchanged. Cohort labels are analyst declarations, not ground truth.");
            Ok(())
        }
        CandidateCommand::Compatibility {
            candidate,
            telemetry,
        } => {
            let candidate = load_candidate(&candidate)?;
            let telemetry = match telemetry {
                Some(telemetry) => telemetry.explicit_telemetry_profile()?,
                None => candidate.telemetry_profile,
            };
            for backend in [
                Backend::AwsWafJson,
                Backend::TerraformAwsWaf,
                Backend::Ossec,
            ] {
                let report = candidate_compatibility(&candidate, backend, telemetry);
                println!(
                    "{}: {:?}\n{}",
                    report.backend,
                    report.status,
                    if report.reasons.is_empty() {
                        "  faithful export available".to_owned()
                    } else {
                        report
                            .reasons
                            .iter()
                            .map(|reason| format!("  - {reason}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    }
                );
            }
            Ok(())
        }
        CandidateCommand::Explain {
            candidate,
            telemetry,
        } => {
            let candidate = load_candidate(&candidate)?;
            if shenron::candidate::uses_source_address_set(&candidate) {
                println!("{}", shenron::address_set::ADDRESS_SET_NOTE);
            }
            let telemetry = match telemetry {
                Some(telemetry) => telemetry.explicit_telemetry_profile()?,
                None => candidate.telemetry_profile,
            };
            println!("Candidate ID: {}\nCandidate kind: {:?}\nEvidence basis: {:?}\nCVEs: {}\nCISA KEV: {}\nRecommended initial action: COUNT\nReplay completed: {}\nHistorical requests evaluated: {}\nKnown threat findings: {}\nKnown threat findings matched: {}\nKnown threat findings missed: {}\nOther historical matches: {}\nThreat coverage: {:?}\nTelemetry source: {:?}\nConditions:\n{:#?}\n\nBackend compatibility:", candidate.id, candidate.candidate_kind, candidate.evidence_basis, candidate.cves.join(", "), candidate.kev, candidate.evidence.replay_completed, candidate.evidence.historical_requests_evaluated, candidate.evidence.known_threat_findings, candidate.evidence.known_threat_findings_matched, candidate.evidence.known_threat_findings_missed, candidate.evidence.other_historical_matches, candidate.evidence.threat_coverage, candidate.telemetry_profile, candidate.conditions);
            for backend in [
                Backend::AwsWafJson,
                Backend::TerraformAwsWaf,
                Backend::Ossec,
            ] {
                let report = candidate_compatibility(&candidate, backend, telemetry);
                println!("{}: {:?}", report.backend, report.status);
                for reason in report.reasons {
                    println!("  - {reason}");
                }
            }
            Ok(())
        }
        CandidateCommand::Export {
            candidate,
            backend,
            output,
            telemetry,
            priority,
            ossec_rule_id,
        } => {
            let candidate = load_candidate(&candidate)?;
            let telemetry = match telemetry {
                Some(telemetry) => telemetry.explicit_telemetry_profile()?,
                None => candidate.telemetry_profile,
            };
            let report = export_candidate(
                &candidate,
                backend.backend(),
                telemetry,
                &output,
                priority,
                ossec_rule_id,
            )?;
            println!("Exported review-only {} artifact: {}\nEvidence sidecar: {}.evidence.json\nRecommended initial action: COUNT\nNo deployment was performed.", report.backend, output.display(), output.file_stem().and_then(|value| value.to_str()).unwrap_or("candidate"));
            Ok(())
        }
    }
}

fn run_export(
    results_dir: PathBuf,
    format: CtiExportFormat,
    output: PathBuf,
    include_observables: bool,
    tlp: Option<TlpLevel>,
) -> Result<()> {
    export_cti_run(&results_dir, &output, format, include_observables, tlp)?;
    if include_observables {
        eprintln!(
            "PRIVATE export: observed connection-peer IPs and URI paths were included by explicit request. This is not attacker attribution or an attack/exploitation/compromise determination."
        );
    }
    println!(
        "Local {:?} export written: {}\nNo network transmission was performed.",
        format,
        output.display()
    );
    Ok(())
}

fn run_trend(
    results_dir: Vec<PathBuf>,
    path: String,
    output_format: TrendOutputFormat,
) -> Result<()> {
    let report = path_trend(&results_dir, &path)?;
    match output_format {
        TrendOutputFormat::Text => print_path_trend(&report),
        TrendOutputFormat::Json => {
            serde_json::to_writer_pretty(io::stdout().lock(), &report)?;
            println!();
        }
    }
    Ok(())
}

fn is_low_confidence_generic_match(finding: &shenron::production::FindingExplanation) -> bool {
    finding.request_specificity == shenron::nuclei::RequestSpecificity::ResponseUnverified
        && path_distinctiveness(finding.uri_path.as_deref().unwrap_or_default())
            == PathDistinctiveness::Generic
}

fn resolve_nuclei_inputs(
    templates: Option<PathBuf>,
    report: Option<PathBuf>,
) -> Result<(PathBuf, PathBuf)> {
    let templates_were_defaulted = templates.is_none();
    let report_was_defaulted = report.is_none();
    let templates = templates.unwrap_or_else(default_templates_dir);
    let report = report.unwrap_or_else(default_nuclei_report);
    if templates_were_defaulted && !templates.is_dir() {
        anyhow::bail!(
            "default Nuclei templates checkout is missing at {}; first run `shenron nuclei update`",
            templates.display()
        );
    }
    if report_was_defaulted && !report.is_file() {
        anyhow::bail!(
            "default frozen Nuclei report is missing at {}; first run `shenron nuclei update`",
            report.display()
        );
    }
    Ok((templates, report))
}

/// Prefer an explicit local dataset; otherwise use the prepared public input
/// only when it already exists. Explain remains strictly offline in both cases.
fn resolve_optional_local_dataset(
    selected: Option<PathBuf>,
    default_path: impl FnOnce() -> PathBuf,
) -> Option<PathBuf> {
    selected.or_else(|| {
        let path = default_path();
        path.is_file().then_some(path)
    })
}

fn parse_rfc3339_utc(value: &str) -> std::result::Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| format!("invalid RFC 3339 UTC timestamp: {value}"))
}

fn parse_positive_usize(value: &str) -> std::result::Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("expected a positive integer, got {value:?}"))
}

fn parse_ipv4_prefix_length(value: &str) -> std::result::Result<u8, String> {
    value
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| format!("invalid IPv4 group prefix {value:?}; expected 0 through 32"))
}

fn parse_ipv6_prefix_length(value: &str) -> std::result::Result<u8, String> {
    value
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= 128)
        .ok_or_else(|| format!("invalid IPv6 group prefix {value:?}; expected 0 through 128"))
}

fn parse_triage_duration(value: &str) -> std::result::Result<Duration, String> {
    if value.len() < 2 {
        return Err(triage_duration_error(value));
    }
    let (amount, suffix) = value.split_at(value.len() - 1);
    let multiplier = match suffix {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(triage_duration_error(value)),
    };
    let seconds = amount
        .parse::<u64>()
        .ok()
        .filter(|amount| *amount > 0)
        .and_then(|amount| amount.checked_mul(multiplier))
        .ok_or_else(|| triage_duration_error(value))?;
    if seconds > MAX_TRIAGE_WINDOW_SECONDS {
        return Err(triage_duration_error(value));
    }
    Ok(Duration::from_secs(seconds))
}

fn triage_duration_error(value: &str) -> String {
    format!(
        "invalid duration {value:?}; use a positive integer with s, m, h, or d (maximum {MAX_TRIAGE_WINDOW_DAYS}d)"
    )
}

fn print_input_discovery(summary: &InputDiscoverySummary, machine_stdout: bool) {
    if let Some(line) = summary.disclosure() {
        if machine_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}

fn print_concentration(
    report: &SanitizedConcentrationReport,
    sanitized_path: &Path,
    private: Option<&PrivateRequestConcentrationReport>,
    show_paths: bool,
    show_source_ips: bool,
    limit: usize,
    focus: Option<&FocusSelector>,
) {
    print_input_discovery(&report.input_discovery, false);
    let time_range = match (&report.filter_from, &report.filter_to) {
        (None, None) => "Time filter:                all timestamps".to_owned(),
        (from, to) => format!(
            "Time filter (UTC):          {} to {}\nOutside range ignored:      {}\nTimestamp missing ignored:  {}",
            from.as_deref().unwrap_or("beginning"),
            to.as_deref().unwrap_or("end"),
            report.requests_outside_time_range,
            report.requests_without_timestamp_excluded,
        ),
    };
    println!(
        "Read-only request concentration complete.\nSanitized report:            {}\nPrivate detail:              {}\n\n{}\n\nTelemetry profile:          {:?}\nRequests analyzed:          {}\nFiles analyzed:             {}\nParse errors:               {}",
        sanitized_path.display(),
        sanitized_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("request-concentration.json")
            .display(),
        time_range,
        report.telemetry_profile,
        report.total_requests_analyzed,
        report.files_analyzed,
        report.parse_errors,
    );
    print_request_concentration_summary(
        &report.request_concentration,
        "request-concentration.json",
    );
    if let (Some(selector), Some(focus_summary)) =
        (focus, report.request_concentration.focus.as_ref())
    {
        let rate = match (
            focus_summary.peak_requests_per_minute,
            focus_summary.median_requests_per_minute,
        ) {
            (Some(peak), Some(median)) => format!("peak {peak} / median {median:.1}"),
            _ => "unavailable (no timestamped focused requests)".to_owned(),
        };
        let (header, selector_label) = match selector {
            FocusSelector::ExactPath(_) => ("Path focus (exact URI path)", "Focus path"),
            FocusSelector::PathPrefix(_) => (
                "Path-prefix focus (this path and everything under it)",
                "Focus prefix",
            ),
            FocusSelector::SourceIp(_) => (
                "Source-IP focus (URI paths these observed connection peers requested)",
                "Focus source IP(s)",
            ),
        };
        let mut lines = vec![
            format!(
                "  {selector_label}: {}",
                terminal_safe(&selector.selector_display())
            ),
            format!("  Requests: {}", focus_summary.total_requests),
        ];
        if !matches!(selector, FocusSelector::ExactPath(_)) {
            lines.push(format!(
                "  Distinct URI paths in focus: {} (beyond cap: {})",
                focus_summary.distinct_uri_paths, focus_summary.paths_beyond_cap,
            ));
        }
        if !matches!(selector, FocusSelector::SourceIp(_)) {
            lines.push(format!(
                "  Distinct observed connection-peer IPs: {} (beyond cap: {})",
                focus_summary.distinct_source_ips, focus_summary.source_ips_beyond_cap,
            ));
        }
        lines.push(format!("  Peak / median requests per minute: {rate}"));
        lines.push(format!(
            "  Requests per distinct observed source IP: {:.1}",
            focus_summary.requests_per_source_ip,
        ));
        lines.push(format!(
            "  Query shape: {}",
            format_query_shape(
                focus_summary.total_requests,
                focus_summary.requests_with_query,
                focus_summary.distinct_query_strings,
                focus_summary.query_strings_beyond_tracking_cap,
                focus_summary.distinct_query_keys,
                focus_summary.query_keys_beyond_tracking_cap,
            )
        ));
        println!(
            "\n{header} (aggregate requests only; not a DoS/attack/abuse/compromise/attribution determination):\n{}\n  Observed peers may be CDN/LB/NAT/proxy addresses and are not attacker attribution.",
            lines.join("\n"),
        );
        print_windowed_request_rates("  Focus rate windows", &focus_summary.request_rates);
        let asn_available = private
            .and_then(|report| report.focus.as_ref())
            .and_then(|focus| focus.asn.as_ref())
            .is_some();
        if !asn_available {
            println!("  ASN grouping omitted because --asn-dataset was not specified.");
        }
    }
    if let Some(private) = private {
        if let Some(disclosure) = &private.source_prefix_aggregation {
            println!("  Source-prefix omissions (missing IP / invalid IP / source-cap observations): {} / {} / {} (group cap: {}; retained-source counts only)",
                disclosure.requests_without_source_ip, disclosure.requests_with_invalid_source_ip,
                disclosure.requests_beyond_source_tracking_cap, disclosure.maximum_prefixes);
            print_prefix_path_omissions(
                (disclosure.requests_beyond_prefix_path_pair_cap > 0)
                    .then_some(disclosure.requests_beyond_prefix_path_pair_cap),
                Some(&disclosure.path_tracking),
            );
        }
        if show_paths {
            println!("\nPrivate top request paths:");
            for item in private.paths.iter().take(display_limit(limit)) {
                println!(
                    "  {}\n    Requests: {} ({:.1}%)\n    Distinct source IPs: {}\n    Requests per distinct source IP: {:.1}\n    Response status classes: {}\n    Response bytes: {}\n    Query shape: {}\n    Query keys (private; names only): {}",
                    terminal_safe(&item.uri_path),
                    item.summary.requests,
                    item.summary.request_share * 100.0,
                    item.summary.distinct_source_ips,
                    item.summary.requests_per_source_ip,
                    format_status_classes(&item.summary.response_status_classes),
                    item.summary
                        .response_bytes
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unavailable for this telemetry profile".to_owned()),
                    format_query_shape(
                        item.summary.requests,
                        item.summary.requests_with_query,
                        item.summary.distinct_query_strings,
                        item.summary.query_strings_beyond_tracking_cap,
                        item.summary.distinct_query_keys,
                        item.summary.query_keys_beyond_tracking_cap,
                    ),
                    if item.query_keys.is_empty() {
                        "none".to_owned()
                    } else {
                        item.query_keys
                            .iter()
                            .map(|key| terminal_safe(key))
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                );
                println!(
                    "    {}",
                    format_status_codes(item.summary.response_status_codes.as_ref())
                );
            }
            if let Some(focus) = &private.focus {
                if !focus.paths.is_empty() {
                    let noun = if focus.focus_kind == "source-ip" {
                        "requested by the focused source IP(s)"
                    } else {
                        "under the focused path prefix"
                    };
                    println!(
                        "\nPrivate URI paths {noun} (requests only; not a DoS/attack/abuse/compromise/attribution determination):"
                    );
                    for item in focus.paths.iter().take(display_limit(limit)) {
                        println!(
                            "  {}\n    Requests: {}",
                            terminal_safe(&item.uri_path),
                            item.requests,
                        );
                        println!(
                            "    Response status classes: {}\n    {}",
                            format_status_classes(&item.response_status_classes),
                            format_status_codes(item.response_status_codes.as_ref())
                        );
                    }
                    if focus.paths.len() > display_limit(limit) {
                        println!(
                            "  {} focused paths omitted. Pass --limit 0 to display all.",
                            focus.paths.len() - display_limit(limit)
                        );
                    }
                    if focus.paths_beyond_cap != 0 {
                        println!(
                            "  Focused path observations beyond tracking cap: {}",
                            focus.paths_beyond_cap
                        );
                    }
                }
                if !focus.query_keys.is_empty() {
                    println!(
                        "  Focus query keys (private; names only): {}",
                        focus
                            .query_keys
                            .iter()
                            .map(|key| terminal_safe(key))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }
            println!(
                "  Query-shape counts are request-volume context for human review, not a cache-evasion, DoS, attack, abuse, compromise, or attribution determination. Query strings and values are never output."
            );
        }
        if show_source_ips {
            if let Some(groups) = &private.source_prefixes {
                println!("\nPrivate observed source-prefix volumes:");
                println!(
                    "  {}",
                    terminal_safe(
                        private
                            .source_prefix_aggregation
                            .as_ref()
                            .map(|detail| detail.safety_note.as_str())
                            .unwrap_or(shenron::concentration::SOURCE_PREFIX_NOTE)
                    )
                );
                for group in groups.iter().take(display_limit(limit)) {
                    println!("  {}: requests {} / distinct source IPs {} / max requests per source IP {} / response bytes {} (byte values unavailable: {}; path observations unavailable: {})",
                        terminal_safe(&group.prefix), group.requests, group.distinct_source_ips,
                        group.max_requests_per_source_ip,
                        group.response_bytes.map(|bytes| bytes.to_string()).unwrap_or_else(|| "unavailable".to_owned()),
                        group.response_bytes_unavailable, group.path_observations_unavailable);
                    println!(
                        "    Response status classes: {}",
                        format_status_classes(&group.response_status_classes)
                    );
                    if let Some(distinct) = group.distinct_uri_paths {
                        println!("    Distinct / once-requested paths: {} / {} (requests omitted at per-prefix / global pair cap: {} / {}; capped distinct counts are lower bounds)",
                            distinct,
                            group.uri_paths_requested_once.map(|count| count.to_string()).unwrap_or_else(|| "unavailable".to_owned()),
                            group.uri_paths_beyond_prefix_cap.unwrap_or(0), group.uri_paths_beyond_global_cap.unwrap_or(0));
                    }
                    if let Some(asns) = &group.asns {
                        for asn in asns {
                            println!(
                                "    ASN {} ({}): requests {} / distinct source IPs {}",
                                asn.asn,
                                terminal_safe(&asn.organization),
                                asn.requests,
                                asn.distinct_source_ips
                            );
                        }
                        println!(
                            "    ASN unresolved sources / requests: {} / {}",
                            group.unresolved_source_ips.unwrap_or(0),
                            group.unresolved_requests.unwrap_or(0)
                        );
                    }
                    if show_paths {
                        println!(
                            "    Most-requested retained path: {}",
                            group
                                .most_requested_uri_path
                                .as_deref()
                                .map(terminal_safe)
                                .unwrap_or_else(|| {
                                    "unavailable (missing or capped path observations)".to_owned()
                                })
                        );
                    }
                }
                if groups.len() > display_limit(limit) {
                    println!(
                        "  {} prefix groups omitted by --limit.",
                        groups.len() - display_limit(limit)
                    );
                }
            }
            println!("\nPrivate top observed connection-peer IPs:");
            for item in private.source_ips.iter().take(display_limit(limit)) {
                println!(
                    "  {}\n    Requests: {}\n    Response status classes: {}\n    Most-requested retained path: {}",
                    terminal_safe(&item.source_ip),
                    item.requests,
                    format_status_classes(&item.response_status_classes),
                    item.most_requested_uri_path
                        .as_deref()
                        .map(terminal_safe)
                        .unwrap_or_else(
                            || "unavailable (not retained before tracking cap)".to_owned()
                        ),
                );
                print_source_response_details(
                    item.response_status_codes.as_ref(),
                    item.response_outcomes.as_ref(),
                );
                if let Some(unavailable) = item.response_bytes_unavailable {
                    println!(
                        "    Response bytes: {} (byte values unavailable: {})",
                        item.response_bytes
                            .map(|bytes| bytes.to_string())
                            .unwrap_or_else(|| "unavailable".to_owned()),
                        unavailable
                    );
                }
            }
            if let Some(focus) = &private.focus {
                let source_ip_selection_count = focus
                    .selector
                    .split(',')
                    .filter(|value| !value.trim().is_empty())
                    .count();
                if focus.focus_kind != "source-ip" || source_ip_selection_count > 1 {
                    let heading = if focus.focus_kind == "source-ip" {
                        "Private selected source-IP request breakdown"
                    } else {
                        "Private observed connection-peer IPs requesting the focused path"
                    };
                    println!(
                        "\n{heading} (requests only; not a DoS/attack/abuse/compromise/attribution determination):"
                    );
                    for source in focus.sources.iter().take(display_limit(limit)) {
                        let count_label = if focus.focus_kind == "source-ip" {
                            "Requests in source-IP focus"
                        } else {
                            "Requests to focus path"
                        };
                        println!(
                            "  {}\n    {count_label}: {}\n    Response status classes: {}",
                            terminal_safe(&source.source_ip),
                            source.requests,
                            format_status_classes(&source.response_status_classes),
                        );
                        print_source_response_details(
                            source.response_status_codes.as_ref(),
                            source.response_outcomes.as_ref(),
                        );
                    }
                    if focus.sources.len() > display_limit(limit) {
                        println!(
                            "  {} focused source IPs omitted. Pass --limit 0 to display all.",
                            focus.sources.len() - display_limit(limit)
                        );
                    }
                    if focus.source_ips_beyond_cap != 0 {
                        println!(
                            "  Focused source IP observations beyond tracking cap: {}",
                            focus.source_ips_beyond_cap
                        );
                    }
                }
                if focus.focus_kind != "source-ip" && !focus.network_prefix_groups.is_empty() {
                    println!(
                        "\nPrivate address-block aggregation for the focused path (network prefix only; not evidence of a shared operator, owner, or actor):"
                    );
                    for group in focus
                        .network_prefix_groups
                        .iter()
                        .take(display_limit(limit))
                    {
                        println!(
                            "  {}\n    Requests: {} ({:.1}%)\n    Distinct observed peer IPs: {}",
                            terminal_safe(&group.network_prefix),
                            group.requests,
                            group.request_share * 100.0,
                            group.distinct_source_ips,
                        );
                        println!(
                            "    Response status classes: {}",
                            format_status_classes(&group.response_status_classes)
                        );
                        print_source_response_details(
                            group.response_status_codes.as_ref(),
                            group.response_outcomes.as_ref(),
                        );
                    }
                    if focus.network_prefix_groups.len() > display_limit(limit) {
                        println!(
                            "  {} address-block groups omitted. Pass --limit 0 to display all.",
                            focus.network_prefix_groups.len() - display_limit(limit)
                        );
                    }
                    println!(
                        "  Shared prefixes can span tenants, and one operator can span many prefixes; this is observed request-volume aggregation only, not attribution or a DoS/attack/abuse determination."
                    );
                }
                if let Some(asn) = &focus.asn {
                    println!(
                        "\nPrivate ASN aggregation for the focus (routing-level groups only; not evidence that one operator controls the traffic):"
                    );
                    for group in asn.groups.iter().take(display_limit(limit)) {
                        println!(
                            "  AS{} {}\n    Requests: {} ({:.1}%)\n    Distinct observed peer IPs: {}",
                            group.asn,
                            terminal_safe(&group.organization),
                            group.requests,
                            group.request_share * 100.0,
                            group.distinct_source_ips,
                        );
                    }
                    if asn.groups.len() > display_limit(limit) {
                        println!(
                            "  {} ASN groups omitted. Pass --limit 0 to display all.",
                            asn.groups.len() - display_limit(limit)
                        );
                    }
                    println!(
                        "  Unresolved observed peer IPs: {} ({} requests)",
                        asn.unresolved_source_ips, asn.unresolved_requests,
                    );
                    println!(
                        "  An ASN is a routing-level grouping. It does not establish that one operator controls the traffic, and it is not attribution or a determination of a denial-of-service attempt, attack, or abuse."
                    );
                }
            }
        }
    }
}

fn normalized_rate_windows(rate_window: Vec<Duration>) -> Vec<u64> {
    if rate_window.is_empty() {
        DEFAULT_RATE_WINDOW_SECONDS.to_vec()
    } else {
        let mut values = rate_window
            .into_iter()
            .map(|window| window.as_secs())
            .collect::<Vec<_>>();
        values.sort_unstable();
        values.dedup();
        values
    }
}

fn format_waf_actions(
    counts: Option<&shenron::waf_summary::WafActionCounts>,
    shares: bool,
) -> String {
    let Some(counts) = counts else {
        return "unavailable (telemetry profile does not expose WAF actions)".to_owned();
    };
    let total: u64 = counts.entries().iter().map(|(_, count)| count).sum();
    if total == 0 {
        return "unavailable (no observations)".to_owned();
    }
    counts
        .entries()
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(name, count)| {
            if shares {
                format!(
                    "{name} {:.1}% ({count})",
                    *count as f64 / total as f64 * 100.0
                )
            } else {
                format!("{name} {count}")
            }
        })
        .collect::<Vec<_>>()
        .join(" / ")
}

fn print_daily_volume_summary(summary: &DailyVolumeSummary, output: Option<&Path>) {
    print_input_discovery(&summary.input_discovery, false);
    println!("Daily request-volume summary (aggregate counts only):");
    println!(
        "  WAF actions: {}",
        format_waf_actions(
            summary.waf.as_ref().and_then(|waf| waf.actions.as_ref()),
            true
        )
    );
    if summary.waf.is_some() {
        println!("  {}", shenron::waf_summary::WAF_OBSERVATION_NOTE);
    }
    println!(
        "  Total requests:                         {}",
        summary.total_requests
    );
    println!(
        "  Distinct observed source IPs:           {}",
        summary.distinct_source_ips
    );
    match (
        summary.top_path_request_share,
        summary.top_path_distinct_source_ips,
        summary.top_path_requests_per_source_ip,
    ) {
        (Some(share), Some(sources), Some(per_source)) => println!(
            "  Top path share / sources / requests per source: {:.1}% / {} / {:.1}",
            share * 100.0,
            sources,
            per_source,
        ),
        _ => println!("  Top path metrics:                       unavailable"),
    }
    match &summary.response_outcomes {
        Some(outcomes) if outcomes.counts.total_observations() == 0 => println!(
            "  Response outcome: unavailable (no observations)"
        ),
        Some(outcomes) if outcomes.counts.total_observations() == outcomes.counts.unavailable => println!(
            "  Response outcome: unavailable (no response status recorded; unavailable 100.0% ({}))",
            outcomes.counts.unavailable,
        ),
        Some(outcomes) => println!(
            "  Response outcome: 2xx {:.1}% ({}) / 3xx {:.1}% ({}) / 4xx excl. 499 {:.1}% ({}) / 499 {:.1}% ({}) / 5xx {:.1}% ({}) / unavailable {:.1}% ({})",
            outcomes.success_share * 100.0,
            outcomes.counts.success,
            outcomes.redirection_share * 100.0,
            outcomes.counts.redirection,
            outcomes.ordinary_client_error_share * 100.0,
            outcomes.counts.ordinary_client_error(),
            outcomes.client_closed_request_499_share * 100.0,
            outcomes.counts.client_closed_request_499,
            outcomes.server_error_share * 100.0,
            outcomes.counts.server_error,
            100.0 * outcomes.counts.unavailable as f64 / outcomes.counts.total_observations() as f64,
            outcomes.counts.unavailable,
        ),
        None => println!(
            "  Response outcome: unavailable (telemetry profile does not expose status)"
        ),
    }
    for rate in &summary.request_rates {
        // Rate statistics retain their existing denominators and admission rules.
        println!(
            "  Rate window {}s peak / median / ratio: {} / {} / {} (undated: {}; beyond cap: {})",
            rate.bucket_width_seconds,
            rate.peak_requests
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned()),
            rate.median_requests
                .map(|value| format!("{value:.1}"))
                .unwrap_or_else(|| "unavailable".to_owned()),
            rate.peak_to_median_ratio
                .map(|value| format!("{value:.2}"))
                .unwrap_or_else(|| "unavailable".to_owned()),
            rate.observations_without_timestamp,
            rate.observations_beyond_bucket_cap,
        );
    }
    if let Some(windows) = &summary.response_outcome_windows {
        for window in windows {
            println!(
                "  Response window {}s minimum 2xx / maximum 5xx share: {} / {} (buckets with >= {} requests: {}; below minimum: {}; undated: {}; beyond cap: {}; without status: {})",
                window.bucket_width_seconds,
                window
                    .minimum_success_share
                    .map(|value| format!("{:.1}%", value * 100.0))
                    .unwrap_or_else(|| "unavailable".to_owned()),
                window
                    .maximum_server_error_share
                    .map(|value| format!("{:.1}%", value * 100.0))
                    .unwrap_or_else(|| "unavailable".to_owned()),
                window.minimum_requests_per_bucket,
                window.eligible_buckets,
                window.buckets_below_minimum,
                window.observations_without_timestamp,
                window.observations_beyond_bucket_cap,
                window.buckets_without_status,
            );
            println!("  {}", format_response_window_context(window));
        }
    }
    println!(
        "  {}",
        format_status_codes(summary.response_status_codes.as_ref())
    );
    println!(
        "  Files / parse errors / outside range / undated excluded: {} / {} / {} / {}",
        summary.files_analyzed,
        summary.parse_errors,
        summary.requests_outside_time_range,
        summary.requests_without_timestamp_excluded,
    );
    println!(
        "  Tracking-cap omissions (paths / source IPs / pairs): {} / {} / {}",
        summary.paths_beyond_tracking_cap,
        summary.source_ips_beyond_tracking_cap,
        summary.source_path_pairs_beyond_tracking_cap,
    );
    print_prefix_path_omissions(
        summary.source_prefix_path_pairs_beyond_tracking_cap,
        summary.source_prefix_path_tracking.as_ref(),
    );
    if let Some(segments) = &summary.source_segment_diversity {
        let unavailable_reason = match segments.corpus_4xx_requests {
            None => "; status unavailable",
            Some(0) => "; no client-error responses to measure",
            _ => "",
        };
        println!("  First path segments (4xx excl. 499) max / median: {} / {} (corpus 4xx requests: {}; sources with >= 1 retained 4xx segment: {} / {} retained{})",
            segments.maximum_4xx_segments.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned()),
            segments.median_4xx_segments_among_sources_with_4xx_segments.map(|v| format!("{v:.1}")).unwrap_or_else(|| "unavailable".to_owned()),
            segments.corpus_4xx_requests.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned()),
            segments.sources_with_4xx_segments.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned()), segments.retained_sources, unavailable_reason);
        println!("  Segment tracking (cap/source: {}; sources capped all/4xx excl. 499: {}/{}; observations omitted all/4xx excl. 499: {}/{}; missing path: {}; capped counts are lower bounds, not classifications)",
            segments.maximum_segments_per_source, segments.sources_beyond_cap,
            segments.sources_4xx_beyond_cap.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned()),
            segments.observations_beyond_cap, segments.observations_4xx_beyond_cap.map(|v| v.to_string()).unwrap_or_else(|| "unavailable".to_owned()), segments.observations_without_path);
    }
    if summary.processed_index_enabled {
        println!(
            "  Previously processed files skipped:          {}",
            summary.files_skipped_as_processed
        );
        println!(
            "  Scope: these aggregates cover files processed in this run only; they are not cumulative."
        );
    }
    if let Some(output) = output {
        println!(
            "  Artifacts written:                      {}",
            output.display()
        );
    } else {
        println!("  Artifacts written:                      none (use --output to opt in)");
    }
    println!(
        "These are observed volume measurements, not thresholds, alerts, or determinations of automation, denial of service, attack, abuse, compromise, or attacker identity."
    );
    println!(
        "Response outcome shares are counts of what the log recorded. A low success share can equally result from redirect-heavy routing, authentication flows, health checks, clients that disconnect early, a slow backend, or an unavailable origin. It is not a determination of an outage, degraded availability, an attack, or abuse."
    );
}

fn print_processed_index_scope(enabled: bool, skipped_files: usize) {
    if enabled {
        println!(
            "\nProcessed-file index: {} unchanged file(s) skipped. These aggregates cover files processed in this run only; they are not cumulative.",
            skipped_files
        );
    }
}

fn print_path_trend(report: &PathTrendReport) {
    println!("Private path trend from existing artifacts only:");
    println!("  URI path: {}", terminal_safe(&report.uri_path));
    for run in &report.runs {
        println!("\n{}", terminal_safe(&run.results_dir));
        match &run.observation {
            Some(observation) => println!(
                "  Requests: {} | share: {:.3}% | distinct observed source IPs: {} | requests per source IP: {:.1} | rank: {}\n  Response status classes: {}",
                observation.requests,
                observation.request_share * 100.0,
                observation.distinct_source_ips,
                observation.requests_per_source_ip,
                observation.rank,
                format_status_classes(&observation.response_status_classes),
            ),
            None => println!(
                "  No retained record for this path (distinct from an observed zero). Paths beyond tracking cap: {}.",
                run.paths_beyond_tracking_cap
            ),
        }
        println!(
            "  Total requests recorded in this run: {}",
            run.total_requests_in_run
        );
    }
    println!(
        "\nThese are observed request-volume measurements from private artifacts, not determinations of denial of service, attack, abuse, compromise, or attacker identity. Source IPs may be CDN/LB/NAT/proxy peers."
    );
}

fn print_temporal_comparison(
    report: &SanitizedTemporalComparison,
    private: &PrivateTemporalComparison,
    show_entities: bool,
    show_paths: bool,
    show_source_ips: bool,
    limit: usize,
) {
    if let Some(references) = &report.reference_distribution {
        println!("Explicit reference-run distribution ({} runs; {} duplicate directory references excluded):", references.reference_runs.len(), references.duplicate_directory_references_excluded);
        for (metric, row) in &references.metrics {
            let display = |v: Option<f64>| {
                v.map(|v| format!("{v:.4}"))
                    .unwrap_or_else(|| "unavailable".into())
            };
            println!("  {} min / median / max / current / current-to-median: {} / {} / {} / {} / {} (available/unavailable runs: {}/{})", metric.label(), display(row.minimum), display(row.median), display(row.maximum), display(row.current), display(row.ratio_to_median), row.available_runs, row.unavailable_runs);
            for (reason, count) in &row.unavailable_reasons {
                println!("    {count} reference runs: {reason}");
            }
            if let Some(reason) = &row.current_unavailable_reason {
                println!("    Current unavailable: {reason}");
            }
        }
        println!("{}", references.note);
    }
    if let Some(conditions) = &report.measurement_conditions {
        println!("Measurement conditions (recorded facts; missing values are unavailable):");
        for (key, baseline) in &conditions.baseline.numeric {
            let display = |v: Option<f64>| {
                v.map(|v| v.to_string())
                    .unwrap_or_else(|| "unavailable".into())
            };
            println!(
                "  {key}: {} -> {}",
                display(*baseline),
                display(conditions.current.numeric[key])
            );
        }
        println!(
            "  Changed recorded facts ({}): {}",
            conditions.changed_recorded_facts.len(),
            conditions.changed_recorded_facts.join(", ")
        );
        println!(
            "  Unavailable facts ({}): {}",
            conditions.unavailable_facts.len(),
            conditions.unavailable_facts.join(", ")
        );
        println!("{}", conditions.note);
    }
    println!(
        "Temporal comparison (local artifact diff only; not an attack, abuse, compromise, or attribution determination):\n  Comparison kind:           {}\n  Baseline-comparable:       {}\n  Newly observed CVEs:       {}\n  Disappeared CVEs:          {}\n  First-seen source IPs:     {}\n  First-seen hosts:          {}\n  First-seen URI paths:      {}\n  First-seen JA4 values:     {}\n  Elevated paths:            {}\n  Elevated source IPs:       {}\n  Low-baseline paths:        {}\n  Low-baseline source IPs:   {}",
        report.comparability.kind,
        report.comparability.comparable,
        report.cve_diff.newly_observed_cves.len(),
        report.cve_diff.disappeared_cves.len(),
        report.first_seen_counts.source_ips,
        report.first_seen_counts.hosts,
        report.first_seen_counts.uri_paths,
        report.first_seen_counts.ja4_fingerprints,
        report.concentration_delta.elevated_paths,
        report.concentration_delta.elevated_source_ips,
        report.concentration_delta.low_baseline_paths,
        report.concentration_delta.low_baseline_source_ips,
    );
    for reason in &report.comparability.reasons {
        println!("  Comparability note:       {reason}");
    }
    if let Some(daily) = &report.concentration_delta.daily_metrics {
        for line in daily.display_lines() {
            println!("{}", terminal_safe(&line));
        }
    }
    if show_entities {
        println!("\nPrivate first-seen entities:");
        for (label, values) in [
            ("host", &private.first_seen_entities.hosts),
            ("JA4", &private.first_seen_entities.ja4_fingerprints),
        ] {
            for value in values.iter().take(display_limit(limit)) {
                println!("  {label}: {}", terminal_safe(value));
            }
        }
    }
    if show_paths {
        println!("\nPrivate first-seen paths:");
        for value in private
            .first_seen_entities
            .uri_paths
            .iter()
            .take(display_limit(limit))
        {
            println!("  {}", terminal_safe(value));
        }
        println!("\nPrivate path comparison:");
        for detail in private
            .concentration_delta_detail
            .paths
            .iter()
            .take(display_limit(limit))
        {
            println!(
                "  {}\n    Baseline/current: {:?}/{}  label={}  ratio={}",
                terminal_safe(&detail.key),
                detail.baseline_requests,
                detail.current_requests,
                detail.label,
                detail
                    .ratio
                    .map(|ratio| format!("{ratio:.2}x"))
                    .unwrap_or_else(|| "unavailable".to_owned()),
            );
        }
    }
    if show_source_ips {
        println!("\nPrivate first-seen source IPs:");
        for value in private
            .first_seen_entities
            .source_ips
            .iter()
            .take(display_limit(limit))
        {
            println!("  {}", terminal_safe(value));
        }
        println!("\nPrivate source-IP comparison:");
        for detail in private
            .concentration_delta_detail
            .source_ips
            .iter()
            .take(display_limit(limit))
        {
            println!(
                "  {}\n    Baseline/current: {:?}/{}  label={}  ratio={}",
                terminal_safe(&detail.key),
                detail.baseline_requests,
                detail.current_requests,
                detail.label,
                detail
                    .ratio
                    .map(|ratio| format!("{ratio:.2}x"))
                    .unwrap_or_else(|| "unavailable".to_owned()),
            );
        }
    }
}

fn format_status_classes(counts: &shenron::concentration::StatusClassCounts) -> String {
    [
        ("1xx", counts.informational),
        ("2xx", counts.success),
        ("3xx", counts.redirection),
        ("4xx excl. 499", counts.ordinary_client_error()),
        ("499", counts.client_closed_request_499),
        ("5xx", counts.server_error),
        ("other", counts.other),
        ("unavailable", counts.unavailable),
    ]
    .into_iter()
    .filter(|(_, count)| *count != 0)
    .map(|(label, count)| format!("{label}: {count}"))
    .collect::<Vec<_>>()
    .join(", ")
}

fn format_status_codes(codes: Option<&shenron::concentration::StatusCodeCounts>) -> String {
    let Some(codes) = codes else {
        return "Response status codes: unavailable (not recorded or profile does not expose status)".to_owned();
    };
    let values = codes
        .counts
        .iter()
        .map(|(code, count)| format!("{code}: {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Response status codes: {values} (observations beyond {}-code tracking cap: {})",
        codes.maximum_codes, codes.observations_beyond_cap
    )
}

fn print_source_response_details(
    codes: Option<&shenron::concentration::StatusCodeCounts>,
    outcomes: Option<&ResponseOutcomeSummary>,
) {
    println!("    {}", format_status_codes(codes));
    if let Some(outcomes) = outcomes {
        println!("    Response shares: 2xx {:.1}% / 499 {:.1}% / 5xx {:.1}% (observed outcomes only, not a cause or attribution determination)", outcomes.success_share * 100.0, outcomes.client_closed_request_499_share * 100.0, outcomes.server_error_share * 100.0);
    }
}

fn format_response_window_context(window: &WindowedResponseOutcomeSummary) -> String {
    let timestamp = |value: Option<DateTime<Utc>>| {
        value
            .map(|value| value.to_rfc3339())
            .unwrap_or_else(|| "unavailable".to_owned())
    };
    format!("Response window {}s bucket starts (UTC), earliest ties: minimum 2xx {}; maximum 5xx {}; eligible buckets with success share strictly below {}%: {} (a descriptive count, not a classification)", window.bucket_width_seconds, timestamp(window.minimum_success_bucket_start), timestamp(window.maximum_server_error_bucket_start), window.success_share_threshold_percent.map(|value| value.to_string()).unwrap_or_else(|| "unavailable".to_owned()), window.buckets_below_success_threshold.map(|value| value.to_string()).unwrap_or_else(|| "unavailable".to_owned()))
}

fn format_query_shape(
    total_requests: u64,
    requests_with_query: u64,
    distinct_query_strings: usize,
    query_strings_beyond_cap: u64,
    distinct_query_keys: usize,
    query_keys_beyond_cap: u64,
) -> String {
    let share = if total_requests == 0 {
        0.0
    } else {
        requests_with_query as f64 / total_requests as f64 * 100.0
    };
    let cardinality = |retained: usize, beyond_cap: u64| {
        if beyond_cap == 0 {
            retained.to_string()
        } else {
            format!(
                "at least {retained} (tracking cap reached; {beyond_cap} observations not admitted)"
            )
        }
    };
    let distinct_ratio = if total_requests == 0 {
        0.0
    } else {
        distinct_query_strings as f64 / total_requests as f64
    };
    let distinct_ratio = if query_strings_beyond_cap == 0 {
        format!("{distinct_ratio:.4}")
    } else {
        format!("at least {distinct_ratio:.4} (retained lower bound)")
    };
    format!(
        "requests with query: {requests_with_query} ({share:.1}%); distinct query strings: {}; distinct query strings / requests: {distinct_ratio}; distinct query keys: {}",
        cardinality(distinct_query_strings, query_strings_beyond_cap),
        cardinality(distinct_query_keys, query_keys_beyond_cap),
    )
}

fn print_request_concentration_summary(
    concentration: &shenron::concentration::RequestConcentrationSummary,
    private_artifact_name: &str,
) {
    let top_path = concentration
        .top_path
        .as_ref()
        .map(|top| {
            format!(
                "{:.1}% of {} requests, from {} distinct source IPs ({:.1} requests per distinct source IP)",
                top.request_share * 100.0,
                concentration.total_requests,
                top.distinct_source_ips,
                top.requests_per_source_ip,
            )
        })
        .unwrap_or_else(|| "unavailable (no URI paths retained)".to_owned());
    let rate = &concentration.requests_per_minute;
    println!(
        "  {}",
        format_status_codes(concentration.response_status_codes.as_ref())
    );
    if let Some(windows) = &concentration.response_outcome_windows {
        for window in windows {
            println!("  {}", format_response_window_context(window));
        }
    }
    let rate = match (
        rate.peak_requests_per_minute,
        rate.median_requests_per_minute,
        rate.peak_to_median_ratio,
    ) {
        (Some(peak), Some(median), Some(ratio)) => {
            format!("peak {peak} / median {median:.1} ({ratio:.1}x)")
        }
        _ => "unavailable (no timestamped events)".to_owned(),
    };
    println!(
        "\nRequest concentration (volume distribution only; separate from the CVE metrics above):\n  This is not a determination of a denial-of-service attempt, attack, abuse, or attacker identity.\n  Requests per distinct source is a ratio of two observed counts; a high ratio can also result from polling, an aggregating proxy, a repeatedly fetched embedded asset, or automated traffic. It is not a determination of automation, denial of service, attack, or abuse.\n  Distinct URI paths:        {}\n  Distinct source IPs:       {}\n  Top path share:            {}\n  Top 10 paths share:        {:.1}%\n  Top 10 source IPs share:   {:.1}%\n  Requests per minute:       {}\n  Requests without path:     {}\n  Requests without source IP:{}\n  Paths beyond tracking cap: {}\n  Source IPs beyond cap:     {}\n  Source/path pairs beyond cap: {}\n  Undated observations:      {}\n  Detail (paths and source IPs) written to the private artifact: {}",
        concentration.distinct_uri_paths,
        concentration.distinct_source_ips,
        top_path,
        concentration.top_ten_paths_request_share * 100.0,
        concentration.top_ten_source_ips_request_share * 100.0,
        rate,
        concentration.requests_without_uri_path,
        concentration.requests_without_source_ip,
        concentration.paths_beyond_tracking_cap,
        concentration.source_ips_beyond_tracking_cap,
        concentration.source_path_pairs_beyond_tracking_cap,
        concentration.requests_per_minute.observations_without_timestamp,
        private_artifact_name,
    );
    print_windowed_request_rates("  Simultaneous rate windows", &concentration.request_rates);
}

fn print_prefix_path_omissions(
    omitted: Option<u64>,
    tracking: Option<&shenron::concentration::SourcePrefixPathTracking>,
) {
    if let Some(count) = omitted {
        let limit = tracking
            .filter(|detail| detail.maximum_prefix_path_pairs > 0)
            .map(|detail| detail.maximum_prefix_path_pairs.to_string())
            .unwrap_or_else(|| "unavailable".to_owned());
        let affected = tracking
            .filter(|detail| detail.maximum_prefix_path_pairs > 0)
            .map(|detail| detail.prefixes_beyond_prefix_path_pair_cap.to_string())
            .unwrap_or_else(|| "unavailable".to_owned());
        println!("  Source-prefix path-pair cap: {count} requests omitted (global pair cap; current --max-source-prefix-path-pairs: {limit}; prefixes with once-requested counts unavailable due to this cap: {affected}; increase --max-source-prefix-path-pairs and rerun)");
    }
    if let Some(detail) = tracking.filter(|detail| detail.requests_beyond_prefix_path_table_cap > 0)
    {
        println!("  Source-prefix path-table cap: {} requests omitted (current --max-source-prefix-paths: {}; prefixes with once-requested counts unavailable due to this cap: {}; increase --max-source-prefix-paths and rerun)", detail.requests_beyond_prefix_path_table_cap, detail.maximum_prefix_paths, detail.prefixes_beyond_prefix_path_table_cap);
    }
}

fn print_windowed_request_rates(
    heading: &str,
    rates: &[shenron::concentration::WindowedRequestRateSummary],
) {
    if rates.is_empty() {
        return;
    }
    println!("{heading} (volume shape only):");
    for rate in rates {
        let width = format_triage_duration(Duration::from_secs(rate.bucket_width_seconds));
        let values = match (
            rate.peak_requests,
            rate.median_requests,
            rate.peak_to_median_ratio,
        ) {
            (Some(peak), Some(median), Some(ratio)) => {
                format!("peak {peak} / median {median:.1} ({ratio:.1}x)")
            }
            _ => "unavailable (no timestamped events)".to_owned(),
        };
        println!(
            "    {width}: {values}; undated {}; beyond bucket cap {}",
            rate.observations_without_timestamp, rate.observations_beyond_bucket_cap,
        );
    }
}

fn display_limit(limit: usize) -> usize {
    if limit == 0 {
        usize::MAX
    } else {
        limit
    }
}

fn print_ablation(report: &AblationReport, output_path: Option<&Path>) {
    print_input_discovery(&report.input_discovery, false);
    println!(
        "Ablation match-volume comparison only: volume rate = matched events / total events evaluated; it is NOT precision, recall, accuracy, ground truth, or an attack/exploitation/compromise determination."
    );
    println!("{}", report.safety_note);
    print_template_filter_summary(report.template_filter.as_ref());
    println!(
        "\nTelemetry profile:          {:?}\nTotal events evaluated:     {}\nFiles analyzed:              {}\nParse errors:                {}\nOutside range ignored:      {}\nTimestamp missing ignored:  {}\n\nStrategy volumes:",
        report.telemetry_profile,
        report.total_events_evaluated,
        report.files_analyzed,
        report.parse_errors,
        report.requests_outside_time_range,
        report.requests_without_timestamp_excluded,
    );
    for strategy in &report.strategies {
        let volume_rate = strategy
            .matched_event_volume_rate
            .map(|rate| format!("{rate:.4}"))
            .unwrap_or_else(|| "unavailable (no evaluated events)".to_owned());
        println!(
            "  {}\n    Matched events:          {}\n    Volume rate:             {}\n    Distinct event × CVE:    {}",
            strategy.strategy,
            strategy.matched_events,
            volume_rate,
            strategy.distinct_event_cve_matches,
        );
    }
    println!(
        "\nThe path_and_query rung does not narrow detections that have no query condition: {} of {} validated detections have none and pass it unchanged from path_only.",
        report.path_and_query_detections_without_query_condition, report.validated_detections,
    );
    println!("\nDeferred strategy:          {}", report.deferred_strategy);
    if let Some(path) = output_path {
        println!("Aggregate-only JSON report:  {}", path.display());
    }
}

fn print_historical_replay(report: &HistoricalReplayReport, output_path: Option<&Path>) {
    print_input_discovery(&report.input_discovery, false);
    let aggregate = &report.aggregate;
    let coverage = aggregate
        .coverage
        .map(|coverage| format!("{coverage:.4}"))
        .unwrap_or_else(|| "unavailable (no source finding request IDs)".to_owned());
    println!("Historical replay coverage is a conservative lower bound based on source-finding request IDs; it is NOT precision, recall, accuracy, ground truth, or an attack/exploitation/compromise determination.");
    println!("{}", report.safety_note);
    print_template_filter_summary(report.inputs.template_filter.as_ref());
    println!(
        "\nTelemetry profile:          {:?}\nTotal events evaluated:     {}\nFiles analyzed:              {}\nParse errors:                {}\nOutside range ignored:      {}\nTimestamp missing ignored:  {}\n\nKnown findings:              {}\nKnown findings re-matched:   {}\nKnown findings missed:       {}\nConservative coverage:       {}\nMatched events total:        {}\nOther matches with request ID:    {}\nOther matches without request ID: {}\nMatched events BLOCK:        {}\nMatched events not blocked:  {}\nMatched events unknown outcome: {}\n\nTop CVE coverage:",
        report.telemetry_profile,
        report.total_events_evaluated,
        report.files_analyzed,
        report.parse_errors,
        report.requests_outside_time_range,
        report.requests_without_timestamp_excluded,
        aggregate.known_findings,
        aggregate.known_matched,
        aggregate.known_missed,
        coverage,
        aggregate.matched_events_total,
        aggregate.other_matches_with_request_id,
        aggregate.other_matches_without_request_id,
        aggregate.matched_events_blocked,
        aggregate.matched_events_not_blocked,
        aggregate.matched_events_unknown_outcome,
    );
    for coverage in report.per_cve.iter().take(10) {
        let value = coverage
            .coverage
            .map(|coverage| format!("{coverage:.4}"))
            .unwrap_or_else(|| "unavailable (no source finding request IDs)".to_owned());
        println!(
            "  {}\n    KEV: {}\n    Known / re-matched / missed: {} / {} / {}\n    Conservative coverage: {}\n    Other matches (with / without request ID): {} / {}",
            terminal_safe(&coverage.cve),
            coverage.is_kev,
            coverage.known_findings,
            coverage.known_matched,
            coverage.known_missed,
            value,
            coverage.other_matches_with_request_id,
            coverage.other_matches_without_request_id,
        );
    }
    if report.per_cve.len() > 10 {
        println!(
            "{} additional CVEs omitted from stdout; see the aggregate-only JSON report for all CVE counts.",
            report.per_cve.len() - 10
        );
    }
    if let Some(path) = output_path {
        println!("Aggregate-only JSON report:  {}", path.display());
    }
}

fn print_count_hypotheses(
    report: &CountHypothesisReport,
    output_path: Option<&Path>,
    limit: usize,
) {
    print_input_discovery(&report.input_discovery, false);
    println!("COUNT hypothesis ladder is an offline, non-deploying simulation. It reports trade-off measurements only and does NOT recommend a rung.");
    println!("{}", report.safety_note);
    print_template_filter_summary(report.inputs.template_filter.as_ref());
    println!(
        "\nTelemetry profile:          {:?}\nTotal events evaluated:     {}\nFiles analyzed:              {}\nParse errors:                {}\nOutside range ignored:      {}\nTimestamp missing ignored:  {}\n\nCVE condition ladders:",
        report.telemetry_profile,
        report.total_events_evaluated,
        report.files_analyzed,
        report.parse_errors,
        report.requests_outside_time_range,
        report.requests_without_timestamp_excluded,
    );
    let displayed = if limit == 0 {
        report.per_cve.as_slice()
    } else {
        &report.per_cve[..report.per_cve.len().min(limit)]
    };
    for hypothesis in displayed {
        println!(
            "  {}\n    KEV: {}\n    Known findings: {}",
            terminal_safe(&hypothesis.cve),
            hypothesis.is_kev,
            hypothesis.known_findings,
        );
        for rung in &hypothesis.rungs {
            let coverage = rung
                .known_coverage
                .map(|coverage| format!("{coverage:.4}"))
                .unwrap_or_else(|| "unavailable (no source finding request IDs)".to_owned());
            println!(
                "    {}\n      Matched events: {}\n      Known re-matched: {}\n      Conservative coverage: {}\n      Other matches (with / without request ID): {} / {}\n      Outcomes (BLOCK / not blocked / unknown): {} / {} / {}",
                rung.strategy,
                rung.matched_events,
                rung.known_matched,
                coverage,
                rung.other_matches_with_request_id,
                rung.other_matches_without_request_id,
                rung.matched_events_blocked,
                rung.matched_events_not_blocked,
                rung.matched_events_unknown_outcome,
            );
        }
    }
    if displayed.len() < report.per_cve.len() {
        println!(
            "{} additional CVE ladders omitted. Pass --limit 0 to display all.",
            report.per_cve.len() - displayed.len()
        );
    }
    if let Some(path) = output_path {
        println!("Aggregate-only JSON report:  {}", path.display());
    }
}

fn print_template_filter_summary(summary: Option<&shenron::production::TemplateFilterSummary>) {
    if let Some(summary) = summary {
        println!(
            "Template metadata filter: {} eligible / {} included; excluded by allowlist: {}, denylist: {}, unknown metadata: {}. Filtering narrows catalog evaluation only and is not an attack, exploitation, or compromise determination.",
            summary.eligible_before_filter,
            summary.included_after_filter,
            summary.excluded_by_allowlist,
            summary.excluded_by_denylist,
            summary.excluded_unknown_metadata,
        );
    }
}

fn disposition_counts(
    findings: &[shenron::production::FindingExplanation],
    store: &DispositionStore,
) -> shenron::production::AnalystDispositionCounts {
    let mut counts = shenron::production::AnalystDispositionCounts::for_store(store);
    for finding in findings {
        let key = finding
            .method
            .as_deref()
            .zip(finding.uri_path.as_deref())
            .map(|(method, path)| {
                DispositionKey::new(
                    finding.source.label(),
                    &finding.template_id,
                    method,
                    path,
                    finding.uri_query.as_deref(),
                )
            });
        counts.record_pattern(key.as_ref(), store);
    }
    counts
}

fn print_analyst_dispositions(counts: Option<&shenron::production::AnalystDispositionCounts>) {
    if let Some(counts) = counts {
        println!(
            "Analyst-authored dispositions (private local opinions; findings remain retained and counted):\n  Reviewed: {}\n  Expected: {}\n  Needs review: {}\n  Unclassified: {}\n  These are analyst opinions, not Shenron determinations of attack, exploitation, compromise, or benignness.",
            counts.reviewed, counts.expected, counts.needs_review, counts.unclassified,
        );
        if let Some(due) = counts.review_due_matching_findings {
            println!("  Matching findings with analyst opinions due for re-review: {due} (original opinions and all findings remain unchanged)");
        }
    }
}

/// Which optional sections `production explain` should print.
struct ExplainDisplay {
    show_request: bool,
    show_evidence: bool,
    show_source_ips: bool,
    show_asn: bool,
    show_fingerprints: bool,
}

/// The triage thresholds and the telemetry capabilities that bound the reachable
/// behavior-score maximum. They travel together through the explain summaries.
#[derive(Clone)]
struct TriageContext {
    policy: TriagePolicy,
    capabilities: TelemetryCapabilities,
}

/// The machine-readable `production explain` report. It mirrors the text output
/// section for section and honors the identical `--show-*` privacy gates: a
/// section that the text mode would not print is omitted here too, so no private
/// value is ever emitted that the analyst did not explicitly request.
#[derive(Serialize)]
struct ExplainReport {
    report_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    waf_outcome_filter: Option<String>,
    total_mappings: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_low_confidence: Option<HiddenSummaryJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analyst_dispositions: Option<shenron::production::AnalystDispositionCounts>,
    /// Present when a triage section is shown and low-confidence generic matches
    /// are hidden from the listing: the groups below are still computed from all
    /// matching findings, so their counts can exceed the listed rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    triage_note: Option<&'static str>,
    request_paths: Vec<PathSummaryRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_ip_groups: Option<Vec<GroupJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn_groups: Option<AsnGroupsJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja4_groups: Option<Vec<GroupJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    individual_findings: Option<Vec<FindingJson>>,
}

#[derive(Serialize)]
struct HiddenSummaryJson {
    count: usize,
    cve_count: usize,
}

#[derive(Serialize)]
struct AsnGroupsJson {
    groups: Vec<GroupJson>,
    unresolved_findings: usize,
}

#[derive(Serialize)]
struct GroupJson {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn_org: Option<String>,
    triage_basis: Option<&'static str>,
    requires_investigation: bool,
    distinct_templates: usize,
    distinct_cves: usize,
    distinct_observations: usize,
    matching_records: usize,
    spread: usize,
    request_specific_observations: usize,
    response_unverified_observations: usize,
    windowed_burst_windows: Vec<shenron::triage::WindowedTriageMatch>,
    sequence: shenron::triage::RequestSequenceSummary,
    score: shenron::triage::BehaviorScore,
    #[serde(skip_serializing_if = "Option::is_none")]
    reputation: Option<ReputationJson>,
}

#[derive(Serialize)]
struct ReputationJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_asn_org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'static str>,
    hits: Vec<shenron::reputation::ReputationHit>,
}

/// A single finding view. Request values appear only under `--show-request`; the
/// full private evidence appears only under `--show-evidence`.
#[derive(Serialize)]
struct FindingJson {
    source: shenron::production::FindingSource,
    cves: Vec<String>,
    template_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sigma_level: Option<String>,
    detectability: shenron::nuclei::Detectability,
    request_specificity: shenron::nuclei::RequestSpecificity,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    waf_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<FindingRequestJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<FindingEvidenceJson>,
}

/// Request targets, gated behind `--show-request`.
#[derive(Serialize)]
struct FindingRequestJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_query: Option<String>,
}

/// Full private evidence, gated behind `--show-evidence`.
#[derive(Serialize)]
struct FindingEvidenceJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    headers: Vec<shenron::event::HttpHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja4: Option<String>,
    waf_labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    waf_rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    waf_rule_type: Option<String>,
    waf_non_terminating_rule_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

fn reputation_json(
    reputation: shenron::reputation::EntityReputation,
    asn: Option<(u32, String)>,
) -> ReputationJson {
    ReputationJson {
        resolved_asn: asn.as_ref().map(|(number, _)| *number),
        resolved_asn_org: asn.map(|(_, org)| org),
        score: reputation.score,
        tier: reputation.tier.map(|tier| tier.label()),
        scope: reputation.score_scope,
        hits: reputation.hits,
    }
}

fn base_group_json(group: &shenron::triage::EntityGroup, show_request: bool) -> GroupJson {
    let mut sequence = group.sequence.clone();
    if !show_request {
        sequence.ordered_observations.clear();
    }
    GroupJson {
        key: group.key.clone(),
        identity: group.identity.map(|identity| identity.label()),
        asn_org: group.asn_org.clone(),
        triage_basis: group.triage_basis,
        requires_investigation: group.requires_investigation(),
        distinct_templates: group.distinct_templates,
        distinct_cves: group.distinct_cves,
        distinct_observations: group.distinct_observations,
        matching_records: group.matching_records,
        spread: group.spread,
        request_specific_observations: group.request_specific_observations,
        response_unverified_observations: group.response_unverified_observations,
        windowed_burst_windows: group.windowed_burst_windows.clone(),
        sequence,
        score: group.score.clone(),
        reputation: None,
    }
}

fn connection_ip_group_json(
    group: &shenron::triage::EntityGroup,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
    show_request: bool,
) -> GroupJson {
    let mut json = base_group_json(group, show_request);
    if let Some(ip) = canonical_ip(&group.key) {
        let asn = asn_database
            .and_then(|database| database.lookup(ip))
            .map(|info| (info.asn, info.org.clone()));
        if let Some(database) = reputation_database {
            let reputation = database.lookup(ip, asn.as_ref().map(|(number, _)| *number));
            json.reputation = Some(reputation_json(reputation, asn));
        } else if let Some((number, org)) = asn {
            json.reputation = Some(ReputationJson {
                resolved_asn: Some(number),
                resolved_asn_org: Some(org),
                score: None,
                tier: None,
                scope: None,
                hits: Vec::new(),
            });
        }
    }
    json
}

fn asn_group_json(
    group: &shenron::triage::EntityGroup,
    reputation_database: Option<&ReputationDatabase>,
    show_request: bool,
) -> GroupJson {
    let mut json = base_group_json(group, show_request);
    if let Some(database) = reputation_database {
        if let Ok(asn) = group.key.parse::<u32>() {
            json.reputation = Some(reputation_json(database.lookup_asn(asn), None));
        }
    }
    json
}

fn finding_json(
    finding: &shenron::production::FindingExplanation,
    display: &ExplainDisplay,
) -> FindingJson {
    let request = display.show_request.then(|| FindingRequestJson {
        method: finding.method.clone(),
        uri_path: finding.uri_path.clone(),
        uri_query: finding.uri_query.clone(),
    });
    let evidence = display.show_evidence.then(|| FindingEvidenceJson {
        source_ip: finding.source_ip.clone(),
        client_ip: finding.client_ip.clone(),
        host: finding.host.clone(),
        headers: finding.headers.clone(),
        ja3: finding.ja3.clone(),
        ja4: finding.ja4.clone(),
        waf_labels: finding.waf_labels.clone(),
        waf_rule_id: finding.waf_rule_id.clone(),
        waf_rule_type: finding.waf_rule_type.clone(),
        waf_non_terminating_rule_ids: finding.waf_non_terminating_rule_ids.clone(),
        request_id: finding.request_id.clone(),
    });
    FindingJson {
        source: finding.source,
        cves: finding.cves.clone(),
        template_id: finding.template_id.clone(),
        rule_title: finding.rule_title.clone(),
        sigma_level: finding.sigma_level.clone(),
        detectability: finding.detectability,
        request_specificity: finding.request_specificity,
        timestamp: finding.timestamp.clone(),
        waf_action: finding.waf_action.clone(),
        request,
        evidence,
    }
}

/// Stated once whenever a triage section is shown while low-confidence generic
/// matches are hidden from the listing, so the group counts (computed from all
/// matching findings) do not look inconsistent with the shorter listing.
const TRIAGE_INCLUDES_HIDDEN_NOTE: &str = "Triage groups are computed from all matching findings, including the low-confidence generic matches hidden from the listing; a group's observation and template counts can therefore exceed the rows shown.";

#[allow(clippy::too_many_arguments)]
fn build_explain_report(
    listed: &[shenron::production::FindingExplanation],
    grouped: &[shenron::production::FindingExplanation],
    hidden: &[shenron::production::FindingExplanation],
    display: &ExplainDisplay,
    waf_outcome_filter: Option<&str>,
    limit: usize,
    triage: TriageContext,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
    analyst_dispositions: Option<shenron::production::AnalystDispositionCounts>,
) -> ExplainReport {
    let truncate = |mut rows: Vec<GroupJson>| {
        if limit != 0 {
            rows.truncate(limit);
        }
        rows
    };
    // The summary and per-finding rows follow the display filter (`listed`);
    // entity grouping and scoring see every matching finding (`grouped`).
    let mut request_paths = explanation_summary(listed);
    if limit != 0 {
        request_paths.truncate(limit);
    }

    let hidden_low_confidence = (!hidden.is_empty()).then(|| HiddenSummaryJson {
        count: hidden.len(),
        cve_count: hidden
            .iter()
            .flat_map(|finding| finding.cves.iter())
            .collect::<BTreeSet<_>>()
            .len(),
    });

    let connection_ip_groups = display.show_source_ips.then(|| {
        truncate(
            entity_groups(
                grouped,
                EntityDimension::ConnectionIp,
                triage.policy.clone(),
                triage.capabilities,
            )
            .iter()
            .map(|group| {
                connection_ip_group_json(
                    group,
                    asn_database,
                    reputation_database,
                    display.show_request,
                )
            })
            .collect(),
        )
    });

    let asn_groups = display
        .show_asn
        .then_some(asn_database)
        .flatten()
        .map(|database| {
            let result = asn_entity_groups(
                grouped,
                triage.policy.clone(),
                database,
                triage.capabilities,
            );
            AsnGroupsJson {
                groups: truncate(
                    result
                        .groups
                        .iter()
                        .map(|group| {
                            asn_group_json(group, reputation_database, display.show_request)
                        })
                        .collect(),
                ),
                unresolved_findings: result.unresolved_findings,
            }
        });

    let ja4_groups = display.show_fingerprints.then(|| {
        truncate(
            entity_groups(
                grouped,
                EntityDimension::Ja4,
                triage.policy.clone(),
                triage.capabilities,
            )
            .iter()
            .map(|group| base_group_json(group, display.show_request))
            .collect(),
        )
    });

    let shows_triage = display.show_source_ips || display.show_asn || display.show_fingerprints;
    let triage_note = (shows_triage && !hidden.is_empty()).then_some(TRIAGE_INCLUDES_HIDDEN_NOTE);

    let individual_findings = (display.show_request || display.show_evidence).then(|| {
        let shown = if limit == 0 {
            listed
        } else {
            &listed[..listed.len().min(limit)]
        };
        shown
            .iter()
            .map(|finding| finding_json(finding, display))
            .collect()
    });

    ExplainReport {
        report_kind: "EXPLAIN_PRIVATE_TRIAGE",
        waf_outcome_filter: waf_outcome_filter.map(str::to_owned),
        total_mappings: listed.len(),
        hidden_low_confidence,
        analyst_dispositions,
        triage_note,
        request_paths,
        connection_ip_groups,
        asn_groups,
        ja4_groups,
        individual_findings,
    }
}

#[allow(clippy::too_many_arguments)]
fn print_explanations(
    listed: &[shenron::production::FindingExplanation],
    grouped: &[shenron::production::FindingExplanation],
    has_hidden: bool,
    display: ExplainDisplay,
    waf_outcome_filter: Option<&str>,
    limit: usize,
    triage: TriageContext,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
) {
    // The summary and per-finding rows follow the display filter (`listed`);
    // entity grouping and scoring see every matching finding (`grouped`).
    let displayed = if limit == 0 {
        listed
    } else {
        &listed[..listed.len().min(limit)]
    };
    match waf_outcome_filter {
        Some(filter) => println!(
            "CVE / Nuclei template mappings: {} (WAF outcome filter: {})",
            listed.len(),
            filter
        ),
        None => println!("CVE / Nuclei template mappings: {}", listed.len()),
    }
    print_explanation_summary(listed, limit);
    let shows_triage = display.show_source_ips || display.show_asn || display.show_fingerprints;
    if shows_triage && has_hidden {
        println!("\n{TRIAGE_INCLUDES_HIDDEN_NOTE}");
    }
    if display.show_source_ips {
        print_source_ip_summary(
            grouped,
            limit,
            triage.clone(),
            asn_database,
            reputation_database,
        );
    } else if (asn_database.is_some() || reputation_database.is_some()) && !display.show_asn {
        println!(
            "Local reputation datasets were supplied, but --show-source-ips was not selected; no IP enrichment was displayed."
        );
    }
    if display.show_asn {
        match asn_database {
            Some(database) => {
                print_asn_summary(
                    grouped,
                    limit,
                    triage.clone(),
                    database,
                    reputation_database,
                )
            }
            None => println!(
                "ASN grouping was requested, but --asn-dataset was not supplied; no ASN groups were displayed."
            ),
        }
    }
    if display.show_fingerprints {
        print_ja4_summary(grouped, limit, triage);
    }
    if !display.show_request && !display.show_evidence {
        println!("Pass --show-request to display individual requests, or --show-evidence to include all locally stored evidence.");
        return;
    }
    if displayed.len() < listed.len() {
        println!(
            "\nShowing first {} individual findings; {} omitted. Pass --limit 0 to display all.",
            displayed.len(),
            listed.len() - displayed.len()
        );
    }
    for (index, finding) in displayed.iter().enumerate() {
        println!(
            "\n[{}]\nCVE: {}\nNuclei template: {}\nTemplate detectability: {:?}\nRequest specificity: {}\nTimestamp (UTC): {}\nWAF action: {}",
            index + 1,
            finding.cves.join(", "),
            terminal_safe(&finding.template_id),
            finding.detectability,
            finding.request_specificity.label(),
            finding
                .timestamp
                .as_deref()
                .map(terminal_safe)
                .unwrap_or_else(|| "unknown".to_owned()),
            finding
                .waf_action
                .as_deref()
                .map(terminal_safe)
                .unwrap_or_else(|| "unavailable".to_owned()),
        );
        if display.show_request {
            let target = match (&finding.uri_path, &finding.uri_query) {
                (Some(path), Some(query)) => {
                    format!("{}?{}", terminal_safe(path), terminal_safe(query))
                }
                (Some(path), None) => terminal_safe(path),
                _ => "unavailable".to_owned(),
            };
            println!(
                "Request: {} {}",
                finding
                    .method
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| "unknown".to_owned()),
                target
            );
            println!(
                "Path distinctiveness: {}",
                path_distinctiveness(finding.uri_path.as_deref().unwrap_or_default()).label()
            );
        } else {
            println!("Request: hidden (pass --show-request to display method/path/query)");
        }
        if display.show_evidence {
            println!(
                "Observed connection source (peer; may be CDN/LB/NAT, not attacker attribution): {}\nValidated forwarded client IP: {}\nHost: {}\nJA3: {}\nJA4: {}\nRequest ID: {}\nTerminating WAF rule ID: {}\nTerminating WAF rule type: {}\nNon-terminating WAF rule IDs: {}\nWAF labels: {}\nHeaders:",
                finding
                    .source_ip
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| "unavailable".to_owned()),
                finding
                    .client_ip
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| {
                        "not available (no trusted-proxy configuration or unverifiable)".to_owned()
                    }),
                finding
                    .host
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| "unavailable".to_owned()),
                finding
                    .ja3
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| "unavailable".to_owned()),
                finding
                    .ja4
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| "unavailable".to_owned()),
                finding
                    .request_id
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| "unavailable".to_owned()),
                finding
                    .waf_rule_id
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| {
                        "not recorded or unsupported by this telemetry source".to_owned()
                    }),
                finding
                    .waf_rule_type
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| {
                        "not recorded or unsupported by this telemetry source".to_owned()
                    }),
                if finding.waf_non_terminating_rule_ids.is_empty() {
                    "none recorded or unsupported by this telemetry source".to_owned()
                } else {
                    finding
                        .waf_non_terminating_rule_ids
                        .iter()
                        .map(|rule_id| terminal_safe(rule_id))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                if finding.waf_labels.is_empty() {
                    "none recorded in this event or unsupported by this telemetry source".to_owned()
                } else {
                    finding
                        .waf_labels
                        .iter()
                        .map(|label| terminal_safe(label))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            if finding.headers.is_empty() {
                println!("  unavailable");
            } else {
                for header in &finding.headers {
                    println!(
                        "  {}: {}",
                        terminal_safe(&header.name),
                        terminal_safe(&header.value)
                    );
                }
            }
        }
    }
}

/// One request-path row of the explain summary, as data so both the text and
/// JSON renderers share the identical bundling and ordering.
#[derive(Serialize)]
struct PathSummaryRow {
    method: Option<String>,
    path: Option<String>,
    matches: usize,
    cves: Vec<String>,
    template_count: usize,
    distinctiveness: &'static str,
}

/// Bundle findings by (method, path) with distinct CVEs and templates, sorted
/// by match count. Returns the full set; callers apply `limit` for display.
fn explanation_summary(
    findings: &[shenron::production::FindingExplanation],
) -> Vec<PathSummaryRow> {
    let mut counts = BTreeMap::<
        (Option<String>, Option<String>),
        (usize, BTreeSet<String>, BTreeSet<String>),
    >::new();
    for finding in findings {
        let count = counts
            .entry((finding.method.clone(), finding.uri_path.clone()))
            .or_default();
        count.0 += 1;
        count.1.extend(finding.cves.iter().cloned());
        count.2.insert(finding.template_id.clone());
    }
    let mut summary = counts.into_iter().collect::<Vec<_>>();
    summary.sort_by(|left, right| {
        right
            .1
             .0
            .cmp(&left.1 .0)
            .then_with(|| left.0 .1.cmp(&right.0 .1))
            .then_with(|| left.0 .0.cmp(&right.0 .0))
    });
    summary
        .into_iter()
        .map(|((method, path), (matches, cves, templates))| {
            let distinctiveness = match path_distinctiveness(path.as_deref().unwrap_or_default()) {
                PathDistinctiveness::Generic => "generic",
                PathDistinctiveness::Distinctive => "distinctive",
            };
            PathSummaryRow {
                method,
                path,
                matches,
                cves: cves.into_iter().collect(),
                template_count: templates.len(),
                distinctiveness,
            }
        })
        .collect()
}

fn print_explanation_summary(findings: &[shenron::production::FindingExplanation], limit: usize) {
    let summary = explanation_summary(findings);
    let displayed = if limit == 0 {
        summary.as_slice()
    } else {
        &summary[..summary.len().min(limit)]
    };
    println!("\nTop request paths (CVEs bundled per path):");
    for row in displayed {
        let method = row.method.as_deref().unwrap_or("<unavailable>");
        let path = row.path.as_deref().unwrap_or("<unavailable>");
        println!(
            "{} {}\n  Matches: {}  |  CVEs ({}): {}\n  Templates: {}  |  Path: {}",
            terminal_safe(method),
            terminal_safe(path),
            row.matches,
            row.cves.len(),
            terminal_safe(&row.cves.join(", ")),
            row.template_count,
            row.distinctiveness,
        );
    }
    if displayed.len() < summary.len() {
        println!(
            "{} additional request paths omitted. Pass --limit 0 to display all.",
            summary.len() - displayed.len()
        );
    }
}

const MAX_TRIAGE_WINDOW_DAYS: u64 = 3650;
const MAX_TRIAGE_WINDOW_SECONDS: u64 = MAX_TRIAGE_WINDOW_DAYS * 24 * 60 * 60;

fn print_source_ip_summary(
    findings: &[shenron::production::FindingExplanation],
    limit: usize,
    triage: TriageContext,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
) {
    let policy = triage.policy;
    let groups = entity_groups(
        findings,
        EntityDimension::ConnectionIp,
        policy.clone(),
        triage.capabilities,
    );
    println!("\nConnection/client IP triage (private findings only):");
    if let Some(database) = asn_database {
        print_dataset_provenance("ASN dataset", database.provenance());
    }
    if let Some(database) = reputation_database {
        print_dataset_provenance("Reputation dataset", database.provenance());
    }
    if asn_database.is_some() || reputation_database.is_some() {
        println!(
            "Offline IP/ASN reputation enrichment is a third-party opinion, not an attack, exploitation, compromise, or attacker-attribution determination. No IP is sent outside this local process."
        );
    }
    if policy.is_default() {
        println!("Triage policy: default fixed baseline");
    } else {
        println!(
            "Triage policy: CUSTOM (non-default; not comparable to the fixed research baseline)"
        );
    }
    if !policy.windows.is_empty() {
        print_triage_windows(&policy.windows);
    }
    println!(
        "Grouping identity: validated-client when a trusted forwarded chain was verified; otherwise observed-peer. Validated-client and observed-peer groups are intentionally never merged: when forwarded resolution applies to only some requests, one actual sender may appear under both identities. A peer may be a CDN, load balancer, NAT, or proxy and is not attacker attribution. A group is marked \"requires investigation\" by breadth (at least {} matching request observations and {} Nuclei template patterns) or depth (at least {} matching request observations, even for one template). This is not an attacker, exploit-success, or compromise determination.",
        policy.breadth_observations,
        policy.breadth_templates,
        policy.depth_observations,
    );
    println!(
        "Behavior priority score (0-100) ranks a group for triage from observed request behavior only. It is not a probability of malice, a precision or true-positive estimate, an exploitation or compromise determination, or attacker attribution."
    );
    println!(
        "Ordered request sequence window: {} (cap {} observations per entity). A short span or regular interval is labeled for review only; it can result from a crawler, page subresources, automation, or a person clicking quickly and does not determine attack, abuse, automation, or identity.",
        format_triage_duration(policy.sequence_window),
        policy.max_sequence_observations,
    );
    let triaged = groups
        .iter()
        .filter(|group| group.requires_investigation())
        .collect::<Vec<_>>();
    let displayed_triaged = if limit == 0 {
        triaged.as_slice()
    } else {
        &triaged[..triaged.len().min(limit)]
    };
    println!("\nIP groups requiring investigation (repeated CVE-pattern behavior):");
    if displayed_triaged.is_empty() {
        println!("No IP group met the repeated-pattern triage threshold.");
    } else {
        for group in displayed_triaged {
            print_ip_group(
                group,
                !policy.windows.is_empty(),
                asn_database,
                reputation_database,
            );
        }
        if displayed_triaged.len() < triaged.len() {
            println!(
                "{} additional triaged IP groups omitted. Pass --limit 0 to display all.",
                triaged.len() - displayed_triaged.len()
            );
        }
    }

    let displayed = if limit == 0 {
        groups.as_slice()
    } else {
        &groups[..groups.len().min(limit)]
    };
    println!("\nIP groups with matching evidence (not an attack determination):");
    if displayed.is_empty() {
        println!("No client or peer IP addresses were recorded in the selected findings.");
        return;
    }
    for group in displayed {
        print_ip_group(
            group,
            !policy.windows.is_empty(),
            asn_database,
            reputation_database,
        );
    }
    if displayed.len() < groups.len() {
        println!(
            "{} additional IP groups omitted. Pass --limit 0 to display all.",
            groups.len() - displayed.len()
        );
    }
}

fn print_ip_group(
    group: &shenron::triage::EntityGroup,
    windowed: bool,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
) {
    println!(
        "{}\n  Grouping identity: {}\n  Triage basis: {}\n  Matching request observations: {}\n  Distinct Nuclei template patterns: {}\n  Unique CVEs: {}\n  Matched template records: {}",
        terminal_safe(&group.key),
        group
            .identity
            .expect("connection-IP groups carry an identity")
            .label(),
        group.triage_basis.unwrap_or("none"),
        group.distinct_observations,
        group.distinct_templates,
        group.distinct_cves,
        group.matching_records,
    );
    if windowed {
        println!(
            "  Undated observations excluded from windowed triage: {}",
            group.undated_observations
        );
        print_windowed_burst_windows(group);
    }
    println!("  Behavior priority score: {}", score_display(&group.score));
    print_sequence_summary(&group.sequence);
    println!(
        "  Request-specific observations: {}\n  Response-unverified observations: {}",
        group.request_specific_observations, group.response_unverified_observations
    );
    print_ip_reputation(group, asn_database, reputation_database);
}

/// Render the behavior score. When the active telemetry profile cannot reach
/// every component, the total is normalized to 100 and the raw reachable ceiling
/// is stated so the number stays auditable.
fn score_display(score: &shenron::triage::BehaviorScore) -> String {
    if score.reachable_max >= 100 {
        format!("{}/100 ({})", score.total, score.tier.label())
    } else {
        format!(
            "{}/100 ({}); normalized against this telemetry profile's reachable maximum of {}/100",
            score.total,
            score.tier.label(),
            score.reachable_max
        )
    }
}

fn print_dataset_provenance(label: &str, provenance: &shenron::reputation::DatasetProvenance) {
    println!(
        "{} provenance: path={} sha256={} records={}",
        label,
        terminal_safe(&provenance.path),
        terminal_safe(&provenance.sha256),
        provenance.records
    );
}

fn print_ip_reputation(
    group: &shenron::triage::EntityGroup,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
) {
    if asn_database.is_none() && reputation_database.is_none() {
        return;
    }
    let Some(ip) = canonical_ip(&group.key) else {
        return;
    };
    let asn = asn_database.and_then(|database| database.lookup(ip));
    if let Some(asn) = asn {
        println!("  Resolved ASN: {} ({})", asn.asn, terminal_safe(&asn.org));
    }
    if let Some(database) = reputation_database {
        let reputation = database.lookup(ip, asn.map(|info| info.asn));
        match (reputation.score, reputation.tier, reputation.score_scope) {
            (Some(score), Some(tier), Some(scope)) => println!(
                "  Reputation: {score}/100 ({}) via {}",
                tier.label(),
                terminal_safe(scope)
            ),
            _ => println!("  Reputation: none"),
        }
        print_reputation_hits(reputation.hits);
    }
}

fn print_reputation_hits(hits: Vec<shenron::reputation::ReputationHit>) {
    for hit in hits {
        let categories = if hit.categories.is_empty() {
            "[]".to_owned()
        } else {
            format!(
                "[{}]",
                hit.categories
                    .iter()
                    .map(|category| terminal_safe(category))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let as_of = hit
            .as_of
            .as_deref()
            .map(|date| format!(" as_of={}", terminal_safe(date)))
            .unwrap_or_default();
        println!(
            "    - {} {} score {} {} source={}{}",
            terminal_safe(hit.scope),
            terminal_safe(&hit.value),
            hit.score,
            categories,
            terminal_safe(&hit.source),
            as_of,
        );
    }
}

fn print_asn_summary(
    findings: &[shenron::production::FindingExplanation],
    limit: usize,
    triage: TriageContext,
    asn_database: &AsnDatabase,
    reputation_database: Option<&ReputationDatabase>,
) {
    let policy = triage.policy;
    let result = asn_entity_groups(findings, policy.clone(), asn_database, triage.capabilities);
    println!("\nASN triage (private findings only):");
    print_dataset_provenance("ASN dataset", asn_database.provenance());
    if let Some(database) = reputation_database {
        print_dataset_provenance("Reputation dataset", database.provenance());
    }
    println!(
        "Offline IP/ASN reputation enrichment is a third-party opinion, not an attack, exploitation, compromise, or attacker-attribution determination. No IP is sent outside this local process."
    );
    if policy.is_default() {
        println!("Triage policy: default fixed baseline");
    } else {
        println!(
            "Triage policy: CUSTOM (non-default; not comparable to the fixed research baseline)"
        );
    }
    if !policy.windows.is_empty() {
        print_triage_windows(&policy.windows);
    }
    println!(
        "Grouping identity: validated-client and observed-peer are intentionally never merged, including when they resolve to the same ASN. Distinct member IPs are the larger of those separately counted identity populations. This is not an attacker, exploit-success, or compromise determination."
    );
    println!(
        "Behavior priority score (0-100) ranks an ASN group for triage from observed request behavior only. It is not a probability of malice, a precision or true-positive estimate, an exploitation or compromise determination, or attacker attribution."
    );
    println!(
        "Ordered request sequence window: {} (cap {} observations per entity). Sequence timing is an observation for review, not a determination of automation, attack, abuse, or identity.",
        format_triage_duration(policy.sequence_window),
        policy.max_sequence_observations,
    );
    let displayed = if limit == 0 {
        result.groups.as_slice()
    } else {
        &result.groups[..result.groups.len().min(limit)]
    };
    println!("\nASN groups with matching evidence (not an attack determination):");
    if displayed.is_empty() {
        println!("No ASN groups were resolved from the selected findings.");
    } else {
        for group in displayed {
            print_asn_group(group, !policy.windows.is_empty(), reputation_database);
        }
        if displayed.len() < result.groups.len() {
            println!(
                "{} additional ASN groups omitted. Pass --limit 0 to display all.",
                result.groups.len() - displayed.len()
            );
        }
    }
    println!(
        "Findings excluded because ASN was unresolved: {}",
        result.unresolved_findings
    );
}

fn print_asn_group(
    group: &shenron::triage::EntityGroup,
    windowed: bool,
    reputation_database: Option<&ReputationDatabase>,
) {
    println!(
        "ASN {} ({})\n  Grouping identity: {}\n  Triage basis: {}\n  Matching request observations: {}\n  Distinct Nuclei template patterns: {}\n  Unique CVEs: {}\n  Matched template records: {}\n  Distinct member IPs: {}",
        terminal_safe(&group.key),
        group
            .asn_org
            .as_deref()
            .map(terminal_safe)
            .unwrap_or_else(|| "unavailable".to_owned()),
        group
            .identity
            .expect("ASN groups carry an identity")
            .label(),
        group.triage_basis.unwrap_or("none"),
        group.distinct_observations,
        group.distinct_templates,
        group.distinct_cves,
        group.matching_records,
        group.spread,
    );
    if windowed {
        println!(
            "  Undated observations excluded from windowed triage: {}",
            group.undated_observations
        );
        print_windowed_burst_windows(group);
    }
    println!("  Behavior priority score: {}", score_display(&group.score));
    print_sequence_summary(&group.sequence);
    println!(
        "  Request-specific observations: {}\n  Response-unverified observations: {}",
        group.request_specific_observations, group.response_unverified_observations
    );
    if let Some(database) = reputation_database {
        let reputation = group
            .key
            .parse::<u32>()
            .ok()
            .map(|asn| database.lookup_asn(asn));
        match reputation {
            Some(reputation) => {
                match (reputation.score, reputation.tier, reputation.score_scope) {
                    (Some(score), Some(tier), Some(scope)) => println!(
                        "  Reputation: {score}/100 ({}) via {}",
                        tier.label(),
                        terminal_safe(scope)
                    ),
                    _ => println!("  Reputation: none"),
                }
                print_reputation_hits(reputation.hits);
            }
            None => println!("  Reputation: none"),
        }
    }
}

fn print_ja4_summary(
    findings: &[shenron::production::FindingExplanation],
    limit: usize,
    triage: TriageContext,
) {
    let groups = entity_groups(
        findings,
        EntityDimension::Ja4,
        triage.policy.clone(),
        triage.capabilities,
    );
    println!("\nJA4 fingerprint triage (private findings only):");
    println!(
        "A JA4 client fingerprint groups requests that share TLS client characteristics. Validated-client and observed-peer identities are intentionally reported separately because they must not be merged. One fingerprint observed across several identities can indicate shared tooling or automation; it is not attacker attribution and does not establish an attack, exploitation, or compromise. Behavior priority score (0-100) ranks a fingerprint for triage from observed request behavior only."
    );
    println!(
        "Ordered request sequence window: {} (cap {} observations per entity). Sequence timing is an observation for review, not a determination of automation, attack, abuse, or identity.",
        format_triage_duration(triage.policy.sequence_window),
        triage.policy.max_sequence_observations,
    );
    let displayed = if limit == 0 {
        groups.as_slice()
    } else {
        &groups[..groups.len().min(limit)]
    };
    if displayed.is_empty() {
        println!("No JA4 fingerprints were recorded in the selected findings.");
        return;
    }
    for group in displayed {
        println!(
            "{}\n  Triage basis: {}\n  Distinct validated clients sharing this fingerprint: {}\n  Distinct observed peers sharing this fingerprint: {}\n  Identity spread used for behavior score: {}\n  Matching request observations: {}\n  Distinct Nuclei template patterns: {}\n  Unique CVEs: {}\n  Matched template records: {}\n  Behavior priority score: {}\n  Request-specific observations: {}\n  Response-unverified observations: {}",
            terminal_safe(&group.key),
            group.triage_basis.unwrap_or("none"),
            group.distinct_validated_clients,
            group.distinct_observed_peers,
            group.spread,
            group.distinct_observations,
            group.distinct_templates,
            group.distinct_cves,
            group.matching_records,
            score_display(&group.score),
            group.request_specific_observations,
            group.response_unverified_observations,
        );
        if !triage.policy.windows.is_empty() {
            println!(
                "  Undated observations excluded from windowed triage: {}",
                group.undated_observations
            );
            print_windowed_burst_windows(group);
        }
        print_sequence_summary(&group.sequence);
    }
    if displayed.len() < groups.len() {
        println!(
            "{} additional JA4 fingerprints omitted. Pass --limit 0 to display all.",
            groups.len() - displayed.len()
        );
    }
}

fn print_windowed_burst_windows(group: &shenron::triage::EntityGroup) {
    if group.windowed_burst_windows.is_empty() {
        println!("  Windowed burst matches: none");
        return;
    }
    println!(
        "  Windowed burst matches: {}",
        group
            .windowed_burst_windows
            .iter()
            .map(|item| format!(
                "{} ({})",
                format_triage_duration(Duration::from_secs(item.window_seconds)),
                item.basis
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn print_sequence_summary(sequence: &shenron::triage::RequestSequenceSummary) {
    let minimum = sequence
        .minimum_interval_seconds
        .map(|value| format!("{value:.3}s"))
        .unwrap_or_else(|| "unavailable".to_owned());
    let median = sequence
        .median_interval_seconds
        .map(|value| format!("{value:.3}s"))
        .unwrap_or_else(|| "unavailable".to_owned());
    println!(
        "  Ordered sequence observation ({} window): distinct patterns max {}, distinctive-path patterns max {}, interval min {}, median {}; undated {}, beyond cap {}",
        format_triage_duration(Duration::from_secs(sequence.window_seconds)),
        sequence.maximum_distinct_patterns_in_window,
        sequence.maximum_distinctive_patterns_in_window,
        minimum,
        median,
        sequence.observations_without_timestamp,
        sequence.observations_beyond_cap,
    );
}

fn print_triage_windows(windows: &[Duration]) {
    if let [window] = windows {
        println!("Triage window: {} sliding", format_triage_duration(*window));
    } else {
        println!(
            "Triage windows: {} sliding",
            windows
                .iter()
                .copied()
                .map(format_triage_duration)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

fn format_triage_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds.is_multiple_of(24 * 60 * 60) {
        format!("{}d", seconds / (24 * 60 * 60))
    } else if seconds.is_multiple_of(60 * 60) {
        format!("{}h", seconds / (60 * 60))
    } else if seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

fn validate(rules: &Path) -> Result<()> {
    let ruleset = load_explicit_rules(rules)?;
    for rule in &ruleset.supported {
        println!("SUPPORTED    {}", rule.title);
    }
    for rule in &ruleset.unsupported {
        println!(
            "UNSUPPORTED  {}\n             reason: {}",
            rule.title.as_deref().unwrap_or(&rule.path),
            rule.reason
        );
    }
    println!(
        "\nRules loaded:       {}\nSupported:          {}\nUnsupported:        {}",
        ruleset.supported.len() + ruleset.unsupported.len(),
        ruleset.supported.len(),
        ruleset.unsupported.len()
    );
    Ok(())
}

#[cfg(test)]
mod duration_tests {
    use super::{parse_triage_duration, Duration, MAX_TRIAGE_WINDOW_SECONDS};

    #[test]
    fn accepts_bounded_triage_window_durations() {
        assert_eq!(parse_triage_duration("10m"), Ok(Duration::from_secs(600)));
        assert_eq!(
            parse_triage_duration("1h"),
            Ok(Duration::from_secs(60 * 60))
        );
        assert_eq!(
            parse_triage_duration("2d"),
            Ok(Duration::from_secs(2 * 24 * 60 * 60))
        );
        assert_eq!(
            parse_triage_duration("3650d"),
            Ok(Duration::from_secs(MAX_TRIAGE_WINDOW_SECONDS))
        );
    }

    #[test]
    fn rejects_excessive_or_unrepresentable_triage_windows() {
        for value in ["4000d", "18446744073709551615d"] {
            let error = parse_triage_duration(value).unwrap_err();
            assert!(error.contains("maximum 3650d"));
        }
    }
}
