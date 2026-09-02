use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use walkdir::WalkDir;

use shenron::{
    access_log::{AccessLogFormat, AccessLogLines},
    candidate::{
        build_batch_from_findings, compatibility as candidate_compatibility,
        export as export_candidate, load as load_candidate, replay as replay_candidate,
        save as save_candidate, save_batch, Backend,
    },
    event::{TelemetryCapabilities, TelemetryProfile, TrustedProxy, TrustedProxySet},
    nuclei::{path_distinctiveness, PathDistinctiveness},
    output::{Finding, FindingWriter},
    paths::{
        default_asn_dataset, default_nuclei_report, default_reputation_dataset,
        default_templates_dir,
    },
    production::{
        ablation_with_optional_kev as production_ablation,
        count_hypotheses_with_optional_kev as production_count_hypotheses,
        explain_private_findings,
        historical_replay_with_optional_kev as production_historical_replay,
        hunt_with_options as production_hunt, inspect_with_trusted_proxies as production_inspect,
        terminal_safe, AblationReport, CountHypothesisReport, HistoricalReplayReport, HuntOptions,
        HuntTimeRange, HuntTriagePolicy, InspectionReport, SanitizedHuntReport,
    },
    reputation::{load_asn_database, load_reputation_database, AsnDatabase, ReputationDatabase},
    sigma::load_rules,
    triage::{asn_entity_groups, entity_groups, EntityDimension, TriagePolicy},
    waf::{maybe_gzip_reader, WafLines},
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
enum Command {
    /// Match supported Sigma rules against AWS WAF JSONL logs.
    Scan {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum)]
        format: InputFormat,
        #[arg(long)]
        rules: PathBuf,
        /// Findings destination. Defaults to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
        output_format: OutputFormat,
    },
    /// Report which user-provided rules are in the intentionally small MVP subset.
    ValidateRules {
        #[arg(long)]
        rules: PathBuf,
    },
    /// Read-only local inspection and hunting against historical AWS WAF logs.
    Production {
        #[command(subcommand)]
        command: ProductionCommand,
    },
    /// Build, review, and export defensive candidates. Never deploys controls.
    Candidate {
        #[command(subcommand)]
        command: CandidateCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CandidateCommand {
    /// Build narrow candidates from private hunt findings. AWS WAF BLOCK and URI-only findings are excluded by default.
    Build {
        #[arg(long)]
        from_findings: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        telemetry: InputFormat,
        /// Include URI-only response-unverified findings. Use only after human review or with additional evidence.
        #[arg(long)]
        include_response_unverified: bool,
    },
    /// Evaluate a candidate against local historical telemetry and write a new candidate file.
    Replay {
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum)]
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

#[derive(Debug, Subcommand)]
enum ProductionCommand {
    /// Inspect local log structure without emitting request values.
    Inspect {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = InputFormat::AwsWaf)]
        format: InputFormat,
        #[arg(long, default_value_t = 10_000)]
        sample: usize,
        /// Trusted direct proxy IP or CIDR. Repeat to trust multiple proxy networks.
        /// Forwarded client IPs remain unavailable unless this is specified.
        #[arg(long, value_name = "IP-or-CIDR")]
        trusted_proxy: Vec<TrustedProxy>,
    },
    /// Hunt with the same validated Nuclei request matchers; writes separate private and sanitized artifacts.
    Hunt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = InputFormat::AwsWaf)]
        format: InputFormat,
        #[arg(long)]
        nuclei_templates: Option<PathBuf>,
        #[arg(long)]
        nuclei_report: Option<PathBuf>,
        #[arg(long)]
        kev_report: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Inclusive UTC start time in RFC 3339 format, for example 2026-04-01T00:00:00Z.
        #[arg(long, value_parser = parse_rfc3339_utc)]
        from: Option<DateTime<Utc>>,
        /// Inclusive UTC end time in RFC 3339 format, for example 2026-04-30T23:59:59Z.
        #[arg(long, value_parser = parse_rfc3339_utc)]
        to: Option<DateTime<Utc>>,
        /// Trusted direct proxy IP or CIDR. Repeat to trust multiple proxy networks.
        /// Forwarded client IPs remain unavailable unless this is specified.
        #[arg(long, value_name = "IP-or-CIDR")]
        trusted_proxy: Vec<TrustedProxy>,
    },
    /// Compare aggregate match volume across predicates derived from one validated Nuclei IR. Never writes private findings.
    Ablation {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = InputFormat::AwsWaf)]
        format: InputFormat,
        #[arg(long)]
        nuclei_templates: Option<PathBuf>,
        #[arg(long)]
        nuclei_report: Option<PathBuf>,
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
    },
    /// Compare broad-to-narrow validated Nuclei conditions as local COUNT-mode simulations. Never deploys a control.
    CountHypotheses {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = InputFormat::AwsWaf)]
        format: InputFormat,
        #[arg(long)]
        nuclei_templates: Option<PathBuf>,
        #[arg(long)]
        nuclei_report: Option<PathBuf>,
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
    },
    /// Measure validated Nuclei matcher coverage and other aggregate historical matches. Never writes private findings.
    Replay {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = InputFormat::AwsWaf)]
        format: InputFormat,
        #[arg(long)]
        nuclei_templates: Option<PathBuf>,
        #[arg(long)]
        nuclei_report: Option<PathBuf>,
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
    },
    /// Show CVE/template mappings from a locally stored private findings file.
    Explain {
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
        triage_window: Option<Duration>,
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
    },
}

/// The rendering format for `production explain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExplainOutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InputFormat {
    /// AWS WAF JSON logs.
    AwsWaf,
    /// Standard nginx Combined Log Format.
    Nginx,
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
    fn telemetry_profile(self) -> TelemetryProfile {
        match self {
            Self::AwsWaf => TelemetryProfile::AwsWaf,
            Self::Nginx => TelemetryProfile::NginxCombined,
            Self::Apache => TelemetryProfile::ApacheCombined,
            Self::ApacheVhost => TelemetryProfile::ApacheVhostCombined,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Jsonl,
    Csv,
}

#[derive(Debug, Default)]
struct ScanStats {
    files: usize,
    events: usize,
    malformed: usize,
    findings: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ValidateRules { rules } => validate(&rules),
        Command::Scan {
            input,
            format,
            rules,
            output,
            output_format,
        } => scan(&input, &rules, output.as_deref(), output_format, format),
        Command::Production { command } => match command {
            ProductionCommand::Inspect {
                input,
                format,
                sample,
                trusted_proxy,
            } => {
                print_inspection(&production_inspect(
                    &input,
                    format.telemetry_profile(),
                    sample,
                    &TrustedProxySet::new(trusted_proxy),
                )?);
                Ok(())
            }
            ProductionCommand::Hunt {
                input,
                format,
                nuclei_templates,
                nuclei_report,
                kev_report,
                output,
                from,
                to,
                trusted_proxy,
            } => {
                let (nuclei_templates, nuclei_report) =
                    resolve_nuclei_inputs(nuclei_templates, nuclei_report)?;
                let output = output.unwrap_or_else(default_hunt_output);
                let report = production_hunt(
                    &input,
                    &nuclei_templates,
                    &nuclei_report,
                    kev_report.as_deref(),
                    &output,
                    format.telemetry_profile(),
                    HuntOptions {
                        time_range: HuntTimeRange { from, to },
                        trusted_proxies: TrustedProxySet::new(trusted_proxy),
                        triage_policy: HuntTriagePolicy::default(),
                    },
                )?;
                let sanitized_path = output.join("sanitized-research.json");
                serde_json::to_writer_pretty(File::create(&sanitized_path)?, &report)?;
                print_hunt(&report, &sanitized_path);
                Ok(())
            }
            ProductionCommand::Ablation {
                input,
                format,
                nuclei_templates,
                nuclei_report,
                kev_report,
                output,
                from,
                to,
            } => {
                let (nuclei_templates, nuclei_report) =
                    resolve_nuclei_inputs(nuclei_templates, nuclei_report)?;
                let report = production_ablation(
                    &input,
                    &nuclei_templates,
                    &nuclei_report,
                    kev_report.as_deref(),
                    format.telemetry_profile(),
                    HuntTimeRange { from, to },
                )?;
                if let Some(path) = output.as_deref() {
                    serde_json::to_writer_pretty(File::create(path)?, &report)?;
                }
                print_ablation(&report, output.as_deref());
                Ok(())
            }
            ProductionCommand::Replay {
                input,
                format,
                nuclei_templates,
                nuclei_report,
                kev_report,
                findings,
                output,
                from,
                to,
            } => {
                let (nuclei_templates, nuclei_report) =
                    resolve_nuclei_inputs(nuclei_templates, nuclei_report)?;
                if let Some(path) = output.as_deref() {
                    shenron::production::ensure_separate_output(&input, path)?;
                }
                let report = production_historical_replay(
                    &input,
                    &nuclei_templates,
                    &nuclei_report,
                    kev_report.as_deref(),
                    &findings,
                    format.telemetry_profile(),
                    HuntTimeRange { from, to },
                )?;
                if let Some(path) = output.as_deref() {
                    serde_json::to_writer_pretty(File::create(path)?, &report)?;
                }
                print_historical_replay(&report, output.as_deref());
                Ok(())
            }
            ProductionCommand::CountHypotheses {
                input,
                format,
                nuclei_templates,
                nuclei_report,
                kev_report,
                findings,
                output,
                from,
                to,
                limit,
            } => {
                let (nuclei_templates, nuclei_report) =
                    resolve_nuclei_inputs(nuclei_templates, nuclei_report)?;
                if let Some(path) = output.as_deref() {
                    shenron::production::ensure_separate_output(&input, path)?;
                }
                let report = production_count_hypotheses(
                    &input,
                    &nuclei_templates,
                    &nuclei_report,
                    kev_report.as_deref(),
                    &findings,
                    format.telemetry_profile(),
                    HuntTimeRange { from, to },
                )?;
                if let Some(path) = output.as_deref() {
                    serde_json::to_writer_pretty(File::create(path)?, &report)?;
                }
                print_count_hypotheses(&report, output.as_deref(), limit);
                Ok(())
            }
            ProductionCommand::Explain {
                findings,
                waf_outcome,
                include_generic,
                show_request,
                show_evidence,
                show_source_ips,
                show_asn,
                asn_dataset,
                reputation_dataset,
                show_fingerprints,
                triage_breadth_observations,
                triage_breadth_templates,
                triage_depth_observations,
                triage_window,
                limit,
                output,
                output_format,
            } => {
                let asn_dataset = resolve_optional_local_dataset(asn_dataset, default_asn_dataset);
                let reputation_dataset =
                    resolve_optional_local_dataset(reputation_dataset, default_reputation_dataset);
                let asn_database = asn_dataset.as_deref().map(load_asn_database).transpose()?;
                let reputation_database = reputation_dataset
                    .as_deref()
                    .map(load_reputation_database)
                    .transpose()?;
                let findings = explain_private_findings(&findings)?;
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
                let findings = match waf_outcome {
                    Some(filter) => findings
                        .into_iter()
                        .filter(|finding| filter.matches(finding))
                        .collect(),
                    None => findings,
                };
                let (findings, hidden) = if include_generic {
                    (findings, Vec::new())
                } else {
                    let (hidden, findings) = findings
                        .into_iter()
                        .partition::<Vec<_>, _>(is_low_confidence_generic_match);
                    (findings, hidden)
                };
                let display = ExplainDisplay {
                    show_request: show_request || show_evidence,
                    show_evidence,
                    show_source_ips,
                    show_asn,
                    show_fingerprints,
                };
                let triage = TriageContext {
                    policy: TriagePolicy::new(
                        triage_breadth_observations,
                        triage_breadth_templates,
                        triage_depth_observations,
                        triage_window,
                    ),
                    capabilities,
                };
                match output_format {
                    ExplainOutputFormat::Json => {
                        let report = build_explain_report(
                            &findings,
                            &hidden,
                            &display,
                            waf_outcome.map(WafOutcomeFilter::label),
                            limit,
                            triage,
                            asn_database.as_ref(),
                            reputation_database.as_ref(),
                        );
                        let json = serde_json::to_string_pretty(&report)?;
                        match output {
                            Some(path) => {
                                std::fs::write(&path, json).with_context(|| {
                                    format!("writing explain report {}", path.display())
                                })?;
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
                        print_explanations(
                            &findings,
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
        },
        Command::Candidate { command } => match command {
            CandidateCommand::Build {
                from_findings,
                output,
                telemetry,
                include_response_unverified,
            } => {
                let findings = explain_private_findings(&from_findings)?;
                let (candidates, stats) = build_batch_from_findings(
                    &findings,
                    telemetry.telemetry_profile(),
                    include_response_unverified,
                );
                if candidates.is_empty() {
                    anyhow::bail!(
                        "no candidate patterns could be built from the supplied findings; response-unverified findings are excluded by default (pass --include-response-unverified only after human review or with additional evidence)"
                    );
                }
                save_batch(&candidates, &output)?;
                println!("Candidates written: {}\nOutput directory: {}\nAWS WAF BLOCK findings excluded: {}\nResponse-unverified findings excluded: {}\nFindings skipped for missing method/path: {}\nRecommended initial action: COUNT\nHistorical replay: required before preventive export.", stats.candidates, output.display(), stats.excluded_blocked_findings, stats.excluded_response_unverified_findings, stats.skipped_incomplete_findings);
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
                    format.telemetry_profile(),
                    &output,
                )?;
                save_candidate(&candidate, &output)?;
                println!("Historical replay complete. Candidate written: {}\nRequests evaluated: {}\nOther historical matches: {}\nPreventive export remains COUNT-only.", output.display(), candidate.evidence.historical_requests_evaluated, candidate.evidence.other_historical_matches);
                Ok(())
            }
            CandidateCommand::Compatibility {
                candidate,
                telemetry,
            } => {
                let candidate = load_candidate(&candidate)?;
                let telemetry = telemetry
                    .map(InputFormat::telemetry_profile)
                    .unwrap_or(candidate.telemetry_profile);
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
                let telemetry = telemetry
                    .map(InputFormat::telemetry_profile)
                    .unwrap_or(candidate.telemetry_profile);
                println!("Candidate ID: {}\nCVEs: {}\nCISA KEV: {}\nRecommended initial action: COUNT\nReplay completed: {}\nHistorical requests evaluated: {}\nKnown threat findings: {}\nKnown threat findings matched: {}\nKnown threat findings missed: {}\nOther historical matches: {}\nThreat coverage: {:?}\nTelemetry source: {:?}\nConditions:\n{:#?}\n\nBackend compatibility:", candidate.id, candidate.cves.join(", "), candidate.kev, candidate.evidence.replay_completed, candidate.evidence.historical_requests_evaluated, candidate.evidence.known_threat_findings, candidate.evidence.known_threat_findings_matched, candidate.evidence.known_threat_findings_missed, candidate.evidence.other_historical_matches, candidate.evidence.threat_coverage, candidate.telemetry_profile, candidate.conditions);
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
                let telemetry = telemetry
                    .map(InputFormat::telemetry_profile)
                    .unwrap_or(candidate.telemetry_profile);
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
        },
    }
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
            "default Nuclei templates checkout is missing at {}; first run `shenron-lab nuclei update`",
            templates.display()
        );
    }
    if report_was_defaulted && !report.is_file() {
        anyhow::bail!(
            "default frozen Nuclei report is missing at {}; first run `shenron-lab nuclei update`",
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

fn default_hunt_output() -> PathBuf {
    PathBuf::from("private-results").join(format!("hunt-{}", Utc::now().format("%Y%m%dT%H%M%SZ")))
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

fn print_inspection(report: &InspectionReport) {
    let fields = &report.fields_available;
    let capabilities = report.telemetry_capabilities;
    let supported = |available: bool, count: usize| {
        if available {
            count.to_string()
        } else {
            "not supported by telemetry profile".to_owned()
        }
    };
    println!("Telemetry profile:          {:?}\nFiles found:                {}\nCompressed files:           {}\nApproximate input bytes:    {}\nParseable events sampled:   {}\nMalformed events sampled:   {}\nEarliest timestamp:         {}\nLatest timestamp:           {}\n\nField availability (sample counts):\nVerified forwarded client IP: {} (requires --trusted-proxy)\nJA4:                        {}\nJA3:                        {}\nURI:                        {}\nQuery:                      {}\nHeaders:                    {}\nHost:                       {}\nMethod:                     {}\nWAF action:                 {}\nWAF labels:                 {}\nTerminating rule ID:        {}\nNon-terminating rules:      {}", report.telemetry_profile, report.files_found, report.compressed_files, report.approximate_input_bytes, report.sampled_events, report.malformed_events, report.earliest_timestamp.as_deref().unwrap_or("unknown"), report.latest_timestamp.as_deref().unwrap_or("unknown"), fields.client_ip, supported(capabilities.ja4, fields.ja4), supported(capabilities.ja3, fields.ja3), supported(capabilities.uri_path, fields.uri), supported(capabilities.uri_query, fields.query), fields.headers, supported(capabilities.host, fields.host), supported(capabilities.method, fields.method), supported(capabilities.waf_action, fields.waf_action), supported(capabilities.waf_labels, fields.waf_labels), supported(capabilities.waf_action, fields.terminating_rule_id), supported(capabilities.waf_action, fields.non_terminating_rules));
}

fn print_hunt(report: &SanitizedHuntReport, sanitized_path: &Path) {
    let metrics = &report.metrics;
    let time_range = match (&metrics.filter_from, &metrics.filter_to) {
        (None, None) => "Time filter:                all timestamps".to_owned(),
        (from, to) => format!(
            "Time filter:                {} to {}\nOutside range ignored:      {}\nTimestamp missing ignored:  {}",
            from.as_deref().unwrap_or("beginning"),
            to.as_deref().unwrap_or("end"),
            metrics.requests_outside_time_range,
            metrics.requests_without_timestamp_excluded,
        ),
    };
    let outcomes = if metrics.waf_outcome_available {
        format!("Existing WAF outcomes:\nBLOCK:                       {}\nAllowed / not blocked:       {}\nCOUNT-related evidence:      {}\nUnknown:                     {}", metrics.blocked, metrics.allowed_or_not_blocked, metrics.count_related_evidence, metrics.unknown_outcome)
    } else {
        "WAF outcome:                unavailable for this telemetry source".to_owned()
    };
    println!("Read-only production hunt complete.\nPrivate findings:            written under the supplied output directory\nSanitized report:            {}\n\n{}\n\nRequests analyzed:           {}\nFiles analyzed:              {}\nParse errors:                {}\nCVE-related request matches: {}\n  Request-specific:          {}\n  Response-unverified:       {}\nUnique CVEs observed:        {}\nUnique CISA KEVs observed:   {}\nSource clusters:             {}\nJA4 fingerprints:            {}\nDetection-match confidence (template detectability; NOT attack/compromise confidence):\n  HIGH:                      {}\n  MEDIUM:                    {}\n  LOW:                       {}\n\n{}", sanitized_path.display(), time_range, metrics.total_requests_analyzed, metrics.files_analyzed, metrics.parse_errors, metrics.cve_related_request_matches, metrics.request_specific_matches, metrics.response_unverified_matches, metrics.unique_cves_observed, metrics.unique_cisa_kevs_observed, metrics.unique_source_clusters, metrics.unique_ja4_fingerprints, metrics.high_confidence_findings, metrics.medium_confidence_findings, metrics.low_confidence_findings, outcomes);
}

fn print_ablation(report: &AblationReport, output_path: Option<&Path>) {
    println!(
        "Ablation match-volume comparison only: volume rate = matched events / total events evaluated; it is NOT precision, recall, accuracy, ground truth, or an attack/exploitation/compromise determination."
    );
    println!("{}", report.safety_note);
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
    let aggregate = &report.aggregate;
    let coverage = aggregate
        .coverage
        .map(|coverage| format!("{coverage:.4}"))
        .unwrap_or_else(|| "unavailable (no source finding request IDs)".to_owned());
    println!("Historical replay coverage is a conservative lower bound based on source-finding request IDs; it is NOT precision, recall, accuracy, ground truth, or an attack/exploitation/compromise determination.");
    println!("{}", report.safety_note);
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
    println!("COUNT hypothesis ladder is an offline, non-deploying simulation. It reports trade-off measurements only and does NOT recommend a rung.");
    println!("{}", report.safety_note);
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
#[derive(Clone, Copy)]
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
    cves: Vec<String>,
    template_id: String,
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

fn base_group_json(group: &shenron::triage::EntityGroup) -> GroupJson {
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
        score: group.score.clone(),
        reputation: None,
    }
}

fn connection_ip_group_json(
    group: &shenron::triage::EntityGroup,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
) -> GroupJson {
    let mut json = base_group_json(group);
    if let Ok(ip) = group.key.parse::<IpAddr>() {
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
) -> GroupJson {
    let mut json = base_group_json(group);
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
        cves: finding.cves.clone(),
        template_id: finding.template_id.clone(),
        detectability: finding.detectability,
        request_specificity: finding.request_specificity,
        timestamp: finding.timestamp.clone(),
        waf_action: finding.waf_action.clone(),
        request,
        evidence,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_explain_report(
    findings: &[shenron::production::FindingExplanation],
    hidden: &[shenron::production::FindingExplanation],
    display: &ExplainDisplay,
    waf_outcome_filter: Option<&str>,
    limit: usize,
    triage: TriageContext,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
) -> ExplainReport {
    let truncate = |mut rows: Vec<GroupJson>| {
        if limit != 0 {
            rows.truncate(limit);
        }
        rows
    };
    let mut request_paths = explanation_summary(findings);
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
                findings,
                EntityDimension::ConnectionIp,
                triage.policy,
                triage.capabilities,
            )
            .iter()
            .map(|group| connection_ip_group_json(group, asn_database, reputation_database))
            .collect(),
        )
    });

    let asn_groups = display
        .show_asn
        .then_some(asn_database)
        .flatten()
        .map(|database| {
            let result = asn_entity_groups(findings, triage.policy, database, triage.capabilities);
            AsnGroupsJson {
                groups: truncate(
                    result
                        .groups
                        .iter()
                        .map(|group| asn_group_json(group, reputation_database))
                        .collect(),
                ),
                unresolved_findings: result.unresolved_findings,
            }
        });

    let ja4_groups = display.show_fingerprints.then(|| {
        truncate(
            entity_groups(
                findings,
                EntityDimension::Ja4,
                triage.policy,
                triage.capabilities,
            )
            .iter()
            .map(base_group_json)
            .collect(),
        )
    });

    let individual_findings = (display.show_request || display.show_evidence).then(|| {
        let shown = if limit == 0 {
            findings
        } else {
            &findings[..findings.len().min(limit)]
        };
        shown
            .iter()
            .map(|finding| finding_json(finding, display))
            .collect()
    });

    ExplainReport {
        report_kind: "EXPLAIN_PRIVATE_TRIAGE",
        waf_outcome_filter: waf_outcome_filter.map(str::to_owned),
        total_mappings: findings.len(),
        hidden_low_confidence,
        request_paths,
        connection_ip_groups,
        asn_groups,
        ja4_groups,
        individual_findings,
    }
}

fn print_explanations(
    findings: &[shenron::production::FindingExplanation],
    display: ExplainDisplay,
    waf_outcome_filter: Option<&str>,
    limit: usize,
    triage: TriageContext,
    asn_database: Option<&AsnDatabase>,
    reputation_database: Option<&ReputationDatabase>,
) {
    let displayed = if limit == 0 {
        findings
    } else {
        &findings[..findings.len().min(limit)]
    };
    match waf_outcome_filter {
        Some(filter) => println!(
            "CVE / Nuclei template mappings: {} (WAF outcome filter: {})",
            findings.len(),
            filter
        ),
        None => println!("CVE / Nuclei template mappings: {}", findings.len()),
    }
    print_explanation_summary(findings, limit);
    if display.show_source_ips {
        print_source_ip_summary(findings, limit, triage, asn_database, reputation_database);
    } else if (asn_database.is_some() || reputation_database.is_some()) && !display.show_asn {
        println!(
            "Local reputation datasets were supplied, but --show-source-ips was not selected; no IP enrichment was displayed."
        );
    }
    if display.show_asn {
        match asn_database {
            Some(database) => {
                print_asn_summary(findings, limit, triage, database, reputation_database)
            }
            None => println!(
                "ASN grouping was requested, but --asn-dataset was not supplied; no ASN groups were displayed."
            ),
        }
    }
    if display.show_fingerprints {
        print_ja4_summary(findings, limit, triage);
    }
    if !display.show_request && !display.show_evidence {
        println!("Pass --show-request to display individual requests, or --show-evidence to include all locally stored evidence.");
        return;
    }
    if displayed.len() < findings.len() {
        println!(
            "\nShowing first {} individual findings; {} omitted. Pass --limit 0 to display all.",
            displayed.len(),
            findings.len() - displayed.len()
        );
    }
    for (index, finding) in displayed.iter().enumerate() {
        println!(
            "\n[{}]\nCVE: {}\nNuclei template: {}\nTemplate detectability: {:?}\nRequest specificity: {}\nTimestamp: {}\nWAF action: {}",
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
        policy,
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
    if let Some(window) = policy.window {
        println!("Triage window: {} sliding", format_triage_duration(window));
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
                policy.window.is_some(),
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
            policy.window.is_some(),
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
    }
    println!("  Behavior priority score: {}", score_display(&group.score));
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
    let Ok(ip) = group.key.parse::<IpAddr>() else {
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
    let result = asn_entity_groups(findings, policy, asn_database, triage.capabilities);
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
    if let Some(window) = policy.window {
        println!("Triage window: {} sliding", format_triage_duration(window));
    }
    println!(
        "Grouping identity: validated-client and observed-peer are intentionally never merged, including when they resolve to the same ASN. Distinct member IPs are the larger of those separately counted identity populations. This is not an attacker, exploit-success, or compromise determination."
    );
    println!(
        "Behavior priority score (0-100) ranks an ASN group for triage from observed request behavior only. It is not a probability of malice, a precision or true-positive estimate, an exploitation or compromise determination, or attacker attribution."
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
            print_asn_group(group, policy.window.is_some(), reputation_database);
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
    }
    println!("  Behavior priority score: {}", score_display(&group.score));
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
        triage.policy,
        triage.capabilities,
    );
    println!("\nJA4 fingerprint triage (private findings only):");
    println!(
        "A JA4 client fingerprint groups requests that share TLS client characteristics. Validated-client and observed-peer identities are intentionally reported separately because they must not be merged. One fingerprint observed across several identities can indicate shared tooling or automation; it is not attacker attribution and does not establish an attack, exploitation, or compromise. Behavior priority score (0-100) ranks a fingerprint for triage from observed request behavior only."
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
    }
    if displayed.len() < groups.len() {
        println!(
            "{} additional JA4 fingerprints omitted. Pass --limit 0 to display all.",
            groups.len() - displayed.len()
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
    let ruleset = load_rules(rules);
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

fn scan(
    input: &Path,
    rules_path: &Path,
    output: Option<&Path>,
    output_format: OutputFormat,
    input_format: InputFormat,
) -> Result<()> {
    let ruleset = load_rules(rules_path);
    let destination: Box<dyn Write> = match output {
        Some(path) => {
            Box::new(File::create(path).with_context(|| format!("creating {}", path.display()))?)
        }
        None => Box::new(io::stdout()),
    };
    let mut writer = match output_format {
        OutputFormat::Jsonl => FindingWriter::jsonl(destination),
        OutputFormat::Csv => FindingWriter::csv(destination),
    };
    writer.write_header()?;
    let mut stats = ScanStats::default();
    for path in input_files(input)? {
        stats.files += 1;
        let compressed = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("gz"));
        let reader = maybe_gzip_reader(
            File::open(&path).with_context(|| format!("opening {}", path.display()))?,
            compressed,
        );
        match input_format {
            InputFormat::AwsWaf => scan_events(
                WafLines::new(reader),
                &path,
                &ruleset.supported,
                &mut writer,
                &mut stats,
            )?,
            InputFormat::Nginx => scan_events(
                AccessLogLines::new(reader, AccessLogFormat::NginxCombined),
                &path,
                &ruleset.supported,
                &mut writer,
                &mut stats,
            )?,
            InputFormat::Apache => scan_events(
                AccessLogLines::new(reader, AccessLogFormat::ApacheCombined),
                &path,
                &ruleset.supported,
                &mut writer,
                &mut stats,
            )?,
            InputFormat::ApacheVhost => scan_events(
                AccessLogLines::new(reader, AccessLogFormat::ApacheVhostCombined),
                &path,
                &ruleset.supported,
                &mut writer,
                &mut stats,
            )?,
        }
    }
    writer.finish()?;
    eprintln!("Files processed:     {}\nEvents processed:    {}\nMalformed events:    {}\nRules loaded:        {}\nSupported rules:     {}\nUnsupported rules:   {}\nFindings:            {}",
        stats.files, stats.events, stats.malformed, ruleset.supported.len() + ruleset.unsupported.len(), ruleset.supported.len(), ruleset.unsupported.len(), stats.findings);
    Ok(())
}

fn scan_events<I, E>(
    events: I,
    path: &Path,
    rules: &[shenron::sigma::CompiledRule],
    writer: &mut FindingWriter<Box<dyn Write>>,
    stats: &mut ScanStats,
) -> Result<()>
where
    I: Iterator<Item = Result<shenron::event::WebEvent, E>>,
    E: std::fmt::Display,
{
    for result in events {
        match result {
            Ok(event) => {
                stats.events += 1;
                for rule in rules {
                    if rule.matches(&event) {
                        writer.write(&Finding::from_rule_and_event(rule, &event))?;
                        stats.findings += 1;
                    }
                }
            }
            Err(error) => {
                stats.malformed += 1;
                eprintln!("warning: {}: {error}", path.display());
            }
        }
    }
    Ok(())
}

fn input_files(input: &Path) -> Result<Vec<PathBuf>> {
    if input.is_file() {
        return Ok(vec![input.to_owned()]);
    }
    if !input.is_dir() {
        anyhow::bail!(
            "input path does not exist or is not a regular file/directory: {}",
            input.display()
        );
    }
    Ok(WalkDir::new(input)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .collect())
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
