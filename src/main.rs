use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use walkdir::WalkDir;

use shenron::{
    access_log::{AccessLogFormat, AccessLogLines},
    candidate::{
        build_batch_from_findings, compatibility as candidate_compatibility,
        export as export_candidate, load as load_candidate, replay as replay_candidate,
        save as save_candidate, save_batch, Backend,
    },
    event::TelemetryProfile,
    output::{Finding, FindingWriter},
    production::{
        explain_private_findings, hunt as production_hunt, inspect as production_inspect,
        terminal_safe, HuntTimeRange, InspectionReport, SanitizedHuntReport,
    },
    sigma::load_rules,
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
    /// Build narrow candidates from private hunt findings. AWS WAF BLOCK findings are excluded.
    Build {
        #[arg(long)]
        from_findings: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        telemetry: InputFormat,
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
    },
    /// Hunt with the same validated Nuclei request matchers; writes separate private and sanitized artifacts.
    Hunt {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = InputFormat::AwsWaf)]
        format: InputFormat,
        #[arg(long)]
        nuclei_templates: PathBuf,
        #[arg(long)]
        nuclei_report: PathBuf,
        #[arg(long)]
        kev_report: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Inclusive UTC start time in RFC 3339 format, for example 2026-04-01T00:00:00Z.
        #[arg(long, value_parser = parse_rfc3339_utc)]
        from: Option<DateTime<Utc>>,
        /// Inclusive UTC end time in RFC 3339 format, for example 2026-04-30T23:59:59Z.
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
        /// Display matched method, path, and query. This may expose sensitive request values.
        #[arg(long)]
        show_request: bool,
        /// Display all private evidence captured by hunt, including IP, host,
        /// headers, JA3/JA4, WAF labels/rule IDs, and request ID. Implies --show-request.
        #[arg(long)]
        show_evidence: bool,
        /// Maximum individual findings to display. Use 0 to display all findings.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InputFormat {
    AwsWaf,
    Nginx,
    Apache,
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
            } => {
                print_inspection(&production_inspect(
                    &input,
                    format.telemetry_profile(),
                    sample,
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
            } => {
                let report = production_hunt(
                    &input,
                    &nuclei_templates,
                    &nuclei_report,
                    &kev_report,
                    &output,
                    format.telemetry_profile(),
                    HuntTimeRange { from, to },
                )?;
                let sanitized_path = output.join("sanitized-research.json");
                serde_json::to_writer_pretty(File::create(&sanitized_path)?, &report)?;
                print_hunt(&report, &sanitized_path);
                Ok(())
            }
            ProductionCommand::Explain {
                findings,
                waf_outcome,
                show_request,
                show_evidence,
                limit,
            } => {
                let findings = explain_private_findings(&findings)?;
                let findings = match waf_outcome {
                    Some(filter) => findings
                        .into_iter()
                        .filter(|finding| filter.matches(finding))
                        .collect(),
                    None => findings,
                };
                print_explanations(
                    &findings,
                    show_request || show_evidence,
                    show_evidence,
                    waf_outcome.map(WafOutcomeFilter::label),
                    limit,
                );
                Ok(())
            }
        },
        Command::Candidate { command } => match command {
            CandidateCommand::Build {
                from_findings,
                output,
                telemetry,
            } => {
                let findings = explain_private_findings(&from_findings)?;
                let (candidates, stats) =
                    build_batch_from_findings(&findings, telemetry.telemetry_profile());
                if candidates.is_empty() {
                    anyhow::bail!(
                        "no candidate patterns could be built from the supplied findings"
                    );
                }
                save_batch(&candidates, &output)?;
                println!("Candidates written: {}\nOutput directory: {}\nAWS WAF BLOCK findings excluded: {}\nFindings skipped for missing method/path: {}\nRecommended initial action: COUNT\nHistorical replay: required before preventive export.", stats.candidates, output.display(), stats.excluded_blocked_findings, stats.skipped_incomplete_findings);
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

fn parse_rfc3339_utc(value: &str) -> std::result::Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| format!("invalid RFC 3339 UTC timestamp: {value}"))
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
    println!("Telemetry profile:          {:?}\nFiles found:                {}\nCompressed files:           {}\nApproximate input bytes:    {}\nParseable events sampled:   {}\nMalformed events sampled:   {}\nEarliest timestamp:         {}\nLatest timestamp:           {}\n\nField availability (sample counts):\nJA4:                        {}\nJA3:                        {}\nURI:                        {}\nQuery:                      {}\nHeaders:                    {}\nHost:                       {}\nMethod:                     {}\nWAF action:                 {}\nWAF labels:                 {}\nTerminating rule ID:        {}\nNon-terminating rules:      {}", report.telemetry_profile, report.files_found, report.compressed_files, report.approximate_input_bytes, report.sampled_events, report.malformed_events, report.earliest_timestamp.as_deref().unwrap_or("unknown"), report.latest_timestamp.as_deref().unwrap_or("unknown"), supported(capabilities.ja4, fields.ja4), supported(capabilities.ja3, fields.ja3), supported(capabilities.uri_path, fields.uri), supported(capabilities.uri_query, fields.query), fields.headers, supported(capabilities.host, fields.host), supported(capabilities.method, fields.method), supported(capabilities.waf_action, fields.waf_action), supported(capabilities.waf_labels, fields.waf_labels), supported(capabilities.waf_action, fields.terminating_rule_id), supported(capabilities.waf_action, fields.non_terminating_rules));
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

fn print_explanations(
    findings: &[shenron::production::FindingExplanation],
    show_request: bool,
    show_evidence: bool,
    waf_outcome_filter: Option<&str>,
    limit: usize,
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
    if !show_request && !show_evidence {
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
        if show_request {
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
        } else {
            println!("Request: hidden (pass --show-request to display method/path/query)");
        }
        if show_evidence {
            println!(
                "Source IP: {}\nHost: {}\nJA3: {}\nJA4: {}\nRequest ID: {}\nTerminating WAF rule ID: {}\nTerminating WAF rule type: {}\nNon-terminating WAF rule IDs: {}\nWAF labels: {}\nHeaders:",
                finding
                    .source_ip
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| "unavailable".to_owned()),
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

fn print_explanation_summary(findings: &[shenron::production::FindingExplanation], limit: usize) {
    let mut counts = BTreeMap::<(String, String), usize>::new();
    for finding in findings {
        *counts
            .entry((finding.cves.join(", "), finding.template_id.clone()))
            .or_default() += 1;
    }
    let mut summary = counts.into_iter().collect::<Vec<_>>();
    summary.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| left.0 .0.cmp(&right.0 .0))
            .then_with(|| left.0 .1.cmp(&right.0 .1))
    });
    let displayed = if limit == 0 {
        summary.as_slice()
    } else {
        &summary[..summary.len().min(limit)]
    };
    println!("\nTop CVE / Nuclei template mappings:");
    for ((cves, template_id), count) in displayed {
        println!(
            "{}\n  Nuclei template: {}\n  Matches: {}",
            terminal_safe(cves),
            terminal_safe(template_id),
            count
        );
    }
    if displayed.len() < summary.len() {
        println!(
            "{} additional CVE/template mappings omitted. Pass --limit 0 to display all.",
            summary.len() - displayed.len()
        );
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
