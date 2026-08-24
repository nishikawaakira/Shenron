use std::{
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use walkdir::WalkDir;

use shenron::{
    access_log::{AccessLogFormat, AccessLogLines},
    event::TelemetryProfile,
    output::{Finding, FindingWriter},
    production::{
        explain_private_findings, hunt as production_hunt, inspect as production_inspect,
        terminal_safe, InspectionReport, SanitizedHuntReport,
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
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InputFormat {
    AwsWaf,
    Nginx,
    Apache,
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
            } => {
                let report = production_hunt(
                    &input,
                    &nuclei_templates,
                    &nuclei_report,
                    &kev_report,
                    &output,
                    format.telemetry_profile(),
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
                );
                Ok(())
            }
        },
    }
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
    let outcomes = if metrics.waf_outcome_available {
        format!("Existing WAF outcomes:\nBLOCK:                       {}\nAllowed / not blocked:       {}\nCOUNT-related evidence:      {}\nUnknown:                     {}", metrics.blocked, metrics.allowed_or_not_blocked, metrics.count_related_evidence, metrics.unknown_outcome)
    } else {
        "WAF outcome:                unavailable for this telemetry source".to_owned()
    };
    println!("Read-only production hunt complete.\nPrivate findings:            written under the supplied output directory\nSanitized report:            {}\n\nRequests analyzed:           {}\nFiles analyzed:              {}\nParse errors:                {}\nCVE exploitation attempts:   {}\nUnique CVEs observed:        {}\nUnique CISA KEVs observed:   {}\nSource clusters:             {}\nJA4 fingerprints:            {}\nHIGH findings:               {}\nMEDIUM findings:             {}\nLOW findings:                {}\n\n{}", sanitized_path.display(), metrics.total_requests_analyzed, metrics.files_analyzed, metrics.parse_errors, metrics.exploitation_attempt_findings, metrics.unique_cves_observed, metrics.unique_cisa_kevs_observed, metrics.unique_source_clusters, metrics.unique_ja4_fingerprints, metrics.high_confidence_findings, metrics.medium_confidence_findings, metrics.low_confidence_findings, outcomes);
}

fn print_explanations(
    findings: &[shenron::production::FindingExplanation],
    show_request: bool,
    show_evidence: bool,
    waf_outcome_filter: Option<&str>,
) {
    match waf_outcome_filter {
        Some(filter) => println!(
            "CVE / Nuclei template mappings: {} (WAF outcome filter: {})",
            findings.len(),
            filter
        ),
        None => println!("CVE / Nuclei template mappings: {}", findings.len()),
    }
    for (index, finding) in findings.iter().enumerate() {
        println!(
            "\n[{}]\nCVE: {}\nNuclei template: {}\nConfidence: {:?}\nTimestamp: {}\nWAF action: {}",
            index + 1,
            finding.cves.join(", "),
            terminal_safe(&finding.template_id),
            finding.detectability,
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
