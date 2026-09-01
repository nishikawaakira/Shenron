use std::{
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

use shenron::event::TelemetryProfile;
use shenron::kev::{coverage as kev_coverage, KevCoverageReport};
use shenron::lab::{
    generate_for_format, measure, validate_corpus, validate_findings, GeneratorConfig, Profile,
    SyntheticFormat, ValidationReport,
};
use shenron::minimum_telemetry::{analyze as minimum_telemetry_analyze, MinimumTelemetryReport};
use shenron::nuclei::{
    compare_telemetry, coverage as nuclei_coverage, coverage_for_telemetry,
    frozen_nuclei_selection, inventory as nuclei_inventory, supported_detections,
    validated_detections, CoverageReport, InventoryReport, RequestMatcherView,
    TelemetryComparisonReport, TelemetryCoverageReport,
};
use shenron::paths::{default_nuclei_report, default_templates_dir};

#[derive(Debug, Parser)]
#[command(
    name = "shenron-lab",
    version,
    about = "Generate and validate passive synthetic AWS WAF corpora"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Generate {
        #[arg(long, value_enum, default_value_t = ProfileArg::Deterministic)]
        profile: ProfileArg,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        ground_truth: PathBuf,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long, default_value_t = 15)]
        events: usize,
        #[arg(long, default_value_t = 0.01)]
        attack_rate: f64,
        #[arg(long, default_value_t = 3)]
        hosts: usize,
        #[arg(long, default_value_t = 32)]
        source_ips: usize,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long, default_value_t = 1_735_689_600_000_i64)]
        start_timestamp_ms: i64,
        #[arg(long, default_value_t = 3_600_000_i64)]
        duration_ms: i64,
        /// Render the same logical requests into this passive telemetry form.
        #[arg(long, value_enum, default_value_t = TelemetryFormatArg::AwsWaf)]
        format: TelemetryFormatArg,
    },
    Validate {
        #[arg(long)]
        findings: Option<PathBuf>,
        #[arg(long)]
        corpus: Option<PathBuf>,
        #[arg(long)]
        truth: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    Measure {
        #[arg(long)]
        corpus: PathBuf,
    },
    Nuclei {
        #[command(subcommand)]
        command: NucleiCommand,
    },
    Kev {
        #[command(subcommand)]
        command: KevCommand,
    },
    /// Measure minimum additional, non-sensitive web telemetry from frozen local artifacts.
    MinimumTelemetry {
        #[arg(long)]
        templates: PathBuf,
        #[arg(long)]
        comparison: PathBuf,
        #[arg(long)]
        kev: PathBuf,
        #[arg(long, default_value = "unknown")]
        revision: String,
        #[arg(long)]
        report: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum NucleiCommand {
    /// Fetch or update the local Nuclei templates checkout over the network.
    /// Downloads public templates only; no customer data is transmitted.
    Update {
        /// Local checkout directory to create or update.
        #[arg(long)]
        templates: Option<PathBuf>,
        /// Pin a specific revision (commit SHA). Omit to use the default branch tip.
        #[arg(long)]
        revision: Option<String>,
        /// Templates git repository URL.
        #[arg(
            long,
            default_value = "https://github.com/projectdiscovery/nuclei-templates.git"
        )]
        repo: String,
        /// Frozen Nuclei coverage report written after checkout.
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Statistically inventory untrusted local Nuclei YAML. Nothing is executed.
    Inventory {
        #[arg(long)]
        templates: PathBuf,
        #[arg(long, default_value = "unknown")]
        revision: String,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Analyze, safely convert the literal subset, and validate synthetic events locally.
    Coverage {
        #[arg(long)]
        templates: PathBuf,
        #[arg(long, default_value = "unknown")]
        revision: String,
        #[arg(long)]
        report: Option<PathBuf>,
        /// Evaluate one source profile; omit to preserve existing AWS WAF coverage output.
        #[arg(long, value_enum)]
        telemetry: Option<TelemetryFormatArg>,
    },
    /// Compare passive CVE detectability across documented telemetry profiles.
    CompareTelemetry {
        #[arg(long)]
        templates: PathBuf,
        #[arg(long, default_value = "unknown")]
        revision: String,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// List static literal matchers used by hunt. Templates are never executed and no network is accessed.
    Matchers {
        #[arg(long)]
        templates: PathBuf,
        /// Pinned checkout revision recorded in the read-only command output.
        #[arg(long)]
        revision: String,
        /// Restrict to the frozen-report template IDs eligible for production hunt.
        #[arg(long)]
        report: Option<PathBuf>,
        /// Optional formatted JSON array containing template-derived matcher definitions only.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// A template-derived literal matcher record for codebook review. It does not
/// contain request telemetry and is intentionally independent of execution.
#[derive(Debug, Serialize)]
struct MatcherRecord {
    template_id: String,
    cves: Vec<String>,
    method: String,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
    headers: Vec<(String, String)>,
    request_specificity: shenron::nuclei::RequestSpecificity,
    path_distinctiveness: shenron::nuclei::PathDistinctiveness,
}

#[derive(Debug, Subcommand)]
enum KevCommand {
    /// Join an offline official CISA KEV JSON snapshot with a Nuclei coverage report.
    Coverage {
        #[arg(long)]
        kev: PathBuf,
        #[arg(long)]
        nuclei_report: PathBuf,
        #[arg(long)]
        report: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    Deterministic,
    Mutations,
    Large,
    Demo,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TelemetryFormatArg {
    AwsWaf,
    Nginx,
    Apache,
}
impl From<TelemetryFormatArg> for SyntheticFormat {
    fn from(value: TelemetryFormatArg) -> Self {
        match value {
            TelemetryFormatArg::AwsWaf => Self::AwsWaf,
            TelemetryFormatArg::Nginx => Self::NginxCombined,
            TelemetryFormatArg::Apache => Self::ApacheCombined,
        }
    }
}
impl From<TelemetryFormatArg> for TelemetryProfile {
    fn from(value: TelemetryFormatArg) -> Self {
        match value {
            TelemetryFormatArg::AwsWaf => Self::AwsWaf,
            TelemetryFormatArg::Nginx => Self::NginxCombined,
            TelemetryFormatArg::Apache => Self::ApacheCombined,
        }
    }
}
impl From<ProfileArg> for Profile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Deterministic => Self::Deterministic,
            ProfileArg::Mutations => Self::Mutations,
            ProfileArg::Large => Self::Large,
            ProfileArg::Demo => Self::Demo,
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate {
            profile,
            output,
            ground_truth,
            manifest,
            events,
            attack_rate,
            hosts,
            source_ips,
            seed,
            start_timestamp_ms,
            duration_ms,
            format,
        } => {
            let config = GeneratorConfig {
                profile: profile.into(),
                events,
                attack_rate,
                hosts,
                source_ips,
                seed,
                start_timestamp_ms,
                duration_ms,
            };
            let manifest = manifest
                .unwrap_or_else(|| PathBuf::from(format!("{}.manifest.json", output.display())));
            let result =
                generate_for_format(&output, &ground_truth, &manifest, &config, format.into())?;
            println!("Generated valid events: {}\nExpected parser errors: {}\nGround truth records: {}\nManifest: {}", result.manifest.valid_events, result.manifest.expected_parser_errors, result.truth_records, manifest.display());
        }
        Command::Validate {
            findings,
            corpus,
            truth,
            rules,
            manifest,
            report,
        } => {
            let validation = match (findings, corpus) {
                (Some(findings), None) => validate_findings(&findings, &truth)?,
                (None, Some(corpus)) => validate_corpus(
                    &corpus,
                    &truth,
                    &rules.ok_or_else(|| anyhow::anyhow!("--rules is required with --corpus"))?,
                    manifest.as_deref(),
                )?,
                _ => anyhow::bail!("provide exactly one of --findings or --corpus"),
            };
            print_report(&validation);
            if let Some(path) = report {
                serde_json::to_writer_pretty(std::fs::File::create(path)?, &validation)?;
            }
            if validation.status != "PASS" {
                std::process::exit(1);
            }
        }
        Command::Measure { corpus } => {
            let (events, bytes, seconds) = measure(&corpus)?;
            let seconds = seconds.max(f64::EPSILON);
            println!("Events: {events}\nInput bytes: {bytes}\nWall seconds: {seconds:.3}\nEvents/sec: {:.0}\nInput MB/sec: {:.2}", events as f64 / seconds, bytes as f64 / 1_000_000.0 / seconds);
        }
        Command::Nuclei { command } => match command {
            NucleiCommand::Update {
                templates,
                revision,
                repo,
                report,
            } => {
                let templates = templates.unwrap_or_else(default_templates_dir);
                let report = report.unwrap_or_else(default_nuclei_report);
                let resolved_revision =
                    update_nuclei_templates(&templates, revision.as_deref(), &repo)?;
                let coverage = nuclei_coverage(&templates, &resolved_revision);
                if let Some(parent) = report
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    std::fs::create_dir_all(parent)?;
                }
                serde_json::to_writer_pretty(std::fs::File::create(&report)?, &coverage)?;
                println!("Frozen Nuclei report: {}", report.display());
                println!("Next: shenron production hunt --input <logs> --format <fmt>");
            }
            NucleiCommand::Inventory {
                templates,
                revision,
                report,
            } => {
                ensure_template_directory(&templates)?;
                let inventory = nuclei_inventory(&templates, &revision);
                print_inventory(&inventory);
                if let Some(path) = report {
                    serde_json::to_writer_pretty(std::fs::File::create(path)?, &inventory)?;
                }
            }
            NucleiCommand::Coverage {
                templates,
                revision,
                report,
                telemetry,
            } => {
                ensure_template_directory(&templates)?;
                if let Some(telemetry) = telemetry {
                    let source_report =
                        coverage_for_telemetry(&templates, telemetry.into(), &revision);
                    print_telemetry_coverage(&source_report);
                    if let Some(path) = report {
                        serde_json::to_writer_pretty(std::fs::File::create(path)?, &source_report)?;
                    }
                    return Ok(());
                }
                let coverage = nuclei_coverage(&templates, &revision);
                print_coverage(&coverage);
                if let Some(path) = report {
                    serde_json::to_writer_pretty(std::fs::File::create(path)?, &coverage)?;
                }
                if coverage.coverage.missed_detections != 0
                    || coverage.coverage.unexpected_matches != 0
                    || coverage.coverage.mutation_failures != 0
                    || coverage.coverage.near_miss_failures != 0
                {
                    std::process::exit(1);
                }
            }
            NucleiCommand::CompareTelemetry {
                templates,
                revision,
                report,
            } => {
                ensure_template_directory(&templates)?;
                let comparison = compare_telemetry(&templates, &revision);
                print_telemetry_comparison(&comparison);
                if let Some(path) = report {
                    serde_json::to_writer_pretty(std::fs::File::create(path)?, &comparison)?;
                }
            }
            NucleiCommand::Matchers {
                templates,
                revision,
                report,
                output,
            } => {
                ensure_template_directory(&templates)?;
                let detections = match report {
                    Some(report) => {
                        let selection = frozen_nuclei_selection(&report)?;
                        validated_detections(&templates, &selection.template_ids)
                    }
                    None => supported_detections(&templates),
                };
                let matchers = matcher_records(detections);
                eprintln!(
                    "Read-only static matcher listing for Nuclei revision {revision}; templates are not executed and no network is accessed."
                );
                print_matchers(&matchers);
                if let Some(path) = output {
                    serde_json::to_writer_pretty(std::fs::File::create(path)?, &matchers)?;
                }
            }
        },
        Command::Kev { command } => match command {
            KevCommand::Coverage {
                kev,
                nuclei_report,
                report,
            } => {
                let coverage = kev_coverage(&kev, &nuclei_report)?;
                print_kev_coverage(&coverage);
                if let Some(path) = report {
                    serde_json::to_writer_pretty(std::fs::File::create(path)?, &coverage)?;
                }
            }
        },
        Command::MinimumTelemetry {
            templates,
            comparison,
            kev,
            revision,
            report,
        } => {
            ensure_template_directory(&templates)?;
            let analysis = minimum_telemetry_analyze(&templates, &comparison, &kev, &revision)?;
            print_minimum_telemetry(&analysis);
            serde_json::to_writer_pretty(std::fs::File::create(report)?, &analysis)?;
        }
    }
    Ok(())
}

fn matcher_records(
    detections: Vec<shenron::nuclei::ValidatedNucleiDetection>,
) -> Vec<MatcherRecord> {
    let mut records = detections
        .into_iter()
        .map(|detection| {
            let RequestMatcherView {
                method,
                path,
                query,
                fragment,
                headers,
                request_specificity,
                path_distinctiveness,
            } = detection.request_matcher_view();
            let mut cves = detection.cves;
            cves.sort();
            MatcherRecord {
                template_id: detection.template_id,
                cves,
                method,
                path,
                query,
                fragment,
                headers,
                request_specificity,
                path_distinctiveness,
            }
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.template_id
            .cmp(&right.template_id)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.query.cmp(&right.query))
            .then_with(|| left.method.cmp(&right.method))
            .then_with(|| left.fragment.cmp(&right.fragment))
            .then_with(|| left.headers.cmp(&right.headers))
    });
    records
}

fn print_matchers(matchers: &[MatcherRecord]) {
    for matcher in matchers {
        let mut target = matcher.path.clone();
        if let Some(query) = &matcher.query {
            target.push('?');
            target.push_str(query);
        }
        if let Some(fragment) = &matcher.fragment {
            target.push('#');
            target.push_str(fragment);
        }
        let specificity = match matcher.request_specificity {
            shenron::nuclei::RequestSpecificity::RequestSpecific => "request-specific",
            shenron::nuclei::RequestSpecificity::ResponseUnverified => "response-unverified",
        };
        let distinctiveness = matcher.path_distinctiveness.label();
        println!(
            "{}  {} {}  [{} headers]  {}  {}",
            matcher.template_id,
            matcher.method,
            target,
            matcher.headers.len(),
            specificity,
            distinctiveness,
        );
    }
}

fn ensure_template_directory(path: &std::path::Path) -> Result<()> {
    if path.is_dir() {
        Ok(())
    } else {
        anyhow::bail!(
            "Nuclei template directory does not exist: {}",
            path.display()
        )
    }
}

/// The only network-capable path in Shenron. It invokes system git solely to
/// download public Nuclei templates; analysis inputs and results are never
/// passed to git or any other external process.
fn update_nuclei_templates(templates: &Path, revision: Option<&str>, repo: &str) -> Result<String> {
    if templates.exists() && templates.join(".git").exists() {
        git_in(templates, &["fetch", "--filter=blob:none", "origin"])?;
    } else {
        if let Some(parent) = templates.parent() {
            std::fs::create_dir_all(parent)?;
        }
        git_clone(repo, templates)?;
    }

    let target = match revision {
        Some(revision) => revision.to_owned(),
        None => default_branch_target(templates)?,
    };
    git_in(templates, &["checkout", &target])?;
    let resolved_revision = git_in(templates, &["rev-parse", "HEAD"])?;

    println!("Resolved Nuclei templates revision: {resolved_revision}");
    println!("Public templates only were downloaded; no customer data was transmitted. The shenron analysis binary remains offline.");
    println!("Pin this revision with --revision for later reproducibility.");
    Ok(resolved_revision)
}

fn default_branch_target(templates: &Path) -> Result<String> {
    let output = git_in(templates, &["ls-remote", "--symref", "origin", "HEAD"])?;
    let branch = output.lines().find_map(|line| {
        line.strip_prefix("ref: refs/heads/")
            .and_then(|value| value.strip_suffix("\tHEAD"))
    });
    let Some(branch) = branch else {
        anyhow::bail!(
            "could not resolve the default branch from origin; specify --revision explicitly"
        );
    };
    Ok(format!("origin/{branch}"))
}

fn git_clone(repo: &str, templates: &Path) -> Result<String> {
    let description = format!(
        "git clone --filter=blob:none --no-checkout {} {}",
        repo,
        templates.display()
    );
    let mut command = ProcessCommand::new("git");
    command
        .args(["clone", "--filter=blob:none", "--no-checkout"])
        .arg(repo)
        .arg(templates);
    checked_git(&mut command, &description)
}

fn git_in(directory: &Path, args: &[&str]) -> Result<String> {
    let description = format!("git -C {} {}", directory.display(), args.join(" "));
    let mut command = ProcessCommand::new("git");
    command.arg("-C").arg(directory).args(args);
    checked_git(&mut command, &description)
}

fn checked_git(command: &mut ProcessCommand, description: &str) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("failed to start system git while running `{description}`"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "`{description}` exited with {}: {}",
            output.status,
            stderr.trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn print_report(report: &ValidationReport) {
    let metrics = &report.metrics;
    println!("Events:                 {}\nExpected malicious:     {}\nExpected benign:        {}\nExpected detections:    {}\nDetected expected:      {}\nMissed:                 {}\nUnexpected matches:     {}\nParser errors:          {}\nTrue positives:         {}\nFalse negatives:        {}\nFalse positives:        {}\nTrue negatives:         {}\nRecall:                 {}\nPrecision:              {}\nFalse positive rate:    {}\n\nDeterministic test status:\n{}",
        metrics.events, metrics.expected_malicious, metrics.expected_benign, metrics.expected_detections, metrics.detected_expected, metrics.missed, metrics.unexpected_matches, metrics.parser_errors, metrics.true_positives, metrics.false_negatives, metrics.false_positives, metrics.true_negatives,
        report.recall.map_or("n/a".to_owned(), |value| format!("{value:.3}")), report.precision.map_or("n/a".to_owned(), |value| format!("{value:.3}")), report.false_positive_rate.map_or("n/a".to_owned(), |value| format!("{value:.3}")), report.status);
    for failure in &report.failures {
        println!(
            "FAIL {} [{}] {}",
            failure.case_id, failure.category, failure.details
        );
    }
}

fn print_inventory(report: &InventoryReport) {
    let metrics = &report.metrics;
    println!("Nuclei revision:             {}\nTemplates scanned:           {}\nCVE templates:               {}\nHTTP CVE templates:          {}\nStructured HTTP:             {}\nRaw HTTP:                    {}\nMultiple requests:           {}\nMethods:                     {}\nPaths:                       {}\nPayloads:                    {}\nAttack modes:                {}\nRequest bodies:              {}\nRequest headers:             {}\nQuery parameters:            {}\nResponse matchers:           {}\nDSL:                         {}\nInteractsh/OAST:             {}\nRedirects:                   {}\nVariables:                   {}\nHelper functions (heuristic):{}\nExtractors:                  {}\nUnsupported constructs:      {}", report.nuclei_revision, metrics.templates_scanned, metrics.cve_templates, metrics.http_cve_templates, metrics.structured_http, metrics.raw_http, metrics.multiple_requests, metrics.methods, metrics.paths, metrics.payloads, metrics.attack_modes, metrics.request_bodies, metrics.request_headers, metrics.query_parameters, metrics.response_matchers, metrics.dsl, metrics.interactsh_oast, metrics.redirects, metrics.variables, metrics.helper_functions, metrics.extractors, metrics.unsupported_constructs);
}

fn print_coverage(report: &CoverageReport) {
    print_inventory(&InventoryReport {
        nuclei_revision: report.nuclei_revision.clone(),
        metrics: report.inventory.clone(),
        templates: Vec::new(),
        detectability_reasons: Default::default(),
        implementation_gaps: Default::default(),
        feature_combinations: Default::default(),
    });
    let coverage = &report.coverage;
    println!("\nTemplate capability funnel (request-side corpus distribution; NOT field precision or attack/compromise confidence):\nCVE templates:               {}\nHTTP CVE templates:          {}\nSupported request IR templates:{}\nSupported request IR detections (alternatives): {}\n  Request-specific:          {}\n  Response-unverified:       {}\n\nLog detectability:\nHIGH:                        {}\nMEDIUM:                      {}\nLOW:                         {}\nUNDETECTABLE:                {}\nUNKNOWN:                     {}\n\nConversion:\nConvertible in principle:    {}\nSupported by Shenron:        {}\nUnsupported by Shenron:      {}\n\nSynthetic validation:\nTemplates tested:            {}\nSynthetic events generated:  {}\nExpected detections:         {}\nCorrect detections:          {}\nMissed detections:           {}\nUnexpected matches:          {}\nMutation cases:              {}\nMutation failures:           {}\nNear-miss cases:             {}\nNear-miss failures:          {}", coverage.cve_templates, coverage.http_cve_templates, coverage.supported_request_ir_templates, coverage.supported_request_ir_detections, coverage.request_specific_detections, coverage.response_unverified_detections, coverage.high, coverage.medium, coverage.low, coverage.undetectable, coverage.unknown, coverage.convertible_in_principle, coverage.supported_by_shenron, coverage.unsupported_by_shenron, coverage.templates_tested, coverage.synthetic_events_generated, coverage.expected_detections, coverage.correct_detections, coverage.missed_detections, coverage.unexpected_matches, coverage.mutation_cases, coverage.mutation_failures, coverage.near_miss_cases, coverage.near_miss_failures);
}

fn print_kev_coverage(report: &KevCoverageReport) {
    let metrics = &report.metrics;
    println!(
        "CISA KEV catalog:           {}\nCatalog released:            {}\nNuclei revision:             {}\n\nKEVs:\nTotal:                       {}\nWeb relevant:                {}\nNot web relevant:            {}\nUnknown relevance:           {}\n\nWeb-relevant KEVs:\nWith Nuclei template:        {}\nWith HTTP Nuclei template:   {}\nObservable:                  {}\nConvertible:                 {}\nValidated:                   {}\nNo Nuclei template:          {}",
        report.catalog_version.as_deref().unwrap_or("unknown"),
        report.catalog_date_released.as_deref().unwrap_or("unknown"),
        report.nuclei_revision,
        metrics.total_kevs,
        metrics.web_relevant,
        metrics.not_web_relevant,
        metrics.unknown_web_relevance,
        metrics.web_relevant_with_nuclei_template,
        metrics.web_relevant_with_http_nuclei_template,
        metrics.web_relevant_observable,
        metrics.web_relevant_convertible,
        metrics.web_relevant_validated,
        metrics.web_relevant_no_nuclei_template,
    );
}

fn print_telemetry_comparison(report: &TelemetryComparisonReport) {
    println!("Nuclei revision: {}\n\nTelemetry                 HTTP CVEs  Observable  Convertible  Validated", report.nuclei_revision);
    for source in &report.reports {
        let metrics = &source.metrics;
        println!(
            "{:24} {:9}  {:10}  {:11}  {}",
            format!("{:?}", source.telemetry),
            metrics.http_cve_templates,
            metrics.observable,
            metrics.convertible,
            metrics.validated
        );
    }
}

fn print_telemetry_coverage(report: &TelemetryCoverageReport) {
    let metrics = &report.metrics;
    println!(
        "Nuclei revision: {}\nTelemetry: {:?}\n\nHTTP CVE templates: {}\nObservable: {}\nConvertible: {}\nValidated: {}\n\nHIGH: {}\nMEDIUM: {}\nLOW: {}\nUNDETECTABLE: {}\nUNKNOWN: {}",
        report.nuclei_revision,
        report.telemetry,
        metrics.http_cve_templates,
        metrics.observable,
        metrics.convertible,
        metrics.validated,
        metrics.high,
        metrics.medium,
        metrics.low,
        metrics.undetectable,
        metrics.unknown,
    );
    for (reason, count) in &report.detectability_reasons {
        println!("{reason}: {count}");
    }
}

fn print_minimum_telemetry(report: &MinimumTelemetryReport) {
    let baseline = &report.baseline;
    println!(
        "Nuclei revision: {}\nBaseline observable templates: {}\nBaseline unique CVEs: {}\nBaseline CISA KEVs: {}\n\nHeader-dependent templates: {}\nHost-only marginal templates: {}\n\nGreedy SAFE profile:",
        report.nuclei_revision,
        baseline.observable_templates,
        baseline.unique_cves,
        baseline.cisa_kev_cves,
        report.header_dependent_templates.len(),
        report.host_counterfactual.additional_templates,
    );
    for step in &report.greedy_safe_profile {
        println!(
            "{}: +{} => {} observable templates ({:.1}% of AWS WAF ceiling)",
            step.added_field,
            step.gain.additional_templates,
            step.coverage.observable_templates,
            step.coverage.aws_waf_observable_recovered_percent,
        );
    }
}
