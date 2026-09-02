use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use flate2::read::GzDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};

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
use shenron::paths::{default_data_dir, default_nuclei_report, default_templates_dir};
use shenron::reputation_update::{
    parse_blocklist_de, parse_cins, parse_firehol_level1, parse_iptoasn_v4, parse_spamhaus_drop,
    write_asn_ranges, write_reputation_jsonl, BLOCKLIST_DE_URL, CINS_URL, FIREHOL_LEVEL1_URL,
    IPTOASN_V4_URL, SPAMHAUS_DROP_URL,
};

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
    /// Download public IP reputation and ASN inputs. No customer data is transmitted.
    Reputation {
        #[command(subcommand)]
        command: ReputationCommand,
    },
    /// Prepare public Nuclei, reputation, and ASN inputs in one download-only step.
    Setup {
        /// Skip the public Nuclei template checkout and frozen coverage report.
        #[arg(long)]
        skip_nuclei: bool,
        /// Skip the public IP reputation dataset.
        #[arg(long)]
        skip_reputation: bool,
        /// Skip the public IPv4 ASN range dataset.
        #[arg(long)]
        skip_asn: bool,
        /// Local directory for every prepared input.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Nuclei templates git repository URL.
        #[arg(
            long,
            default_value = "https://github.com/projectdiscovery/nuclei-templates.git"
        )]
        nuclei_repo: String,
        /// Optional pinned Nuclei revision.
        #[arg(long)]
        nuclei_revision: Option<String>,
        /// Public Spamhaus DROP source URL.
        #[arg(long, default_value = SPAMHAUS_DROP_URL)]
        spamhaus_drop_source: String,
        /// Public FireHOL level 1 source URL.
        #[arg(long, default_value = FIREHOL_LEVEL1_URL)]
        firehol_source: String,
        /// Public CINS Army source URL.
        #[arg(long, default_value = CINS_URL)]
        cins_source: String,
        /// Public blocklist.de source URL.
        #[arg(long, default_value = BLOCKLIST_DE_URL)]
        blocklist_de_source: String,
        /// Public iptoasn IPv4 source URL.
        #[arg(long, default_value = IPTOASN_V4_URL)]
        iptoasn_source: String,
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

#[derive(Debug, Subcommand)]
enum ReputationCommand {
    /// Download public lists and write local, offline explain inputs only.
    Update {
        /// Output directory (defaults to Shenron's local data directory).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Generate reputation.jsonl. Pass --reputation false to omit it.
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        reputation: bool,
        /// Generate asn-ranges.tsv. Pass --asn false to omit it.
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        asn: bool,
        /// Public Spamhaus DROP source URL.
        #[arg(long, default_value = SPAMHAUS_DROP_URL)]
        spamhaus_drop_source: String,
        /// Public FireHOL level 1 source URL.
        #[arg(long, default_value = FIREHOL_LEVEL1_URL)]
        firehol_source: String,
        /// Public CINS Army source URL.
        #[arg(long, default_value = CINS_URL)]
        cins_source: String,
        /// Public blocklist.de source URL.
        #[arg(long, default_value = BLOCKLIST_DE_URL)]
        blocklist_de_source: String,
        /// Public iptoasn IPv4 source URL.
        #[arg(long, default_value = IPTOASN_V4_URL)]
        iptoasn_source: String,
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
                run_nuclei_update(templates, revision, &repo, report)?;
                println!("Public templates only were downloaded; no customer data was transmitted. The shenron analysis binary remains offline.");
                println!("Pin this revision with --revision for later reproducibility.");
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
        Command::Reputation { command } => match command {
            ReputationCommand::Update {
                out_dir,
                reputation,
                asn,
                spamhaus_drop_source,
                firehol_source,
                cins_source,
                blocklist_de_source,
                iptoasn_source,
            } => update_reputation_inputs(
                &out_dir.unwrap_or_else(default_data_dir),
                reputation,
                asn,
                ReputationSources {
                    spamhaus_drop: &spamhaus_drop_source,
                    firehol: &firehol_source,
                    cins: &cins_source,
                    blocklist_de: &blocklist_de_source,
                    iptoasn: &iptoasn_source,
                },
                true,
            )?,
        },
        Command::Setup {
            skip_nuclei,
            skip_reputation,
            skip_asn,
            data_dir,
            nuclei_repo,
            nuclei_revision,
            spamhaus_drop_source,
            firehol_source,
            cins_source,
            blocklist_de_source,
            iptoasn_source,
        } => run_setup(
            &data_dir.unwrap_or_else(default_data_dir),
            setup_plan(skip_nuclei, skip_reputation, skip_asn),
            &nuclei_repo,
            nuclei_revision,
            ReputationSources {
                spamhaus_drop: &spamhaus_drop_source,
                firehol: &firehol_source,
                cins: &cins_source,
                blocklist_de: &blocklist_de_source,
                iptoasn: &iptoasn_source,
            },
        )?,
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

/// Run the existing Nuclei preparation workflow with either explicit or
/// standard local paths. The caller owns next-step and privacy messaging so
/// `setup` can present them once for all preparation sources.
fn run_nuclei_update(
    templates: Option<PathBuf>,
    revision: Option<String>,
    repo: &str,
    report: Option<PathBuf>,
) -> Result<()> {
    let templates = templates.unwrap_or_else(default_templates_dir);
    let report = report.unwrap_or_else(default_nuclei_report);
    let resolved_revision = update_nuclei_templates(&templates, revision.as_deref(), repo)?;
    let coverage = nuclei_coverage(&templates, &resolved_revision);
    if let Some(parent) = report
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    serde_json::to_writer_pretty(File::create(&report)?, &coverage)?;
    println!("Frozen Nuclei report: {}", report.display());
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupPlan {
    include_nuclei: bool,
    include_reputation: bool,
    include_asn: bool,
}

fn setup_plan(skip_nuclei: bool, skip_reputation: bool, skip_asn: bool) -> SetupPlan {
    SetupPlan {
        include_nuclei: !skip_nuclei,
        include_reputation: !skip_reputation,
        include_asn: !skip_asn,
    }
}

fn run_setup(
    data_dir: &Path,
    plan: SetupPlan,
    nuclei_repo: &str,
    nuclei_revision: Option<String>,
    reputation_sources: ReputationSources<'_>,
) -> Result<()> {
    if !plan.include_nuclei && !plan.include_reputation && !plan.include_asn {
        println!("Setup summary: no preparation steps selected (all were skipped).");
        return Ok(());
    }

    let mut completed = Vec::new();
    let mut failures = Vec::new();
    if plan.include_nuclei {
        match run_nuclei_update(
            Some(data_dir.join("nuclei-templates")),
            nuclei_revision,
            nuclei_repo,
            Some(data_dir.join("nuclei-report.json")),
        ) {
            Ok(()) => completed.push("Nuclei templates and frozen report"),
            Err(error) => failures.push(("Nuclei templates and frozen report", error)),
        }
    }
    if plan.include_reputation || plan.include_asn {
        match update_reputation_inputs(
            data_dir,
            plan.include_reputation,
            plan.include_asn,
            reputation_sources,
            false,
        ) {
            Ok(()) => completed.push("reputation/ASN inputs"),
            Err(error) => failures.push(("reputation/ASN inputs", error)),
        }
    }

    println!("Setup summary:");
    for step in completed {
        println!("  completed: {step}");
    }
    for (step, error) in &failures {
        println!("  failed: {step}: {error}");
    }
    // The privacy guarantee holds regardless of outcome: only public URLs are
    // ever passed to git/curl. Print the reassurance before any failure return
    // so a partial failure still surfaces it.
    println!("Public intelligence only was downloaded; no customer data was transmitted. The shenron analysis binary remains offline.");
    println!("Review and comply with each source's terms of use before relying on these lists.");
    if let Some((_, error)) = failures.into_iter().next() {
        bail!("setup completed with failures: {error}");
    }
    println!("Next: shenron production hunt --input <logs> --format <fmt>");
    Ok(())
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

struct ReputationSources<'a> {
    spamhaus_drop: &'a str,
    firehol: &'a str,
    cins: &'a str,
    blocklist_de: &'a str,
    iptoasn: &'a str,
}

#[derive(Serialize)]
struct ReputationUpdateManifest {
    report_kind: &'static str,
    generated_at: chrono::DateTime<Utc>,
    safety_note: &'static str,
    sources: Vec<ReputationSourceManifest>,
    outputs: Vec<ReputationOutputManifest>,
}

#[derive(Serialize)]
struct ReputationSourceManifest {
    name: &'static str,
    url: String,
    records: usize,
}

#[derive(Serialize)]
struct ReputationOutputManifest {
    path: String,
    sha256: String,
    records: usize,
}

/// The only network-capable reputation path: curl downloads public lists to
/// temporary local files. Neither logs nor findings nor observed IPs are ever
/// provided to curl or any remote service.
fn update_reputation_inputs(
    out_dir: &Path,
    include_reputation: bool,
    include_asn: bool,
    sources: ReputationSources<'_>,
    announce: bool,
) -> Result<()> {
    if !include_reputation && !include_asn {
        bail!("at least one of --reputation or --asn must be true");
    }
    fs::create_dir_all(out_dir)
        .with_context(|| format!("creating reputation output directory {}", out_dir.display()))?;
    let download_dir = out_dir.join(format!(
        ".reputation-downloads-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    fs::create_dir(&download_dir).with_context(|| {
        format!(
            "creating temporary download directory {}",
            download_dir.display()
        )
    })?;

    let result = (|| {
        let mut source_manifest = Vec::new();
        let mut output_manifest = Vec::new();

        if include_reputation {
            let spamhaus = download_dir.join("spamhaus-drop.txt");
            curl_download(sources.spamhaus_drop, &spamhaus)?;
            let spamhaus_records = parse_spamhaus_drop(&fs::read_to_string(&spamhaus)?);
            source_manifest.push(ReputationSourceManifest {
                name: "spamhaus-drop",
                url: sources.spamhaus_drop.to_owned(),
                records: spamhaus_records.len(),
            });

            let firehol = download_dir.join("firehol-level1.netset");
            curl_download(sources.firehol, &firehol)?;
            let firehol_records = parse_firehol_level1(&fs::read_to_string(&firehol)?);
            source_manifest.push(ReputationSourceManifest {
                name: "firehol-level1",
                url: sources.firehol.to_owned(),
                records: firehol_records.len(),
            });

            let cins = download_dir.join("cins.txt");
            curl_download(sources.cins, &cins)?;
            let cins_records = parse_cins(&fs::read_to_string(&cins)?);
            source_manifest.push(ReputationSourceManifest {
                name: "cins-army",
                url: sources.cins.to_owned(),
                records: cins_records.len(),
            });

            let blocklist_de = download_dir.join("blocklist-de.txt");
            curl_download(sources.blocklist_de, &blocklist_de)?;
            let blocklist_de_records = parse_blocklist_de(&fs::read_to_string(&blocklist_de)?);
            source_manifest.push(ReputationSourceManifest {
                name: "blocklist.de",
                url: sources.blocklist_de.to_owned(),
                records: blocklist_de_records.len(),
            });

            let reputation = out_dir.join("reputation.jsonl");
            let reputation_records = [
                spamhaus_records,
                firehol_records,
                cins_records,
                blocklist_de_records,
            ]
            .concat();
            write_reputation_jsonl(&reputation, &reputation_records)?;
            output_manifest.push(output_manifest_entry(
                &reputation,
                reputation_records.len(),
            )?);
        }

        if include_asn {
            let iptoasn = download_dir.join("ip2asn-v4.tsv.gz");
            curl_download(sources.iptoasn, &iptoasn)?;
            let mut source = GzDecoder::new(File::open(&iptoasn)?);
            let mut text = String::new();
            source.read_to_string(&mut text).with_context(|| {
                format!(
                    "decompressing public iptoasn download {}",
                    iptoasn.display()
                )
            })?;
            let ranges = parse_iptoasn_v4(&text);
            source_manifest.push(ReputationSourceManifest {
                name: "iptoasn-v4",
                url: sources.iptoasn.to_owned(),
                records: ranges.len(),
            });
            let asn = out_dir.join("asn-ranges.tsv");
            write_asn_ranges(&asn, &ranges)?;
            output_manifest.push(output_manifest_entry(&asn, ranges.len())?);
        }

        let manifest = ReputationUpdateManifest {
            report_kind: "PUBLIC_REPUTATION_UPDATE",
            generated_at: Utc::now(),
            safety_note: "Public threat-intelligence downloads only. No customer logs, findings, observed IP addresses, request values, or other customer data were transmitted.",
            sources: source_manifest,
            outputs: output_manifest,
        };
        let manifest_path = out_dir.join("reputation-manifest.json");
        serde_json::to_writer_pretty(File::create(&manifest_path)?, &manifest)?;

        if announce {
            println!(
                "Public reputation/ASN inputs written to: {}",
                out_dir.display()
            );
            println!("Manifest: {}", manifest_path.display());
            println!("Public lists only were downloaded; no customer data was transmitted. The shenron analysis binary remains offline.");
            println!("production explain automatically uses these local files when no --reputation-dataset or --asn-dataset override is supplied.");
            println!(
                "Review and comply with each source's terms of use before relying on these lists."
            );
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&download_dir);
    result
}

fn curl_download(url: &str, destination: &Path) -> Result<()> {
    let description = format!("curl download from {url}");
    let output = ProcessCommand::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--output",
        ])
        .arg(destination)
        .arg(url)
        .output()
        .with_context(|| {
            format!(
                "failed to start system curl while running `{description}`; install curl and retry"
            )
        })?;
    if !output.status.success() {
        bail!(
            "`{description}` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn output_manifest_entry(path: &Path, records: usize) -> Result<ReputationOutputManifest> {
    Ok(ReputationOutputManifest {
        path: path.display().to_string(),
        sha256: sha256_file(path)?,
        records,
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("hashing output {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
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

#[cfg(test)]
mod setup_tests {
    use super::{setup_plan, SetupPlan};

    #[test]
    fn setup_skip_flags_select_the_expected_preparation_inputs() {
        assert_eq!(
            setup_plan(false, false, false),
            SetupPlan {
                include_nuclei: true,
                include_reputation: true,
                include_asn: true,
            }
        );
        assert_eq!(
            setup_plan(true, false, true),
            SetupPlan {
                include_nuclei: false,
                include_reputation: true,
                include_asn: false,
            }
        );
        assert_eq!(
            setup_plan(true, true, true),
            SetupPlan {
                include_nuclei: false,
                include_reputation: false,
                include_asn: false,
            }
        );
    }
}
