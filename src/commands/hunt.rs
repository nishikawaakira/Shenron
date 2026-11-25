use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use shenron::{
    bot_ranges::load_bot_range_database,
    comparison::{compare_runs, write_comparison, SanitizedTemporalComparison, TemporalComparison},
    concentration::FocusPrefixLengths,
    event::{TelemetryCapabilities, TelemetryProfile, TrustedProxy, TrustedProxySet},
    observation_store::{update_observation_store, ObservationStoreLimits},
    output::write_json_pretty,
    paths::{
        default_asn_dataset, default_bot_range_snapshot, default_kev_report,
        default_reputation_dataset, default_sigma_rules_dir,
    },
    production::{
        explain_private_findings, hunt_to_writer_with_options as production_hunt_to_writer,
        hunt_with_optional_nuclei_options as production_hunt, load_private_concentration,
        terminal_safe, FindingSource, HuntOptions, HuntTimeRange, HuntTriagePolicy,
        SanitizedHuntReport, SENSITIVE_CONFIG_PROBE_RULE_ID,
    },
    report::{render_report, ReportArtifacts, ReportTriageView, SensitiveSuccessFinding},
    reputation::{load_asn_database, load_reputation_database},
    sigma::{load_explicit_rules, load_rules, RuleSet},
    slack::{
        notify_best_effort, SlackComparisonSummary, SlackNotificationConfig,
        SlackNotificationMetrics,
    },
    triage::TriagePolicy,
    triage_view::{build_triage_view, PrivateTriageView, SanitizedTriageSummary},
};

use crate::{
    display_limit, format_triage_duration, format_waf_actions, parse_ipv4_prefix_length,
    parse_ipv6_prefix_length, parse_rfc3339_utc, parse_triage_duration, print_analyst_dispositions,
    print_input_discovery, print_request_concentration_summary, resolve_nuclei_inputs,
    resolve_optional_local_dataset, ConcentrationLimitArgs, DispositionSelectionArgs, InputFormat,
    OutputFormat, ReportLanguage, TemplateFilterArgs,
};

#[derive(Debug, clap::Args)]
pub(crate) struct HuntArgs {
    #[command(flatten)]
    disposition_selection: DispositionSelectionArgs,
    /// Add private input-file/physical-line evidence references. Manifest hashes identify stored bytes.
    #[arg(long, requires = "output", conflicts_with = "results_dir")]
    include_source_references: bool,
    #[command(flatten)]
    tracking_limits: ConcentrationLimitArgs,
    /// Verbatim private analyst label recorded in the run manifest, not an inferred identity.
    #[arg(long, requires = "output", conflicts_with = "results_dir")]
    corpus_label: Option<String>,
    /// Raw web telemetry to analyze. Mutually exclusive with --results-dir.
    #[arg(
        long,
        required_unless_present = "results_dir",
        conflicts_with = "results_dir"
    )]
    input: Option<PathBuf>,
    /// Existing run directory to render without re-analyzing raw logs.
    #[arg(long, conflicts_with = "input")]
    results_dir: Option<PathBuf>,
    #[arg(
        long,
        value_enum,
        default_value_t = InputFormat::Auto,
        conflicts_with = "results_dir"
    )]
    format: InputFormat,
    #[arg(long, conflicts_with = "results_dir")]
    nuclei_templates: Option<PathBuf>,
    #[arg(long, conflicts_with = "results_dir")]
    nuclei_report: Option<PathBuf>,
    #[command(flatten)]
    template_filter: TemplateFilterArgs,
    #[arg(long, conflicts_with = "results_dir")]
    kev_report: Option<PathBuf>,
    /// Write the full private/sanitized run artifacts under this directory.
    /// Without this option, stdout contains private findings only.
    #[arg(long, conflicts_with = "results_dir")]
    output: Option<PathBuf>,
    /// Private finding format for stdout mode. Stdout can contain raw IPs,
    /// paths, hosts, headers, and other request evidence; do not share it.
    #[arg(
        long,
        value_enum,
        default_value_t = OutputFormat::Jsonl,
        conflicts_with_all = ["results_dir", "output"]
    )]
    output_format: OutputFormat,
    /// Inclusive UTC start time in RFC 3339 format, for example 2026-04-01T00:00:00Z.
    #[arg(
        long,
        value_parser = parse_rfc3339_utc,
        conflicts_with_all = ["results_dir", "since"]
    )]
    from: Option<DateTime<Utc>>,
    /// Inclusive UTC end time in RFC 3339 format, for example 2026-04-30T23:59:59Z.
    #[arg(
        long,
        value_parser = parse_rfc3339_utc,
        conflicts_with_all = ["results_dir", "since"]
    )]
    to: Option<DateTime<Utc>>,
    /// Analyze events since DURATION before this run starts (for example
    /// 24h or 1d). This moving boundary is convenient but not reproducible;
    /// use explicit --from/--to timestamps for an auditable fixed window.
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_triage_duration,
        conflicts_with_all = ["results_dir", "from", "to"]
    )]
    since: Option<Duration>,
    /// Trusted direct proxy IP or CIDR. Repeat to trust multiple proxy networks.
    /// Forwarded client IPs remain unavailable unless this is specified.
    #[arg(long, value_name = "IP-or-CIDR", conflicts_with = "results_dir")]
    trusted_proxy: Vec<TrustedProxy>,
    /// Supported Sigma rules directory for the generic detection pass.
    /// Defaults to the prepared <data-dir>/sigma-rules when present.
    #[arg(long, conflicts_with = "results_dir")]
    rules: Option<PathBuf>,
    /// Disable the Sigma pass entirely (Nuclei CVE hunting is unaffected).
    #[arg(long, conflicts_with = "results_dir")]
    no_sigma: bool,
    /// Disable Nuclei/CVE matching and its prepared inputs. This enables a
    /// setup-free Sigma-only hunt when --rules is supplied.
    #[arg(long, conflicts_with = "results_dir")]
    no_nuclei: bool,
    /// Write plain private-findings.jsonl instead of lossless gzip.
    #[arg(long, conflicts_with = "results_dir")]
    uncompressed_findings: bool,
    /// Frozen operator-published crawler ranges. Defaults to the prepared
    /// data-directory snapshot when present; all matching remains offline.
    #[arg(long, conflicts_with = "results_dir")]
    bot_ranges: Option<PathBuf>,
    /// Opt in to append-only private memory of recurring network prefixes
    /// and optional locally resolved ASNs across completed runs.
    #[arg(long, conflicts_with = "results_dir")]
    observation_store: Option<PathBuf>,
    /// Private append-only analyst disposition store. Matching opinions
    /// classify findings for review but never remove or recount them.
    #[arg(long, conflicts_with = "results_dir")]
    disposition_store: Option<PathBuf>,
    /// IPv4 prefix length recorded in the private observation store (default: 24).
    #[arg(long, value_parser = parse_ipv4_prefix_length, conflicts_with = "results_dir")]
    ipv4_group_prefix: Option<u8>,
    /// IPv6 prefix length recorded in the private observation store (default: 48).
    #[arg(long, value_parser = parse_ipv6_prefix_length, conflicts_with = "results_dir")]
    ipv6_group_prefix: Option<u8>,
    /// Optional local ASN dataset for private observation-store entries.
    #[arg(long, conflicts_with = "results_dir")]
    asn_dataset: Option<PathBuf>,
    /// Prior local run-artifact directory to compare after this hunt completes.
    #[arg(long, conflicts_with_all = ["results_dir", "baseline_latest"])]
    baseline: Option<PathBuf>,
    /// Select the lexicographically latest valid prior run below RUN-ROOT as
    /// the baseline. Use sortable directory names such as hunt-<UTC>.
    #[arg(
        long,
        value_name = "RUN-ROOT",
        conflicts_with_all = ["results_dir", "baseline"]
    )]
    baseline_latest: Option<PathBuf>,
    /// Display ranked private connection/client-IP triage entries.
    #[arg(long, conflicts_with = "results_dir")]
    show_triage: bool,
    /// Maximum private triage entries to display. Use 0 to display all.
    #[arg(long, default_value_t = 20)]
    limit: usize,
    /// Also write a private HTML report. Omit PATH to use <run-dir>/report.html.
    #[arg(long, num_args = 0..=1, value_name = "PATH")]
    report: Option<Option<PathBuf>>,
    /// Human-readable HTML report language.
    #[arg(long, value_enum, default_value_t = ReportLanguage::En)]
    lang: ReportLanguage,
}

struct PreparedHunt {
    nuclei_inputs: Option<(PathBuf, PathBuf)>,
    kev_report: Option<PathBuf>,
    telemetry_profile: TelemetryProfile,
    options: HuntOptions,
}

pub(crate) fn run_hunt(mut args: HuntArgs) -> Result<()> {
    // Parse notification policy before any hunt or render work so
    // an invalid explicit threshold fails clearly. With no webhook
    // configured, the later notification call is a strict no-op.
    let slack_config = SlackNotificationConfig::from_env()?;
    if let Some(run_dir) = args.results_dir.take() {
        return rerender_existing_run(&run_dir, args, &slack_config);
    }
    // clap requires one of --input or --results-dir. This branch is
    // therefore the raw-log hunt path.
    let input = args
        .input
        .take()
        .expect("clap requires --input unless --results-dir is present");
    validate_raw_hunt_flags(&args)?;
    let prepared = prepare_hunt(&input, &mut args)?;
    let Some(output) = args.output.take() else {
        return run_stdout_hunt(&input, prepared, args.output_format, &slack_config);
    };
    let report = run_artifact_hunt(&input, &output, prepared)?;
    if let Some(store_path) = args.observation_store.take() {
        update_hunt_observation_store(
            &input,
            &output,
            &store_path,
            args.ipv4_group_prefix,
            args.ipv6_group_prefix,
            args.asn_dataset.take(),
        )?;
    }
    let (first_seen_source_ips, temporal_comparison) =
        match resolve_baseline(args.baseline.take(), args.baseline_latest.take(), &output)? {
            Some(baseline) => {
                let (first_seen, comparison) = compare_with_baseline(&baseline, &output)?;
                (first_seen, Some(comparison))
            }
            None => (BTreeSet::new(), None),
        };
    finish_artifact_hunt(
        &input,
        &output,
        &report,
        &first_seen_source_ips,
        temporal_comparison.as_ref(),
        args,
        &slack_config,
    )
}

fn rerender_existing_run(
    run_dir: &Path,
    args: HuntArgs,
    slack_config: &SlackNotificationConfig,
) -> Result<()> {
    if args.disposition_selection.disposition_scope.is_some()
        || args.disposition_selection.disposition_as_of.is_some()
    {
        anyhow::bail!("disposition scope/as-of cannot be combined with --results-dir");
    }
    if args.tracking_limits.resolve().is_some() {
        anyhow::bail!(
            "tracking limits cannot be combined with --results-dir because no hunt is run"
        );
    }
    if args.template_filter.is_active() {
        anyhow::bail!("template metadata filters cannot be combined with --results-dir because no hunt is run");
    }
    if !run_dir.is_dir() {
        anyhow::bail!(
            "--results-dir must be an existing hunt or concentration output directory: {}",
            run_dir.display()
        );
    }
    let report_output = args
        .report
        .flatten()
        .unwrap_or_else(|| run_dir.join("report.html"));
    write_html_report(run_dir, run_dir, &report_output, args.limit, args.lang)?;
    notify_slack_from_existing_run(slack_config, run_dir, Some(&report_output));
    Ok(())
}

fn validate_raw_hunt_flags(args: &HuntArgs) -> Result<()> {
    if args.no_nuclei && args.no_sigma {
        anyhow::bail!("--no-nuclei and --no-sigma cannot be combined; at least one detection path must remain enabled");
    }
    if args.output.is_none() {
        if args.report.is_some() {
            anyhow::bail!("--report requires --output <DIR>");
        }
        if args.baseline.is_some() {
            anyhow::bail!("--baseline requires --output <DIR>");
        }
        if args.baseline_latest.is_some() {
            anyhow::bail!("--baseline-latest requires --output <DIR>");
        }
        if args.observation_store.is_some() {
            anyhow::bail!("--observation-store requires --output <DIR>");
        }
    }
    if args.observation_store.is_none()
        && (args.ipv4_group_prefix.is_some()
            || args.ipv6_group_prefix.is_some()
            || args.asn_dataset.is_some())
    {
        anyhow::bail!("--ipv4-group-prefix, --ipv6-group-prefix, and --asn-dataset require --observation-store on hunt");
    }
    Ok(())
}

fn prepare_hunt(input: &Path, args: &mut HuntArgs) -> Result<PreparedHunt> {
    let nuclei_inputs = if args.no_nuclei {
        eprintln!(
            "Nuclei pass: disabled with --no-nuclei; prepared Nuclei inputs are not required."
        );
        None
    } else {
        Some(resolve_nuclei_inputs(
            args.nuclei_templates.take(),
            args.nuclei_report.take(),
        )?)
    };
    let kev_report = resolve_optional_local_dataset(args.kev_report.take(), default_kev_report);
    let sigma_ruleset = resolve_sigma_ruleset(args.rules.take(), args.no_sigma)?;
    let bot_range_path = args.bot_ranges.take().or_else(|| {
        let path = default_bot_range_snapshot();
        path.is_file().then_some(path)
    });
    let bot_range_database = bot_range_path
        .as_deref()
        .map(load_bot_range_database)
        .transpose()?;
    let telemetry_profile = args.format.telemetry_profile_for_input(input)?;
    let time_range = if let Some(since) = args.since {
        let duration = chrono::Duration::from_std(since)
            .context("--since duration does not fit the supported UTC range")?;
        let run_time = Utc::now();
        let from = run_time
            .checked_sub_signed(duration)
            .context("--since resolves before the supported UTC timestamp range")?;
        HuntTimeRange {
            from: Some(from),
            to: None,
        }
    } else {
        HuntTimeRange {
            from: args.from,
            to: args.to,
        }
    };
    let options = HuntOptions {
        include_source_references: args.include_source_references,
        tracking_limits: args.tracking_limits.resolve(),
        uncompressed_findings: args.uncompressed_findings,
        corpus_label: args.corpus_label.take(),
        time_range,
        trusted_proxies: TrustedProxySet::new(std::mem::take(&mut args.trusted_proxy)),
        triage_policy: HuntTriagePolicy::default(),
        sigma_ruleset,
        bot_range_database,
        bot_range_snapshot_path: bot_range_path,
        template_filter: std::mem::take(&mut args.template_filter).into_options(),
        disposition_store: std::mem::take(&mut args.disposition_selection)
            .load(args.disposition_store.as_deref())?,
    };
    Ok(PreparedHunt {
        nuclei_inputs,
        kev_report,
        telemetry_profile,
        options,
    })
}

fn run_stdout_hunt(
    input: &Path,
    prepared: PreparedHunt,
    output_format: OutputFormat,
    slack_config: &SlackNotificationConfig,
) -> Result<()> {
    let PreparedHunt {
        nuclei_inputs,
        kev_report,
        telemetry_profile,
        options,
    } = prepared;
    let resolved_nuclei = nuclei_inputs
        .as_ref()
        .map(|(templates, report)| (templates.as_path(), report.as_path()));
    eprintln!("PRIVATE stdout mode: findings can contain raw IP addresses, request paths, hosts, headers, and other log values. Do not share without review.");
    let report = {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        production_hunt_to_writer(
            input,
            resolved_nuclei,
            kev_report.as_deref(),
            &mut stdout,
            output_format.hunt_format(),
            telemetry_profile,
            options,
        )?
    };
    print_streaming_hunt_summary(&report);
    if slack_config.is_enabled() {
        eprintln!("Slack notification skipped (requires --output)");
    }
    Ok(())
}

fn run_artifact_hunt(
    input: &Path,
    output: &Path,
    prepared: PreparedHunt,
) -> Result<SanitizedHuntReport> {
    let PreparedHunt {
        nuclei_inputs,
        kev_report,
        telemetry_profile,
        options,
    } = prepared;
    let resolved_nuclei = nuclei_inputs
        .as_ref()
        .map(|(templates, report)| (templates.as_path(), report.as_path()));
    let report = production_hunt(
        input,
        resolved_nuclei,
        kev_report.as_deref(),
        output,
        telemetry_profile,
        options,
    )?;
    let sanitized_path = output.join("sanitized-research.json");
    write_json_pretty(&sanitized_path, &report)?;
    print_hunt(&report, &sanitized_path);
    Ok(report)
}

fn update_hunt_observation_store(
    input: &Path,
    output: &Path,
    store_path: &Path,
    ipv4_group_prefix: Option<u8>,
    ipv6_group_prefix: Option<u8>,
    asn_dataset: Option<PathBuf>,
) -> Result<()> {
    shenron::production::ensure_separate_output(input, store_path)?;
    let default_prefixes = FocusPrefixLengths::default();
    let prefixes = FocusPrefixLengths {
        ipv4: ipv4_group_prefix.unwrap_or(default_prefixes.ipv4),
        ipv6: ipv6_group_prefix.unwrap_or(default_prefixes.ipv6),
    };
    let asn_path = resolve_optional_local_dataset(asn_dataset, default_asn_dataset);
    let asn_database = asn_path.as_deref().map(load_asn_database).transpose()?;
    let update = update_observation_store(
        store_path,
        output,
        prefixes,
        asn_database.as_ref(),
        ObservationStoreLimits::default(),
    )?;
    println!(
        "Private append-only observation store: {}\n  Run ID: {}\n  Already recorded: {}\n  Runs recorded: {}\n  Retained prefix/ASN entries: {}\n  Entity observations retained / beyond cap: {} / {}\n  Invalid source IPs excluded: {}",
        store_path.display(), terminal_safe(&update.run_id), update.already_recorded,
        update.runs_recorded, update.retained_entities, update.retained_entity_observations,
        update.entity_observations_beyond_cap, update.invalid_source_ips_excluded,
    );
    println!("{}", update.safety_note);
    Ok(())
}

fn resolve_baseline(
    baseline: Option<PathBuf>,
    baseline_latest: Option<PathBuf>,
    output: &Path,
) -> Result<Option<PathBuf>> {
    Ok(match (baseline, baseline_latest) {
        (Some(baseline), None) => Some(baseline),
        (None, Some(run_root)) => match latest_baseline_run(&run_root, output)? {
            Some(selected) => {
                println!(
                    "Latest baseline selected by directory-name order: {}",
                    selected.display()
                );
                Some(selected)
            }
            None => {
                println!(
                    "no prior run found under {}; skipping temporal comparison",
                    run_root.display()
                );
                None
            }
        },
        (None, None) => None,
        (Some(_), Some(_)) => {
            unreachable!("clap prevents --baseline and --baseline-latest from being combined")
        }
    })
}

fn compare_with_baseline(
    baseline: &Path,
    output: &Path,
) -> Result<(BTreeSet<String>, TemporalComparison)> {
    let comparison = compare_runs(baseline, output)?;
    write_comparison(output, &comparison)?;
    let first_seen_source_ips = comparison
        .private
        .first_seen_entities
        .source_ips
        .iter()
        .cloned()
        .collect();
    println!(
        "Baseline comparison written: {}\n  Newly observed CVEs: {}\n  First-seen entities: {}\n  Elevated paths: {}",
        output.join("comparison-summary.json").display(), comparison.sanitized.cve_diff.newly_observed_cves.len(),
        first_seen_entity_total(&comparison.sanitized), comparison.sanitized.concentration_delta.elevated_paths,
    );
    Ok((first_seen_source_ips, comparison))
}

fn finish_artifact_hunt(
    input: &Path,
    output: &Path,
    report: &SanitizedHuntReport,
    first_seen_source_ips: &BTreeSet<String>,
    temporal_comparison: Option<&TemporalComparison>,
    args: HuntArgs,
    slack_config: &SlackNotificationConfig,
) -> Result<()> {
    write_hunt_triage_view(output, first_seen_source_ips, args.show_triage, args.limit)?;
    print_daily_review_summary(
        report,
        temporal_comparison.map(|comparison| &comparison.sanitized),
    );
    let report_output = args
        .report
        .map(|selected_report| selected_report.unwrap_or_else(|| output.join("report.html")));
    if let Some(report_output) = &report_output {
        write_html_report(output, input, report_output, args.limit, args.lang)?;
    }
    let slack_metrics = SlackNotificationMetrics::from_hunt(&report.metrics);
    let slack_comparison = temporal_comparison
        .map(|comparison| SlackComparisonSummary::from_comparison(&comparison.sanitized));
    notify_best_effort(
        slack_config,
        &slack_metrics,
        slack_comparison,
        output,
        report_output.as_deref(),
    );
    Ok(())
}

/// Load only already-generated local artifacts. Missing files remain absent so
/// the renderer can label their sections unavailable without approximation.
/// The run-artifact file names a report reads. The output must not clobber one
/// of these when it is written inside the same run directory.
const REPORT_SOURCE_ARTIFACTS: &[&str] = &[
    "sanitized-research.json",
    "private-findings.jsonl",
    "private-findings.jsonl.gz",
    "request-concentration.json",
    "triage-view.json",
    "triage-summary.json",
    "run-manifest.json",
    "comparison-summary.json",
    "comparison-detail.json",
];

/// Allow writing the report inside its own run directory (its input is already
/// produced artifacts, not raw logs), but refuse to overwrite a directory or a
/// source artifact the report reads.
fn ensure_report_output_is_safe(input: &Path, output: &Path) -> Result<()> {
    if output.is_dir() {
        anyhow::bail!(
            "--output must be a file path, not a directory: {}",
            output.display()
        );
    }
    if let Some(name) = output.file_name().and_then(|name| name.to_str()) {
        let inside_run_dir = output.parent().is_some_and(|parent| parent == input);
        if inside_run_dir && REPORT_SOURCE_ARTIFACTS.contains(&name) {
            anyhow::bail!(
                "--output would overwrite the source artifact {name}; choose a different report file name"
            );
        }
    }
    Ok(())
}

/// Render one run's existing artifacts to a private, self-contained HTML file.
///
/// `safe_input_ref` is the raw input for a new hunt and the run directory for
/// a render-only invocation. This keeps report output separate from raw logs
/// while still allowing `<run-dir>/report.html` for existing artifacts.
fn write_html_report(
    run_dir: &Path,
    safe_input_ref: &Path,
    output: &Path,
    limit: usize,
    lang: ReportLanguage,
) -> Result<()> {
    ensure_report_output_is_safe(safe_input_ref, output)?;
    if safe_input_ref != run_dir {
        shenron::production::ensure_separate_output(safe_input_ref, output)?;
        ensure_report_output_is_safe(run_dir, output)?;
    }

    let artifacts = load_report_artifacts(run_dir)?;
    let html = render_report(&artifacts, limit, 240, lang);
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating report output directory {}", parent.display()))?;
    }
    std::fs::write(output, html)
        .with_context(|| format!("writing private HTML report {}", output.display()))?;
    eprintln!("{}", lang.private_warning());
    match lang {
        ReportLanguage::En => {
            eprintln!("Private HTML report written: {}", output.display());
        }
        ReportLanguage::Ja => {
            eprintln!(
                "プライベート HTML レポートを出力しました: {}",
                output.display()
            );
        }
    }
    Ok(())
}

fn load_report_artifacts(input: &Path) -> Result<ReportArtifacts> {
    let concentration_path = input.join("request-concentration.json");
    Ok(ReportArtifacts {
        sanitized: read_optional_json(&input.join("sanitized-research.json"))?,
        manifest: read_optional_json(&input.join("run-manifest.json"))?,
        concentration: concentration_path
            .is_file()
            .then(|| load_private_concentration(&concentration_path))
            .transpose()?,
        triage: read_optional_json::<ReportTriageView>(&input.join("triage-view.json"))?,
        sensitive_success_findings: load_sensitive_success_findings(
            &input.join("private-findings.jsonl"),
        )?,
    })
}

/// Load notification inputs only from sanitized artifacts. This deliberately
/// does not call `load_report_artifacts`, because that report loader also reads
/// private findings for the private HTML review view.
fn notify_slack_from_existing_run(
    config: &SlackNotificationConfig,
    run_dir: &Path,
    report_path: Option<&Path>,
) {
    if !config.is_enabled() {
        return;
    }
    let context = (|| -> Result<_> {
        let sanitized =
            read_optional_json::<serde_json::Value>(&run_dir.join("sanitized-research.json"))?
                .context("sanitized-research.json is unavailable for Slack notification")?;
        let metrics = SlackNotificationMetrics::from_sanitized_value(&sanitized)?;
        let comparison =
            read_optional_json::<serde_json::Value>(&run_dir.join("comparison-summary.json"))?
                .map(|value| SlackComparisonSummary::from_sanitized_value(&value))
                .transpose()?;
        Ok((metrics, comparison))
    })();
    match context {
        Ok((metrics, comparison)) => {
            notify_best_effort(config, &metrics, comparison, run_dir, report_path)
        }
        Err(error) => eprintln!("Slack notification failed: {error:#}"),
    }
}

#[derive(Deserialize)]
struct ReportPrivateFinding {
    #[serde(default)]
    source: FindingSource,
    template_id: String,
    #[serde(default)]
    response_status: Option<u16>,
    #[serde(default)]
    uri_path: Option<String>,
    #[serde(default)]
    source_ip: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
}

/// Stream the private findings artifact and retain only the response-status
/// review context needed by the private HTML report. A 2xx is not interpreted
/// as content disclosure, exploitation, or compromise.
fn load_sensitive_success_findings(path: &Path) -> Result<Vec<SensitiveSuccessFinding>> {
    let path = shenron::findings_io::resolve(path);
    if !path.is_file() {
        return Ok(Vec::new());
    }

    let reader = shenron::findings_io::open(&path)?;
    let mut findings = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("reading {} line {}", path.display(), index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let finding: ReportPrivateFinding = serde_json::from_str(&line)
            .with_context(|| format!("parsing {} line {}", path.display(), index + 1))?;
        let Some(response_status @ 200..=299) = finding.response_status else {
            continue;
        };
        if finding.source != FindingSource::Sigma
            || finding.template_id != SENSITIVE_CONFIG_PROBE_RULE_ID
        {
            continue;
        }
        findings.push(SensitiveSuccessFinding {
            uri_path: finding.uri_path,
            source_ip: finding.source_ip,
            response_status,
            timestamp: finding.timestamp,
        });
    }
    findings.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.uri_path.cmp(&right.uri_path))
            .then_with(|| left.source_ip.cmp(&right.source_ip))
            .then_with(|| left.response_status.cmp(&right.response_status))
    });
    Ok(findings)
}

fn read_optional_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    if !path.is_file() {
        return Ok(None);
    }
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("reading {}", path.display()))
        .map(Some)
}

/// Build the post-hunt consolidated triage artifacts from the private findings
/// that hunt just wrote. Findings are deliberately re-read instead of retained
/// during streaming, keeping the hunt path bounded by its normal output files.
fn write_hunt_triage_view(
    output: &Path,
    first_seen_source_ips: &BTreeSet<String>,
    show_triage: bool,
    limit: usize,
) -> Result<()> {
    let asn_dataset = resolve_optional_local_dataset(None, default_asn_dataset);
    let reputation_dataset = resolve_optional_local_dataset(None, default_reputation_dataset);
    let asn_database = asn_dataset.as_deref().map(load_asn_database).transpose()?;
    let reputation_database = reputation_dataset
        .as_deref()
        .map(load_reputation_database)
        .transpose()?;
    let findings_path = output.join("private-findings.jsonl");
    let findings = explain_private_findings(&findings_path)?;
    // Bound scores by the union of source capabilities, matching the existing
    // `production explain` behavior. Legacy findings retain the full-capability
    // default rather than being penalized by an absent source marker.
    let capabilities = findings
        .iter()
        .filter_map(|finding| {
            finding
                .log_source
                .map(|source| source.telemetry_profile().capabilities())
        })
        .reduce(TelemetryCapabilities::union)
        .unwrap_or_default();
    let (summary, view) = build_triage_view(
        &findings,
        capabilities,
        TriagePolicy::default(),
        asn_database.as_ref(),
        reputation_database.as_ref(),
        first_seen_source_ips,
    );
    let summary_path = output.join("triage-summary.json");
    let view_path = output.join("triage-view.json");
    write_json_pretty(&summary_path, &summary)?;
    write_json_pretty(&view_path, &view)?;
    print_hunt_triage_summary(&summary, &view_path);
    if show_triage {
        print_hunt_triage_entries(&view, limit);
    }
    Ok(())
}

/// The default hunt transcript contains aggregate triage context only. It
/// deliberately omits IPs, ASN organizations, and reputation details; pass
/// `--show-triage` to opt in to the private ranking.
fn print_hunt_triage_summary(summary: &SanitizedTriageSummary, view_path: &Path) {
    println!(
        "Consolidated triage summary (priority order for human review; NOT threat severity or a probability of malice):\n  Entities: {}\n  Requiring investigation: {}\n  Behavior-priority tiers: info={} low={} medium={} high={}\n  First-seen entities (new = review, not malicious): {}\n  Ordered sequence window: {}\n  Sequence observations retained / undated / beyond cap: {} / {} / {}\nTriage view written: {}",
        summary.total_entities,
        summary.entities_requiring_investigation,
        summary.tier_histogram.info,
        summary.tier_histogram.low,
        summary.tier_histogram.medium,
        summary.tier_histogram.high,
        summary.first_seen_entities,
        format_triage_duration(Duration::from_secs(summary.sequence.window_seconds)),
        summary.sequence.retained_observations,
        summary.sequence.observations_without_timestamp,
        summary.sequence.observations_beyond_cap,
        view_path.display(),
    );
}

/// Print private ranked entries only after the analyst explicitly requests
/// them. The order is an inspection ordinal, never an attacker attribution or
/// a conclusion about abuse, exploitation, or compromise.
fn print_hunt_triage_entries(view: &PrivateTriageView, limit: usize) {
    println!(
        "\nConsolidated triage view (private; review order only, not threat severity or malice):"
    );
    let displayed = &view.entities[..view.entities.len().min(display_limit(limit))];
    if displayed.is_empty() {
        println!("No connection/client-IP entities were available from the private findings.");
        return;
    }
    for (index, entity) in displayed.iter().enumerate() {
        println!(
            "[{}] {}\n  Identity: {}\n  Behavior priority score: {}/100 ({}, reachable maximum {}/100)\n  Triage basis: {}\n  Requires investigation: {}\n  Distinct observations/templates/CVEs: {}/{}/{}\n  Matching records: {}\n  Request-specific / response-unverified observations: {}/{}\n  Sequence max patterns / distinctive patterns: {}/{} within {}\n  Sequence interval min / median: {} / {} seconds\n  Sequence undated / beyond cap: {}/{}\n  First seen: {}",
            index + 1,
            terminal_safe(&entity.key),
            terminal_safe(entity.identity),
            entity.behavior_score.total,
            terminal_safe(&entity.behavior_score.tier),
            entity.behavior_score.reachable_max,
            entity.triage_basis.unwrap_or("none"),
            entity.requires_investigation,
            entity.distinct_observations,
            entity.distinct_templates,
            entity.distinct_cves,
            entity.matching_records,
            entity.request_specific_observations,
            entity.response_unverified_observations,
            entity.sequence.maximum_distinct_patterns_in_window,
            entity.sequence.maximum_distinctive_patterns_in_window,
            format_triage_duration(Duration::from_secs(entity.sequence.window_seconds)),
            entity
                .sequence
                .minimum_interval_seconds
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "unavailable".to_owned()),
            entity
                .sequence
                .median_interval_seconds
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "unavailable".to_owned()),
            entity.sequence.observations_without_timestamp,
            entity.sequence.observations_beyond_cap,
            entity.first_seen,
        );
        match &entity.resolved_asn {
            Some(asn) => println!("  Resolved ASN: {} ({})", asn.asn, terminal_safe(&asn.org)),
            None => println!("  Resolved ASN: unavailable"),
        }
        match &entity.reputation {
            Some(reputation) => println!(
                "  Reputation opinion: {}/100 ({}) via {}",
                reputation.score,
                terminal_safe(&reputation.tier),
                terminal_safe(&reputation.scope),
            ),
            None => println!("  Reputation opinion: unavailable"),
        }
    }
    if displayed.len() < view.entities.len() {
        println!(
            "{} additional private triage entities omitted. Pass --limit 0 to display all.",
            view.entities.len() - displayed.len()
        );
    }
}

/// Select the lexicographically greatest valid immediate child run while
/// explicitly excluding the current output directory. Filesystem mtimes are
/// deliberately ignored so sortable run names remain deterministic.
fn latest_baseline_run(run_root: &Path, current_output: &Path) -> Result<Option<PathBuf>> {
    if !run_root.is_dir() {
        return Ok(None);
    }
    let current_output = fs::canonicalize(current_output).with_context(|| {
        format!(
            "failed to resolve current hunt output {}",
            current_output.display()
        )
    })?;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(run_root)
        .with_context(|| format!("failed to read run root {}", run_root.display()))?
    {
        let entry = entry
            .with_context(|| format!("failed to read an entry under {}", run_root.display()))?;
        let path = entry.path();
        if !path.is_dir() || !path.join("run-manifest.json").is_file() {
            continue;
        }
        let resolved = fs::canonicalize(&path)
            .with_context(|| format!("failed to resolve candidate run {}", path.display()))?;
        if resolved != current_output {
            candidates.push((entry.file_name(), path));
        }
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(candidates.pop().map(|(_, path)| path))
}

/// Resolve the Sigma ruleset for a hunt. The Sigma pass is on by default: it
/// uses `--rules` when given, otherwise the prepared `<data-dir>/sigma-rules`
/// when present. Explicit paths must contain rule files. A missing default is
/// allowed. `--no-sigma` disables the pass and skips rule loading.
fn resolve_sigma_ruleset(rules: Option<PathBuf>, no_sigma: bool) -> Result<Option<RuleSet>> {
    if no_sigma {
        if let Some(path) = rules {
            eprintln!(
                "Sigma pass: skipping --rules {} because --no-sigma is set.",
                terminal_safe(&path.to_string_lossy())
            );
        } else {
            eprintln!("Sigma pass: disabled with --no-sigma.");
        }
        return Ok(None);
    }

    let explicit = rules
        .map(|path| load_explicit_rules(&path).map(|ruleset| (path, ruleset)))
        .transpose()?;
    let ruleset = explicit.or_else(|| {
        let default = default_sigma_rules_dir();
        default.is_dir().then(|| {
            let ruleset = load_rules(&default);
            (default, ruleset)
        })
    });
    match ruleset {
        Some((dir, ruleset)) => {
            eprintln!(
                "Sigma pass: {} supported rules from {} ({} unsupported skipped).",
                ruleset.supported.len(),
                dir.display(),
                ruleset.unsupported.len()
            );
            Ok(Some(ruleset))
        }
        None => {
            eprintln!(
                "Sigma pass: no rules directory found (looked for {}). Pass --rules <dir> to enable it, or --no-sigma to silence this note. Continuing without Sigma matching.",
                default_sigma_rules_dir().display()
            );
            Ok(None)
        }
    }
}

fn print_hunt(report: &SanitizedHuntReport, sanitized_path: &Path) {
    print_input_discovery(&report.metrics.input_discovery, false);
    println!(
        "Findings by WAF action (matching records): {}",
        format_waf_actions(report.metrics.findings_by_waf_action.as_ref(), false)
    );
    if report.metrics.findings_by_waf_action.is_some() {
        println!("{}", shenron::waf_summary::WAF_OBSERVATION_NOTE);
    }
    let metrics = &report.metrics;
    let time_range = match (&metrics.filter_from, &metrics.filter_to) {
        (None, None) => "Time filter:                all timestamps".to_owned(),
        (from, to) => format!(
            "Time filter (UTC):          {} to {}\nOutside range ignored:      {}\nTimestamp missing ignored:  {}",
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
    println!("\n{}", input_quality_summary(metrics));
    print_analyst_dispositions(metrics.analyst_dispositions.as_ref());
    println!(
        "\nSigma (generic request-pattern pass; separate from the CVE metrics above):\n  Rules evaluated:           {}\n  Matched requests:          {}\n  Rule matches:              {} (one request can match several rules, so this can exceed matched requests)\n  Distinct rules matched:    {}",
        metrics.sigma_rules_evaluated,
        metrics.sigma_matched_requests,
        metrics.sigma_rule_matches,
        metrics.distinct_sigma_rules,
    );
    if metrics.bot_range_snapshot_loaded {
        println!(
            "\nSelf-declared bot User-Agent / published-range comparison (offline frozen snapshot):"
        );
        if metrics.bot_range_observations.is_empty() {
            println!("  No configured self-declared bot User-Agent patterns were observed.");
        }
        for item in &metrics.bot_range_observations {
            let rate = item
                .outside_published_ranges_rate
                .map(|value| format!("{:.1}%", value * 100.0))
                .unwrap_or_else(|| "unavailable".to_owned());
            println!(
                "  {} ({})\n    User-Agent declarations: {}\n    Within published ranges: {} requests / {} distinct observed peers\n    Outside published ranges: {} requests / {} distinct observed peers ({rate})\n    Observed peer unavailable: {}",
                terminal_safe(&item.operator_name),
                terminal_safe(&item.operator_id),
                item.declared_requests,
                item.within_published_ranges_requests,
                item.within_published_ranges_distinct_source_ips,
                item.outside_published_ranges_requests,
                item.outside_published_ranges_distinct_source_ips,
                item.source_ip_unavailable_requests,
            );
        }
        println!(
            "  A User-Agent-named operator whose observed peer is outside its published ranges is only that: outside the frozen published ranges. Lists may be incomplete or stale, intermediaries can rewrite peers, and any client can set a User-Agent. This is for review, not a determination of impersonation, attack, or abuse."
        );
    } else {
        println!(
            "\nSelf-declared bot range comparison: skipped (no frozen snapshot; run `shenron bot-ranges update`). CVE and Sigma metrics are unaffected."
        );
    }
    if !metrics.declared_observed_consistency.checks.is_empty() {
        println!("\nDeclared-versus-observed consistency checks:");
        for check in &metrics.declared_observed_consistency.checks {
            println!(
                "  {}\n    Match: {}\n    Mismatch: {}\n    Unavailable: {} (reference data missing: {}, telemetry does not expose: {}, observed value missing: {})",
                terminal_safe(&check.check_id),
                check.matches,
                check.mismatches,
                check.unavailable,
                check.unavailable_reasons.reference_data_missing,
                check.unavailable_reasons.telemetry_does_not_expose,
                check.unavailable_reasons.observed_value_missing,
            );
        }
        println!(
            "  A mismatch between a self-declared attribute and an observed one is a labeled observation. Declarations are freely settable, reference data can be incomplete or stale, and intermediaries can rewrite both. It is not a determination of impersonation, automation, attack, abuse, compromise, or attacker identity."
        );
        if metrics
            .declared_observed_consistency
            .private_observations_beyond_cap
            != 0
        {
            println!(
                "  Private mismatch observations beyond cap: {}",
                metrics
                    .declared_observed_consistency
                    .private_observations_beyond_cap
            );
        }
    }
    if let Some(concentration) = &metrics.request_concentration {
        print_request_concentration_summary(concentration, "request-concentration.json");
    }
}

/// Keep stdout machine-readable in no-artifact mode. This intentionally
/// summarizes only aggregate observations and never repeats private finding
/// values; the private JSONL/CSV stream itself is written to stdout.
fn print_streaming_hunt_summary(report: &SanitizedHuntReport) {
    print_input_discovery(&report.metrics.input_discovery, true);
    eprintln!(
        "Findings by WAF action (matching records): {}",
        format_waf_actions(report.metrics.findings_by_waf_action.as_ref(), false)
    );
    if report.metrics.findings_by_waf_action.is_some() {
        eprintln!("{}", shenron::waf_summary::WAF_OBSERVATION_NOTE);
    }
    let metrics = &report.metrics;
    eprintln!(
        "Read-only production hunt complete (stdout-only private findings).\nRequests analyzed: {}\nFiles analyzed: {}\nParse errors: {}\nCVE-related request matches: {}\nUnique CVEs observed: {}\nSigma-matched requests: {}\nNo run directory or artifact files were created.",
        metrics.total_requests_analyzed,
        metrics.files_analyzed,
        metrics.parse_errors,
        metrics.cve_related_request_matches,
        metrics.unique_cves_observed,
        metrics.sigma_matched_requests,
    );
    eprintln!("\n{}", input_quality_summary(metrics));
    if let Some(counts) = &metrics.analyst_dispositions {
        if let Some(due) = counts.review_due_matching_findings {
            eprintln!("Matching findings with analyst opinions due for re-review: {due} (original opinions unchanged)");
        }
        eprintln!(
            "Analyst-authored dispositions (private local opinions; findings remain retained and counted): reviewed {}, expected {}, needs-review {}, unclassified {}. These are not Shenron determinations.",
            counts.reviewed, counts.expected, counts.needs_review, counts.unclassified,
        );
    }
    eprintln!(
        "Review signals are observed matches and aggregates, not determinations of attack, exploitation, compromise, or attacker identity."
    );
}

/// Aggregate-only input-quality display shared by artifact and stdout-only
/// hunts. Counts cover every parseable event included in the selected hunt
/// time range and never reveal field values.
fn input_quality_summary(metrics: &shenron::production::HuntMetrics) -> String {
    let fields = &metrics.fields_available;
    let parse_note = if metrics.parse_errors == 0 {
        String::new()
    } else {
        "\n  Note: parse errors can indicate a mismatched --format, mixed formats, or malformed records; review the input and selected format."
            .to_owned()
    };
    format!(
        "Input field availability & quality (populated event counts):\n  Parseable events:          {}\n  Parse errors:              {}\n  Earliest timestamp (UTC):  {}\n  Latest timestamp (UTC):    {}\n  Verified client IP:        {} (requires --trusted-proxy)\n  JA4:                       {}\n  JA3:                       {}\n  TLS protocol:              {}\n  TLS cipher:                {}\n  URI:                       {}\n  Query:                     {}\n  Headers:                   {}\n  Host:                      {}\n  Method:                    {}\n  WAF action:                {}\n  WAF labels:                {}\n  Terminating rule ID:       {}\n  Non-terminating rules:     {}{}",
        metrics.total_requests_analyzed,
        metrics.parse_errors,
        metrics.earliest_timestamp.as_deref().unwrap_or("unknown"),
        metrics.latest_timestamp.as_deref().unwrap_or("unknown"),
        fields.client_ip,
        fields.ja4,
        fields.ja3,
        fields.tls_protocol,
        fields.tls_cipher,
        fields.uri,
        fields.query,
        fields.headers,
        fields.host,
        fields.method,
        fields.waf_action,
        fields.waf_labels,
        fields.terminating_rule_id,
        fields.non_terminating_rules,
        parse_note,
    )
}

fn print_daily_review_summary(
    report: &SanitizedHuntReport,
    comparison: Option<&SanitizedTemporalComparison>,
) {
    let metrics = &report.metrics;
    println!("\nDaily review signals (aggregate observations only):");
    println!(
        "  Observed CVEs (unique):                          {}",
        metrics.unique_cves_observed
    );
    if metrics.sensitive_config_probe_matches != 0 {
        println!(
            "  Sensitive file/config probe matches / 2xx response status: {} / {}",
            metrics.sensitive_config_probe_matches,
            metrics.sensitive_config_probe_success_responses,
        );
        println!(
            "  Sensitive probe status unavailable:             {}",
            metrics.sensitive_config_probe_status_unavailable
        );
        if metrics.sensitive_config_probe_success_responses != 0 {
            println!(
                "  HIGHEST REVIEW PRIORITY: {} sensitive file/config probe matches returned a 2xx response. A 2xx is the response status only, not confirmation that file contents were disclosed or that exploitation or compromise occurred.",
                metrics.sensitive_config_probe_success_responses
            );
        }
    }
    println!(
        "  Sigma-matched requests:                          {}",
        metrics.sigma_matched_requests
    );
    if let Some(concentration) = &metrics.request_concentration {
        let peak = concentration
            .requests_per_minute
            .peak_requests_per_minute
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unavailable".to_owned());
        println!(
            "  Request-concentration peak/minute / top-10 path share: {} / {:.1}%",
            peak,
            concentration.top_ten_paths_request_share * 100.0
        );
    }
    if let Some(comparison) = comparison {
        println!(
            "  Baseline delta — newly observed CVEs / first-seen entities / elevated paths: {} / {} / {}",
            comparison.cve_diff.newly_observed_cves.len(),
            first_seen_entity_total(comparison),
            comparison.concentration_delta.elevated_paths
        );
    }
    println!(
        "Review signals are observed aggregates and priorities, not determinations of attack, exploitation, compromise, or attacker identity."
    );
}

fn first_seen_entity_total(comparison: &SanitizedTemporalComparison) -> usize {
    comparison.first_seen_counts.source_ips
        + comparison.first_seen_counts.hosts
        + comparison.first_seen_counts.uri_paths
        + comparison.first_seen_counts.ja4_fingerprints
        + comparison.first_seen_counts.client_ips.unwrap_or(0)
}
