use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use shenron::{
    concentration::{FocusPrefixLengths, FocusSelector},
    event::TelemetryProfile,
    lab::{
        generate, generate_for_format, validate_corpus, GeneratorConfig, Profile, SyntheticFormat,
        VOLUMETRIC_CONCENTRATION_DURATION_MS, VOLUMETRIC_CONCENTRATION_EVENTS,
        VOLUMETRIC_CONCENTRATION_PATH,
    },
    production::{concentration, load_private_concentration, HuntTimeRange},
};
use tempfile::tempdir;

fn generated_paths(
    directory: &std::path::Path,
    name: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    (
        directory.join(format!("{name}.jsonl.gz")),
        directory.join(format!("{name}.truth.jsonl")),
        directory.join(format!("{name}.manifest.json")),
    )
}

#[test]
fn deterministic_corpus_is_a_perfect_end_to_end_validation() {
    let directory = tempdir().unwrap();
    let (corpus, truth, manifest) = generated_paths(directory.path(), "deterministic");
    generate(&corpus, &truth, &manifest, &GeneratorConfig::default()).unwrap();
    let report = validate_corpus(
        &corpus,
        &truth,
        std::path::Path::new("tests/rules"),
        Some(&manifest),
    )
    .unwrap();
    assert_eq!(report.status, "PASS");
    assert_eq!(report.metrics.events, 15);
    assert_eq!(report.metrics.expected_detections, 7);
    assert_eq!(report.metrics.detected_expected, 7);
    assert_eq!(report.metrics.parser_errors, 1);
    assert!(report.failures.is_empty());
}

#[test]
fn mutation_corpus_preserves_expected_matches_and_rejects_near_misses() {
    let directory = tempdir().unwrap();
    let (corpus, truth, manifest) = generated_paths(directory.path(), "mutations");
    let config = GeneratorConfig {
        profile: Profile::Mutations,
        ..GeneratorConfig::default()
    };
    generate(&corpus, &truth, &manifest, &config).unwrap();
    let report = validate_corpus(
        &corpus,
        &truth,
        std::path::Path::new("tests/rules"),
        Some(&manifest),
    )
    .unwrap();
    assert_eq!(report.status, "PASS");
    assert_eq!(report.metrics.detected_expected, 3);
    assert_eq!(report.metrics.true_negatives, 3);
}

#[test]
fn seeded_large_corpora_are_byte_reproducible() {
    let directory = tempdir().unwrap();
    let (first_corpus, first_truth, first_manifest) = generated_paths(directory.path(), "first");
    let (second_corpus, second_truth, second_manifest) =
        generated_paths(directory.path(), "second");
    let config = GeneratorConfig {
        profile: Profile::Large,
        events: 1_000,
        attack_rate: 0.02,
        ..GeneratorConfig::default()
    };
    generate(&first_corpus, &first_truth, &first_manifest, &config).unwrap();
    generate(&second_corpus, &second_truth, &second_manifest, &config).unwrap();
    assert_eq!(
        fs::read(&first_corpus).unwrap(),
        fs::read(&second_corpus).unwrap()
    );
    assert_eq!(
        fs::read(&first_truth).unwrap(),
        fs::read(&second_truth).unwrap()
    );
    let report = validate_corpus(
        &second_corpus,
        &second_truth,
        std::path::Path::new("tests/rules"),
        Some(&second_manifest),
    )
    .unwrap();
    assert_eq!(report.status, "PASS");
}

#[test]
fn volumetric_concentration_profile_is_reproducible_and_preserves_distributed_shape() {
    let directory = tempdir().unwrap();
    let (first_corpus, first_truth, first_manifest) =
        generated_paths(directory.path(), "volume-first");
    let (second_corpus, second_truth, second_manifest) =
        generated_paths(directory.path(), "volume-second");
    let config = GeneratorConfig {
        profile: Profile::VolumetricConcentration,
        events: VOLUMETRIC_CONCENTRATION_EVENTS,
        duration_ms: VOLUMETRIC_CONCENTRATION_DURATION_MS,
        seed: 7,
        ..GeneratorConfig::default()
    };
    generate(&first_corpus, &first_truth, &first_manifest, &config).unwrap();
    generate(&second_corpus, &second_truth, &second_manifest, &config).unwrap();
    assert_eq!(
        fs::read(&first_corpus).unwrap(),
        fs::read(&second_corpus).unwrap()
    );
    assert_eq!(
        fs::read(&first_truth).unwrap(),
        fs::read(&second_truth).unwrap()
    );
    assert_eq!(
        fs::read(&first_manifest).unwrap(),
        fs::read(&second_manifest).unwrap()
    );

    let output = directory.path().join("concentration");
    let report = concentration(
        &first_corpus,
        &output,
        TelemetryProfile::AwsWaf,
        HuntTimeRange::default(),
        Some(FocusSelector::ExactPath(
            VOLUMETRIC_CONCENTRATION_PATH.to_owned(),
        )),
        FocusPrefixLengths::default(),
    )
    .unwrap();
    let summary = &report.request_concentration;
    let top_path = summary.top_path.as_ref().unwrap();
    assert!((0.26..=0.34).contains(&top_path.request_share));
    assert!((248..=659).contains(&top_path.distinct_source_ips));
    assert!((23_000..=67_000).contains(&summary.distinct_source_ips));
    assert!((0.076..=0.123).contains(&summary.top_ten_source_ips_request_share));
    assert!(summary.top_ten_source_ips_request_share < 0.20);
    let peak_to_median = summary.requests_per_minute.peak_to_median_ratio.unwrap();
    assert!((4.0..=39.0).contains(&peak_to_median));

    let private = load_private_concentration(&output.join("request-concentration.json")).unwrap();
    let focus = private.focus.as_ref().unwrap();
    let leading_seven_share = focus
        .network_prefix_groups
        .iter()
        .take(7)
        .map(|group| group.requests)
        .sum::<u64>() as f64
        / focus.total_requests as f64;
    assert!((0.54..=0.56).contains(&leading_seven_share));
    assert!(focus
        .network_prefix_groups
        .iter()
        .all(|group| (10..=15).contains(&group.distinct_source_ips)));
    assert_eq!(focus.response_status_classes.success, 120);
    assert_eq!(focus.response_status_classes.client_error, 11_880);
}

#[test]
fn volumetric_concentration_profile_renders_every_supported_telemetry_format() {
    let directory = tempdir().unwrap();
    let config = GeneratorConfig {
        profile: Profile::VolumetricConcentration,
        events: VOLUMETRIC_CONCENTRATION_EVENTS,
        duration_ms: VOLUMETRIC_CONCENTRATION_DURATION_MS,
        ..GeneratorConfig::default()
    };
    for (name, format) in [
        ("aws", SyntheticFormat::AwsWaf),
        ("nginx", SyntheticFormat::NginxCombined),
        ("apache", SyntheticFormat::ApacheCombined),
    ] {
        let corpus = directory.path().join(format!("{name}.jsonl"));
        let truth = directory.path().join(format!("{name}.truth.jsonl"));
        let manifest = directory.path().join(format!("{name}.manifest.json"));
        let result = generate_for_format(&corpus, &truth, &manifest, &config, format).unwrap();
        assert_eq!(
            result.manifest.valid_events,
            VOLUMETRIC_CONCENTRATION_EVENTS
        );
        assert_eq!(result.manifest.telemetry_format, format);
        assert!(fs::metadata(corpus).unwrap().len() > 0);
        assert!(fs::metadata(truth).unwrap().len() > 0);
    }
}

#[test]
fn setup_reports_an_explicit_kev_skip_without_network_access() {
    Command::cargo_bin("shenron-lab")
        .unwrap()
        .args([
            "setup",
            "--skip-nuclei",
            "--skip-kev",
            "--skip-reputation",
            "--skip-asn",
            "--skip-sigma",
            "--skip-bot-ranges",
        ])
        .assert()
        .success()
        .stdout(contains("skipped: CISA KEV preparation (--skip-kev)"));
}
