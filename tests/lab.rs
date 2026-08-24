use std::fs;

use shenron::lab::{generate, validate_corpus, GeneratorConfig, Profile};
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
