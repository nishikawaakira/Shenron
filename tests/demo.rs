use std::{fs, path::Path};

use shenron::{
    event::TelemetryProfile,
    lab::{generate_for_format, GeneratorConfig, Profile, SyntheticFormat},
    production::hunt,
};
use tempfile::tempdir;

#[test]
fn demo_corpora_regenerate_byte_for_byte_and_keep_documented_hunt_counts() {
    let directory = tempdir().unwrap();
    for (format, filename, telemetry, expected_findings, expected_cves) in [
        (
            SyntheticFormat::AwsWaf,
            "aws-waf.jsonl",
            TelemetryProfile::AwsWaf,
            5,
            4,
        ),
        (
            SyntheticFormat::NginxCombined,
            "nginx-combined.log",
            TelemetryProfile::NginxCombined,
            4,
            3,
        ),
        (
            SyntheticFormat::ApacheCombined,
            "apache-combined.log",
            TelemetryProfile::ApacheCombined,
            4,
            3,
        ),
    ] {
        let corpus = directory.path().join(filename);
        let truth = directory.path().join(format!("{filename}.truth.jsonl"));
        let manifest = directory.path().join(format!("{filename}.manifest.json"));
        let config = GeneratorConfig {
            profile: Profile::Demo,
            ..GeneratorConfig::default()
        };
        generate_for_format(&corpus, &truth, &manifest, &config, format).unwrap();
        assert_eq!(
            fs::read(&corpus).unwrap(),
            fs::read(Path::new("examples/demo").join(filename)).unwrap()
        );
        let result = hunt(
            &corpus,
            Path::new("examples/nuclei-templates"),
            Path::new("examples/demo/nuclei-report.json"),
            Path::new("examples/demo/kev-report.json"),
            &directory.path().join(format!("results-{filename}")),
            telemetry,
        )
        .unwrap();
        assert_eq!(result.metrics.total_requests_analyzed, 11);
        assert_eq!(
            result.metrics.exploitation_attempt_findings,
            expected_findings
        );
        assert_eq!(result.metrics.unique_cves_observed, expected_cves);
        assert_eq!(
            result.metrics.waf_outcome_available,
            telemetry == TelemetryProfile::AwsWaf
        );
        if telemetry == TelemetryProfile::AwsWaf {
            assert_eq!(result.metrics.blocked, 1);
            assert_eq!(result.metrics.allowed_or_not_blocked, 4);
            assert_eq!(result.metrics.unique_ja4_fingerprints, 2);
        } else {
            assert_eq!(result.metrics.blocked, 0);
            assert_eq!(result.metrics.allowed_or_not_blocked, 0);
            assert_eq!(result.metrics.unique_ja4_fingerprints, 0);
        }
    }
}
