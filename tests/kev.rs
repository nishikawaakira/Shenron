use std::path::Path;

use shenron::kev::{coverage, KevNucleiState, WebRelevance};

#[test]
fn joins_offline_kev_entries_with_nuclei_cve_results() {
    let report = coverage(
        Path::new("tests/fixtures/kev/catalog.json"),
        Path::new("tests/fixtures/kev/nuclei-report.json"),
    )
    .unwrap();
    assert_eq!(report.metrics.total_kevs, 5);
    assert_eq!(report.metrics.web_relevant, 3);
    assert_eq!(report.metrics.not_web_relevant, 1);
    assert_eq!(report.metrics.unknown_web_relevance, 1);
    assert_eq!(report.metrics.web_relevant_with_nuclei_template, 2);
    assert_eq!(report.metrics.web_relevant_with_http_nuclei_template, 2);
    assert_eq!(report.metrics.web_relevant_observable, 2);
    assert_eq!(report.metrics.web_relevant_convertible, 1);
    assert_eq!(report.metrics.web_relevant_validated, 1);
    assert_eq!(report.metrics.web_relevant_no_nuclei_template, 1);

    let by_cve = |cve: &str| {
        report
            .entries
            .iter()
            .find(|entry| entry.cve == cve)
            .unwrap()
    };
    assert_eq!(
        by_cve("CVE-2024-10001").best_nuclei_state,
        KevNucleiState::HttpTemplateValidated
    );
    assert_eq!(
        by_cve("CVE-2024-10002").best_nuclei_state,
        KevNucleiState::HttpTemplateObservableUnsupported
    );
    assert_eq!(
        by_cve("CVE-2024-10003").web_relevance,
        WebRelevance::NotWebRelevant
    );
    assert_eq!(
        by_cve("CVE-2024-10004").best_nuclei_state,
        KevNucleiState::NoNucleiTemplate
    );
    assert_eq!(
        by_cve("CVE-2024-10004").web_relevance,
        WebRelevance::WebRelevant
    );
}
