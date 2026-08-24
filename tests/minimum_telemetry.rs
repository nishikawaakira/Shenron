use shenron::minimum_telemetry::RECOMMENDED_SAFE_HEADERS;

#[test]
fn reviewed_server_examples_contain_exactly_the_measured_safe_headers() {
    let document = include_str!("../docs/minimum-telemetry.md").to_ascii_lowercase();
    for header in RECOMMENDED_SAFE_HEADERS {
        assert!(document.contains(header));
    }
    for sensitive in [
        "$http_cookie",
        "$http_authorization",
        "%{cookie}i",
        "%{authorization}i",
    ] {
        assert!(!document.contains(sensitive));
    }
}
