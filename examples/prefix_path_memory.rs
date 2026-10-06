//! Manual deterministic accumulator memory exercise (not a timing test).
//! Run with `/usr/bin/time -l ...` on macOS, or `time -v` on Linux.
use shenron::{
    access_log::{parse_combined_line_with_raw_retention, AccessLogFormat},
    concentration::{ConcentrationLimits, FocusPrefixLengths, RequestConcentration},
    event::RawRetention,
};

fn main() {
    let disabled = std::env::args().any(|arg| arg == "--disabled");
    let limits = ConcentrationLimits {
        // Keep unrelated path/source-pair tracking small to measure the opt-in
        // increment, not the memory of multiple full legacy detail tables.
        max_paths: 1,
        max_source_path_pairs: 1,
        max_paths_per_source_prefix: 5_000,
        max_source_prefix_path_pairs: 10_000_000,
        ..ConcentrationLimits::default()
    };
    let mut accumulator = RequestConcentration::with_limits(true, limits);
    if !disabled {
        accumulator
            .enable_source_prefixes(FocusPrefixLengths::default())
            .unwrap();
    }
    let mut event = parse_combined_line_with_raw_retention(
        "192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 10 \"-\" \"-\"",
        AccessLogFormat::ApacheCombined,
        RawRetention::Drop,
    )
    .unwrap();
    let paths = (0..5_000)
        .map(|index| format!("/shared/static/assets/versioned/resource-{index:04}.js"))
        .collect::<Vec<_>>();
    let mut requests = 0_u64;
    for prefix in 0_u32..250_000 {
        // Synthetic distinct /24s only: no network requests or real log input.
        event.source_ip = Some(std::net::Ipv4Addr::from((prefix << 8) | 1).to_string());
        let path_count = if prefix < 10 { 5_000 } else { 30 };
        for path in paths.iter().take(path_count) {
            event.uri_path = Some(path.clone());
            event.uri.clone_from(&event.uri_path);
            accumulator.observe(&event);
            requests += 1;
        }
    }
    // Keep all tracking live until the peak-RSS measurement. No private report
    // materialization or JSON I/O is included in this accumulator-only exercise.
    std::hint::black_box(&accumulator);
    println!("prefix_opt_in={} prefixes=250000 requests={requests} expected_pairs_if_enabled={requests} shared_paths={} path_bytes={}", !disabled, paths.len(), paths[0].len());
}
