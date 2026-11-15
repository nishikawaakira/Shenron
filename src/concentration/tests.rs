#[test]
fn waf_fields_are_bounded_private_and_capability_aware() {
    let caps = crate::event::TelemetryProfile::AwsWaf.capabilities();
    let limits = ConcentrationLimits {
        max_waf_values_per_entity: 1,
        max_waf_values: 2,
        max_ja4_source_associations: 2,
        ..ConcentrationLimits::default()
    };
    let mut measured = RequestConcentration::with_limits(false, limits);
    measured.configure_waf(caps);
    let mut unchanged = RequestConcentration::with_limits(false, limits);
    let mut uncapped = RequestConcentration::new(false);
    uncapped.configure_waf(caps);
    for (ip, ja3, ja4, country, action) in [
        (
            "198.51.100.1",
            "private-ja3-a",
            "private-ja4-a",
            "JP",
            "ALLOW",
        ),
        (
            "198.51.100.2",
            "private-ja3-a",
            "private-ja4-a",
            "US",
            "BLOCK",
        ),
        (
            "198.51.100.1",
            "private-ja3-b",
            "private-ja4-b",
            "US",
            "ALLOW",
        ),
        (
            "198.51.100.3",
            "private-ja3-c",
            "private-ja4-c",
            "DE",
            "untrusted-value",
        ),
    ] {
        let mut event = event(Some("/private-waf-path"), Some(ip), Some(0));
        event.ja3 = Some(ja3.to_owned());
        event.ja4 = Some(ja4.to_owned());
        event.country = Some(country.to_owned());
        event.waf_action = Some(action.to_owned());
        event.waf_labels = vec![ja3.to_owned()];
        measured.observe(&event);
        unchanged.observe(&event);
        uncapped.observe(&event);
    }
    let report = measured.private_report();
    let complete = uncapped.private_report();
    assert_eq!(
        complete.source_ips[0]
            .waf
            .as_ref()
            .unwrap()
            .ja3
            .as_ref()
            .unwrap()
            .distinct_values,
        2
    );
    assert_eq!(
        complete.source_ips[0]
            .waf
            .as_ref()
            .unwrap()
            .ja4
            .as_ref()
            .unwrap()
            .distinct_values,
        2
    );
    let waf = report.waf.as_ref().unwrap();
    assert_eq!(waf.actions.as_ref().unwrap().allow, 2);
    assert_eq!(waf.actions.as_ref().unwrap().block, 1);
    assert_eq!(waf.actions.as_ref().unwrap().other, 1);
    assert_eq!(waf.countries.as_ref().unwrap().values["US"], 2);
    assert_eq!(waf.countries.as_ref().unwrap().observations_beyond_cap, 1);
    assert_eq!(waf.labels.as_ref().unwrap().observations_beyond_cap, 1);
    let source = report.source_ips[0].waf.as_ref().unwrap();
    assert_eq!(source.ja3.as_ref().unwrap().distinct_values, 1);
    assert_eq!(source.ja4.as_ref().unwrap().distinct_values, 1);
    assert_eq!(source.ja3.as_ref().unwrap().observations_beyond_cap, 1);
    assert_eq!(source.ja4.as_ref().unwrap().observations_beyond_cap, 1);
    assert_eq!(source.actions.as_ref().unwrap().allow, 2);
    assert_eq!(
        report.paths[0].summary.waf_actions.as_ref().unwrap().allow,
        2
    );
    assert_eq!(
        report.ja4_sources.as_ref().unwrap()[0].distinct_source_ips,
        2
    );
    let inverse = report
        .summary
        .waf
        .as_ref()
        .unwrap()
        .ja4_sources
        .as_ref()
        .unwrap();
    assert_eq!(inverse.observations_beyond_fingerprint_cap, 1);
    assert_eq!(inverse.observations_beyond_association_cap, 1);
    let serialized = serde_json::to_string(&report.summary).unwrap();
    for value in [
        "198.51.100",
        "/private-waf-path",
        "private-ja",
        "untrusted-value",
        "\"JP\"",
        "\"US\"",
    ] {
        assert!(!serialized.contains(value));
    }
    let mut before = serde_json::to_value(unchanged.summary()).unwrap();
    let mut after = serde_json::to_value(&report.summary).unwrap();
    for value in [&mut before, &mut after] {
        value.as_object_mut().unwrap().remove("waf");
        value["top_path"]
            .as_object_mut()
            .unwrap()
            .remove("waf_actions");
    }
    assert_eq!(before, after);
    let mut legacy = serde_json::to_value(&report).unwrap();
    legacy.as_object_mut().unwrap().remove("waf");
    legacy.as_object_mut().unwrap().remove("ja4_sources");
    legacy["summary"].as_object_mut().unwrap().remove("waf");
    for path in legacy["paths"].as_array_mut().unwrap() {
        path.as_object_mut().unwrap().remove("waf_actions");
    }
    for source in legacy["source_ips"].as_array_mut().unwrap() {
        source.as_object_mut().unwrap().remove("waf");
    }
    assert!(serde_json::from_value::<PrivateRequestConcentrationReport>(legacy).is_ok());
    let mut unavailable = RequestConcentration::new(true);
    unavailable.configure_waf(crate::event::TelemetryProfile::ApacheCombined.capabilities());
    unavailable.observe(&event(Some("/x"), Some("198.51.100.1"), Some(0)));
    assert!(unavailable.summary().waf.is_none());
    assert!(unavailable.private_report().source_ips[0].waf.is_none());
    let mut partial_caps = caps;
    partial_caps.ja3 = false;
    partial_caps.country = false;
    partial_caps.waf_labels = false;
    partial_caps.waf_action = false;
    let mut partial = RequestConcentration::new(false);
    partial.configure_waf(partial_caps);
    let summary = partial.summary().waf.unwrap();
    assert!(
        summary.ja3.is_none()
            && summary.actions.is_none()
            && summary.labels.is_none()
            && summary.countries.is_none()
    );
    assert!(summary.ja4.is_some());
}

use std::collections::BTreeMap;

use chrono::TimeZone;

use super::{accumulate::*, focus::path_is_under, *};
use crate::event::{LogSource, WebEvent};
use crate::triage::AsnResolver;
use crate::triage::ResolvedAsn;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use std::{collections::BTreeSet, net::IpAddr};

struct TestAsnResolver(BTreeMap<IpAddr, ResolvedAsn>);

impl AsnResolver for TestAsnResolver {
    fn resolve(&self, ip: IpAddr) -> Option<ResolvedAsn> {
        self.0.get(&ip).cloned()
    }
}

fn event(path: Option<&str>, source_ip: Option<&str>, minute: Option<i64>) -> WebEvent {
    WebEvent {
        timestamp: minute.map(|minute| Utc.timestamp_opt(minute * 60, 0).unwrap()),
        source_ip: source_ip.map(str::to_owned),
        client_ip: None,
        source_port: None,
        country: None,
        host: None,
        method: Some("GET".to_owned()),
        uri: path.map(str::to_owned),
        uri_path: path.map(str::to_owned),
        uri_query: None,
        uri_fragment: None,
        headers: Vec::new(),
        user_agent: None,
        referer: None,
        status: Some(403),
        response_bytes: Some(10),
        request_body: None,
        request_time_seconds: None,
        content_type: None,
        protocol: Some("HTTP/1.1".to_owned()),
        request_id: None,
        ja3: None,
        ja4: None,
        tls_protocol: None,
        tls_cipher: None,
        waf_action: None,
        waf_rule_id: None,
        waf_rule_type: None,
        waf_labels: Vec::new(),
        waf_non_terminating_rule_ids: Vec::new(),
        log_source: LogSource::ApacheCombined,
        raw: String::new(),
    }
}

#[test]
fn prefix_path_counts_distinguish_revisits_without_queries_or_legacy_cap_bias() {
    let limits = ConcentrationLimits {
        max_paths: 1,
        max_source_path_pairs: 1,
        ..ConcentrationLimits::default()
    };
    let mut ordinary = RequestConcentration::with_limits(true, limits);
    let mut enabled = RequestConcentration::with_limits(true, limits);
    enabled
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    for path in ["/private-one", "/private-two", "/private-three"] {
        for ip in ["192.0.2.1", "::ffff:192.0.2.1", "198.51.100.1"] {
            let mut request = event(Some(path), Some(ip), Some(0));
            request.uri_query = Some(format!("private-query={ip}"));
            ordinary.observe(&request);
            enabled.observe(&request);
        }
    }
    // Missing paths add no synthetic path or singleton.
    let missing = event(None, Some("198.51.100.1"), Some(0));
    ordinary.observe(&missing);
    enabled.observe(&missing);
    let report = enabled.private_report();
    let groups = report.source_prefixes.as_ref().unwrap();
    assert_eq!(groups[0].prefix, "192.0.2.0/24");
    assert_eq!(groups[0].distinct_uri_paths, Some(3));
    assert_eq!(groups[0].uri_paths_requested_once, Some(0));
    assert_eq!(groups[1].distinct_uri_paths, Some(3));
    assert_eq!(groups[1].uri_paths_requested_once, Some(3));
    for group in groups {
        assert_eq!(group.uri_paths_beyond_prefix_cap, Some(0));
        assert_eq!(group.uri_paths_beyond_global_cap, Some(0));
        assert!(group.path_observations_unavailable > 0);
        assert!(group.most_requested_uri_path.is_none());
    }
    // The separate opt-in tracker never changes existing concentration metrics.
    assert_eq!(
        serde_json::to_vec(&enabled.summary()).unwrap(),
        serde_json::to_vec(&ordinary.summary()).unwrap()
    );
    let sanitized = serde_json::to_string(&enabled.summary()).unwrap();
    for value in ["192.0.2", "198.51.100", "/private-", "private-query"] {
        assert!(!sanitized.contains(value));
    }
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("private-query"));
    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&enabled.private_report()).unwrap()
    );
}

#[test]
fn shared_prefix_path_names_are_bounded_reused_and_disclosed_without_changing_sanitized_counts() {
    let defaults = ConcentrationLimits::default();
    assert_eq!(defaults.max_source_prefix_path_pairs, 10_000_000);
    assert_eq!(defaults.max_source_prefix_paths, 10_000_000);
    assert_eq!(defaults.max_paths_per_source_prefix, 5_000);
    let limits = ConcentrationLimits {
        max_source_prefix_paths: 2,
        max_source_prefix_path_pairs: 10,
        max_paths_per_source_prefix: 5,
        ..defaults
    };
    let mut enabled = RequestConcentration::with_limits(true, limits);
    enabled
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    let mut disabled = RequestConcentration::with_limits(true, limits);
    for (ip, path) in [
        ("192.0.2.1", "/z"),
        ("192.0.2.1", "/a"),
        ("192.0.2.1", "/unretained"),
        ("192.0.2.1", "/z"),
        ("198.51.100.1", "/z"),
        ("198.51.100.1", "/unretained"),
        ("198.51.100.1", "/a"),
        ("198.51.100.1", "/z"),
        ("2001:db8::1", "/a"),
    ] {
        let request = event(Some(path), Some(ip), Some(0));
        enabled.observe(&request);
        disabled.observe(&request);
    }
    assert_eq!(
        enabled.prefix_path_names,
        BTreeMap::from([("/z".to_owned(), 0), ("/a".to_owned(), 1)])
    );
    assert!(disabled.prefix_path_names.is_empty());
    let report = enabled.private_report();
    let groups = report.source_prefixes.as_ref().unwrap();
    for group in &groups[..2] {
        assert_eq!(group.distinct_uri_paths, Some(2));
        assert_eq!(group.uri_paths_requested_once, None);
        assert_eq!(group.uri_paths_beyond_path_table_cap, Some(1));
        assert_eq!(group.uri_paths_beyond_prefix_cap, Some(0));
        assert_eq!(group.uri_paths_beyond_global_cap, Some(0));
    }
    assert_eq!(groups[2].uri_paths_requested_once, Some(1));
    assert_eq!(groups[2].uri_paths_beyond_path_table_cap, None);
    let detail = &report
        .source_prefix_aggregation
        .as_ref()
        .unwrap()
        .path_tracking;
    assert_eq!(detail.prefix_path_pairs_retained, 5);
    assert_eq!(detail.prefix_paths_retained, 2);
    assert_eq!(detail.maximum_prefix_paths, 2);
    assert_eq!(detail.requests_beyond_prefix_path_table_cap, 2);
    assert_eq!(detail.prefixes_beyond_prefix_path_table_cap, 2);
    assert_eq!(detail.prefixes_beyond_prefix_path_pair_cap, 0);
    assert_eq!(
        serde_json::to_vec(&enabled.summary()).unwrap(),
        serde_json::to_vec(&disabled.summary()).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&enabled.private_report()).unwrap()
    );
    // Old private disclosures deserialize without the new diagnostics.
    let mut old = serde_json::to_value(report.source_prefix_aggregation.as_ref().unwrap()).unwrap();
    for key in serde_json::to_value(detail)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
    {
        old.as_object_mut().unwrap().remove(key);
    }
    let old: SourcePrefixAggregation = serde_json::from_value(old).unwrap();
    assert_eq!(old.path_tracking.prefix_path_pairs_retained, 0);
}

#[test]
fn prefix_path_caps_are_independent_disclosed_and_keep_retained_counts_exact() {
    let mut accumulator = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_paths_per_source_prefix: 2,
            max_source_prefix_path_pairs: 3,
            ..ConcentrationLimits::default()
        },
    );
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    for (ip, paths) in [
        ("192.0.2.1", vec!["/a", "/b", "/a", "/c", "/c"]),
        ("198.51.100.1", vec!["/x", "/y", "/y", "/x"]),
    ] {
        for path in paths {
            accumulator.observe(&event(Some(path), Some(ip), Some(0)));
        }
    }
    accumulator.observe(&event(None, Some("2001:db8::1"), Some(0)));
    let report = accumulator.private_report();
    let groups = report.source_prefixes.as_ref().unwrap();
    assert_eq!(groups[0].distinct_uri_paths, Some(2));
    assert_eq!(groups[0].uri_paths_requested_once, None);
    assert_eq!(groups[0].uri_paths_beyond_prefix_cap, Some(2));
    assert_eq!(groups[0].uri_paths_beyond_global_cap, Some(0));
    assert_eq!(groups[1].distinct_uri_paths, Some(1));
    assert_eq!(groups[1].uri_paths_requested_once, None);
    assert_eq!(groups[1].uri_paths_beyond_prefix_cap, Some(0));
    assert_eq!(groups[1].uri_paths_beyond_global_cap, Some(2));
    assert_eq!(groups[2].distinct_uri_paths, Some(0));
    assert_eq!(groups[2].uri_paths_requested_once, Some(0));
    assert_eq!(groups[2].path_observations_unavailable, 1);
    assert_eq!(
        report
            .source_prefix_aggregation
            .as_ref()
            .unwrap()
            .requests_beyond_prefix_path_pair_cap,
        2
    );
    assert_eq!(accumulator.prefix_path_pair_count, 3);
    let detail = &report
        .source_prefix_aggregation
        .as_ref()
        .unwrap()
        .path_tracking;
    assert_eq!(detail.prefix_path_pairs_retained, 3);
    assert_eq!(detail.maximum_prefix_path_pairs, 3);
    assert_eq!(detail.prefixes_beyond_prefix_path_pair_cap, 1);
    assert_eq!(detail.prefix_paths_retained, 3);
    assert_eq!(detail.requests_beyond_prefix_path_table_cap, 0);
    assert_eq!(
        accumulator.prefix_paths[&"192.0.2.0/24".parse::<IpNet>().unwrap()].paths
            [&accumulator.prefix_path_names["/a"]],
        2
    );
    assert_eq!(
        accumulator.prefix_paths[&"198.51.100.0/24".parse::<IpNet>().unwrap()].paths
            [&accumulator.prefix_path_names["/x"]],
        2
    );
    let value = serde_json::to_value(&report).unwrap();
    assert!(value["source_prefixes"][0]
        .get("uri_paths_requested_once")
        .is_none());
    assert!(value["source_prefixes"][1]
        .get("uri_paths_requested_once")
        .is_none());
}

#[test]
fn prefix_path_capacity_preserves_exact_singletons_until_rejection_and_reads_old_json() {
    let mut accumulator = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_paths_per_source_prefix: 1,
            max_source_prefix_path_pairs: 1,
            ..ConcentrationLimits::default()
        },
    );
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    accumulator.observe(&event(Some("/one"), Some("192.0.2.1"), None));
    let group = accumulator
        .private_report()
        .source_prefixes
        .unwrap()
        .remove(0);
    assert_eq!(group.distinct_uri_paths, Some(1));
    assert_eq!(group.uri_paths_beyond_prefix_cap, Some(0));
    assert_eq!(group.uri_paths_requested_once, Some(1));
    assert_eq!(group.uri_paths_beyond_global_cap, Some(0));
    assert_eq!(
        serde_json::to_value(&group).unwrap()["uri_paths_requested_once"],
        1
    );
    let mut old = serde_json::to_value(&group).unwrap();
    for key in [
        "distinct_uri_paths",
        "uri_paths_requested_once",
        "uri_paths_beyond_prefix_cap",
        "uri_paths_beyond_global_cap",
    ] {
        old.as_object_mut().unwrap().remove(key);
    }
    let decoded: PrivateSourcePrefix = serde_json::from_value(old.clone()).unwrap();
    assert!(decoded.distinct_uri_paths.is_none());
    assert_eq!(serde_json::to_value(decoded).unwrap(), old);

    accumulator.observe(&event(Some("/one"), Some("192.0.2.1"), None));
    assert_eq!(
        accumulator.private_report().source_prefixes.unwrap()[0].uri_paths_requested_once,
        Some(0)
    );
    accumulator.observe(&event(Some("/two"), Some("192.0.2.1"), None));
    let rejected = accumulator
        .private_report()
        .source_prefixes
        .unwrap()
        .remove(0);
    assert_eq!(rejected.uri_paths_beyond_prefix_cap, Some(1));
    assert_eq!(rejected.uri_paths_requested_once, None);
    assert!(serde_json::to_value(rejected)
        .unwrap()
        .get("uri_paths_requested_once")
        .is_none());
}

#[test]
fn cached_prefix_paths_match_hand_counted_reports_for_aliases_invalid_peers_and_both_caps() {
    let limits = ConcentrationLimits {
        max_source_ips: 6,
        max_paths_per_source_prefix: 2,
        max_source_prefix_path_pairs: 3,
        ..ConcentrationLimits::default()
    };
    let mut enabled = RequestConcentration::with_limits(true, limits);
    enabled
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    let mut disabled = RequestConcentration::with_limits(true, limits);
    for (ip, path) in [
        (Some("::ffff:192.0.2.1"), Some("/a")),
        (Some("192.0.2.1"), Some("/b")),
        (Some("192.0.2.1"), Some("/a")),
        (Some("::ffff:192.0.2.1"), Some("/c")),
        (Some("2001:DB8::1"), Some("/x")),
        (Some("2001:db8::1"), Some("/y")),
        (Some("2001:db8::1"), Some("/x")),
        (Some("invalid"), Some("/invalid")),
        (Some("198.51.100.1"), Some("/z")),
        (Some("192.0.2.1"), Some("/b")),
        (Some("::ffff:192.0.2.1"), None),
        (None, Some("/missing-source")),
        (Some("203.0.113.1"), Some("/capped-source")),
    ] {
        let request = event(path, ip, Some(0));
        enabled.observe(&request);
        disabled.observe(&request);
    }
    // Hand-counted groups include legacy volumes and status/byte detail,
    // not just the new path counters. Raw aliases remain separate rows.
    let expected = [
        ("192.0.2.0/24", 6, None, 1, 2, 1, 0),
        ("2001:db8::/48", 3, Some("/x"), 0, 1, 0, 1),
        ("198.51.100.0/24", 1, Some("/z"), 0, 0, 0, 1),
    ]
    .into_iter()
    .map(
        |(prefix, requests, top_path, missing_paths, distinct, per_cap, global_cap)| {
            PrivateSourcePrefix {
                prefix: prefix.to_owned(),
                requests,
                response_bytes: Some(requests * 10),
                response_bytes_unavailable: 0,
                distinct_source_ips: 1,
                max_requests_per_source_ip: requests,
                most_requested_uri_path: top_path.map(str::to_owned),
                path_observations_unavailable: missing_paths,
                response_status_classes: StatusClassCounts {
                    client_error: requests,
                    ..Default::default()
                },
                asns: None,
                unresolved_source_ips: None,
                unresolved_requests: None,
                distinct_uri_paths: Some(distinct),
                uri_paths_requested_once: None,
                uri_paths_beyond_prefix_cap: Some(per_cap),
                uri_paths_beyond_global_cap: Some(global_cap),
                uri_paths_beyond_path_table_cap: None,
            }
        },
    )
    .collect::<Vec<_>>();
    let report = enabled.private_report();
    assert_eq!(
        serde_json::to_value(&report.source_prefixes).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    let disclosure = report.source_prefix_aggregation.unwrap();
    assert_eq!(disclosure.requests_beyond_prefix_path_pair_cap, 2);
    assert_eq!(disclosure.requests_without_source_ip, 1);
    assert_eq!(disclosure.requests_with_invalid_source_ip, 1);
    assert_eq!(disclosure.requests_beyond_source_tracking_cap, 1);
    for (peer, prefix) in [
        ("192.0.2.1", "192.0.2.0/24"),
        ("::ffff:192.0.2.1", "192.0.2.0/24"),
        ("2001:DB8::1", "2001:db8::/48"),
        ("2001:db8::1", "2001:db8::/48"),
    ] {
        assert_eq!(
            enabled.source_ips[peer].prefix,
            Some(prefix.parse().unwrap())
        );
    }
    assert!(enabled.source_ips["invalid"].prefix.is_none());
    assert!(disabled
        .source_ips
        .values()
        .all(|item| item.prefix.is_none()));
    assert!(disabled.prefix_paths.is_empty());
    assert!(enabled
        .enable_source_prefixes(FocusPrefixLengths::default())
        .is_err());
    assert_eq!(
        serde_json::to_vec(&enabled.summary()).unwrap(),
        serde_json::to_vec(&disabled.summary()).unwrap()
    );
    assert_eq!(
        enabled.prefix_paths[&"192.0.2.0/24".parse().unwrap()].paths,
        BTreeMap::from([
            (enabled.prefix_path_names["/a"], 2),
            (enabled.prefix_path_names["/b"], 2)
        ])
    );
    assert_eq!(
        enabled.prefix_paths[&"2001:db8::/48".parse().unwrap()].paths
            [&enabled.prefix_path_names["/x"]],
        2
    );
}

fn event_with_query(path: &str, source_ip: &str, query: Option<String>) -> WebEvent {
    let mut event = event(Some(path), Some(source_ip), Some(0));
    event.uri_query = query.clone();
    event.uri = Some(match query {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    });
    event
}

#[test]
fn source_ip_focus_matches_canonical_aliases_but_preserves_raw_rows_and_selector() {
    let mut accumulator = RequestConcentration::new(true);
    accumulator.focus_on(FocusSelector::SourceIp(BTreeSet::from([
        "192.0.2.1".to_owned()
    ])));
    for ip in ["192.0.2.1", "::ffff:192.0.2.1", "192.0.2.2"] {
        accumulator.observe(&event(Some("/focus"), Some(ip), Some(0)));
    }
    let focus = accumulator.private_report().focus.unwrap();
    assert_eq!(focus.total_requests, 2);
    assert_eq!(focus.selector, "192.0.2.1");
    assert_eq!(
        focus
            .sources
            .iter()
            .map(|source| source.source_ip.as_str())
            .collect::<Vec<_>>(),
        ["192.0.2.1", "::ffff:192.0.2.1"]
    );
    assert!(focus.sources.iter().all(|source| source.requests == 1));
}

#[test]
fn source_ip_focus_matches_reverse_mapped_and_ipv6_case_aliases() {
    for (selector, peer) in [
        ("::ffff:192.0.2.1", "192.0.2.1"),
        ("2001:DB8::1", "2001:db8::1"),
    ] {
        let mut accumulator = RequestConcentration::new(true);
        accumulator.focus_on(FocusSelector::SourceIp(BTreeSet::from([
            selector.to_owned()
        ])));
        accumulator.observe(&event(Some("/focus"), Some(peer), Some(0)));
        let focus = accumulator.private_report().focus.unwrap();
        assert_eq!(focus.total_requests, 1);
        assert_eq!(focus.selector, selector);
        assert_eq!(focus.sources[0].source_ip, peer);
    }
}

#[test]
fn source_ip_focus_keeps_invalid_selectors_exact_and_caches_only_address_selectors() {
    let mut accumulator = RequestConcentration::new(true);
    accumulator.focus_on(FocusSelector::SourceIp(BTreeSet::from([
        "not-an-ip".to_owned()
    ])));
    assert!(accumulator
        .focus_source_addresses
        .as_ref()
        .unwrap()
        .is_empty());
    for ip in [
        Some("not-an-ip"),
        Some("NOT-AN-IP"),
        Some("not-an-ip "),
        Some("192.0.2.1"),
        None,
    ] {
        accumulator.observe(&event(Some("/focus"), ip, Some(0)));
    }
    let focus = accumulator.private_report().focus.unwrap();
    assert_eq!(focus.total_requests, 1);
    assert_eq!(focus.sources[0].source_ip, "not-an-ip");
    for selector in [
        FocusSelector::ExactPath("/focus".to_owned()),
        FocusSelector::PathPrefix("/focus".to_owned()),
    ] {
        accumulator.focus_on(FocusSelector::SourceIp(BTreeSet::from([
            "192.0.2.1".to_owned()
        ])));
        assert_eq!(
            accumulator.focus_source_addresses.as_ref().unwrap().len(),
            1
        );
        accumulator.focus_on(selector);
        assert!(accumulator.focus_source_addresses.is_none());
    }
}

#[test]
fn source_ip_focus_aliases_still_obey_raw_source_tracking_caps() {
    let mut accumulator = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_focus_source_ips: 1,
            ..ConcentrationLimits::default()
        },
    );
    accumulator.focus_on(FocusSelector::SourceIp(BTreeSet::from([
        "192.0.2.1".to_owned()
    ])));
    for ip in ["192.0.2.1", "::ffff:192.0.2.1"] {
        accumulator.observe(&event(Some("/focus"), Some(ip), Some(0)));
    }
    let focus = accumulator.private_report().focus.unwrap();
    assert_eq!(focus.total_requests, 2);
    assert_eq!(focus.sources.len(), 1);
    assert_eq!(focus.sources[0].source_ip, "192.0.2.1");
    assert_eq!(focus.source_ips_beyond_cap, 1);
}

#[test]
fn focus_asn_groups_resolve_canonical_peers_and_deduplicate_unresolved_addresses() {
    let mut accumulator = RequestConcentration::new(true);
    accumulator.focus_on_path("/focus");
    for ip in [
        "::ffff:192.0.2.1",
        "192.0.2.1",
        "::ffff:192.0.2.2",
        "192.0.2.2",
        "2001:DB8::1",
        "2001:db8::1",
        "not-an-ip",
        "not-an-ip",
        "another-invalid",
    ] {
        accumulator.observe(&event(Some("/focus"), Some(ip), Some(0)));
    }
    let resolver = TestAsnResolver(BTreeMap::from([(
        "192.0.2.1".parse().unwrap(),
        ResolvedAsn {
            asn: 64500,
            org: "Example Transit".to_owned(),
        },
    )]));
    let mut focus = accumulator.private_report().focus.unwrap();
    let raw_sources = serde_json::to_vec(&focus.sources).unwrap();
    add_focus_asn_groups(&mut focus, &resolver);
    assert_eq!(serde_json::to_vec(&focus.sources).unwrap(), raw_sources);
    let asn = focus.asn.as_ref().unwrap();
    assert_eq!(asn.groups.len(), 1);
    assert_eq!(asn.groups[0].asn, 64500);
    assert_eq!(asn.groups[0].requests, 2);
    assert_eq!(asn.groups[0].distinct_source_ips, 1);
    // One unresolved IPv4, one unresolved IPv6, and two invalid spellings.
    assert_eq!(asn.unresolved_source_ips, 4);
    assert_eq!(asn.unresolved_requests, 7);
    assert_eq!(
        asn.groups.iter().map(|group| group.requests).sum::<u64>() + asn.unresolved_requests,
        focus.total_requests
    );
    let before = serde_json::to_vec(&focus).unwrap();
    add_focus_asn_groups(&mut focus, &resolver);
    assert_eq!(serde_json::to_vec(&focus).unwrap(), before);
}

#[test]
fn source_prefix_asns_resolve_canonical_peers_and_disclose_unresolved_totals() {
    let mut accumulator = RequestConcentration::new(true);
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    for (ip, requests) in [
        ("::ffff:192.0.2.1", 2),
        ("192.0.2.1", 1),
        ("192.0.2.2", 1),
        ("192.0.2.3", 2),
        ("192.0.2.4", 2),
        ("192.0.2.5", 1),
        ("::ffff:192.0.2.5", 1),
        ("2001:DB8::1", 1),
        ("2001:db8::1", 1),
    ] {
        for _ in 0..requests {
            accumulator.observe(&event(Some("/private-prefix"), Some(ip), Some(0)));
        }
    }
    let resolver = TestAsnResolver(
        [
            ("192.0.2.1", 64503, "Z Example"),
            ("192.0.2.2", 64503, "A Example"),
            ("192.0.2.3", 64502, "Second Example"),
            ("192.0.2.4", 64501, "First Example"),
            ("2001:db8::1", 64504, "IPv6 Example"),
        ]
        .into_iter()
        .map(|(ip, asn, org)| {
            (
                ip.parse().unwrap(),
                ResolvedAsn {
                    asn,
                    org: org.to_owned(),
                },
            )
        })
        .collect(),
    );
    let plain = accumulator.private_report();
    let enriched =
        accumulator.private_report_with_query_keys_and_source_asns(false, Some(&resolver));
    let groups = enriched.source_prefixes.as_ref().unwrap();
    assert_eq!(groups.len(), 2);
    let ipv4 = &groups[0];
    assert_eq!(ipv4.prefix, "192.0.2.0/24");
    let asns = ipv4.asns.as_ref().unwrap();
    assert_eq!(
        asns.iter()
            .map(|item| (item.asn, item.requests, item.distinct_source_ips))
            .collect::<Vec<_>>(),
        [(64503, 4, 2), (64501, 2, 1), (64502, 2, 1)]
    );
    assert_eq!(asns[0].organization, "A Example");
    assert_eq!(ipv4.unresolved_source_ips, Some(1));
    assert_eq!(ipv4.unresolved_requests, Some(2));
    assert_eq!(groups[1].asns.as_ref().unwrap()[0].distinct_source_ips, 1);
    assert_eq!(groups[1].asns.as_ref().unwrap()[0].requests, 2);
    for group in groups {
        assert_eq!(
            group
                .asns
                .as_ref()
                .unwrap()
                .iter()
                .map(|item| item.requests)
                .sum::<u64>()
                + group.unresolved_requests.unwrap(),
            group.requests
        );
    }
    assert_eq!(
        serde_json::to_vec(&plain.source_ips).unwrap(),
        serde_json::to_vec(&enriched.source_ips).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&plain.summary).unwrap(),
        serde_json::to_vec(&enriched.summary).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&enriched).unwrap(),
        serde_json::to_vec(
            &accumulator.private_report_with_query_keys_and_source_asns(false, Some(&resolver))
        )
        .unwrap()
    );
    assert!(enriched
        .source_prefix_aggregation
        .unwrap()
        .safety_note
        .contains(SOURCE_PREFIX_ASN_NOTE));

    let unresolved = accumulator.private_report_with_query_keys_and_source_asns(
        false,
        Some(&TestAsnResolver(BTreeMap::new())),
    );
    for group in unresolved.source_prefixes.unwrap() {
        assert!(group.asns.unwrap().is_empty());
        assert_eq!(group.unresolved_requests, Some(group.requests));
        assert_eq!(group.unresolved_source_ips, Some(group.distinct_source_ips));
    }
}

#[test]
fn source_prefix_asns_are_absent_without_a_resolver_or_prefix_opt_in() {
    struct UnexpectedResolver;
    impl AsnResolver for UnexpectedResolver {
        fn resolve(&self, _ip: IpAddr) -> Option<ResolvedAsn> {
            panic!("a default report must not resolve ASNs");
        }
    }
    let mut accumulator = RequestConcentration::new(true);
    accumulator.observe(&event(Some("/private-prefix"), Some("192.0.2.1"), Some(0)));
    assert_eq!(
        serde_json::to_vec(&accumulator.private_report()).unwrap(),
        serde_json::to_vec(
            &accumulator
                .private_report_with_query_keys_and_source_asns(false, Some(&UnexpectedResolver))
        )
        .unwrap()
    );
    let mut accumulator = RequestConcentration::new(true);
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    accumulator.observe(&event(Some("/private-prefix"), Some("192.0.2.1"), Some(0)));
    let report = accumulator.private_report();
    let group = &report.source_prefixes.as_ref().unwrap()[0];
    let encoded = serde_json::to_string(group).unwrap();
    for key in ["asns", "unresolved_source_ips", "unresolved_requests"] {
        assert!(!encoded.contains(key));
    }
    // Older prefix artifacts round-trip without introducing optional keys.
    let decoded: PrivateSourcePrefix = serde_json::from_str(&encoded).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
}

#[test]
fn source_and_focus_prefixes_group_mapped_ipv4_with_native_ipv4() {
    let mut accumulator = RequestConcentration::new(true);
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    accumulator.focus_on_path("/prefix");
    for ip in ["::ffff:192.0.2.1", "192.0.2.2"] {
        accumulator.observe(&event(Some("/prefix"), Some(ip), Some(0)));
    }
    let report = accumulator.private_report();
    let groups = report.source_prefixes.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].prefix, "192.0.2.0/24");
    assert_eq!(groups[0].requests, 2);
    assert_eq!(groups[0].distinct_source_ips, 2);
    assert!(groups.iter().all(|group| group.prefix != "::/48"));
    let mut focus = report.focus.unwrap();
    let sources_before = serde_json::to_vec(&focus.sources).unwrap();
    add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
    assert_eq!(focus.network_prefix_groups.len(), 1);
    let group = &focus.network_prefix_groups[0];
    assert_eq!(group.network_prefix, "192.0.2.0/24");
    assert_eq!(group.requests, 2);
    assert_eq!(group.distinct_source_ips, 2);
    assert_eq!(serde_json::to_vec(&focus.sources).unwrap(), sources_before);
}

#[test]
fn source_prefixes_merge_canonical_peer_totals_before_selecting_maxima_and_paths() {
    let mut accumulator = RequestConcentration::new(true);
    let mut disabled = RequestConcentration::new(true);
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    accumulator.focus_on(FocusSelector::PathPrefix("/".to_owned()));
    disabled.focus_on(FocusSelector::PathPrefix("/".to_owned()));
    for (ip, path, status, bytes) in [
        ("::ffff:192.0.2.1", "/a", 200, Some(10)),
        ("::ffff:192.0.2.1", "/b", 200, Some(10)),
        ("::ffff:192.0.2.1", "/b", 200, Some(10)),
        ("192.0.2.1", "/a", 404, Some(20)),
        ("192.0.2.1", "/a", 404, None),
    ] {
        let mut record = event(Some(path), Some(ip), Some(0));
        record.status = Some(status);
        record.response_bytes = bytes;
        accumulator.observe(&record);
        disabled.observe(&record);
    }
    let report = accumulator.private_report();
    let groups = report.source_prefixes.as_ref().unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.prefix, "192.0.2.0/24");
    assert_eq!(group.requests, 5);
    assert_eq!(group.distinct_source_ips, 1);
    assert_eq!(group.max_requests_per_source_ip, 5);
    assert_eq!(group.response_bytes, Some(50));
    assert_eq!(group.response_bytes_unavailable, 1);
    assert_eq!(group.response_status_classes.success, 3);
    assert_eq!(group.response_status_classes.client_error, 2);
    assert_eq!(group.most_requested_uri_path.as_deref(), Some("/a"));
    assert_eq!(group.path_observations_unavailable, 0);
    assert_eq!(report.source_ips.len(), 2);
    assert_eq!(report.source_ips[0].source_ip, "::ffff:192.0.2.1");
    assert_eq!(report.source_ips[0].requests, 3);
    assert_eq!(
        report.source_ips[0].most_requested_uri_path.as_deref(),
        Some("/b")
    );
    assert_eq!(report.source_ips[1].source_ip, "192.0.2.1");
    assert_eq!(report.source_ips[1].requests, 2);
    assert_eq!(
        serde_json::to_vec(&accumulator.summary()).unwrap(),
        serde_json::to_vec(&disabled.summary()).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&accumulator.private_report()).unwrap()
    );
    let mut focus = report.focus.unwrap();
    add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
    assert_eq!(focus.network_prefix_groups.len(), 1);
    assert_eq!(
        focus.network_prefix_groups[0].network_prefix,
        "192.0.2.0/24"
    );
    assert_eq!(focus.network_prefix_groups[0].distinct_source_ips, 1);
    assert_eq!(focus.network_prefix_groups[0].requests, 5);
    assert_eq!(
        focus.network_prefix_groups[0]
            .response_status_classes
            .success,
        3
    );
    assert_eq!(
        focus.network_prefix_groups[0]
            .response_status_classes
            .client_error,
        2
    );
}

#[test]
fn source_and_focus_prefixes_deduplicate_ipv6_spelling_without_rewriting_source_rows() {
    let mut accumulator = RequestConcentration::new(true);
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    accumulator.focus_on_path("/ipv6");
    for ip in ["2001:DB8::1", "2001:db8::1", "2001:db8::1"] {
        accumulator.observe(&event(Some("/ipv6"), Some(ip), Some(0)));
    }
    let report = accumulator.private_report();
    let groups = report.source_prefixes.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].prefix, "2001:db8::/48");
    assert_eq!(groups[0].distinct_source_ips, 1);
    assert_eq!(groups[0].max_requests_per_source_ip, 3);
    assert_eq!(groups[0].requests, 3);
    assert_eq!(report.source_ips.len(), 2);
    assert_eq!(report.source_ips[0].source_ip, "2001:db8::1");
    assert_eq!(report.source_ips[1].source_ip, "2001:DB8::1");
    let mut focus = report.focus.unwrap();
    add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
    assert_eq!(focus.network_prefix_groups.len(), 1);
    assert_eq!(
        focus.network_prefix_groups[0].network_prefix,
        "2001:db8::/48"
    );
    assert_eq!(focus.network_prefix_groups[0].distinct_source_ips, 1);
    assert_eq!(focus.network_prefix_groups[0].requests, 3);
    assert_eq!(focus.sources.len(), 2);
}

#[test]
fn canonical_source_prefixes_preserve_raw_tracking_caps_and_request_accounting() {
    let mut accumulator = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_source_ips: 3,
            max_source_path_pairs: 1,
            ..ConcentrationLimits::default()
        },
    );
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    for ip in [
        Some("::ffff:192.0.2.1"),
        Some("::ffff:192.0.2.1"),
        Some("::ffff:192.0.2.1"),
        Some("192.0.2.1"),
        Some("192.0.2.1"),
        Some("invalid"),
        Some("192.0.2.2"),
        None,
    ] {
        accumulator.observe(&event(Some("/capped"), ip, Some(0)));
    }
    let report = accumulator.private_report();
    assert_eq!(report.summary.distinct_source_ips, 3);
    assert_eq!(report.summary.source_ips_beyond_tracking_cap, 1);
    let groups = report.source_prefixes.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].requests, 5);
    assert_eq!(groups[0].distinct_source_ips, 1);
    assert_eq!(groups[0].max_requests_per_source_ip, 5);
    assert_eq!(groups[0].path_observations_unavailable, 2);
    assert!(groups[0].most_requested_uri_path.is_none());
    let disclosure = report.source_prefix_aggregation.unwrap();
    assert_eq!(disclosure.requests_without_source_ip, 1);
    assert_eq!(disclosure.requests_with_invalid_source_ip, 1);
    assert_eq!(disclosure.requests_beyond_source_tracking_cap, 1);
    assert_eq!(
        groups.iter().map(|group| group.requests).sum::<u64>()
            + disclosure.requests_without_source_ip
            + disclosure.requests_with_invalid_source_ip
            + disclosure.requests_beyond_source_tracking_cap,
        report.summary.total_requests
    );
}

#[test]
fn source_prefix_volumes_keep_per_peer_maxima_and_do_not_change_existing_metrics() {
    let mut ordinary = RequestConcentration::new(true);
    let mut enabled = RequestConcentration::new(true);
    enabled
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    let mut observe = |ip: &str, requests: usize| {
        for _ in 0..requests {
            let event = event(Some("/private-volume"), Some(ip), Some(0));
            ordinary.observe(&event);
            enabled.observe(&event);
        }
    };
    observe("192.0.2.1", 1000);
    for i in 1..=100 {
        observe(&format!("198.51.100.{i}"), 10);
    }
    observe("2001:db8:1234:1::1", 20);
    observe("2001:db8:1234:2::2", 30);
    let legacy = serde_json::to_value(ordinary.private_report()).unwrap();
    let report = enabled.private_report();
    let groups = report.source_prefixes.as_ref().unwrap();
    assert_eq!(groups.len(), 3);
    assert_eq!(
        groups.iter().map(|g| g.requests).sum::<u64>(),
        report.summary.total_requests
    );
    assert_eq!(
        (
            &groups[0].prefix,
            groups[0].requests,
            groups[0].distinct_source_ips,
            groups[0].max_requests_per_source_ip
        ),
        (&"192.0.2.0/24".to_owned(), 1000, 1, 1000)
    );
    assert_eq!(
        (
            &groups[1].prefix,
            groups[1].requests,
            groups[1].distinct_source_ips,
            groups[1].max_requests_per_source_ip
        ),
        (&"198.51.100.0/24".to_owned(), 1000, 100, 10)
    );
    assert_eq!(groups[2].prefix, "2001:db8:1234::/48");
    assert_eq!(groups[2].distinct_source_ips, 2);
    assert_eq!(groups[0].response_bytes, Some(10_000));
    assert_eq!(groups[0].response_status_classes.client_error, 1000);
    assert_eq!(
        groups[0].most_requested_uri_path.as_deref(),
        Some("/private-volume")
    );
    assert_eq!(
        report
            .source_ips
            .iter()
            .filter_map(|s| s.response_bytes)
            .sum::<u64>(),
        report.paths[0].summary.response_bytes.unwrap()
    );
    let mut value = serde_json::to_value(&report).unwrap();
    value.as_object_mut().unwrap().remove("source_prefixes");
    value
        .as_object_mut()
        .unwrap()
        .remove("source_prefix_aggregation");
    for source in value["source_ips"].as_array_mut().unwrap() {
        source.as_object_mut().unwrap().remove("response_bytes");
        source
            .as_object_mut()
            .unwrap()
            .remove("response_bytes_unavailable");
    }
    assert_eq!(value, legacy);
    assert!(legacy.get("source_prefixes").is_none());
    assert!(legacy["source_ips"][0].get("response_bytes").is_none());
    let decoded: PrivateRequestConcentrationReport =
        serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&enabled.private_report()).unwrap()
    );
    let sanitized = serde_json::to_string(&enabled.summary()).unwrap();
    assert_eq!(
        sanitized,
        serde_json::to_string(&ordinary.summary()).unwrap()
    );
    for private in [
        "192.0.2.",
        "198.51.100.",
        "2001:db8",
        "/private-volume",
        "source_prefixes",
    ] {
        assert!(!sanitized.contains(private));
    }
}

#[test]
fn source_prefix_caps_and_invalid_or_missing_peers_are_disclosed_without_estimates() {
    for (paths, pairs) in [(1, 10), (10, 1)] {
        let mut accumulator = RequestConcentration::with_limits(
            true,
            ConcentrationLimits {
                max_source_ips: 2,
                max_paths: paths,
                max_source_path_pairs: pairs,
                ..ConcentrationLimits::default()
            },
        );
        accumulator
            .enable_source_prefixes(FocusPrefixLengths::default())
            .unwrap();
        for (ip, path) in [
            (Some("192.0.2.1"), "/first"),
            (Some("192.0.2.1"), "/second"),
            (Some("invalid"), "/first"),
            (Some("198.51.100.1"), "/first"),
            (None, "/first"),
        ] {
            accumulator.observe(&event(Some(path), ip, Some(0)));
        }
        let report = accumulator.private_report();
        let groups = report.source_prefixes.unwrap();
        let disclosure = report.source_prefix_aggregation.unwrap();
        assert_eq!(groups.len(), 1);
        assert!(groups.len() <= disclosure.maximum_prefixes);
        assert_eq!(groups[0].requests, 2);
        assert_eq!(groups[0].path_observations_unavailable, 1);
        assert!(groups[0].most_requested_uri_path.is_none());
        assert_eq!(disclosure.requests_without_source_ip, 1);
        assert_eq!(disclosure.requests_with_invalid_source_ip, 1);
        assert_eq!(disclosure.requests_beyond_source_tracking_cap, 1);
        assert_eq!(
            groups.iter().map(|g| g.requests).sum::<u64>()
                + disclosure.requests_without_source_ip
                + disclosure.requests_with_invalid_source_ip
                + disclosure.requests_beyond_source_tracking_cap,
            report.summary.total_requests
        );
    }
}

#[test]
fn source_prefix_bytes_distinguish_zero_partial_and_unavailable() {
    for capability in [true, false] {
        let mut accumulator = RequestConcentration::new(capability);
        accumulator
            .enable_source_prefixes(FocusPrefixLengths::default())
            .unwrap();
        for (ip, bytes) in [
            ("192.0.2.1", Some(0)),
            ("192.0.2.2", None),
            ("198.51.100.1", None),
            ("203.0.113.1", Some(40)),
            ("203.0.113.1", None),
        ] {
            let mut event = event(Some("/bytes"), Some(ip), Some(0));
            event.response_bytes = bytes;
            accumulator.observe(&event);
        }
        let report = accumulator.private_report();
        let groups = report.source_prefixes.unwrap();
        let find = |prefix: &str| groups.iter().find(|g| g.prefix == prefix).unwrap();
        assert_eq!(find("192.0.2.0/24").response_bytes, capability.then_some(0));
        assert_eq!(
            find("192.0.2.0/24").response_bytes_unavailable,
            if capability { 1 } else { 2 }
        );
        assert_eq!(find("198.51.100.0/24").response_bytes, None);
        assert_eq!(
            find("203.0.113.0/24").response_bytes,
            capability.then_some(40)
        );
        assert_eq!(
            find("203.0.113.0/24").response_bytes_unavailable,
            if capability { 1 } else { 2 }
        );
        let source = report
            .source_ips
            .iter()
            .find(|s| s.source_ip == "192.0.2.1")
            .unwrap();
        assert_eq!(source.response_bytes, capability.then_some(0));
        assert_eq!(
            source.response_bytes_unavailable,
            Some(u64::from(!capability))
        );
    }
}

#[test]
fn source_prefix_top_path_uses_all_retained_pairs_and_lexical_ties() {
    let mut accumulator = RequestConcentration::new(true);
    accumulator
        .enable_source_prefixes(FocusPrefixLengths::default())
        .unwrap();
    for (ip, path, count) in [
        ("192.0.2.1", "/b", 3),
        ("192.0.2.1", "/a", 2),
        ("192.0.2.2", "/c", 3),
        ("192.0.2.2", "/a", 2),
        ("192.0.2.2", "/d", 4),
    ] {
        for _ in 0..count {
            accumulator.observe(&event(Some(path), Some(ip), Some(0)));
        }
    }
    let groups = accumulator.private_report().source_prefixes.unwrap();
    assert_eq!(groups[0].most_requested_uri_path.as_deref(), Some("/a"));
    assert_eq!(groups[0].max_requests_per_source_ip, 9);
}

#[test]
fn measures_top_path_source_convergence_and_minute_rate() {
    let mut concentration = RequestConcentration::new(true);
    for (path, ip, minute) in [
        ("/popular", "198.51.100.1", 0),
        ("/popular", "198.51.100.2", 0),
        ("/popular", "198.51.100.1", 1),
        ("/other", "198.51.100.3", 1),
    ] {
        concentration.observe(&event(Some(path), Some(ip), Some(minute)));
    }
    let summary = concentration.summary();
    let top = summary.top_path.unwrap();
    assert_eq!(top.requests, 3);
    assert_eq!(top.distinct_source_ips, 2);
    assert_eq!(top.requests_per_source_ip, 1.5);
    assert_eq!(top.request_share, 0.75);
    assert_eq!(top.response_status_classes.client_error, 3);
    assert_eq!(top.response_bytes, Some(30));
    assert_eq!(
        summary.requests_per_minute.peak_requests_per_minute,
        Some(2)
    );
    assert_eq!(
        summary.requests_per_minute.median_requests_per_minute,
        Some(2.0)
    );
    assert_eq!(summary.requests_per_minute.peak_to_median_ratio, Some(1.0));
}

#[test]
fn groups_retained_focus_sources_by_asn_and_discloses_unresolved_counts() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on(FocusSelector::ExactPath("/focus".to_owned()));
    for (ip, count) in [("198.51.100.1", 3), ("198.51.101.2", 2), ("203.0.113.9", 1)] {
        for _ in 0..count {
            concentration.observe(&event(Some("/focus"), Some(ip), Some(0)));
        }
    }
    let mut focus = concentration.private_report().focus.unwrap();
    add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
    let resolver = TestAsnResolver(BTreeMap::from([
        (
            "198.51.100.1".parse().unwrap(),
            ResolvedAsn {
                asn: 64_500,
                org: "Example Transit".to_owned(),
            },
        ),
        (
            "198.51.101.2".parse().unwrap(),
            ResolvedAsn {
                asn: 64_500,
                org: "Example Transit".to_owned(),
            },
        ),
    ]));
    add_focus_asn_groups(&mut focus, &resolver);

    assert_eq!(focus.network_prefix_groups.len(), 3);
    let asn = focus.asn.unwrap();
    assert_eq!(asn.groups.len(), 1);
    assert_eq!(asn.groups[0].asn, 64_500);
    assert_eq!(asn.groups[0].requests, 5);
    assert_eq!(asn.groups[0].distinct_source_ips, 2);
    assert_eq!(asn.groups[0].request_share, 5.0 / 6.0);
    assert_eq!(asn.unresolved_source_ips, 1);
    assert_eq!(asn.unresolved_requests, 1);
}

#[test]
fn keeps_private_minute_series_sorted_and_discloses_bucket_caps() {
    let mut concentration = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_minute_buckets: 2,
            ..ConcentrationLimits::default()
        },
    );
    concentration.focus_on_path("/target");
    for minute in [2, 0, 2, 3] {
        concentration.observe(&event(Some("/target"), Some("198.51.100.1"), Some(minute)));
    }

    let private = concentration.private_report();
    assert_eq!(
        private.requests_per_minute_series,
        vec![
            MinuteRequestCount {
                minute_epoch: 0,
                requests: 1,
            },
            MinuteRequestCount {
                minute_epoch: 2,
                requests: 2,
            },
        ]
    );
    assert_eq!(private.minute_buckets_beyond_cap, 1);
    assert_eq!(private.status_class_requests_per_minute_series.len(), 2);
    assert_eq!(
        private
            .status_class_requests_per_minute_series
            .iter()
            .map(|point| point.client_error)
            .sum::<u64>(),
        3
    );
    let focus = private.focus.unwrap();
    assert_eq!(focus.requests_per_minute_series.len(), 2);
    assert_eq!(focus.minute_buckets_beyond_cap, 1);

    let sanitized = serde_json::to_string(&concentration.summary()).unwrap();
    assert!(!sanitized.contains("requests_per_minute_series"));
    assert!(!sanitized.contains("status_class_requests_per_minute_series"));
    assert!(!sanitized.contains("198.51.100.1"));
    assert!(!sanitized.contains("/target"));
}

#[test]
fn loads_private_artifacts_created_before_minute_series_fields() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on_path("/target");
    let mut value = serde_json::to_value(concentration.private_report()).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("requests_per_minute_series");
    object.remove("status_class_requests_per_minute_series");
    object.remove("minute_buckets_beyond_cap");
    let focus = object
        .get_mut("focus")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap();
    focus.remove("requests_per_minute_series");
    focus.remove("minute_buckets_beyond_cap");
    let loaded: PrivateRequestConcentrationReport = serde_json::from_value(value).unwrap();
    assert!(loaded.requests_per_minute_series.is_empty());
    assert!(loaded.status_class_requests_per_minute_series.is_empty());
    assert_eq!(loaded.minute_buckets_beyond_cap, 0);
    let focus = loaded.focus.unwrap();
    assert!(focus.requests_per_minute_series.is_empty());
    assert_eq!(focus.minute_buckets_beyond_cap, 0);
}

#[test]
fn keeps_status_class_minute_series_sorted_and_counted_by_class() {
    let mut concentration = RequestConcentration::new(true);
    for (minute, status) in [(2, 200), (0, 404), (0, 201), (1, 302), (1, 500), (1, 101)] {
        let mut observed = event(Some("/status"), Some("198.51.100.1"), Some(minute));
        observed.status = Some(status);
        concentration.observe(&observed);
    }

    assert_eq!(
        concentration
            .private_report()
            .status_class_requests_per_minute_series,
        vec![
            StatusClassMinuteCount {
                minute_epoch: 0,
                success: 1,
                client_error: 1,
                ..StatusClassMinuteCount::default()
            },
            StatusClassMinuteCount {
                minute_epoch: 1,
                informational: 1,
                redirection: 1,
                server_error: 1,
                ..StatusClassMinuteCount::default()
            },
            StatusClassMinuteCount {
                minute_epoch: 2,
                success: 1,
                ..StatusClassMinuteCount::default()
            },
        ]
    );
}

#[test]
fn finds_path_concentration_even_when_sources_are_distributed() {
    let mut concentration = RequestConcentration::new(true);
    for index in 0..200 {
        concentration.observe(&event(
            Some("/shared-resource"),
            Some(&format!("198.51.100.{index}")),
            Some(index),
        ));
    }
    for index in 0..200 {
        concentration.observe(&event(
            Some("/other-resource"),
            Some(&format!("203.0.113.{index}")),
            Some(index),
        ));
    }
    let top = concentration.summary().top_path.unwrap();
    assert_eq!(top.requests, 200);
    assert_eq!(top.distinct_source_ips, 200);
    assert_eq!(top.requests_per_source_ip, 1.0);
    assert_eq!(top.request_share, 0.5);
    assert!(concentration
        .private_report()
        .source_ips
        .iter()
        .all(|source| source.requests * 100 < 400));
}

#[test]
fn requests_per_distinct_source_avoids_a_zero_denominator() {
    assert_eq!(requests_per_distinct_source(12, 3), 4.0);
    let zero = requests_per_distinct_source(12, 0);
    assert_eq!(zero, 0.0);
    assert!(zero.is_finite());
}

#[test]
fn discloses_tracking_caps_and_undated_observations() {
    let mut concentration = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_paths: 1,
            max_source_ips: 1,
            max_focus_source_ips: 1,
            max_focus_paths: 1,
            max_source_path_pairs: 1,
            max_minute_buckets: 1,
            max_query_strings_per_path: 1,
            max_query_keys_per_path: 1,
            max_status_codes_per_entity: DEFAULT_MAX_STATUS_CODES_PER_ENTITY,
            max_source_segments: DEFAULT_MAX_SOURCE_SEGMENTS,
            ..ConcentrationLimits::default()
        },
    );
    concentration.observe(&event(Some("/one"), Some("198.51.100.1"), Some(0)));
    concentration.observe(&event(Some("/two"), Some("198.51.100.2"), None));
    let summary = concentration.summary();
    assert_eq!(summary.paths_beyond_tracking_cap, 1);
    assert_eq!(summary.source_ips_beyond_tracking_cap, 1);
    assert_eq!(
        summary.requests_per_minute.observations_without_timestamp,
        1
    );
}

#[test]
fn marks_response_bytes_unavailable_when_telemetry_lacks_them() {
    let mut concentration = RequestConcentration::new(false);
    concentration.observe(&event(Some("/resource"), Some("198.51.100.1"), Some(0)));
    assert_eq!(
        concentration.summary().top_path.unwrap().response_bytes,
        None
    );
}

#[test]
fn finds_the_most_requested_path_with_the_existing_tie_breaker() {
    let mut concentration = RequestConcentration::new(true);
    for path in ["/zebra", "/alpha", "/zebra", "/alpha"] {
        concentration.observe(&event(Some(path), Some("198.51.100.1"), Some(0)));
    }
    assert_eq!(
        concentration.most_requested_path("198.51.100.1"),
        Some("/alpha".to_owned())
    );
}

#[test]
fn leaves_a_source_top_path_unavailable_after_pair_tracking_is_incomplete() {
    let mut concentration = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_paths: 10,
            max_source_ips: 10,
            max_focus_source_ips: 10,
            max_focus_paths: 10,
            max_source_path_pairs: 1,
            max_minute_buckets: 10,
            max_query_strings_per_path: 10,
            max_query_keys_per_path: 10,
            max_status_codes_per_entity: DEFAULT_MAX_STATUS_CODES_PER_ENTITY,
            max_source_segments: DEFAULT_MAX_SOURCE_SEGMENTS,
            ..ConcentrationLimits::default()
        },
    );
    concentration.observe(&event(Some("/first"), Some("198.51.100.1"), Some(0)));
    concentration.observe(&event(Some("/second"), Some("198.51.100.1"), Some(0)));
    assert_eq!(concentration.most_requested_path("198.51.100.1"), None);
    assert_eq!(concentration.source_path_pair_count, 1);
    assert_eq!(
        concentration
            .summary()
            .source_path_pairs_beyond_tracking_cap,
        1
    );
}

#[test]
fn range_lookup_matches_the_previous_full_map_scan() {
    let mut concentration = RequestConcentration::new(true);
    for source in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
        for path in ["/alpha", "/beta", "/beta", "/gamma", "/gamma", "/gamma"] {
            concentration.observe(&event(Some(path), Some(source), Some(0)));
        }
    }
    for source in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
        let previous_full_scan = concentration
            .source_path_pairs
            .iter()
            .flat_map(|(candidate, paths)| {
                paths
                    .iter()
                    .map(move |(path, count)| ((candidate, path), count))
            })
            .filter(|((candidate, _), _)| candidate.as_str() == source)
            .max_by(|((_, left_path), left), ((_, right_path), right)| {
                left.cmp(right).then_with(|| right_path.cmp(left_path))
            })
            .map(|((_, path), _)| path.clone());
        assert_eq!(
            concentration.most_requested_path(source),
            previous_full_scan
        );
    }
}

#[test]
fn focuses_on_one_exact_path_and_sorts_private_sources_deterministically() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on_path("/target");
    for (path, ip, minute) in [
        ("/target", "198.51.100.2", 0),
        ("/target", "198.51.100.1", 0),
        ("/target", "198.51.100.1", 1),
        ("/other", "198.51.100.9", 1),
    ] {
        concentration.observe(&event(Some(path), Some(ip), Some(minute)));
    }
    let focus = concentration.private_report().focus.unwrap();
    assert_eq!(focus.uri_path, "/target");
    assert_eq!(focus.total_requests, 3);
    assert_eq!(focus.distinct_source_ips, 2);
    assert_eq!(focus.peak_requests_per_minute, Some(2));
    assert_eq!(focus.median_requests_per_minute, Some(1.5));
    assert_eq!(
        focus
            .sources
            .iter()
            .map(|source| (source.source_ip.as_str(), source.requests))
            .collect::<Vec<_>>(),
        vec![("198.51.100.1", 2), ("198.51.100.2", 1)]
    );
    let serialized = serde_json::to_string(&concentration.summary()).unwrap();
    assert!(!serialized.contains("/target"));
    assert!(!serialized.contains("198.51.100.1"));
}

#[test]
fn discloses_focus_source_ip_cap_without_adding_new_sources() {
    let mut concentration = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_paths: 10,
            max_source_ips: 10,
            max_focus_source_ips: 1,
            max_focus_paths: 1,
            max_source_path_pairs: 10,
            max_minute_buckets: 10,
            max_query_strings_per_path: 10,
            max_query_keys_per_path: 10,
            max_status_codes_per_entity: DEFAULT_MAX_STATUS_CODES_PER_ENTITY,
            max_source_segments: DEFAULT_MAX_SOURCE_SEGMENTS,
            ..ConcentrationLimits::default()
        },
    );
    concentration.focus_on_path("/target");
    concentration.observe(&event(Some("/target"), Some("198.51.100.1"), Some(0)));
    concentration.observe(&event(Some("/target"), Some("198.51.100.2"), Some(0)));
    let focus = concentration.summary().focus.unwrap();
    assert_eq!(focus.distinct_source_ips, 1);
    assert_eq!(focus.source_ips_beyond_cap, 1);
}

#[test]
fn groups_retained_focus_sources_by_prefix_without_changing_individual_sources() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on_path("/target");
    for host in 1..=10 {
        let source = format!("198.51.100.{host}");
        for _ in 0..100 {
            concentration.observe(&event(Some("/target"), Some(&source), Some(0)));
        }
    }
    for _ in 0..50 {
        concentration.observe(&event(Some("/target"), Some("203.0.113.1"), Some(0)));
    }
    let mut focus = concentration.private_report().focus.unwrap();
    let individual_sources = focus.sources.clone();
    add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
    assert_eq!(focus.network_prefix_groups.len(), 2);
    let top = &focus.network_prefix_groups[0];
    assert_eq!(top.network_prefix, "198.51.100.0/24");
    assert_eq!(top.requests, 1_000);
    assert_eq!(top.distinct_source_ips, 10);
    assert_eq!(top.request_share, 1_000.0 / 1_050.0);
    assert_eq!(focus.sources, individual_sources);
    let sanitized = serde_json::to_string(&concentration.summary()).unwrap();
    assert!(!sanitized.contains("198.51.100.0/24"));
    assert!(!sanitized.contains("198.51.100.1"));
    assert!(!sanitized.contains("/target"));
}

#[test]
fn changing_the_ipv4_prefix_changes_focus_groups() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on_path("/target");
    for source in ["198.51.100.1", "198.51.101.1"] {
        concentration.observe(&event(Some("/target"), Some(source), Some(0)));
    }
    let focus = concentration.private_report().focus.unwrap();
    let mut by_24 = focus.clone();
    add_focus_prefix_groups(&mut by_24, FocusPrefixLengths { ipv4: 24, ipv6: 48 });
    let mut by_16 = focus;
    add_focus_prefix_groups(&mut by_16, FocusPrefixLengths { ipv4: 16, ipv6: 48 });
    assert_eq!(by_24.network_prefix_groups.len(), 2);
    assert_eq!(by_16.network_prefix_groups.len(), 1);
    assert_eq!(
        by_16.network_prefix_groups[0].network_prefix,
        "198.51.0.0/16"
    );
}

#[test]
fn uses_the_default_ipv6_prefix_for_focus_groups() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on_path("/target");
    for source in ["2001:db8:1:1::1", "2001:db8:1:ffff::2"] {
        concentration.observe(&event(Some("/target"), Some(source), Some(0)));
    }
    let mut focus = concentration.private_report().focus.unwrap();
    add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
    assert_eq!(focus.network_prefix_groups.len(), 1);
    assert_eq!(
        focus.network_prefix_groups[0].network_prefix,
        "2001:db8:1::/48"
    );
    assert_eq!(focus.network_prefix_groups[0].distinct_source_ips, 2);
}

#[test]
fn path_is_under_matches_on_segment_boundaries() {
    assert!(path_is_under("/api", "/api"));
    assert!(path_is_under("/api/users", "/api"));
    assert!(path_is_under("/api/users", "/api/"));
    assert!(path_is_under("/anything", "/"));
    assert!(!path_is_under("/apixyz", "/api"));
    assert!(!path_is_under("/ap", "/api"));
}

#[test]
fn path_prefix_focus_lists_subpaths_and_peers() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on(FocusSelector::PathPrefix("/wp-admin".to_owned()));
    for (path, ip) in [
        ("/wp-admin", "198.51.100.1"),
        ("/wp-admin/index.php", "198.51.100.1"),
        ("/wp-admin/index.php", "198.51.100.2"),
        ("/wp-adminx", "198.51.100.9"), // outside the subtree
        ("/other", "198.51.100.9"),
    ] {
        concentration.observe(&event(Some(path), Some(ip), Some(0)));
    }
    let focus = concentration.private_report().focus.unwrap();
    assert_eq!(focus.focus_kind, "path-prefix");
    assert_eq!(focus.total_requests, 3);
    assert_eq!(focus.distinct_source_ips, 2);
    // Sub-paths under the prefix are listed, most-requested first.
    assert_eq!(focus.paths.len(), 2);
    assert_eq!(focus.paths[0].uri_path, "/wp-admin/index.php");
    assert_eq!(focus.paths[0].requests, 2);
}

#[test]
fn source_ip_focus_lists_requested_paths() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on(FocusSelector::SourceIp(
        ["198.51.100.7".to_owned()].into_iter().collect(),
    ));
    for (path, ip) in [
        ("/a", "198.51.100.7"),
        ("/a", "198.51.100.7"),
        ("/b", "198.51.100.7"),
        ("/a", "198.51.100.8"), // different peer, ignored
    ] {
        concentration.observe(&event(Some(path), Some(ip), Some(0)));
    }
    let focus = concentration.private_report().focus.unwrap();
    assert_eq!(focus.focus_kind, "source-ip");
    assert_eq!(focus.selector, "198.51.100.7");
    assert_eq!(focus.total_requests, 3);
    assert_eq!(focus.paths.len(), 2);
    assert_eq!(focus.paths[0].uri_path, "/a");
    assert_eq!(focus.paths[0].requests, 2);
}

#[test]
fn multiple_source_ip_focus_unions_paths_and_retains_per_ip_counts() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on(FocusSelector::SourceIp(
        [
            "198.51.100.2".to_owned(),
            "198.51.100.1".to_owned(),
            "198.51.100.2".to_owned(),
        ]
        .into_iter()
        .collect(),
    ));
    for (path, ip) in [
        ("/shared", "198.51.100.1"),
        ("/one", "198.51.100.1"),
        ("/shared", "198.51.100.2"),
        ("/two", "198.51.100.2"),
        ("/two", "198.51.100.2"),
        ("/ignored", "198.51.100.3"),
    ] {
        concentration.observe(&event(Some(path), Some(ip), Some(0)));
    }

    let focus = concentration.private_report().focus.unwrap();
    assert_eq!(focus.selector, "198.51.100.1, 198.51.100.2");
    assert_eq!(focus.total_requests, 5);
    assert_eq!(
        focus
            .sources
            .iter()
            .map(|source| (source.source_ip.as_str(), source.requests))
            .collect::<Vec<_>>(),
        vec![("198.51.100.2", 3), ("198.51.100.1", 2)]
    );
    assert_eq!(
        focus
            .paths
            .iter()
            .map(|path| (path.uri_path.as_str(), path.requests))
            .collect::<Vec<_>>(),
        vec![("/shared", 2), ("/two", 2), ("/one", 1)]
    );

    let sanitized = serde_json::to_string(&concentration.summary()).unwrap();
    assert!(!sanitized.contains("198.51.100.1"));
    assert!(!sanitized.contains("198.51.100.2"));
    assert!(!sanitized.contains("/shared"));
    assert!(sanitized.contains("source-ip"));
}

#[test]
fn sanitized_focus_summary_contains_no_raw_path_or_ip() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on(FocusSelector::PathPrefix("/secret-area".to_owned()));
    concentration.observe(&event(Some("/secret-area/x"), Some("203.0.113.5"), Some(0)));
    let sanitized = concentration.summary();
    let json = serde_json::to_string(&sanitized).unwrap();
    assert!(!json.contains("/secret-area"));
    assert!(!json.contains("203.0.113.5"));
    assert!(json.contains("path-prefix"));
}

#[test]
fn simultaneous_rate_windows_distinguish_short_spikes_from_long_elevation() {
    let limits = ConcentrationLimits::default();
    let mut short = RequestConcentration::with_limits_and_rate_windows(true, limits, &[60, 3_600]);
    short.focus_on_path("/focus");
    for minute in 0..60 {
        short.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(minute)));
    }
    for _ in 0..99 {
        short.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(30)));
    }
    let short_summary = short.summary();
    assert_eq!(
        short_summary.request_rates[0].peak_to_median_ratio,
        Some(100.0)
    );
    assert_eq!(
        short_summary.request_rates[1].peak_to_median_ratio,
        Some(1.0)
    );
    assert_eq!(
        short_summary.focus.as_ref().unwrap().request_rates,
        short_summary.request_rates
    );

    let mut sustained =
        RequestConcentration::with_limits_and_rate_windows(true, limits, &[60, 3_600]);
    sustained.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(0)));
    for minute in 60..120 {
        sustained.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(minute)));
    }
    sustained.observe(&event(Some("/focus"), Some("198.51.100.1"), Some(120)));
    let sustained_summary = sustained.summary();
    assert_eq!(
        sustained_summary.request_rates[0].peak_to_median_ratio,
        Some(1.0)
    );
    assert_eq!(
        sustained_summary.request_rates[1].peak_to_median_ratio,
        Some(60.0)
    );
}

#[test]
fn simultaneous_rate_windows_are_deterministic_and_preserve_single_minute_semantics() {
    let build = || {
        let mut concentration = RequestConcentration::with_limits_and_rate_windows(
            true,
            ConcentrationLimits::default(),
            &[3_600, 60, 600, 60],
        );
        for minute in [0, 0, 1, 10, 11, 59, 60] {
            concentration.observe(&event(
                Some("/deterministic"),
                Some("203.0.113.7"),
                Some(minute),
            ));
        }
        serde_json::to_string(&concentration.summary()).unwrap()
    };
    assert_eq!(build(), build());

    let mut one_minute = RequestConcentration::with_limits_and_rate_windows(
        true,
        ConcentrationLimits::default(),
        &[60],
    );
    for minute in [0, 0, 1] {
        one_minute.observe(&event(Some("/one"), Some("192.0.2.1"), Some(minute)));
    }
    let summary = one_minute.summary();
    let rate = &summary.request_rates[0];
    assert_eq!(
        rate.peak_requests,
        summary.requests_per_minute.peak_requests_per_minute
    );
    assert_eq!(
        rate.median_requests,
        summary.requests_per_minute.median_requests_per_minute
    );
    assert_eq!(
        rate.peak_to_median_ratio,
        summary.requests_per_minute.peak_to_median_ratio
    );
}

#[test]
fn measures_reused_query_strings_and_keys_for_one_path_and_focus() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on_path("/asset");
    for index in 0..10_000 {
        concentration.observe(&event_with_query(
            "/asset",
            "198.51.100.1",
            Some(format!("v={:03}", index % 1_000)),
        ));
    }

    let summary = concentration.summary();
    let top = summary.top_path.unwrap();
    assert_eq!(top.requests, 10_000);
    assert_eq!(top.request_share, 1.0);
    assert_eq!(top.distinct_source_ips, 1);
    assert_eq!(top.response_status_classes.client_error, 10_000);
    assert_eq!(top.response_bytes, Some(100_000));
    assert_eq!(top.requests_with_query, 10_000);
    assert_eq!(top.distinct_query_strings, 1_000);
    assert_eq!(top.distinct_query_keys, 1);
    assert_eq!(top.query_strings_beyond_tracking_cap, 0);
    let focus = summary.focus.unwrap();
    assert_eq!(focus.requests_with_query, 10_000);
    assert_eq!(focus.distinct_query_strings, 1_000);
    assert_eq!(focus.distinct_query_keys, 1);
    assert_eq!(
        concentration.private_report_with_query_keys(true).paths[0].query_keys,
        vec!["v"]
    );
}

#[test]
fn measures_unique_or_absent_queries_without_dividing_by_zero() {
    let mut unique = RequestConcentration::new(true);
    for index in 0..100 {
        unique.observe(&event_with_query(
            "/unique",
            "198.51.100.2",
            Some(format!("nonce={index}")),
        ));
    }
    let unique = unique.summary().top_path.unwrap();
    assert_eq!(unique.distinct_query_strings as u64, unique.requests);

    let mut absent = RequestConcentration::new(true);
    absent.observe(&event_with_query("/plain", "198.51.100.3", None));
    let absent = absent.summary().top_path.unwrap();
    assert_eq!(absent.requests_with_query, 0);
    assert_eq!(absent.distinct_query_strings, 0);
    assert_eq!(absent.distinct_query_keys, 0);
    assert_eq!(
        absent.requests_with_query as f64 / absent.requests as f64,
        0.0
    );

    let empty = RequestConcentration::new(true).summary();
    assert_eq!(empty.total_requests, 0);
    assert!(empty.top_path.is_none());
}

#[test]
fn query_tracking_caps_are_disclosed_without_serializing_query_values() {
    let mut concentration = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_query_strings_per_path: 2,
            max_query_keys_per_path: 1,
            ..ConcentrationLimits::default()
        },
    );
    concentration.focus_on_path("/private-query");
    for query in [
        "first=secret-one",
        "second=secret-two",
        "third=secret-three",
    ] {
        concentration.observe(&event_with_query(
            "/private-query",
            "203.0.113.8",
            Some(query.to_owned()),
        ));
    }
    let summary = concentration.summary();
    let top = summary.top_path.as_ref().unwrap();
    assert_eq!(top.distinct_query_strings, 2);
    assert_eq!(top.query_strings_beyond_tracking_cap, 1);
    assert_eq!(top.distinct_query_keys, 1);
    assert_eq!(top.query_keys_beyond_tracking_cap, 2);

    let sanitized = serde_json::to_string(&summary).unwrap();
    let private = serde_json::to_string(&concentration.private_report()).unwrap();
    let opted_in =
        serde_json::to_string(&concentration.private_report_with_query_keys(true)).unwrap();
    for value in [
        "secret-one",
        "secret-two",
        "secret-three",
        "first=",
        "second=",
    ] {
        assert!(!sanitized.contains(value));
        assert!(!private.contains(value));
        assert!(!opted_in.contains(value));
    }
    assert!(!sanitized.contains("first"));
    assert!(!private.contains("first"));
    assert!(opted_in.contains("first"));
}

#[test]
fn records_status_classes_for_each_private_observed_peer() {
    let mut concentration = RequestConcentration::new(true);
    concentration.focus_on_path("/status");
    for status in [Some(101), Some(204), Some(302), Some(404), Some(503), None] {
        let mut request = event(Some("/status"), Some("198.51.100.9"), Some(0));
        request.status = status;
        concentration.observe(&request);
    }
    let private = concentration.private_report();
    let source = &private.source_ips[0];
    assert_eq!(source.requests, 6);
    assert_eq!(source.response_status_classes.informational, 1);
    assert_eq!(source.response_status_classes.success, 1);
    assert_eq!(source.response_status_classes.redirection, 1);
    assert_eq!(source.response_status_classes.client_error, 1);
    assert_eq!(source.response_status_classes.server_error, 1);
    assert_eq!(source.response_status_classes.unavailable, 1);
    assert_eq!(
        private.focus.unwrap().sources[0].response_status_classes,
        source.response_status_classes
    );
}

#[test]
fn summarizes_corpus_response_outcomes_and_separates_499_from_other_4xx() {
    let mut concentration = RequestConcentration::new(true);
    for status in [200, 302, 404, 499, 502] {
        let mut request = event(Some("/status"), Some("198.51.100.9"), Some(0));
        request.status = Some(status);
        concentration.observe(&request);
    }
    let summary = concentration.summary();
    assert_eq!(summary.total_requests, 5);
    let top_path = summary.top_path.as_ref().unwrap();
    assert_eq!(top_path.requests, 5);
    assert_eq!(top_path.request_share, 1.0);
    assert_eq!(top_path.distinct_source_ips, 1);
    assert_eq!(top_path.requests_per_source_ip, 5.0);
    let outcome = summary.response_outcomes.unwrap();
    assert_eq!(outcome.counts.success, 1);
    assert_eq!(outcome.counts.redirection, 1);
    assert_eq!(outcome.counts.client_error, 2);
    assert_eq!(outcome.counts.ordinary_client_error(), 1);
    assert_eq!(outcome.counts.client_closed_request_499, 1);
    assert_eq!(outcome.counts.server_error, 1);
    assert_eq!(outcome.success_share, 0.2);
    assert_eq!(outcome.ordinary_client_error_share, 0.2);
    assert_eq!(outcome.client_closed_request_499_share, 0.2);
    assert_eq!(outcome.server_error_share, 0.2);
}

#[test]
fn response_windows_expose_short_zero_success_periods_without_labeling_them() {
    let mut concentration = RequestConcentration::with_limits_and_rate_windows(
        true,
        ConcentrationLimits::default(),
        &[60, 86_400],
    );
    for minute in 0..1_440 {
        for source in 0..10 {
            let mut request = event(
                Some("/status"),
                Some(&format!("198.51.100.{source}")),
                Some(minute),
            );
            request.status = Some(if (1_085..1_097).contains(&minute) {
                504
            } else {
                200
            });
            concentration.observe(&request);
        }
    }
    let windows = concentration.summary().response_outcome_windows.unwrap();
    let minute = windows
        .iter()
        .find(|item| item.bucket_width_seconds == 60)
        .unwrap();
    let day = windows
        .iter()
        .find(|item| item.bucket_width_seconds == 86_400)
        .unwrap();
    assert_eq!(minute.minimum_success_share, Some(0.0));
    assert_eq!(minute.maximum_server_error_share, Some(1.0));
    assert!(day.minimum_success_share.unwrap() > 0.99);
    assert!(day.maximum_server_error_share.unwrap() < 0.01);
}

#[test]
fn response_window_floor_excludes_sparse_buckets_and_status_can_be_unavailable() {
    let mut concentration = RequestConcentration::with_limits_and_rate_windows(
        true,
        ConcentrationLimits::default(),
        &[60],
    );
    concentration.set_response_bucket_minimum_requests(10);
    let mut sparse = event(Some("/status"), Some("198.51.100.1"), Some(0));
    sparse.status = Some(503);
    concentration.observe(&sparse);
    for source in 0..10 {
        let mut dense = event(
            Some("/status"),
            Some(&format!("203.0.113.{source}")),
            Some(1),
        );
        dense.status = Some(200);
        concentration.observe(&dense);
    }
    let window = &concentration.summary().response_outcome_windows.unwrap()[0];
    assert_eq!(window.eligible_buckets, 1);
    assert_eq!(window.buckets_below_minimum, 1);
    assert_eq!(window.minimum_success_share, Some(1.0));
    assert_eq!(window.maximum_server_error_share, Some(0.0));

    let unavailable = RequestConcentration::with_capabilities(true, false).summary();
    assert!(unavailable.response_outcomes.is_none());
    assert!(unavailable.response_outcome_windows.is_none());
}

#[test]
fn old_concentration_json_without_response_fields_remains_readable() {
    let summary = RequestConcentration::new(true).summary();
    let mut value = serde_json::to_value(summary).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("response_outcomes");
    object.remove("response_outcome_windows");
    object.remove("response_status_codes");
    object.remove("source_segment_diversity");
    let decoded: RequestConcentrationSummary = serde_json::from_value(value).unwrap();
    assert!(decoded.response_outcomes.is_none());
    assert!(decoded.response_outcome_windows.is_none());
    assert!(decoded.response_status_codes.is_none());
    assert!(decoded.source_segment_diversity.is_none());
}

#[test]
fn statusless_buckets_are_excluded_before_the_minimum_request_check() {
    let mut accumulator = RequestConcentration::with_capabilities_and_rate_windows(
        true,
        true,
        ConcentrationLimits::default(),
        &[60],
    );
    accumulator.set_response_bucket_minimum_requests(2);
    for (minute, status) in [
        (0, None),
        (0, None),
        (1, Some(200)),
        (1, None),
        (2, Some(200)),
        (3, None),
    ] {
        let mut e = event(Some("/private"), Some("198.51.100.1"), Some(minute));
        e.status = status;
        accumulator.observe(&e);
    }
    let summary = accumulator.summary();
    let outcomes = summary.response_outcomes.unwrap();
    assert_eq!(outcomes.counts.unavailable, 4);
    assert_eq!(outcomes.counts.success, 2);
    assert_eq!(outcomes.counts.total_observations(), 6);
    assert_eq!(outcomes.success_share, 2.0 / 6.0);
    let window = &summary.response_outcome_windows.unwrap()[0];
    assert_eq!(window.eligible_buckets, 1);
    assert_eq!(window.buckets_without_status, 2);
    assert_eq!(window.buckets_below_minimum, 1);
    assert_eq!(window.minimum_success_share, Some(0.5));
    assert_eq!(window.maximum_server_error_share, Some(0.0));
    assert_eq!(window.buckets_below_success_threshold, Some(0));
    assert_eq!(
        window.minimum_success_bucket_start,
        DateTime::from_timestamp(60, 0)
    );
    assert_eq!(
        summary.requests_per_minute.peak_requests_per_minute,
        Some(2)
    );
}

#[test]
fn all_missing_status_produces_unavailable_window_measurements_and_reads_legacy_counts() {
    let mut accumulator = RequestConcentration::with_capabilities_and_rate_windows(
        true,
        true,
        ConcentrationLimits::default(),
        &[60],
    );
    for _ in 0..20 {
        let mut e = event(Some("/private"), Some("198.51.100.1"), Some(0));
        e.status = None;
        accumulator.observe(&e);
    }
    let summary = accumulator.summary();
    assert_eq!(
        summary
            .response_outcomes
            .as_ref()
            .unwrap()
            .counts
            .unavailable,
        20
    );
    let window = &summary.response_outcome_windows.unwrap()[0];
    assert_eq!(window.buckets_without_status, 1);
    assert_eq!(window.eligible_buckets, 0);
    assert_eq!(window.minimum_success_share, None);
    assert_eq!(window.maximum_server_error_share, None);
    assert_eq!(window.minimum_success_bucket_start, None);
    assert_eq!(window.maximum_server_error_bucket_start, None);
    assert_eq!(window.buckets_below_success_threshold, None);
    let mut legacy = serde_json::to_value(window).unwrap();
    assert!(legacy["buckets_below_success_threshold"].is_null());
    legacy
        .as_object_mut()
        .unwrap()
        .remove("buckets_without_status");
    legacy["buckets_below_success_threshold"] = serde_json::json!(0);
    let legacy: WindowedResponseOutcomeSummary = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy.buckets_below_success_threshold, Some(0));
    assert_eq!(legacy.buckets_without_status, 0);
}

#[test]
fn client_error_segments_include_forbidden_responses_but_not_499() {
    let mut accumulator = RequestConcentration::new(true);
    for (path, status) in [
        ("/secret-a/x", 403),
        ("/secret-b/y", 403),
        ("/secret-b/z", 403),
        ("/closed/x", 499),
    ] {
        let mut e = event(Some(path), Some("198.51.100.1"), None);
        e.status = Some(status);
        accumulator.observe(&e);
    }
    let private = accumulator.private_report();
    let source = private.source_ips[0]
        .path_segment_diversity
        .as_ref()
        .unwrap();
    assert_eq!(source.distinct_404_segments, Some(0));
    assert_eq!(source.distinct_4xx_segments, Some(2));
    let stats = private.summary.source_segment_diversity.as_ref().unwrap();
    assert_eq!(stats.corpus_4xx_requests, Some(3));
    assert_eq!(stats.maximum_404_segments, Some(0));
    assert_eq!(stats.maximum_4xx_segments, Some(2));
    assert_eq!(stats.median_4xx_segments, Some(2.0));
    assert_eq!(stats.sources_with_4xx_segments, Some(1));
    assert_eq!(
        stats.median_4xx_segments_among_sources_with_4xx_segments,
        Some(2.0)
    );
    let safe = serde_json::to_string(&private.summary).unwrap();
    for raw in ["198.51.100.1", "secret-a", "secret-b", "/closed"] {
        assert!(!safe.contains(raw));
    }
    let mut legacy = serde_json::to_value(stats).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .retain(|key, _| !key.contains("4xx"));
    let legacy: SourceSegmentDiversitySummary = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy.maximum_404_segments, Some(0));
    assert_eq!(legacy.maximum_4xx_segments, None);
    assert_eq!(legacy.corpus_4xx_requests, None);
    let mut legacy_source = serde_json::to_value(source).unwrap();
    legacy_source
        .as_object_mut()
        .unwrap()
        .retain(|key, _| !key.contains("4xx"));
    let legacy_source: SourceSegmentDiversity = serde_json::from_value(legacy_source).unwrap();
    assert_eq!(legacy_source.distinct_404_segments, Some(0));
    assert_eq!(legacy_source.distinct_4xx_segments, None);
}

#[test]
fn mixed_client_error_segment_medians_preserve_404_counts() {
    let mut accumulator = RequestConcentration::new(true);
    for (ip, segments) in [
        ("198.51.100.1", 2),
        ("198.51.100.2", 5),
        ("198.51.100.3", 0),
        ("198.51.100.4", 0),
        ("198.51.100.5", 0),
    ] {
        for segment in 0..segments.max(1) {
            let mut e = event(Some(&format!("/private-{segment}/x")), Some(ip), None);
            e.status = Some(if segments == 0 {
                200
            } else if segment == 0 {
                404
            } else {
                403
            });
            accumulator.observe(&e);
        }
    }
    let stats = accumulator.summary().source_segment_diversity.unwrap();
    assert_eq!(stats.corpus_4xx_requests, Some(7));
    assert_eq!(stats.maximum_4xx_segments, Some(5));
    assert_eq!(stats.median_4xx_segments, Some(0.0));
    assert_eq!(stats.sources_with_4xx_segments, Some(2));
    assert_eq!(
        stats.median_4xx_segments_among_sources_with_4xx_segments,
        Some(3.5)
    );
    assert_eq!(stats.maximum_404_segments, Some(1));
    assert_eq!(stats.median_404_segments, Some(0.0));
    assert_eq!(
        stats.median_404_segments_among_sources_with_404_segments,
        Some(1.0)
    );
}

#[test]
fn segment_sets_disclose_independent_caps_and_missing_paths() {
    let mut accumulator = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_source_segments: 1,
            ..ConcentrationLimits::default()
        },
    );
    for (path, status) in [
        (Some("/a"), 200),
        (Some("/b"), 403),
        (Some("/b"), 403),
        (Some("/c"), 404),
        (Some("/d"), 404),
        (Some("/e"), 499),
        (None, 403),
    ] {
        let mut e = event(path, Some("198.51.100.1"), None);
        e.status = Some(status);
        accumulator.observe(&e);
    }
    let private = accumulator.private_report();
    let source = private.source_ips[0]
        .path_segment_diversity
        .as_ref()
        .unwrap();
    assert_eq!(source.observations_beyond_cap, 5);
    assert_eq!(source.observations_404_beyond_cap, Some(1));
    assert_eq!(source.observations_4xx_beyond_cap, Some(2));
    assert_eq!(source.distinct_404_segments, Some(1));
    assert_eq!(source.distinct_4xx_segments, Some(1));
    let stats = private.summary.source_segment_diversity.as_ref().unwrap();
    assert_eq!(stats.sources_4xx_beyond_cap, Some(1));
    assert_eq!(stats.observations_4xx_beyond_cap, Some(2));
    assert_eq!(stats.observations_without_path, 1);
    assert_eq!(stats.corpus_4xx_requests, Some(5));
}

#[test]
fn client_error_denominator_is_global_and_empty_subset_is_unavailable() {
    let mut accumulator = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_source_ips: 0,
            ..ConcentrationLimits::default()
        },
    );
    for ip in [Some("198.51.100.1"), None] {
        let mut e = event(None, ip, None);
        e.status = Some(403);
        accumulator.observe(&e);
    }
    let stats = accumulator.summary().source_segment_diversity.unwrap();
    assert_eq!(stats.corpus_4xx_requests, Some(2));
    assert_eq!(stats.retained_sources, 0);
    assert_eq!(stats.sources_with_4xx_segments, Some(0));
    assert_eq!(stats.maximum_4xx_segments, None);
    assert_eq!(stats.median_4xx_segments, None);
    assert_eq!(
        stats.median_4xx_segments_among_sources_with_4xx_segments,
        None
    );
}

#[test]
fn zero_client_errors_and_missing_status_are_unavailable_not_zero_extrema() {
    for status_available in [true, false] {
        let mut accumulator = RequestConcentration::with_capabilities(true, status_available);
        for status in [Some(200), Some(499), None] {
            let mut e = event(Some("/private"), Some("198.51.100.1"), None);
            e.status = status;
            accumulator.observe(&e);
        }
        let private = accumulator.private_report();
        let stats = private.summary.source_segment_diversity.as_ref().unwrap();
        assert_eq!(stats.corpus_4xx_requests, status_available.then_some(0));
        assert_eq!(stats.maximum_4xx_segments, None);
        assert_eq!(stats.median_4xx_segments, None);
        assert_eq!(
            stats.median_4xx_segments_among_sources_with_4xx_segments,
            None
        );
        assert_eq!(
            stats.sources_with_4xx_segments,
            status_available.then_some(0)
        );
        assert_eq!(stats.median_404_segments, status_available.then_some(0.0));
        let source = private.source_ips[0]
            .path_segment_diversity
            .as_ref()
            .unwrap();
        assert_eq!(source.distinct_404_segments, status_available.then_some(0));
        assert_eq!(source.distinct_4xx_segments, status_available.then_some(0));
        assert_eq!(
            source.observations_4xx_beyond_cap,
            status_available.then_some(0)
        );
    }
}

#[test]
fn segment_medians_disclose_their_distinct_denominators() {
    let mut accumulator = RequestConcentration::new(true);
    for (ip, segments, status) in [
        ("198.51.100.1", 2, 404),
        ("198.51.100.2", 5, 404),
        ("198.51.100.3", 1, 200),
        ("198.51.100.4", 1, 200),
        ("198.51.100.5", 1, 200),
    ] {
        for segment in 0..segments {
            let mut e = event(
                Some(&format!("/private-segment-{segment}/x")),
                Some(ip),
                None,
            );
            e.status = Some(status);
            accumulator.observe(&e);
        }
    }
    let summary = accumulator.summary();
    let stats = summary.source_segment_diversity.as_ref().unwrap();
    assert_eq!(stats.median_404_segments, Some(0.0));
    assert_eq!(stats.sources_with_404_segments, Some(2));
    assert_eq!(
        stats.median_404_segments_among_sources_with_404_segments,
        Some(3.5)
    );
    assert_eq!(stats.maximum_404_segments, Some(5));
    assert_eq!(stats.retained_sources, 5);
    let serialized = serde_json::to_string(&summary).unwrap();
    assert!(!serialized.contains("198.51.100"));
    assert!(!serialized.contains("private-segment"));
    let mut legacy = serde_json::to_value(stats).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("sources_with_404_segments");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("median_404_segments_among_sources_with_404_segments");
    let legacy: SourceSegmentDiversitySummary = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy.median_404_segments, Some(0.0));
    assert_eq!(legacy.sources_with_404_segments, None);
}

#[test]
fn empty_404_subset_and_missing_status_remain_distinct() {
    for status_available in [true, false] {
        let mut accumulator = RequestConcentration::with_capabilities(true, status_available);
        let mut e = event(Some("/private"), Some("198.51.100.1"), None);
        e.status = Some(200);
        accumulator.observe(&e);
        let stats = accumulator.summary().source_segment_diversity.unwrap();
        assert_eq!(stats.median_404_segments, status_available.then_some(0.0));
        assert_eq!(
            stats.sources_with_404_segments,
            status_available.then_some(0)
        );
        assert_eq!(
            stats.median_404_segments_among_sources_with_404_segments,
            None
        );
    }
}

#[test]
fn first_segments_measure_breadth_without_normalizing_or_exposing_values() {
    let mut accumulator = RequestConcentration::new(true);
    for path in ["/images/a", "/images/b", "/images/c"] {
        let mut e = event(Some(path), Some("198.51.100.1"), Some(0));
        e.status = Some(404);
        accumulator.observe(&e);
    }
    for path in ["/", "/Images/a", "/images/a", "/%69mages/a"] {
        let mut e = event(Some(path), Some("198.51.100.2"), Some(0));
        e.status = Some(404);
        accumulator.observe(&e);
    }
    let private = accumulator.private_report();
    assert_eq!(
        private.source_ips[0]
            .path_segment_diversity
            .as_ref()
            .unwrap()
            .distinct_404_segments,
        Some(4)
    );
    assert_eq!(
        private.source_ips[1]
            .path_segment_diversity
            .as_ref()
            .unwrap()
            .distinct_404_segments,
        Some(1)
    );
    let stats = private.summary.source_segment_diversity.as_ref().unwrap();
    assert_eq!(stats.maximum_404_segments, Some(4));
    assert_eq!(stats.median_404_segments, Some(2.5));
    assert_eq!(private.summary.total_requests, 7);
    assert_eq!(
        private
            .summary
            .response_outcomes
            .as_ref()
            .unwrap()
            .counts
            .client_error,
        7
    );
    assert_eq!(
        private.summary.requests_per_minute.peak_requests_per_minute,
        Some(7)
    );
    let safe = serde_json::to_string(&private.summary).unwrap();
    for raw in ["198.51.100", "images", "Images", "%69mages"] {
        assert!(!safe.contains(raw));
    }
}

#[test]
fn first_segment_caps_and_missing_capabilities_remain_explicit() {
    let mut accumulator = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_source_segments: 1,
            ..ConcentrationLimits::default()
        },
    );
    for path in [Some("/"), Some("/a"), Some("/a"), None] {
        let mut e = event(path, Some("198.51.100.1"), None);
        e.status = Some(404);
        accumulator.observe(&e);
    }
    let summary = accumulator.summary().source_segment_diversity.unwrap();
    assert_eq!(summary.maximum_404_segments, Some(1));
    assert_eq!(summary.sources_beyond_cap, 1);
    assert_eq!(summary.sources_404_beyond_cap, Some(1));
    assert_eq!(summary.observations_404_beyond_cap, Some(2));
    assert_eq!(summary.observations_without_path, 1);
    let mut unavailable = RequestConcentration::with_capabilities(true, false);
    unavailable.observe(&event(Some("/"), Some("198.51.100.1"), None));
    let private = unavailable.private_report();
    assert_eq!(
        private.source_ips[0]
            .path_segment_diversity
            .as_ref()
            .unwrap()
            .distinct_segments,
        1
    );
    assert!(private.source_ips[0]
        .path_segment_diversity
        .as_ref()
        .unwrap()
        .distinct_404_segments
        .is_none());
    assert!(private
        .summary
        .source_segment_diversity
        .unwrap()
        .maximum_404_segments
        .is_none());
}

#[test]
fn response_window_times_use_earliest_ties_and_disclose_threshold_counts() {
    let mut concentration = RequestConcentration::with_limits_and_rate_windows(
        true,
        ConcentrationLimits::default(),
        &[60],
    );
    concentration.set_response_bucket_minimum_requests(2);
    concentration
        .set_response_success_share_threshold_percent(50)
        .unwrap();
    // Deliberately unordered input: equal extrema must select the earliest UTC bucket.
    for (minute, statuses) in [
        (Some(3), [504, 504]),
        (Some(1), [502, 502]),
        (Some(2), [200, 499]),
        (Some(0), [200, 200]),
        (None, [504, 504]),
    ] {
        for status in statuses {
            let mut observation = event(Some("/private"), Some("198.51.100.1"), minute);
            observation.status = Some(status);
            concentration.observe(&observation);
        }
    }
    let window = &concentration.summary().response_outcome_windows.unwrap()[0];
    assert_eq!(
        window.minimum_success_bucket_start,
        Some(Utc.timestamp_opt(60, 0).unwrap())
    );
    assert_eq!(
        window.maximum_server_error_bucket_start,
        window.minimum_success_bucket_start
    );
    assert_eq!(window.minimum_success_share, Some(0.0));
    assert_eq!(window.maximum_server_error_share, Some(1.0));
    assert_eq!(window.buckets_below_success_threshold, Some(2)); // 50% itself is not below 50%.
    assert_eq!(window.observations_without_timestamp, 2);
    concentration
        .set_response_success_share_threshold_percent(51)
        .unwrap();
    assert_eq!(
        concentration.summary().response_outcome_windows.unwrap()[0]
            .buckets_below_success_threshold,
        Some(3)
    );
    assert!(concentration
        .set_response_success_share_threshold_percent(101)
        .is_err());
}

#[test]
fn individual_codes_sources_and_focus_prefixes_preserve_class_totals() {
    for selector in [
        FocusSelector::ExactPath("/private-status".to_owned()),
        FocusSelector::PathPrefix("/private-status".to_owned()),
        FocusSelector::SourceIp(BTreeSet::from([
            "198.51.100.1".to_owned(),
            "198.51.100.2".to_owned(),
        ])),
    ] {
        let mut concentration = RequestConcentration::new(true);
        concentration.focus_on(selector);
        for (ip, statuses) in [
            ("198.51.100.1", vec![499, 499]),
            ("198.51.100.2", vec![502, 504, 429, 401, 403, 200]),
        ] {
            for status in statuses {
                let mut observation = event(Some("/private-status"), Some(ip), Some(0));
                observation.status = Some(status);
                concentration.observe(&observation);
            }
        }
        let summary = concentration.summary();
        let codes = &summary.response_status_codes.as_ref().unwrap().counts;
        for code in [502, 504, 429, 401, 403, 200] {
            assert_eq!(codes[&code], 1);
        }
        assert_eq!(codes[&499], 2);
        let classes = &summary.response_outcomes.as_ref().unwrap().counts;
        assert_eq!(classes.server_error, codes[&502] + codes[&504]);
        assert_eq!(classes.client_error, 5); // 499 remains part of the existing 4xx count.
        assert_eq!(classes.ordinary_client_error(), 3);
        let private = concentration.private_report();
        let json = serde_json::to_string(&private).unwrap();
        let decoded: PrivateRequestConcentrationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
        assert_eq!(private.paths[0].summary.requests, 8);
        assert_eq!(private.paths[0].summary.request_share, 1.0);
        assert_eq!(private.paths[0].summary.distinct_source_ips, 2);
        assert_eq!(private.paths[0].summary.response_bytes, Some(80));
        assert_eq!(
            private.paths[0]
                .summary
                .response_status_codes
                .as_ref()
                .unwrap()
                .counts,
            *codes
        );
        let source = private
            .source_ips
            .iter()
            .find(|source| source.source_ip == "198.51.100.1")
            .unwrap();
        assert_eq!(
            source
                .response_outcomes
                .as_ref()
                .unwrap()
                .client_closed_request_499_share,
            1.0
        );
        assert_eq!(
            source
                .response_outcomes
                .as_ref()
                .unwrap()
                .server_error_share,
            0.0
        );
        let mut focus = private.focus.unwrap();
        assert_eq!(focus.response_status_codes.as_ref().unwrap().counts, *codes);
        assert!(focus.sources.iter().any(|source| source
            .response_status_codes
            .as_ref()
            .unwrap()
            .counts
            .contains_key(&504)));
        add_focus_prefix_groups(&mut focus, FocusPrefixLengths::default());
        let group = &focus.network_prefix_groups[0];
        assert_eq!(group.response_status_codes.as_ref().unwrap().counts, *codes);
        assert_eq!(
            group
                .response_outcomes
                .as_ref()
                .unwrap()
                .client_closed_request_499_share,
            0.25
        );
        assert_eq!(
            group.response_outcomes.as_ref().unwrap().success_share,
            0.125
        );
        let sanitized = serde_json::to_string(&summary).unwrap();
        for private_value in ["/private-status", "198.51.100", "\"source_ip\":"] {
            assert!(!sanitized.contains(private_value));
        }
    }
}

#[test]
fn status_code_caps_bound_each_entity_without_dropping_class_counts() {
    let mut concentration = RequestConcentration::with_limits(
        true,
        ConcentrationLimits {
            max_status_codes_per_entity: 1,
            ..ConcentrationLimits::default()
        },
    );
    concentration.focus_on(FocusSelector::PathPrefix("/private".to_owned()));
    for status in [Some(502), Some(504), Some(504), Some(502), None] {
        let mut observation = event(Some("/private/status"), Some("198.51.100.1"), Some(0));
        observation.status = status;
        concentration.observe(&observation);
    }
    let mut private = concentration.private_report();
    add_focus_prefix_groups(
        private.focus.as_mut().unwrap(),
        FocusPrefixLengths::default(),
    );
    let focus = private.focus.as_ref().unwrap();
    for codes in [
        &private.summary.response_status_codes,
        &private.paths[0].summary.response_status_codes,
        &private.source_ips[0].response_status_codes,
        &focus.response_status_codes,
        &focus.sources[0].response_status_codes,
        &focus.paths[0].response_status_codes,
        &focus.network_prefix_groups[0].response_status_codes,
    ] {
        let codes = codes.as_ref().unwrap();
        assert_eq!(codes.maximum_codes, 1);
        assert_eq!(codes.counts, BTreeMap::from([(502, 2)]));
        assert_eq!(codes.observations_beyond_cap, 2);
    }
    let classes = &private.summary.response_outcomes.as_ref().unwrap().counts;
    assert_eq!(classes.server_error, 4);
    assert_eq!(classes.unavailable, 1);
    assert_eq!(private.summary.total_requests, 5);
    // Additive fields are absent in older private artifacts.
    let mut old_source = serde_json::to_value(&private.source_ips[0]).unwrap();
    old_source
        .as_object_mut()
        .unwrap()
        .remove("response_status_codes");
    old_source
        .as_object_mut()
        .unwrap()
        .remove("response_outcomes");
    let source: PrivateSourceConcentration = serde_json::from_value(old_source).unwrap();
    assert!(source.response_status_codes.is_none());
    assert!(source.response_outcomes.is_none());
}
