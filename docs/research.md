# Phase 0 research

Research was performed on 2026-08-24 against primary documentation; this repository does not bundle SigmaHQ rules or Nuclei templates.

## AWS WAF

AWS documents the request record under `httpRequest`, including `clientIp`, `country`, `headers`, `httpMethod`, `uri`, `httpVersion`, and `requestId`. The top-level record includes the millisecond `timestamp`, action and terminating-rule information, non-terminating matches, labels, rule-group and rate-based information. See [AWS WAF log fields](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html).

The MVP preserves its raw record and normalizes the request fields needed for hunting. It additionally parses the currently relevant top-level `ja3Fingerprint` and `ja4Fingerprint`. AWS says these fingerprints are available for CloudFront and ALB requests when sufficient TLS ClientHello data exists; JA3 is 32 characters and JA4 is 36. They are absent for other protected resource types, so both are optional. See [AWS WAF request components](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields-list.html).

AWS examples and delivery configuration commonly produce newline-delimited JSON records. The initial parser deliberately supports that streaming form, including `.gz`; it does not buffer a complete file or collection. A future parser can add top-level JSON-array/Firehose envelope support behind the same `Iterator<Result<WebEvent>>` interface.

## Sigma web rules

The current [Sigma Rules Specification 2.1.0](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) defines YAML rules with a mandatory `logsource` and `detection`. It describes `webserver` as a logical category for web access logs, permits generic category rules, and specifies logical conditions, lists, keyword searches, field modifiers, and wildcard values. Values are normally case-insensitive strings; regexes are case-sensitive by default.

Web telemetry conventions encountered in the Sigma ecosystem use fields including `cs-method`, `cs-uri`, `cs-uri-stem`, `cs-uri-query`, `cs-host`, `cs-user-agent`/`c-useragent`, `cs-referer`, `c-ip`, and `sc-status`. This aligns with the normalized alias table in [sigma-support.md](sigma-support.md). The engine also defines local normalized fields for `ja3`, `ja4`, `waf_action`, `waf_rule_id`, and `waf_labels`; they are not presented as standard Sigma taxonomy fields.

The MVP compiles deterministic scalar/list equality, `contains`, `all`, `keywords`, and parenthesized `and`/`or`/`not`. It rejects unsupported constructs during loading so results cannot silently claim compatibility. The next compatibility phase should test a pinned SigmaHQ web-rule snapshot rather than make support claims from a moving upstream branch.

## Licensing and content boundary

Sigma is an upstream rule repository and its project points users to its [rule specification](https://github.com/SigmaHQ/sigma-specification) and rule content separately. This scanner contains only original test fixtures and accepts user-provided YAML; it does not redistribute third-party rule content. Nuclei conversion and template licensing research are explicitly deferred to the requested Phase 6.

## Nuclei static-analysis update

The current [ProjectDiscovery HTTP template documentation](https://docs.projectdiscovery.io/templates/protocols/http/basic-http) documents structured HTTP `method`, `path`, `headers`, `body`, redirects, and runtime variables. Its [syntax reference](https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md) additionally documents raw requests, payloads, attack modes, and legacy request forms. Raw requests can contain helper expressions, while [unsafe HTTP](https://docs.projectdiscovery.io/templates/protocols/http/unsafe-http) can represent malformed/non-RFC behavior; neither is executed or emulated by Shenron.

The Nuclei template repository describes CVE tags and classifications in its [template creation guide](https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATE-CREATION-GUIDE.md). Shenron therefore extracts CVEs only from explicit metadata fields and records a pinned revision supplied by the analyst. It bundles no upstream templates: the test corpus is original.
