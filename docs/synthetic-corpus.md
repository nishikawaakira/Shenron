# Synthetic corpus

The generator writes valid AWS WAF-style JSONL (or `.gz`), a sidecar truth JSONL, and an experiment manifest. It follows the current [AWS WAF logging fields](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html): request path is `httpRequest.uri`, query is `httpRequest.args`, and optional JA3/JA4, labels, actions, terminating rule fields, and non-terminating COUNT metadata are represented where appropriate.

Profiles:

- `deterministic`: 15 valid events plus one intentional malformed line. It covers browser/API/static background, path traversal and Log4Shell-style request characteristics, exact and compound JA4 rules, shared-JA4 benign traffic, wrong-JA4 and wrong-URI near misses, BLOCK and ALLOW attacks, multiple labels, missing JA4, and a POST.
- `mutations`: request-side variations that retain the test indicator (query ordering/extra parameters, header ordering, absent User-Agent, host change) plus near misses.
- `large`: seeded background traffic and a selectable attack rate. It is generated on demand, never committed.

`--events`, `--attack-rate`, `--hosts`, `--source-ips`, `--start-timestamp-ms`, `--duration-ms`, and `--seed` control large generation. The manifest records all values, tool version, a project-native rule revision label, and JA4 scenarios. The same parameters and seed produce byte-identical output.

JA4 values are intentionally not a simple bad/good split: the deterministic corpus has a malicious-only exact JA4, a shared JA4 used by an attack and benign assets, and a common background JA4. The compound test verifies that URI + JA4 avoids the shared-JA4 background match.

Use `shenron-lab measure --corpus path` for an on-demand parser throughput measurement. It reports input bytes, wall time, events/sec, and input MB/sec; it does not claim peak-memory measurement.
