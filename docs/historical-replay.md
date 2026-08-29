# Historical replay coverage

`shenron production replay` measures the validated Nuclei request matchers against a complete local historical corpus. It is the workflow's **VALIDATE** measurement: it does not build a candidate, export a control, deploy anything, execute a template, or contact a network.

```bash
shenron production replay \
  --input ./historical-logs \
  --format aws-waf \
  --nuclei-templates ./nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --findings ./private-results/hunt/private-findings.jsonl \
  --output ./research/replay-coverage.json
```

The report is aggregate-only. It records frozen-input SHA-256 values, telemetry profile, optional time filter, parse/exclusion counts, per-CVE counts, and cross-CVE event totals. It never contains raw request values, request IDs, IP addresses, hostnames, URI/query values, or header values.

For each CVE, `known_findings` counts the prior private source findings. Only a matching historical event carrying the same source-finding request ID is a `known_matched` re-observation. `coverage` is `known_matched / known_findings`, and is `null` when that CVE has no source request ID. Consequently, coverage is a conservative lower bound on re-observation, not precision, recall, accuracy, ground truth, attack evidence, exploitation success, compromise, or product vulnerability evidence.

`other_matches_with_request_id` and `other_matches_without_request_id` count historical events that match the same CVE matcher without a known re-match for that CVE. They may be additional relevant attempts or accidental matches; both require human review. Aggregate other-match and WAF-outcome totals are distinct-event counts, so one event matching several CVEs is counted once there. `BLOCK`, `ALLOW`/`COUNT`, and unavailable/other actions are context only: they can support an over-block or protection-gap review, but do not establish exploitation outcome.

This differs from [candidate replay](waf-candidate-model.md#why-replay-matters). Candidate replay is an **ACT** gate for one analyst-authored defensive condition and records whether that condition has been replayed before export. Production historical replay is a **VALIDATE** measurement across all approved Nuclei Detection IR matchers and writes only a sanitized research report.
