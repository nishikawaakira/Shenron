# Production AWS WAF hunting

Production hunting is read-only and local. Shenron never modifies source logs, calls AWS, creates a WAF rule, replays traffic, scans a target, or executes a Nuclei template. Use a local JSON, JSONL, gzip, or directory-tree export.

Inspect structure before a hunt. This command reports only counts, timestamps, and field availability; it never prints raw requests.

```bash
cargo run --bin shenron -- production inspect --input ./production-waf-logs --format aws-waf --sample 10000
```

Run a full hunt only with the pinned Nuclei template checkout and frozen reports that validated the detections:

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --nuclei-templates /path/to/nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --output ./private-results/hunt-2026-08-24
```

Restrict a hunt to an inclusive UTC time interval with RFC 3339 timestamps. The report records the selected interval and how many parseable events were excluded because they were outside the interval or had no timestamp.

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --nuclei-templates /path/to/nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --from 2026-04-01T00:00:00Z \
  --to 2026-04-30T23:59:59Z \
  --output ./private-results/april-2026
```

`--output` must be outside the raw-input tree. The command writes `private-findings.jsonl` locally with investigation evidence, including fields that may be sensitive. `sanitized-research.json` has aggregate CVE/KEV counts, time ranges, WAF outcomes, and cardinalities only; it never includes raw request values, IPs, hostnames, JA3/JA4 values, queries, or headers. The default `private-results/` location is ignored by Git, but that is only an additional safeguard and not a data-security boundary.

Review the request-to-template mappings locally with `production explain`. It displays a CVE/template summary (up to 20 mappings) by default so a large hunt remains readable; small demo hunts therefore display all their mappings just as before. Add `--show-request` for individual matched method/path/query records, or `--show-evidence` for all locally stored evidence. Use `--limit 0` only when intentionally reviewing every mapping and individual finding.

```bash
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-request
```

The hunt rebuilds only request matchers whose template IDs have both `SUPPORTED` conversion and `passed` synthetic validation in the supplied frozen report. It uses the same normalization and matcher as the Nuclei validation pipeline; there is no simplified production matcher. A response-dependent generic root probe such as `GET {{BaseURL}}` is not converted into passive CVE evidence: request logs alone cannot reproduce the response fingerprint that makes that probe meaningful. If its template also contains an explicit exploit path, query, or distinctive request header, that explicit alternative remains eligible. `--format nginx` and `--format apache` parse standard combined access logs into the same event model. Their standard profiles do not expose WAF actions, so outcome and protection-gap metrics are explicitly unavailable for those sources.

An `ALLOW` or `COUNT` result is reported as **not blocked according to available WAF action evidence**. This is a protection gap, not evidence that exploitation succeeded. Non-terminating WAF matches are reported separately as COUNT-related evidence. Candidate WAF controls remain analyst-authored defensive hypotheses and must be replayed and reviewed before any deployment; Shenron does not generate or deploy blocking rules in this command.
