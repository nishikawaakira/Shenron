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

`--output` must be outside the raw-input tree. The command writes `private-findings.jsonl` locally with investigation evidence, including fields that may be sensitive. `sanitized-research.json` has aggregate CVE/KEV counts, time ranges, WAF outcomes, and cardinalities only; it never includes raw request values, IPs, hostnames, JA3/JA4 values, queries, or headers. The default `private-results/` location is ignored by Git, but that is only an additional safeguard and not a data-security boundary.

The hunt rebuilds only request matchers whose template IDs have both `SUPPORTED` conversion and `passed` synthetic validation in the supplied frozen report. It uses the same normalization and matcher as the Nuclei validation pipeline; there is no simplified production matcher. `--format nginx` and `--format apache` parse standard combined access logs into the same event model. Their standard profiles do not expose WAF actions, so outcome and protection-gap metrics are explicitly unavailable for those sources.

An `ALLOW` or `COUNT` result is reported as **not blocked according to available WAF action evidence**. This is a protection gap, not evidence that exploitation succeeded. Non-terminating WAF matches are reported separately as COUNT-related evidence. Candidate WAF controls remain analyst-authored defensive hypotheses and must be replayed and reviewed before any deployment; Shenron does not generate or deploy blocking rules in this command.
