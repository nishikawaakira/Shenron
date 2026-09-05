# Synthetic validation

`shenron-lab` is a passive local validation harness. It generates AWS WAF-shaped JSONL records and a separate JSONL ground-truth sidecar, then compares scanner findings to exact expected rule IDs. Test metadata is never inserted into a WAF record: `httpRequest.requestId` is the join key already present in the schema.

```bash
cargo run --bin shenron-lab -- generate --profile deterministic \
  --output /tmp/waf.jsonl.gz --ground-truth /tmp/truth.jsonl --seed 42
cargo run --bin shenron-lab -- validate --corpus /tmp/waf.jsonl.gz \
  --truth /tmp/truth.jsonl --rules ./tests/rules \
  --manifest /tmp/waf.jsonl.gz.manifest.json --report /tmp/report.json
```

Validation returns non-zero on a missed expected rule, unexpected rule finding, or parser-error count mismatch. It reports a machine-readable JSON report with `PARSER_ERROR`, `EXPECTED_RULE_MISSED`, or `EXPECTED_BEHAVIOR_ERROR` failure categories. Corpus validation parses and matches in-process, so parser errors are included. Prefer this corpus path for synthetic validation; `hunt` stdout uses the operational private-finding schema and is not a synthetic ground-truth sidecar.

True/false positive and negative, recall, precision, and false-positive rate are valid only here because the synthetic truth labels are explicit. Production analysis must continue to use neutral terms such as known threat matches and other historical matches.

For CTI research that needs shareable request-volume shape rather than labeled
detections, use `--profile volumetric-concentration`. Its truth records are
explicitly `unknown`, and its documented concentration ratios do not represent
a real attack, attacker, campaign, vulnerability, or denial-of-service event.
See [Synthetic corpus](synthetic-corpus.md).
