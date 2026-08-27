# WAF candidate model

Candidates are source-neutral defensive hypotheses, not automatic policy changes. `shenron candidate compatibility`, `explain`, and `export` perform local review-only analysis. AWS WAF JSON and Terraform exports are COUNT-only and refuse candidates without historical replay evidence, an explicit priority, or fully faithful backend compatibility. OSSEC export is a detection-control XML rule, not a WAF rule.

See [AWS WAF JSON](exporters/aws-waf.md), [Terraform](exporters/terraform.md), and [OSSEC](exporters/ossec.md).

```bash
# Build one candidate per CVE and exact request pattern. For AWS WAF, BLOCK
# findings are excluded by default because they already have a recorded control outcome.
# URI-only response-unverified findings are also excluded by default.
shenron candidate build --from-findings ./hunt/private-findings.jsonl \
  --telemetry aws-waf --output ./candidates/

# Replay a reviewed candidate against the complete local historical source.
# It writes a new file.
# The output must be outside the immutable raw-input tree.
shenron candidate replay --candidate ./candidates/shenron-cve-202x-xxxxx-001.json \
  --input ./historical-logs --format aws-waf --output ./candidates/candidate-replayed.json

shenron candidate compatibility --candidate ./candidates/candidate-replayed.json
shenron candidate export --candidate ./candidates/candidate-replayed.json \
  --backend aws-waf-json --priority 100 --output ./exports/candidate.aws-waf.json
```

Replay measures known-threat coverage only by comparing source-finding request IDs with matching historical events. `known_threat_findings_matched` is the number of unique known request IDs seen again; `other_historical_matches` counts matching events with another or no request ID. Coverage is `null` when the source findings have no request IDs, rather than claiming complete coverage.

URI-only `response-unverified` findings do not create candidates by default. Request telemetry cannot reproduce Nuclei response confirmation, so converting URI-only matches directly into blocking conditions creates an elevated over-blocking risk. Include them only after human review or with additional evidence by passing `--include-response-unverified` to `shenron candidate build`; this changes candidate selection only and does not make the finding an attack or compromise determination.

`threat_coverage` is `known_threat_findings_matched` divided by `known_threat_findings` — the total source-finding count, not the number of request IDs. So a source finding that carries no request ID, or several findings that share one ID, lowers the ratio: those findings cannot be confirmed individually in the replay input and are reported under `known_threat_findings_missed` rather than matched. Read coverage as a conservative lower bound on how many known findings were re-observed, not as a false-positive rate.

Compatibility, explanation, and export use the candidate's recorded telemetry profile unless `--telemetry` explicitly overrides it. This prevents an AWS WAF candidate from being accidentally evaluated as standard nginx telemetry.

Export rejects exact sensitive header names such as `Authorization`, `Cookie`, and API-key headers, plus values containing authorization/cookie/bearer material or a JWT-like value. It does not reject a URI merely because it contains a word such as `token` or `secret`.
