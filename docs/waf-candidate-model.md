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

## Why replay matters

For an aggregate, matcher-wide VALIDATE measurement rather than one defensive-condition gate, see [historical replay coverage](historical-replay.md).

Candidate replay is the ACT-side pre-export gate of the hunting workflow. A candidate built from findings only describes the specific past requests that matched a known indicator; it says nothing about how the proposed condition would behave against the rest of your traffic. Replay closes that gap by evaluating the candidate against the complete local history — every request, not only the source findings — entirely offline, with no deployment and no network call.

That answers the questions an analyst must settle before shipping a control:

- **Impact and over-block risk before deployment.** Replay reports how many historical requests the condition matches, so collateral risk to legitimate traffic can be weighed before the rule ever runs. Exports are COUNT-only for the same reason: observe first, block later.
- **Known-threat coverage.** Of the CVE-related attempts hunting already surfaced, how many would this candidate actually re-catch (`threat_coverage`)? A low value means the condition is too narrow to be worth deploying.
- **Other historical matches as a signal.** `other_historical_matches` are matches outside the source findings. They may be attempts hunting missed, or legitimate traffic an over-broad condition would hit — either way, a prompt to review before deployment.
- **Safe, offline what-if.** Tune a candidate and replay again to see the coverage-versus-collateral trade-off against real history, without touching production.

Because export refuses a preventive candidate without replay evidence, replay is the mandatory gate that turns a defensive hypothesis into a reviewable, evidence-backed control. It never establishes an attack, exploitation, or compromise, and its coverage figure is a conservative lower bound, not a false-positive rate.

Replay measures known-threat coverage only by comparing source-finding request IDs with matching historical events. `known_threat_findings_matched` is the number of unique known request IDs seen again; `other_historical_matches` counts matching events with another or no request ID. Coverage is `null` when the source findings have no request IDs, rather than claiming complete coverage.

URI-only `response-unverified` findings do not create candidates by default. Request telemetry cannot reproduce Nuclei response confirmation, so converting URI-only matches directly into blocking conditions creates an elevated over-blocking risk. Include them only after human review or with additional evidence by passing `--include-response-unverified` to `shenron candidate build`; this changes candidate selection only and does not make the finding an attack or compromise determination.

`threat_coverage` is `known_threat_findings_matched` divided by `known_threat_findings` — the total source-finding count, not the number of request IDs. So a source finding that carries no request ID, or several findings that share one ID, lowers the ratio: those findings cannot be confirmed individually in the replay input and are reported under `known_threat_findings_missed` rather than matched. Read coverage as a conservative lower bound on how many known findings were re-observed, not as a false-positive rate.

Compatibility, explanation, and export use the candidate's recorded telemetry profile unless `--telemetry` explicitly overrides it. This prevents an AWS WAF candidate from being accidentally evaluated as standard nginx telemetry.

Export rejects exact sensitive header names such as `Authorization`, `Cookie`, and API-key headers, plus values containing authorization/cookie/bearer material or a JWT-like value. It does not reject a URI merely because it contains a word such as `token` or `secret`.
