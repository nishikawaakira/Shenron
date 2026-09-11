# WAF candidate model

## Frozen source-address conditions (explicit opt-in)

`candidate build --source-address-set <FILE>` narrows each request-content
candidate with an additional AND condition on the **observed connection peer**.
This is different evidence from a method, path, or header match: it tests
membership in an operator-selected address snapshot, not identity, ownership,
intent, or a finding of attack or abuse. No address set is used by default.
Combined logs suffice; forwarded client headers are not used or inferred.
The operator must verify that the log's observed peer is the same address that
the target WAF evaluates; proxy/CDN topologies can invalidate that assumption.

The UTF-8 input contains one IP or CIDR per line, with optional `#` comments.
IPv4 and IPv6 are supported; invalid records are excluded with counts, duplicate
normalized networks are counted separately, and an empty usable set is rejected.
The candidate carries the frozen normalized networks and a reference to the
original file. The private `run-manifest.json` in the candidate output directory
records its path, stored byte length, and SHA-256 using the existing input
fingerprint mechanism. Loading/replaying/exporting a source-set candidate checks
the snapshot bytes and normalized contents; changing or losing the source file
requires rebuilding. Preserve this private file with the candidate. Source
addresses missing or invalid in replay are explicitly counted as unmeasurable,
never inferred or silently treated as evidence of nonmembership.

AWS IP sets have separate address families. Bind the frozen IPv4 and IPv6 subsets
with `--source-ip-set-v4-arn` and `--source-ip-set-v6-arn`, respectively. An ARN
is an operator-supplied reference to an existing set, not a request to create it.
Mixed-family sets render as OR of two IPSetReferenceStatements. Missing bindings,
unsupported address ranges, or excessive logical nesting refuse faithful export.
The operator must ensure those sets contain exactly the frozen subsets, in the
correct account, region, and scope. Shenron does not call AWS to verify remote
contents, create sets, or deploy rules. OSSEC cannot faithfully represent this
condition and is rejected. AWS JSON and Terraform remain COUNT-only and require
historical replay and explicit priority, exactly as other candidates do.

Address allocations and remote IP sets change. Replay against a frozen snapshot
is not a guarantee about future traffic. Large cloud ranges also contain
legitimate search and AI crawlers; blocking them can affect search indexing and
AI citations as well as ordinary shared-cloud clients. Before considering a
manual COUNT-to-BLOCK promotion outside Shenron, review representative COUNT
matches and near misses, legitimate users and crawlers, source-address visibility,
the request conditions, the exact set contents and age, IPv4/IPv6 bindings, scope,
rollback procedures, and downstream effects. Neither shared address space nor
snapshot membership determines a shared operator, actor, attack, or abuse.

For example (all paths and the ARNs are private local configuration):

```bash
shenron candidate build --from-findings ./hunt \
  --telemetry apache --output ./source-scoped-candidates \
  --source-address-set ./frozen-addresses.txt \
  --source-ip-set-v4-arn "$REVIEWED_IPV4_IP_SET_ARN" \
  --source-ip-set-v6-arn "$REVIEWED_IPV6_IP_SET_ARN"
```

Omit a family's reference when the snapshot contains no addresses in that family.
AWS's [IPSet definition](https://docs.aws.amazon.com/waf/latest/APIReference/API_IPSet.html)
uses a single address family and excludes `/0`; its
[IPSetReferenceStatement](https://docs.aws.amazon.com/waf/latest/APIReference/API_IPSetReferenceStatement.html)
requires the operator-maintained set's ARN. Local `/0` membership remains
well-defined, but export refuses it rather than changing the snapshot's meaning.

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

## Opt-in Sigma TTP candidates

Sigma-derived candidates are a separate candidate class from CVE/Nuclei
candidates. A CVE candidate is anchored to a validated Nuclei request IR and a
specific CVE mapping. A Sigma TTP candidate instead carries the evidence bar
that a supported local Sigma rule matched and that its literal request
conditions can be translated faithfully. It has no CVE/KEV claim, and Shenron
does not present it as equivalent evidence. `candidate build` therefore keeps
excluding Sigma findings by default; `--include-sigma-ttp --rules <DIR>` is an
explicit opt-in.

One Sigma rule produces at most one candidate. Literal alternatives declared
by the rule are combined with `OR`; no path or value absent from the rule is
invented. The candidate records its `sigma_ttp` kind and Sigma-specific
evidence note, while CVE candidates remain `cve_nuclei`. Both classes must be
replayed against complete local history, pass faithful backend compatibility,
and export in COUNT mode only. No control is deployed.

Before promoting a COUNT hypothesis outside Shenron, an operator must inspect
all historical matches, expected application routes, exceptions, and the
effect of the exact translated condition. Literal substring rules can overlap
legitimate routes: for example, a rule containing `/.env` can also match
`/docs/.env-setup`. Replay volume is context for that review, not a false-positive
rate or proof of attack, exploitation, or compromise. The different evidence
bar and potential collateral effect are why Sigma TTP and CVE candidates are
never merged into one class.

`threat_coverage` is `known_threat_findings_matched` divided by `known_threat_findings` — the total source-finding count, not the number of request IDs. So a source finding that carries no request ID, or several findings that share one ID, lowers the ratio: those findings cannot be confirmed individually in the replay input and are reported under `known_threat_findings_missed` rather than matched. Read coverage as a conservative lower bound on how many known findings were re-observed, not as a false-positive rate.

Compatibility, explanation, and export use the candidate's recorded telemetry profile unless `--telemetry` explicitly overrides it. This prevents an AWS WAF candidate from being accidentally evaluated as standard nginx telemetry.

Export rejects exact sensitive header names such as `Authorization`, `Cookie`, and API-key headers, plus values containing authorization/cookie/bearer material or a JWT-like value. It does not reject a URI merely because it contains a word such as `token` or `secret`.
