# Iteration 01 — Multiple Literal Path Alternatives

## Change

One structured Nuclei request can contain multiple literal `path` values. Shenlon now represents those values as alternative request-side detection branches. It does not treat them as a multi-request flow, resolve arbitrary variables, execute a template, or use response evidence. A dedicated fixture covers two alternatives and exact, mutation, and near-miss validation.

The feature was selected after the baseline because it had a bounded request-side interpretation and low semantic and safety risk. The larger remaining categories involve state, payload expansion, helpers, bodies, or response/OAST semantics and are not automatically safe expansions.

## Ranking used for this decision

| Candidate | Affected baseline CVE templates | Observable impact | Complexity | Semantic/safety risk | Decision |
| --- | ---: | --- | --- | --- | --- |
| Multiple literal structured paths | 255 | Reclassified correction: 202 `HIGH`, 41 `MEDIUM`, 243 total | Low | Low | Implemented |
| Multi-request stateful flow | 686 | Mostly `MEDIUM` | High | High | Intentionally deferred |
| Multiple raw requests | 665 | Parsing-dependent | High | High | Intentionally deferred |
| Raw helpers/variables | 420 | Parsing-dependent | Medium | Medium | Deferred pending literal-only design |
| Request body semantics | 267 | `MEDIUM` | Medium | Medium | Deferred; AWS WAF body availability is constrained |
| OAST verification | 359 | `MEDIUM` | High | High | Out of scope for historical logs |

The old baseline classifier reported multiple literal paths as `UNKNOWN` because it reused conversion parsing to identify request observables. That conflated telemetry capability with Shenlon support. This iteration corrects the classification: alternatives with literal method/path/query/header evidence are observable even when a different construct remains unsupported. The before/after values are preserved below rather than rewriting the baseline.

## Before / after (template level)

| Stage | Baseline | After | Delta |
| --- | ---: | ---: | ---: |
| Observable | 2,379 / 4,347 (54.73%) | 2,622 / 4,347 (60.32%) | +243 |
| Convertible | 1,375 / 4,347 (31.63%) | 1,577 / 4,347 (36.28%) | +202 |
| Validated | 1,375 / 1,375 (100.00%) | 1,577 / 1,577 (100.00%) | +202 |
| Unsupported | 3,113 | 2,911 | -202 |

The observable delta is a documented detectability-policy correction, not coverage gaming. The conversion feature accounts for the +202 converted templates; the remaining affected templates still have another unsupported construct.

## After: validation and CVE counts

The final run produced 1,852 detection branches across 1,577 converted templates. It generated 5,556 synthetic AWS WAF records: exact detections 1,852/1,852, mutation failures 0/1,852, near-miss failures 0/1,852, and unexpected matches 0.

At unique-CVE level: 2,657/4,467 observable (59.48%), 1,598/4,467 convertible (35.77%), and 1,598/1,598 validated (100.00%).

The full coverage-analysis and validation run took 24.46 seconds wall-clock (about 558 templates/second over all 13,657 templates). Inventory-only runtime in the baseline was about 21.27 seconds. Peak memory was not measured. The benchmark is deterministic; its mutation and near-miss profiles are in [manifest.json](manifest.json).

## Representative cases

- `CVE-2022-42475` is a `HIGH` validated example after literal-path support.
- No `MEDIUM` template is currently converted and validated; those require an intentionally unsupported body, OAST, or stateful-flow semantic.
- `CVE-2025-71260` is request-observable but remains unsupported because it is a multi-request flow.
- `CVE-2022-27925` has non-HTTP file/hash variants and is `UNDETECTABLE` for AWS WAF request telemetry.
- `CVE-2025-25291` remains `UNKNOWN` due raw helper/variable semantics.
- `CVE-2024-39903` is the URI-fragment field-mapping bug found by validation and now covered by regression testing.
- No overbroad conversion was found: all 1,852 deterministic near misses were rejected.

## Remaining implementation gaps

The post-iteration leading gaps are multi-request flow (708), multiple raw requests (665), raw helpers/variables (420), OAST-required semantics (355), body semantics (278), payload expansion (111), variable resolution (109), and malformed/non-literal raw request shapes. These are recorded independently of telemetry limitations. They are research candidates, not a mandate to add arbitrary evaluation.
