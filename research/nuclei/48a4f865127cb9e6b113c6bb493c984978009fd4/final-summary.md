# Frozen Nuclei Coverage Benchmark

## Dataset and safety boundary

The final benchmark uses the official ProjectDiscovery `nuclei-templates` repository at `48a4f865127cb9e6b113c6bb493c984978009fd4` (commit date 2026-08-24). It scanned 13,657 templates, including 4,488 CVE templates, 4,347 HTTP CVE templates, and 4,467 unique CVEs.

All work is static and local: Shenlon parsed untrusted YAML, generated in-memory AWS WAF-shaped records, and performed no template execution, HTTP requests, DSL evaluation, OAST/interactsh activity, or target contact.

## Final coverage

| Measure | Templates | Unique CVEs |
| --- | ---: | ---: |
| HTTP CVE denominator | 4,347 | 4,467 |
| Observable (`HIGH` + `MEDIUM`) | 2,622 (60.32%) | 2,657 (59.48%) |
| Convertible | 1,577 (36.28%) | 1,598 (35.77%) |
| Validated | 1,577 / 1,577 converted (100.00%) | 1,598 / 1,598 converted (100.00%) |

Final detectability is `HIGH` 1,577, `MEDIUM` 1,045, `LOW` 21, `UNDETECTABLE` 141, and `UNKNOWN` 1,704. The observable, convertible, and validated columns are intentionally separate measurements.

Exact validation passed 1,852/1,852 generated request branches. Mutation validation passed 1,852/1,852; near-miss validation rejected 1,852/1,852. There were no deterministic exact, mutation, or near-miss failures.

## Engineering history

| Stage | Observable templates | Convertible templates | Validated templates | Convertible unique CVEs |
| --- | ---: | ---: | ---: | ---: |
| Historical baseline | 2,379 | 1,375 | 1,375 | 1,392 |
| Iteration 01: multiple literal paths | 2,622 | 1,577 (+202) | 1,577 (+202) | 1,598 (+206) |
| Final | 2,622 | 1,577 | 1,577 | 1,598 |

Iteration 01 also corrected a classifier defect: the historical baseline had tied observability to converter parsing. 243 templates moved from `UNKNOWN` to `HIGH`/`MEDIUM` because their request-side observables were present even before Shenlon could convert them. This correction is preserved in the history; it is not attributed to converter coverage.

No Iteration 02 or 03 was implemented. The final observable-but-unvalidated set is 1,045 templates: 708 require a stateful multi-request flow, 278 depend on request-body semantics, and 59 require OAST verification. All are `MEDIUM`, and each requires semantics outside the deliberately bounded passive request-side model. Adding arbitrary workflow, body, or OAST behavior would weaken the benchmark’s meaning rather than produce a safe coverage improvement.

## Remaining limitations

Implementation limits are the 1,045 observable-but-unvalidated templates above. Telemetry limits are separate: 141 CVE templates are non-HTTP for this AWS WAF model, `LOW` templates are too generic to make high-confidence exploitation inferences, response matchers do not appear in historical request telemetry, and OAST/response/state evidence cannot be reconstructed from a single access-log event.

The complete per-template final JSON is [final.json](final.json); it contains template path/ID, CVE IDs, detectability and reasons, conversion state and reason, and exact/mutation/near-miss status.
