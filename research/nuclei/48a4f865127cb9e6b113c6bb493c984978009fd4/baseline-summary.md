# Nuclei Coverage Benchmark — Baseline

This is a passive, local analysis of the official ProjectDiscovery corpus at revision `48a4f865127cb9e6b113c6bb493c984978009fd4` (2026-08-24T06:28:54Z). Shenlon did not execute templates, send requests, evaluate DSL, invoke OAST, or contact targets. The benchmark ran against AWS WAF-shaped synthetic records only.

The full per-template baseline is recorded externally and checksummed in [manifest.json](manifest.json). It is deliberately not vendored or committed.

## Dataset

| Measure | Count |
| --- | ---: |
| Templates scanned | 13,657 |
| CVE templates | 4,488 |
| HTTP CVE templates | 4,347 |
| Unique CVEs | 4,467 |

The inventory found 1,901 structured HTTP templates, 2,477 raw HTTP templates, and 979 multi-request templates. It also recorded bodies (1,584), payloads (112), attack modes (44), request headers (121), query parameters (1,019), DSL (1,589), OAST/interactsh (383), redirects (262), variables (reported in later iteration), helpers (heuristic, later iteration), and extractors (later iteration).

## Template-level measurement

| Stage | Count | Denominator | Rate |
| --- | ---: | ---: | ---: |
| Observable in principle (`HIGH` + `MEDIUM`) | 2,379 | 4,347 HTTP CVE templates | 54.73% |
| Convertible | 1,375 | 4,347 HTTP CVE templates | 31.63% |
| Convertible among observable | 1,375 | 2,379 observable templates | 57.80% |
| Validated exact + mutation + near-miss | 1,375 | 1,375 converted templates | 100.00% |

Detectability: `HIGH` 1,375; `MEDIUM` 1,004; `LOW` 21; `UNDETECTABLE` 141; `UNKNOWN` 1,947. Convertible and validated are intentionally distinct from observable.

## Unique-CVE-level measurement

| Stage | Count | Denominator | Rate |
| --- | ---: | ---: | ---: |
| Observable CVEs | 2,413 | 4,467 unique CVEs | 54.02% |
| Convertible CVEs | 1,392 | 4,467 unique CVEs | 31.16% |
| Validated CVEs | 1,392 | 1,392 converted CVEs | 100.00% |

Templates and CVEs are both reported because multiple template variants can map to one CVE.

## Validation and correctness

The corrected baseline generated 4,125 synthetic events: 1,375 exact, 1,375 mutation, and 1,375 near-miss cases. Exact detections: 1,375/1,375; mutation failures: 0/1,375; near-miss failures: 0/1,375.

An earlier baseline run exposed one deterministic conversion bug for `CVE-2024-39903`: its raw request used a URI fragment, but AWS WAF supplies that value in top-level `fragment`, which Shenlon had discarded. Shenlon now preserves `uri_fragment`, adds an AWS WAF parser regression test, and validates that template successfully. This was treated as a field-mapping correctness fix, not a coverage feature.

## Main limitations at baseline

Telemetry limitations are not implementation defects: response-only evidence is absent from AWS WAF request records (4,286 templates declare response matchers), non-HTTP protocols are undetectable in this model (141 CVE templates), and OAST verification is not historical request-side telemetry (383 templates mention it). Bodies and stateful flows may retain partial request observability, therefore they are classified separately rather than silently counted as converted.

The largest implementation gaps were multi-request flow (686), multiple raw requests (665), raw helpers/variables (420), OAST-required conversion (359), request bodies (267), and multiple literal paths (255). These counts are template-level and can overlap with other characteristics.
