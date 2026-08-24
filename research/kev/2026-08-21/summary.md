# CISA KEV × Shenlon Coverage

## Snapshot

This benchmark uses CISA KEV catalog version `2026.08.21`, released 2026-08-21T17:46:43.6019Z. The catalog has 1,674 entries. Its official source URL and SHA-256 are in [manifest.json](manifest.json). Analysis consumed that local snapshot and the frozen Nuclei report; it did not execute templates or contact targets.

## Web relevance

| Category | KEVs | Denominator | Rate |
| --- | ---: | ---: | ---: |
| Total KEVs | 1,674 | 1,674 | 100.00% |
| Web relevant | 505 | 1,674 | 30.17% |
| Not web relevant | 43 | 1,674 | 2.57% |
| Unknown relevance | 1,126 | 1,674 | 67.26% |

`UNKNOWN` is retained: product names and absence of Nuclei evidence are not enough to claim a vulnerability is, or is not, web-relevant.

## Web-relevant KEV coverage

| Measure | Count | Denominator | Rate |
| --- | ---: | ---: | ---: |
| With any Nuclei template | 461 | 505 web-relevant KEVs | 91.29% |
| With HTTP Nuclei template | 459 | 505 web-relevant KEVs | 90.89% |
| Observable in AWS WAF telemetry | 224 | 459 web KEVs with HTTP Nuclei | 48.80% |
| Convertible | 116 | 459 web KEVs with HTTP Nuclei | 25.27% |
| Validated | 116 | 459 web KEVs with HTTP Nuclei | 25.27% |
| Validated | 116 | 505 web-relevant KEVs | 22.97% |
| Validated | 116 | 1,674 total KEVs | 6.93% |
| Convertible among observable | 116 | 224 observable web KEVs | 51.79% |

44 web-relevant KEVs have no Nuclei template. This means no Nuclei evidence is available for this benchmark; it does **not** mean those CVEs are not detectable by a future native or Sigma-derived Shenlon rule.

## Strongest Nuclei state for web-relevant KEVs

| State | Count |
| --- | ---: |
| `HTTP_TEMPLATE_VALIDATED` | 116 |
| `HTTP_TEMPLATE_OBSERVABLE_UNSUPPORTED` | 108 |
| `HTTP_TEMPLATE_NOT_OBSERVABLE` | 235 |
| `NON_HTTP_NUCLEI_TEMPLATE` | 2 |
| `NO_NUCLEI_TEMPLATE` | 44 |

The complete per-CVE machine-readable result is [coverage.json](coverage.json). It records the CISA metadata, relevance reason, all matching Nuclei template summaries, and strongest aggregate state.
