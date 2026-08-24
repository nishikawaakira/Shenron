# Minimum web security telemetry

## Result

The measured minimum SAFE profile is standard nginx/Apache combined access logging plus these five selected request headers: `Content-Type`, `Accept`, `Accept-Encoding`, `SOAPAction`, and `Accept-Language`.

| Step | Added field | Marginal templates | Marginal unique CVEs | Marginal CISA KEVs | Observable templates |
| ---: | --- | ---: | ---: | ---: | ---: |
| 0 | Standard combined | – | – | – | 2,198 |
| 1 | Content-Type | +261 | +267 | +34 | 2,459 |
| 2 | Accept | +36 | +38 | +5 | 2,495 |
| 3 | Accept-Encoding | +12 | +14 | +9 | 2,507 |
| 4 | SOAPAction | +4 | +4 | +2 | 2,511 |
| 5 | Accept-Language | +3 | +3 | +1 | 2,514 |

The resulting profile recovers 95.9% of the AWS WAF request-side observable-template reference (2,514 / 2,622), with 2,549 unique CVEs and 196 CISA KEV CVEs versus the combined baseline's 2,227 and 147.

## Boundaries and counterfactuals

- All required request headers would reach 2,622 observable templates (the AWS WAF reference), 2,657 unique CVEs, and 224 KEV CVEs. This is a technical counterfactual, not a recommendation to log all headers.
- `Host` alone adds zero template, CVE, or KEV coverage in this exact Detection-IR corpus.
- `Cookie`, `Authorization`, API-key, and token headers provide some theoretical gain but are **not recommended** because raw values commonly contain session material or credentials.
- The frozen inventory has 1,584 templates with request-body semantics. Shenlon does not assign a numeric incremental gain because it does not model body matching; this avoids overstating evidence. Logging complete request bodies is **not recommended** by default.
- JA4 is treated as enrichment for pivoting and defensive-rule refinement, not as a Nuclei-CVE observability input.
- No log-volume percentage is reported: the corpus does not contain representative values for the newly selected headers, and inventing value lengths would make the estimate misleading. Measure serialized size with an organization's approved synthetic fixtures before deployment.

The machine-readable [report.json](report.json) contains every header ranking, its single-field marginal gain, multi-header dependency count, exact-vs-presence matching semantics, and KEV joins. Header values are intentionally omitted.

## Reproduce

```bash
cargo run --release --bin webhunt-lab -- minimum-telemetry \
  --templates /private/tmp/shenlon-nuclei-exact-checkout \
  --comparison research/telemetry/48a4f865127cb9e6b113c6bb493c984978009fd4/comparison.json \
  --kev research/kev/2026-08-21/coverage.json \
  --revision 48a4f865127cb9e6b113c6bb493c984978009fd4 \
  --report research/minimum-telemetry/48a4f865127cb9e6b113c6bb493c984978009fd4/report.json
```
