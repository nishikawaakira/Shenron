# Shenron safe demo datasets

`demo/` contains deterministic, synthetic historical telemetry only. It has no production records, credentials, personal data, customer domains, or real public IP addresses. The AWS WAF records use RFC 5737 `198.51.100.0/24` documentation addresses and `api.demo.example.com`.

The three datasets are rendered from the same existing `shenron generate --profile demo` logical event set:

- `demo/aws-waf.jsonl`
- `demo/nginx-combined.log`
- `demo/apache-combined.log`

Each has 11 requests: browser/API background traffic, four synthetic CVE-style request patterns, four near misses, and a duplicate traversal-style request marked `BLOCK` in the AWS WAF rendering. AWS WAF also includes two synthetic JA4 examples. nginx/Apache combined logs naturally omit WAF outcome and JA4 fields.

The companion templates use deliberately non-real `CVE-2099-*` identifiers and are local static input only; Shenron never executes them.

## Inspect

```bash
cargo run --bin shenron -- inspect --input examples/demo/aws-waf.jsonl --format aws-waf
cargo run --bin shenron -- inspect --input examples/demo/nginx-combined.log --format nginx
cargo run --bin shenron -- inspect --input examples/demo/apache-combined.log --format apache
```

## Hunt

Use a new local output directory for each run. The command writes private raw findings and a sanitized aggregate report locally; it does not contact any host or modify a WAF.

```bash
cargo run --bin shenron -- hunt \
  --input examples/demo/aws-waf.jsonl --format aws-waf \
  --nuclei-templates examples/nuclei-templates \
  --nuclei-report examples/demo/nuclei-report.json \
  --kev-report examples/demo/kev-report.json \
  --output /tmp/shenron-demo-aws

cargo run --bin shenron -- hunt \
  --input examples/demo/nginx-combined.log --format nginx \
  --nuclei-templates examples/nuclei-templates \
  --nuclei-report examples/demo/nuclei-report.json \
  --kev-report examples/demo/kev-report.json \
  --output /tmp/shenron-demo-nginx

cargo run --bin shenron -- hunt \
  --input examples/demo/apache-combined.log --format apache \
  --nuclei-templates examples/nuclei-templates \
  --nuclei-report examples/demo/nuclei-report.json \
  --kev-report examples/demo/kev-report.json \
  --output /tmp/shenron-demo-apache
```

## View sanitized results

```bash
cat /tmp/shenron-demo-aws/sanitized-research.json
cat /tmp/shenron-demo-nginx/sanitized-research.json
cat /tmp/shenron-demo-apache/sanitized-research.json
```

To view Shenron's local request-to-CVE-to-template mapping (rather than using `jq`), explicitly opt in to request-target display:

```bash
cargo run --bin shenron -- explain \
  --findings /tmp/shenron-demo-aws/private-findings.jsonl \
  --show-request
```

This command does not print source IPs, hosts, headers, JA3/JA4, or request IDs. `--show-request` can expose sensitive URI/query values in non-demo data, so use it only in an approved local terminal.

To display all private evidence captured by `hunt`, including JA3/JA4, WAF labels, terminating and non-terminating WAF rule IDs, Host, source IP, request ID, and header values, use the stronger explicit opt-in:

```bash
cargo run --bin shenron -- explain \
  --findings /tmp/shenron-demo-aws/private-findings.jsonl \
  --show-evidence
```

To review only requests that were blocked, add `--waf-outcome block`:

```bash
cargo run --bin shenron -- explain \
  --findings /tmp/shenron-demo-aws/private-findings.jsonl \
  --waf-outcome block \
  --show-evidence
```

To review exploitation-attempt findings that were not blocked (for example,
AWS WAF `ALLOW` or `COUNT`), use `--waf-outcome not-blocked`:

```bash
cargo run --bin shenron -- explain \
  --findings /tmp/shenron-demo-aws/private-findings.jsonl \
  --waf-outcome not-blocked \
  --show-evidence
```

`--waf-outcome unknown` selects findings without a recorded WAF action. This
is the expected outcome for standard nginx and Apache combined logs; those
logs cannot establish whether AWS WAF blocked a request.

Expected deterministic results:

| Dataset | Requests | CVE-attempt findings | Unique CVEs | WAF outcome | JA4 pivots |
| --- | ---: | ---: | ---: | --- | ---: |
| AWS WAF | 11 | 5 | 4 | 1 BLOCK, 4 ALLOW | 2 |
| nginx combined | 11 | 4 | 3 | unavailable | 0 |
| Apache combined | 11 | 4 | 3 | unavailable | 0 |

The selected-header pattern is intentionally observable only in the AWS WAF dataset. The four near misses do not match. `tests/demo.rs` regenerates each corpus and verifies both byte-for-byte corpus stability and these finding counts.
