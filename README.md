# Shenron

[日本語版 README](README.ja.md)

Shenron is a passive Rust threat-hunting engine for historical web telemetry. Its purpose is not merely to alert on suspicious requests: it helps analysts turn public threat intelligence into local evidence and into reviewable AWS WAF rule candidates validated by historical replay.

## How it works (architecture overview)

In one line: **Shenron correlates public CTI with your own historical logs in an offline analysis pipeline, producing confidence-labeled evidence and COUNT-only WAF rule candidates that you review before deploying.** Explicit preparation commands `shenron-lab nuclei update` and `shenron-lab reputation update` may download public intelligence, but never upload customer logs, findings, IPs, request values, or other customer data.

```
input logs ─▶ parser ─▶ WebEvent ─▶ matching engine ─▶ findings ─▶ aggregate / triage / scoring ─▶ candidates / COUNT rules
(AWS WAF /            (source-        (Sigma or Nuclei-    (private +          (per IP / ASN / JA4,             (a human reviews,
 nginx / Apache)      neutral)         derived matchers)    sanitized split)   behavior score + reputation)     then applies)
```

1. **Normalize inputs.** Different log formats are parsed into one internal `WebEvent`, so downstream logic is format-agnostic. Fields a log does not contain (JA3/JA4, WAF outcome, request body) are never invented.
2. **Ingest public CTI statically.** `shenron-lab nuclei update` can explicitly download public Nuclei templates, and `shenron-lab reputation update` can download public IP-reputation and IPv4 ASN lists; both write local, reviewable inputs and never receive customer data. Nuclei templates are parsed locally, never executed, into a literal request subset (method, path, query, fragment, headers). Anything needing payload expansion, multi-request state, or response/OAST confirmation is rejected with a stable reason instead of being silently approximated.
3. **Match.** Those matchers run over each historical `WebEvent` to surface CVE-related requests. A small Sigma subset provides a second, independent rule-matching path.
4. **Label fidelity.** Every match is labeled on two transparent axes: request-specificity (`request-specific` vs `response-unverified`) and path-distinctiveness (`distinctive` vs `generic` — `/robots.txt` and `/login` are generic). Matches are labeled, never dropped.
5. **Triage and score.** Findings are grouped by connection/client IP, JA4, or (with a dataset) ASN, and each group gets an offline behavior priority score from observed behavior alone. `shenron-lab reputation update` can prepare optional local IP/ASN inputs; `explain` reads them locally with no external API calls.
6. **Candidates and COUNT output.** Defensive conditions are proposed and simulated across the full history offline. Exported WAF rules always start as `COUNT` (observe, do not block); a human applies them.

The whole tool follows a **FIND → EXPLAIN → PIVOT → ACT → VALIDATE** workflow:

| Stage | Purpose | Commands |
| --- | --- | --- |
| FIND | Match known indicators in historical logs | `production hunt` |
| EXPLAIN / PIVOT | Read results by CVE/template, IP, JA4, ASN | `production explain`, `production ablation` |
| ACT | Propose and COUNT-evaluate defensive conditions | `production count-hypotheses`, `candidate ...` |
| VALIDATE | Measure threat coverage across the corpus | `production replay` |

Four design pillars: (1) static conversion — templates are never executed; (2) fidelity made explicit as scores and labels; (3) reproducibility via frozen input snapshots recorded with SHA-256; and (4) never asserting an attack, exploitation, compromise, or attacker identity.

## Capabilities

The scanner pipeline streams AWS WAF JSONL (including gzip) → normalized `WebEvent` → a deliberately small Sigma subset → JSONL or CSV findings. It supports AWS WAF action, labels, request metadata, and optional JA3/JA4 fingerprints. Analysis commands, including `shenron production ...` and `shenron candidate ...`, never access the network, upload customer data, execute exploits, change AWS, deploy candidates, or take automatic BLOCK actions. Only explicit `shenron-lab` preparation commands such as `nuclei update` and `reputation update` may download public threat-intelligence inputs.

It also includes a reproducible synthetic validation loop: project-owned AWS WAF-shaped corpora, separate ground truth, mutation tests, regression fixtures, and machine-readable validation results. See [validation](docs/validation.md) and [synthetic corpus generation](docs/synthetic-corpus.md).

Static Nuclei CVE analysis is available through `shenron-lab nuclei inventory` and `shenron-lab nuclei coverage`. `shenron-lab nuclei update` can prepare a local checkout by downloading public templates only; inventory and coverage remain passive local YAML analysis, and no template is executed or transmitted. See [detectability policy](docs/nuclei-detectability.md) and [Nuclei test generation](docs/nuclei-test-generation.md).

Read-only local AWS WAF production inspection and validated Nuclei hunting are available through `shenron production inspect` and `shenron production hunt`. They separate private investigation evidence from sanitized aggregate output and make no AWS changes. See [production hunting](docs/production-hunting.md).

`shenron production explain` reviews private findings locally: its summary groups CVEs and templates by request method/path, alongside per-request evidence and breadth/depth/windowed triage of connection/client IP groups (`--show-source-ips`), locally resolved ASN groups (`--show-asn`), or JA4 client fingerprints (`--show-fingerprints`). By default it hides only response-unverified matches on generic paths; pass `--include-generic` to review every stored finding. `shenron-lab reputation update` prepares public reputation/ASN inputs that explain automatically reads from the local data directory when present; explicit dataset paths remain available. Each group carries an offline [behavior priority score](docs/production-hunting.md#behavior-priority-score) computed only from observed request behavior; it transparently limits repeated generic-path depth and gives a small distinctiveness component, normalizes the total against the maximum the finding's telemetry profile can reach (so combined logs without a WAF outcome are not systematically depressed), ranks entities for triage, and is never a probability of malice, an exploitation or compromise determination, or attacker attribution. Optional local [IP/ASN reputation enrichment](docs/production-hunting.md#ipasn-reputation-enrichment-offline) uses frozen datasets only, never an inline external lookup, and remains a third-party opinion rather than a conclusion. `--output-format json` (with optional `--output <PATH>`) emits the same content — scores, score components, triage basis, and groupings — as a machine-readable `EXPLAIN_PRIVATE_TRIAGE` report that honors the identical `--show-*` privacy gates.

`shenron production ablation` compares aggregate match volume from URI-only through validated Nuclei IR and request-specific IR. It is a volume comparison, not precision, ground truth, or an attack/compromise determination; see [detection-strategy ablation](docs/ablation.md).

`production explain` and sanitized hunt reports also label matched paths as `generic` or `distinctive` with a transparent, non-excluding triage heuristic; this is not a precision, attack, exploitation, or compromise determination.

`shenron production replay` measures conservative known-finding re-observation and other aggregate historical matcher matches across a local corpus, writing only a sanitized report; see [historical replay coverage](docs/historical-replay.md).

`shenron production count-hypotheses` compares broad-to-narrow per-CVE WAF-condition measurements as offline, non-deploying COUNT simulations and deliberately does not recommend a rung; see [COUNT hypothesis ladder](docs/count-hypotheses.md).

Defensive candidates can be built from private hunt findings, replayed locally, reviewed for backend compatibility, and exported as COUNT-only AWS WAF JSON, Terraform rule fragments, or OSSEC detection XML. Export never deploys a control and refuses non-faithful translations. See the [candidate model](docs/waf-candidate-model.md).

The same passive scanner supports explicit `--format nginx` parsing for standard combined logs. `--format apache` automatically accepts both standard Combined and vhost-prefixed Combined logs per line; `--format apache-vhost` remains available when a vhost prefix must be required. Source capabilities remain explicit; see [telemetry capabilities](docs/telemetry-capabilities.md).

## Quick start

```bash
cargo run --bin shenron -- scan \
  --input ./tests/fixtures/aws-waf/ \
  --format aws-waf \
  --rules ./tests/fixtures/rules/
```

Findings go to stdout as JSONL; the scan summary and malformed-record warnings go to stderr. Use `--output findings.csv --output-format csv` for CSV. Check rule compatibility before a scan:

```bash
cargo run --bin shenron -- validate-rules --rules ./rules/
```

## Quick production hunt

Prepare public Nuclei, reputation, and ASN intelligence once, then hunt local
logs with only an input and its format:

```bash
shenron-lab setup
shenron production hunt --input ./logs --format apache
```

`setup` stores its Nuclei checkout in `$SHENRON_DATA_DIR/nuclei-templates`
and its reputation/ASN inputs in the same data directory when
`SHENRON_DATA_DIR` is set; otherwise it uses
`$XDG_DATA_HOME/shenron/nuclei-templates` or
`~/.local/share/shenron/nuclei-templates`. It writes the matching frozen report
alongside it as `nuclei-report.json`, plus optional `reputation.jsonl` and
`asn-ranges.tsv`. Hunt, ablation, replay, and
count-hypotheses use those locations by default. A hunt without `--output`
writes private artifacts to `./private-results/hunt-<UTC timestamp>/`.
`--nuclei-templates`, `--nuclei-report`, `--kev-report`, and `--output` remain
available for an explicit, reproducible workflow. KEV is optional; omitting it
uses an empty KEV set.

`shenron-lab nuclei update` and `shenron-lab reputation update` remain available
when only one public input family should be refreshed. `setup` downloads public
intelligence only and never transmits customer data.

## Sigma and log limits

See [supported aliases and syntax](docs/sigma-support.md). Unsupported rules are reported and skipped; nothing is matched with silently weakened logic. This MVP expects newline-delimited AWS WAF JSON records, not a complete JSON array or Firehose envelope.

This tool identifies known suspicious characteristics in historical web telemetry. A lack of findings does not prove that an application was not attacked or compromised.

Generated AWS WAF conditions are defensive hypotheses. They must be reviewed and validated before deployment.

## Candidate workflow

Candidates are deliberately separate from findings. A preventive export requires a local historical replay, fully faithful backend compatibility, and an explicit Web ACL priority. Shenron defaults to COUNT and never calls AWS or runs Terraform.

```bash
# Build one narrow candidate per CVE/request pattern from local private hunt evidence.
# For AWS WAF findings, records already terminated with BLOCK are excluded.
shenron candidate build --from-findings ./hunt/private-findings.jsonl \
  --telemetry aws-waf --output ./candidates/

# Replay an individual reviewed candidate against the full local historical log set.
# Coverage is measured from source-finding request IDs; it remains unavailable
# when those IDs were not recorded.
shenron candidate replay --candidate ./candidates/shenron-cve-202x-xxxxx-001.json \
  --input ./historical-logs --format aws-waf \
  --output ./candidates/candidate-replayed.json

# Emit a review-only COUNT rule and an evidence sidecar. No deployment occurs.
shenron candidate export --candidate ./candidates/candidate-replayed.json \
  --backend aws-waf-json --priority 100 \
  --output ./exports/candidate.aws-waf.json
```

`candidate compatibility`, `explain`, and `export` use the candidate's recorded telemetry profile by default. Pass `--telemetry` only to deliberately review or export against a different profile.

For OSSEC, the exporter produces a detection XML rule for raw nginx/Apache combined logs; it does not block edge traffic. Unsupported conditions, such as JA4 on standard combined logs, cause export refusal rather than condition removal.

## Design

The current design, AWS schema research, Sigma research, workflow, candidate safety model, and Nuclei limitation are documented under [docs](docs/). A worked, four-dataset evaluation is in the [case study](docs/case-study.md).

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
