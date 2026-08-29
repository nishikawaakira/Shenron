# Shenron

[日本語版 README](README.ja.md)

Shenron is a passive Rust threat-hunting engine for historical web telemetry. Its purpose is not merely to alert on suspicious requests: it is designed to help analysts turn public threat intelligence into local evidence and, in later phases, reviewable AWS WAF rule candidates with historical replay.

The MVP implements the first reliable vertical slice: streamed AWS WAF JSONL (including gzip) → normalized `WebEvent` → a deliberately small Sigma subset → JSONL or CSV findings. It supports AWS WAF action, labels, request metadata, and optional JA3/JA4 fingerprints. No network requests, exploit execution, AWS changes, candidate deployment, or automatic BLOCK actions occur.

It also includes a reproducible synthetic validation loop: project-owned AWS WAF-shaped corpora, separate ground truth, mutation tests, regression fixtures, and machine-readable validation results. See [validation](docs/validation.md) and [synthetic corpus generation](docs/synthetic-corpus.md).

Static Nuclei CVE analysis is available through `shenron-lab nuclei inventory` and `shenron-lab nuclei coverage`. It is passive local YAML analysis only; no template is executed or transmitted. See [detectability policy](docs/nuclei-detectability.md) and [Nuclei test generation](docs/nuclei-test-generation.md).

Read-only local AWS WAF production inspection and validated Nuclei hunting are available through `shenron production inspect` and `shenron production hunt`. They separate private investigation evidence from sanitized aggregate output and make no AWS changes. See [production hunting](docs/production-hunting.md).

`shenron production explain` reviews private findings locally: CVE/template mappings, per-request evidence, and breadth/depth/windowed triage of connection/client IP groups (`--show-source-ips`) or JA4 client fingerprints (`--show-fingerprints`). Each group carries an offline [behavior priority score](docs/production-hunting.md#behavior-priority-score) computed only from observed request behavior; it ranks entities for triage and is never a probability of malice, an exploitation or compromise determination, or attacker attribution. IP/ASN reputation is a separate, planned offline-enrichment layer joined from locally provided frozen datasets, never an inline external lookup.

`shenron production ablation` compares aggregate match volume from URI-only through validated Nuclei IR and request-specific IR. It is a volume comparison, not precision, ground truth, or an attack/compromise determination; see [detection-strategy ablation](docs/ablation.md).

Defensive candidates can be built from private hunt findings, replayed locally, reviewed for backend compatibility, and exported as COUNT-only AWS WAF JSON, Terraform rule fragments, or OSSEC detection XML. Export never deploys a control and refuses non-faithful translations. See the [candidate model](docs/waf-candidate-model.md).

The same passive scanner supports explicit `--format nginx` and `--format apache` parsing for standard combined logs. Source capabilities remain explicit; see [telemetry capabilities](docs/telemetry-capabilities.md).

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

The current design, AWS schema research, Sigma research, workflow, candidate safety model, and Nuclei limitation are documented under [docs](docs/).

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
