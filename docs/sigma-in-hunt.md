# Sigma detection inside `hunt`

## Why

`hunt` is CVE-anchored: it matches the validated Nuclei Detection IR and
reports per-CVE evidence. That is the right design for tracking known
vulnerabilities and it does not change. But a source that systematically
enumerates secret-file paths — `.env` and its variants, `/.aws/credentials`,
`/.ssh/id_rsa`, `/.git/config`, `/terraform.tfstate`, service-account JSON, AI-tool
config files — produces only the few findings whose paths happen to map to a CVE
template. The remaining requests are a generic TTP, not a known CVE, so they are
invisible to a CVE-only pass.

`hunt` is the single detection entry point and streams every event exactly once.
The Sigma engine runs in that same pass, covering generic path-pattern detection
alongside the CVE-anchored Nuclei pass. For a setup-free Sigma-only stream, use
`hunt --no-nuclei --rules <PATH>`; Nuclei inputs are then neither resolved nor
required. `--no-nuclei` and `--no-sigma` cannot be combined.

## Default on

Sigma evaluation is **on by default**. `hunt` loads its rules from the default
rules directory (`<data-dir>/sigma-rules`) when present, or from an explicit
`--rules <PATH>`. If neither exists, Sigma is skipped with a one-line note (not an
error), so a hunt with no Sigma rules behaves exactly as before. `--no-sigma`
disables the pass explicitly.

Without `--output`, `hunt` writes private findings only to stdout as JSONL (or
flattened CSV with `--output-format csv`) and creates no files. These records can
contain raw IPs, paths, hosts, headers, and other request evidence. With
`--output <DIR>`, the same pass writes the complete private and sanitized run
artifacts. `validate-rules` remains available for checking the supported Sigma
subset without running a hunt.

`shenron-lab setup` populates that default directory. It installs the **bundled
Shenron pack** — a small set of curated, Shenron-supported generic-TTP rules
embedded in the binary (secret/config-file probes, version-control exposure
probes, management/actuator endpoint probes) — into
`<data-dir>/sigma-rules/shenron-pack/`, so the default-on pass works out of the
box with no network fetch. `setup --sigma-source <git-url>` additionally fetches
an external source's `rules/web` subtree (download-only, e.g.
`https://github.com/SigmaHQ/sigma.git`) into a sibling
`<data-dir>/sigma-rules/external/<name>/` directory; only the supported subset
loads, and each source's license is the user's responsibility. The two origins
stay in separate directories so they remain distinguishable. `--skip-sigma`
omits the whole Sigma step. Only the intentionally small supported Sigma subset
runs; unsupported rules are reported and skipped, never matched with weakened
logic. Templates are never executed and no network is accessed.

## How a Sigma-sourced finding is represented

Every finding carries a `source` discriminator: `nuclei` (the serde default, so
older private findings load unchanged) or `sigma`. A Sigma finding records:

- `source: "sigma"`,
- `template_id`: the Sigma rule id (its stable identifier in artefacts),
- `rule_title`: the Sigma rule title,
- `sigma_level`: the rule's declared level, when present,
- `cves`: the CVE tags the Sigma rule itself carries (often empty — a Sigma
  finding is a TTP match, not a per-CVE claim).

Two fields are deliberately **not** borrowed from the Nuclei model:

- `detectability` is a Nuclei-conversion concept and is recorded as `UNKNOWN` for
  Sigma. Sigma matches are therefore not counted in the Nuclei HIGH/MEDIUM/LOW
  detectability histogram; they are counted separately (see below).
- `request_specificity` is conservatively `response-unverified`: a Sigma match is a
  request-side heuristic with no Nuclei response confirmation. Consequently a
  Sigma match on a **generic** path is hidden by `explain`'s default low-confidence
  filter exactly as a response-unverified Nuclei match is, while a Sigma match on a
  **distinctive** path (for example `/.aws/credentials`) is surfaced. Path
  distinctiveness is path-based and applies to Sigma findings unchanged.

## The two sources stay distinguishable in every artefact

- **`private-findings.jsonl`**: the `source` field on every record.
- **`sanitized-research.json`**: separate aggregate counts kept apart from the
  CVE metrics — `sigma_rules_evaluated`, `sigma_matched_requests`,
  `sigma_rule_matches`, and `distinct_sigma_rules`. **`sigma_matched_requests`**
  is the number of distinct requests that carried at least one Sigma detection;
  **`sigma_rule_matches`** is the number of rule matches, and because one request
  can match several rules it can exceed `sigma_matched_requests`. Report request
  counts with `sigma_matched_requests`, not `sigma_rule_matches`. Sigma matches
  never enter `cve_related_request_matches` or the CVE findings list, even when a
  Sigma rule carries a CVE tag; the CVE track stays Nuclei-only.
- **`run-manifest.json`**: records how many supported Sigma rules were evaluated
  (0 when the pass was disabled or no rules were found).
- **`explain`**: the source is shown per finding and in the JSON view;
  the low-confidence display filter treats Sigma matches by the same
  request-specificity/path-distinctiveness rule as Nuclei matches.

## Highest-priority review for 2xx sensitive/config-file probes

For the bundled `shenron-secret-config-file-probe` rule, `hunt` records the
observed HTTP response status in each private finding. The sanitized metrics
separately count all matching requests, those with a 2xx response, and those
whose telemetry did not provide a status. A missing status is always reported
as unavailable and is never treated as 2xx. No match is removed by this label.

When at least one matching request received a 2xx response, the CLI marks that
count as the highest priority for human review. A generated private HTML report
also lists the matching request path, observed connection peer, status, and
timestamp in a prominent private section. A 2xx is only the recorded response
outcome: it does not confirm that file contents were disclosed or that an
attack, exploitation, or compromise occurred. The observed peer may be a CDN,
load balancer, NAT, or proxy and is not attacker attribution.

## Candidate eligibility

Sigma findings do **not** feed `candidate build`. Defensive candidates stay
CVE- and Nuclei-IR-anchored: the COUNT-candidate evidence bar depends on the
validated Nuclei request-specific IR and per-CVE anchoring, which a generic Sigma
TTP match does not carry. `candidate build` skips `source: "sigma"` findings and
reports how many it excluded, so a Sigma finding is never silently promoted into a
WAF rule candidate. Sigma is a visibility and detection layer; turning a generic
TTP into an enforcement control remains a deliberate, separate human decision.

## Non-assertion

A Sigma match is a labeled detection of a request-side pattern. Like every other
Shenron output it never asserts an attack, exploitation, compromise, vulnerable
product, or attacker identity.
