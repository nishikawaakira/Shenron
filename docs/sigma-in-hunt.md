# Sigma detection inside `production hunt`

## Why

`production hunt` is CVE-anchored: it matches the validated Nuclei Detection IR and
reports per-CVE evidence. That is the right design for tracking known
vulnerabilities and it does not change. But a source that systematically
enumerates secret-file paths — `.env` and its variants, `/.aws/credentials`,
`/.ssh/id_rsa`, `/.git/config`, `/terraform.tfstate`, service-account JSON, AI-tool
config files — produces only the few findings whose paths happen to map to a CVE
template. The remaining requests are a generic TTP, not a known CVE, so they are
invisible to a CVE-only pass.

`hunt` already streams every event exactly once. The Sigma engine (previously
reachable only from the separate `scan` command) can run in that same pass at
almost no additional cost, covering generic path-pattern detection alongside the
CVE-anchored Nuclei pass.

## Default on

Sigma evaluation is **on by default**. `hunt` loads its rules from the default
rules directory (`<data-dir>/sigma-rules`) when present, or from an explicit
`--rules <PATH>`. If neither exists, Sigma is skipped with a one-line note (not an
error), so a hunt with no Sigma rules behaves exactly as before. `--no-sigma`
disables the pass explicitly. Only the intentionally small supported Sigma subset
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
- **`sanitized-research.json`**: separate aggregate counts — `sigma_rule_matches`,
  `distinct_sigma_rules`, and `sigma_rules_evaluated` — kept apart from the CVE
  metrics. Sigma matches never enter `cve_related_request_matches` or the CVE
  findings list, even when a Sigma rule carries a CVE tag; the CVE track stays
  Nuclei-only.
- **`run-manifest.json`**: records how many supported Sigma rules were evaluated
  (0 when the pass was disabled or no rules were found).
- **`production explain`**: the source is shown per finding and in the JSON view;
  the low-confidence display filter treats Sigma matches by the same
  request-specificity/path-distinctiveness rule as Nuclei matches.

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
