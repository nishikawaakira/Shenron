# Production AWS WAF hunting

Production hunting is read-only and local. Shenron never modifies source logs, calls AWS, creates a WAF rule, replays traffic, scans a target, or executes a Nuclei template. Use a local JSON, JSONL, gzip, or directory-tree export.

Inspect structure before a hunt. This command reports only counts, timestamps, and field availability; it never prints raw requests.

```bash
cargo run --bin shenron -- production inspect --input ./production-waf-logs --format aws-waf --sample 10000
```

Prepare public Nuclei templates, reputation, and ASN inputs once. This
downloads public intelligence only and never sends customer data:

```bash
shenron-lab setup
```

The default data directory is `$SHENRON_DATA_DIR` when set, otherwise
`$XDG_DATA_HOME/shenron` and then `~/.local/share/shenron`. Update writes
`nuclei-templates/`, `nuclei-report.json`, `reputation.jsonl`,
`asn-ranges.tsv`, and the bundled Sigma pack under `sigma-rules/shenron-pack/`
there. A full hunt then needs only the local input and its explicit format:

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf
```

`--nuclei-templates` and `--nuclei-report` remain available to select an
explicit frozen checkout/report pair. If neither default input exists, Shenron
asks you to run `shenron-lab nuclei update` or `shenron-lab setup` first. `--kev-report` is optional;
when omitted, KEV membership is empty. The same prepared-input defaults apply
to `production ablation`, `production replay`, and `production count-hypotheses`.

`shenron-lab setup` is an explicit download-only preparation command. It
refreshes public Nuclei templates and their frozen report together with public
reputation and ASN inputs in one local data directory; it never uploads logs,
findings, observed IPs, request values, or other customer data. Use
`--skip-nuclei`, `--skip-reputation`, `--skip-asn`, or `--skip-sigma` to omit a
family. `setup` installs the bundled, Shenron-supported Sigma pack into
`<data-dir>/sigma-rules/shenron-pack/` (no network needed for it), which the
default-on hunt Sigma pass then picks up automatically. Pass
`--sigma-source <git-url>` (repeatable; suggested public source
`https://github.com/SigmaHQ/sigma.git`) to also fetch that repository's
`rules/web` subtree — download-only, into a sibling `sigma-rules/external/`
directory, with only the supported subset loaded and each source's license the
user's responsibility. The existing `nuclei update` and `reputation update`
commands remain available for individual refreshes. The main `shenron` analysis
binary remains offline.

By default `setup` writes to the standard data directory that `hunt`, `explain`,
and the other analysis commands read automatically. If you pass `--data-dir` to
write somewhere else, those commands do not look there by default, so pass the
matching `--nuclei-templates`, `--nuclei-report`, `--reputation-dataset`, and
`--asn-dataset` paths at analysis time. A partial failure (for example, one
temporarily unreachable list) still completes the other steps, prints a summary,
and exits non-zero; the privacy guarantee that no customer data is transmitted
holds on every outcome.

If the direct peer is a known CDN, load balancer, or reverse proxy, supply every trusted proxy IP or CIDR explicitly to verify a forwarded end-client address. Shenron ignores `X-Forwarded-For` unless the observed direct peer is in this configured set: an untrusted peer can forge that header. Shenron evaluates a verified chain from right to left, removes only trusted proxy hops, and uses the first non-trusted address as `client_ip`. A missing, malformed, or all-trusted chain remains unavailable. Standard nginx/Apache Combined Log Format does not retain `X-Forwarded-For`, so it normally cannot provide `client_ip` even when `--trusted-proxy` is supplied.

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --trusted-proxy 198.51.100.0/24 \
  --trusted-proxy 2001:db8:1234::/48
```

Restrict a hunt to an inclusive UTC time interval with RFC 3339 timestamps. The report records the selected interval and how many parseable events were excluded because they were outside the interval or had no timestamp.

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --from 2026-04-01T00:00:00Z \
  --to 2026-04-30T23:59:59Z
```

Alongside the CVE-anchored Nuclei pass, `hunt` runs a generic **Sigma** detection pass **on by default**, in the same single stream over the corpus. It loads supported Sigma rules from `--rules <DIR>`, or from the prepared `<data-dir>/sigma-rules` when present; a missing rules directory is not an error (the hunt continues with Nuclei only), and `--no-sigma` disables the pass. Sigma covers generic request-pattern TTPs — for example secret-file path enumeration (`.env`, `/.aws/credentials`, `/.git/config`) — that map to no CVE template and are otherwise invisible to a CVE-only hunt. Sigma findings are kept fully distinct from the CVE track: every finding carries a `source` (`nuclei` or `sigma`), the sanitized report counts `sigma_matched_requests` (distinct requests with a Sigma detection), `sigma_rule_matches` (rule matches, which can exceed the request count because one request can match several rules), `distinct_sigma_rules`, and `sigma_rules_evaluated` separately from the CVE metrics, and Sigma findings never feed `candidate build` (candidates stay CVE- and Nuclei-IR-anchored). See [Sigma detection inside hunt](sigma-in-hunt.md).

Every hunt also measures [request concentration](request-concentration.md) in the
same stream, independently of Nuclei and Sigma. The sanitized report receives
counts and ratios only, while `request-concentration.json` is a private artifact
that contains paths and observed connection-peer IPs. Use the CTI-independent
`production concentration` command when this volume context is needed without a
hunt. Neither command classifies concentration as a denial-of-service attempt,
attack, abuse, compromise, or attacker identity.

Long streaming commands (`hunt`, `ablation`, `replay`, `count-hypotheses`) emit a periodic progress heartbeat to stderr during a large scan. It reports only a running record count and a fixed command label — never a request value, IP address, or hostname — and stdout continues to carry findings and reports.

`--output` must be outside the raw-input tree. When omitted, hunt writes to `./private-results/hunt-<UTC timestamp>/`. The command writes `private-findings.jsonl` locally with investigation evidence, including fields that may be sensitive. `sanitized-research.json` has aggregate CVE/KEV counts, time ranges, WAF outcomes, and cardinalities only; it never includes raw request values, IPs, hostnames, JA3/JA4 values, queries, or headers. The default `private-results/` location is ignored by Git, but that is only an additional safeguard and not a data-security boundary.

Every hunt also writes `run-manifest.json` beside the sanitized report. It records the Shenron version, generated time, telemetry profile, Nuclei report revision and provenance, optional KEV/Nuclei report byte lengths, trusted-proxy configuration, fixed triage baseline, time filters, and aggregate exclusion counts. The Nuclei report and, when supplied, the KEV report receive streaming SHA-256 values so reviewers can verify that frozen research inputs are identical; the templates directory remains identified by its pinned Nuclei revision rather than a directory-wide hash. This makes a run reviewable and reproducible without placing raw telemetry in the artifact: the manifest never contains raw request values, client or peer IP addresses, hosts, URI/query values, headers, or JA3/JA4 values.

Review the request-to-template mappings locally with `production explain`. By default it hides only low-confidence display noise: findings that are both `response-unverified` and on a `generic` path such as `/robots.txt`. Pass `--include-generic` to restore every locally stored finding. This is a **display filter only**: it changes what is *listed* — the per-finding rows and the "Top request paths" summary — but it does **not** affect triage grouping or scoring. Entity grouping (IP/ASN/JA4) and the behavior priority score always see every finding that passed the `--waf-outcome` selection, so a source that mixes one distinctive probe with several generic ones still meets the repeated-pattern (breadth) basis. Because a group's observation and template counts are computed from all matching findings, they can exceed the rows shown; when low-confidence matches are hidden and a triage section is displayed, `explain` states this once in both text and JSON. `--include-generic` therefore changes only what is listed, never a group's score, observation count, or triage basis. Hunt records and sanitized reports always retain every match. The summary groups results by request method and path (up to 20 paths by default), bundling every distinct CVE and template that matched that path into one entry; this keeps paths shared by several CVEs readable. Each entry labels the path as `distinctive` or `generic`, and `--show-request` prints the deterministic path label for each individual matched method/path/query record. Generic paths, especially with response-unverified evidence, may be shared by unrelated applications and deserve closer review; the label is a triage heuristic only, never a precision, attack, exploitation, compromise, or vulnerable-product determination, and it never excludes a match. Add `--show-evidence` for all locally stored evidence, `--show-source-ips` for an IP-group summary, or `--show-fingerprints` for a JA4 client-fingerprint summary. Evidence labels distinguish the observed connection peer from a validated forwarded client IP. IP addresses and JA4 values are shown only from the local private findings file and are never added to the sanitized report. Use `--limit 0` only when intentionally reviewing every request path, IP address, and individual finding.

```bash
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-request
```

```bash
# Triage client IPs only when a trusted forwarded chain was verified; otherwise
# the observed connection peer is used. The fixed breadth rule is at least
# three matching request observations and two template patterns. The fixed
# depth rule is at least ten matching request observations, including one-template repetition.
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-source-ips
```

`requires investigation` means that breadth or depth of CVE-pattern behavior was observed for the selected grouping identity: `validated-client` where a trusted forwarded chain was verified, otherwise `observed-peer`. `validated-client` and `observed-peer` groups are intentionally never merged: if forwarded resolution works for only some requests, one actual sender can appear under both identities. `breadth` means several request observations across template patterns; `depth` means repeated observations even when only one template matched. It does **not** establish that the IP belongs to an attacker, that a vulnerability was exploited, or that a compromise occurred. An observed peer can be a proxy, CDN, load balancer, or NAT; monitoring and authorized vulnerability scanners can also produce either pattern. The default thresholds are fixed so the research baseline remains comparable and the CLI stays small.

The default triage policy is the fixed research baseline: breadth is three distinct request observations across two templates, and depth is ten distinct request observations. `production explain` can explicitly override these with `--triage-breadth-observations`, `--triage-breadth-templates`, and `--triage-depth-observations`; any non-default value is labelled `CUSTOM` and is not comparable to the fixed baseline. Add `--triage-window 10m` (or a positive `s`, `m`, `h`, or `d` duration) to require the breadth/depth condition within one sliding time window. Without it, all observations remain eligible as before. Timestamp-less observations are excluded only from windowed evaluation and their count is shown for each group.

`production explain` writes the human-readable text report to stdout by default. Pass `--output-format json` to emit the same content — the path summary, the entity groupings with their behavior scores and score-component breakdowns, the triage basis, and (with `--show-*`) the requested private detail — as a machine-readable report carrying `report_kind: EXPLAIN_PRIVATE_TRIAGE`, and `--output <PATH>` to write it to a file. The JSON honors the identical privacy gates as the text: fields behind `--show-request`, `--show-evidence`, `--show-source-ips`, `--show-asn`, and `--show-fingerprints` stay gated, so no request value, IP, host, header, JA3/JA4, or request ID appears unless it was explicitly requested. Like the text report, the JSON is private analyst output and is never added to the sanitized report or run manifest.

## Behavior priority score

Each IP group (`--show-source-ips`) and JA4 fingerprint (`--show-fingerprints`) carries a **behavior priority score** in the range 0–100 with an `info`/`low`/`medium`/`high` tier. The score is a deterministic, transparent sum of capped contributions computed only from local hunt evidence:

- **template-breadth** (up to 24): distinct Nuclei template patterns matched.
- **cve-breadth** (up to 16): distinct CVEs matched.
- **observation-depth** (up to 16): distinct matching request observations, with repeated generic paths intentionally contributing only a small capped amount while distinctive-path observations contribute directly.
- **path-distinctiveness** (up to 4): distinct matching request observations on paths classified as `distinctive` by the documented transparent heuristic.
- **spread** (up to 20): for an IP group, distinct hosts targeted; for a JA4 fingerprint, the larger of separately counted validated-client and observed-peer identity populations. These identity types are never merged.
- **waf-unblocked** (up to 15): the fraction of deduplicated matched requests that the WAF recorded as `ALLOW` or `COUNT`, among requests with a known `BLOCK` / `ALLOW` / `COUNT` outcome. Unknown actions contribute neither numerator nor denominator.
- **windowed-burst** (5): added when `--triage-window` is set and the group met the breadth or depth condition within a single sliding window.

The weights total 100 when every reachable component saturates, and each contribution is monotonic in its signal, so the number is auditable rather than an opaque model output. Repeated generic paths remain visible but cannot dominate the observation-depth contribution; distinctive-path observations receive an explicit, small triage contribution. These labels are request-side heuristics, not ground truth. The output separately reports `request-specific` and `response-unverified` request observations. A group with only response-unverified (URI-only) evidence is capped at 74/100 (`medium`): Nuclei response confirmation cannot be reproduced from request telemetry. It ranks entities for human triage from observed request behavior only. It is **not** a probability of malice, a precision or true-/false-positive estimate, an exploitation, compromise, or vulnerable-product determination, or attacker attribution.

**Normalization against the reachable maximum.** Some components are unreachable for a given telemetry profile: nginx/Apache combined logs record no WAF outcome, so **waf-unblocked** (15) is structurally 0, and standard nginx/Apache combined logs carry no host, so an IP or ASN group's **spread** (20) cannot be measured. Rather than leave those profiles systematically depressed against a fixed 100-point denominator, the raw total is normalized against the maximum the active profile and dimension can actually reach, then the same `info`/`low`/`medium`/`high` thresholds apply. The tiers themselves are unchanged; only the denominator adapts. The profile is taken from the telemetry source recorded on each finding (older findings without one fall back to the full-capability maximum). Unreachable components are still listed in the breakdown with 0 points and a reason stating that they do not count toward the reachable maximum, and the displayed score names the reachable ceiling (for example `64/100 (medium); normalized against this telemetry profile's reachable maximum of 85/100`) so the number stays auditable. What each documented profile can reach:

| Component | AWS WAF | nginx / Apache combined | Apache vhost combined |
| --- | --- | --- | --- |
| template-breadth, cve-breadth, observation-depth, path-distinctiveness, windowed-burst | reachable | reachable | reachable |
| spread (IP / ASN groups) | reachable (host) | unreachable (no host) | reachable (host) |
| spread (JA4 groups) | reachable | n/a (no JA4) | n/a (no JA4) |
| waf-unblocked | reachable | unreachable (no WAF outcome) | unreachable (no WAF outcome) |

Reachability follows the telemetry *capability*, not the corpus: on a corpus with a single host the `host` capability is present, so the 20-point `spread` component stays in the denominator while `spread` is 1 for every entity, so scores compress toward the bottom tier. This is deliberate — making reachability depend on how many hosts a particular file happens to contain would make scores incomparable between runs — so on a single-host corpus the ranking of entities *within the run* matters more than the absolute tier.

This behavioral score is intentionally computed offline and involves no network lookup. IP and ASN reputation enrichment is a separate local layer; it does not change behavior-score inputs, weights, or tiers.

## IP/ASN reputation enrichment (offline)

`production explain --show-source-ips` can join the private IP groups to frozen local datasets without any HTTP request or external API call. `shenron-lab reputation update` can prepare public reputation and ASN inputs once; when `<data-dir>/reputation.jsonl` and/or `<data-dir>/asn-ranges.tsv` exist, `explain` automatically uses them unless an explicit `--reputation-dataset` or `--asn-dataset` path overrides them. The data directory is `SHENRON_DATA_DIR`, then `$XDG_DATA_HOME/shenron`, then `~/.local/share/shenron`. Explicit datasets also remain supported: `--asn-dataset ./GeoLite2-ASN-Blocks-CSV.csv` accepts a GeoLite2-ASN-compatible CSV, while the prepared `asn-ranges.tsv` is a sorted IPv4 `start_ip<TAB>end_ip<TAB>asn<TAB>org` file resolved by binary search. The JSONL dataset has one record per opinion, for example `{"scope":"ip","value":"203.0.113.7","score":90,"source":"example-feed","categories":["scanner"],"as_of":"2026-08-01"}`. `scope` is `ip`, `cidr`, or `asn`; scores are integer values from 0 through 100, categories default to an empty list, and ASN values can be strings or numbers.

```bash
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-source-ips \
  --asn-dataset ./datasets/GeoLite2-ASN-Blocks-CSV.csv \
  --reputation-dataset ./datasets/reputation.jsonl
```

The display records each supplied dataset's path, streaming SHA-256, and record count. For connection/client IP groups, it retains all matching local opinions but selects the reputation headline from the most-specific available scope: IP first, then CIDR, then ASN (using the highest score within that scope). `validated-client` and `observed-peer` identities are never merged. Dataset values and private IPs are printed only in local `explain` output and are never copied to sanitized reports or run manifests. Reputation is a third-party opinion, not evidence of an attack, exploitation, compromise, vulnerable product, or attacker identity; all evaluation remains offline and no IP is sent outside Shenron.

### ASN grouping

Add `--show-asn` to group private findings by a locally resolved ASN. It uses the prepared default ASN file when available, or an explicit `--asn-dataset`; without either it prints a warning and no ASN groups. Like IP grouping, it keeps `validated-client` and `observed-peer` identities separate even when they resolve to the same ASN. Its spread is the number of distinct member IPs in the larger of those two separate identity populations; they are never merged. Findings whose selected client/peer IP is absent, malformed, or unresolved by the local ASN dataset are excluded from ASN aggregation and counted in the output.

```bash
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-asn \
  --asn-dataset ./datasets/GeoLite2-ASN-Blocks-CSV.csv \
  --reputation-dataset ./datasets/reputation.jsonl
```

When a reputation dataset is also supplied, each ASN group displays only ASN-scoped opinions and the highest ASN score as its headline. ASN grouping and reputation are local analyst aids, not a determination of an attack, exploitation, compromise, or attacker identity. They make no network request, send no IP externally, and never add private values to sanitized artifacts.

The hunt rebuilds only request matchers whose template IDs have both `SUPPORTED` conversion and `passed` synthetic validation in the supplied frozen report. It uses the same normalization and matcher as the Nuclei validation pipeline; there is no simplified production matcher. A response-dependent generic root probe such as `GET {{BaseURL}}` is not converted into passive CVE-related request evidence: request logs alone cannot reproduce the response fingerprint that makes that probe meaningful. If its template also contains an explicit exploit path, query, or distinctive request header, that explicit alternative remains eligible. `--format nginx` parses standard Combined access logs. `--format apache` automatically recognizes standard Apache Combined and vhost-prefixed `other_vhosts_access.log` lines in the same input, preserving a vhost as `host` only when present; `--format apache-vhost` remains available to require the prefix strictly. These profiles do not expose WAF actions, so outcome and protection-gap metrics are explicitly unavailable for those sources.

Each CVE-related request match has a separate request-specificity label. `request-specific` means that the recovered Detection IR requires a query, URI fragment, or explicit header. `response-unverified` means that only method and path matched; even a familiar path such as `/.env` remains response-unverified because Nuclei's response confirmation cannot be reproduced from request telemetry alone. This label measures resistance to accidental request-side matches, not severity, attack confidence, exploitation success, compromise, or the presence of a vulnerable product. The `HIGH`/`MEDIUM`/`LOW` totals are template detectability only, never attack or compromise confidence. Sanitized hunt reports retain only per-CVE and aggregate `distinctive_path_matches` / `generic_path_matches` counts, never paths themselves; they label the same transparent path-distinctiveness heuristic used by `explain` and do not remove a match.

An `ALLOW` or `COUNT` result is reported as **not blocked according to available WAF action evidence** for a CVE-related request match. This is a protection gap, not evidence that exploitation succeeded. Non-terminating WAF matches are reported separately as COUNT-related evidence. Candidate WAF controls remain analyst-authored defensive hypotheses and must be replayed and reviewed before any deployment; Shenron does not generate or deploy blocking rules in this command.
