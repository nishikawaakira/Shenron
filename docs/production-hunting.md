# Production AWS WAF hunting

Production hunting is read-only and local. Shenron never modifies source logs, calls AWS, creates a WAF rule, replays traffic, scans a target, or executes a Nuclei template. Use a local JSON, JSONL, gzip, or directory-tree export.

Inspect structure before a hunt. This command reports only counts, timestamps, and field availability; it never prints raw requests.

```bash
cargo run --bin shenron -- inspect --input ./production-waf-logs --sample 10000
```

Prepare public Nuclei templates, CISA KEV, reputation, ASN, and published crawler-range
inputs once. This
downloads public intelligence only and never sends customer data:

```bash
shenron-lab setup
```

The default data directory is `$SHENRON_DATA_DIR` when set, otherwise
`$XDG_DATA_HOME/shenron` and then `~/.local/share/shenron`. Update writes
`nuclei-templates/`, `nuclei-report.json`, the downloaded CISA catalog as
`known_exploited_vulnerabilities.json`, its frozen join as `kev-report.json`,
KEV provenance as `kev-manifest.json`, `reputation.jsonl`, `asn-ranges.tsv`,
`bot-ranges.json`, and the bundled Sigma pack under
`sigma-rules/shenron-pack/` there. A full hunt then needs only a safely
recognizable local input:

```bash
cargo run --bin shenron -- hunt \
  --input ./production-waf-logs
```

Log-reading commands default to `--format auto`. Auto mode recognizes AWS WAF
JSON and vhost-prefixed Apache Combined input. Standard nginx and Apache
Combined lines are structurally identical, so Shenron does not assign a source
identity by guessing; pass `--format nginx` or `--format apache` for those
inputs. `--format apache` accepts both standard and vhost-prefixed lines,
including a mixture in one run, while `--format apache-vhost` strictly requires
the vhost prefix. If the format cannot be determined safely, the CLI asks for
one of those explicit formats.

`--nuclei-templates` and `--nuclei-report` remain available to select an
explicit frozen checkout/report pair. If neither default input exists, Shenron
asks you to run `shenron-lab nuclei update` or `shenron-lab setup` first. `--kev-report` is optional;
when omitted, the prepared default is used if present and otherwise KEV
membership is empty. The same prepared-input defaults apply
to `ablation`, `replay`, and `count-hypotheses`.

`shenron-lab setup` is an explicit download-only preparation command. It
refreshes public Nuclei templates and their frozen report together with the
public CISA KEV catalog and frozen Nuclei join, public reputation, and ASN
inputs in one local data directory; it never uploads logs,
findings, observed IPs, request values, or other customer data. Use
`--skip-nuclei`, `--skip-kev`, `--skip-reputation`, `--skip-asn`, `--skip-sigma`, or
`--skip-bot-ranges` to omit a family. `setup` installs the bundled,
Shenron-supported Sigma pack into
`<data-dir>/sigma-rules/shenron-pack/` (no network needed for it), which the
default-on hunt Sigma pass then picks up automatically. Pass
`--sigma-source <git-url>` (repeatable; suggested public source
`https://github.com/SigmaHQ/sigma.git`) to also fetch that repository's
`rules/web` subtree — download-only, into a sibling `sigma-rules/external/`
directory, with only the supported subset loaded and each source's license the
user's responsibility. The existing `nuclei update` and `reputation update`
commands remain available for individual refreshes, and `bot-ranges update`
refreshes only the operator-published crawler snapshot. The main `shenron`
analysis binary remains offline.

KEV preparation records the source URL, retrieval time, SHA-256, record count,
and output hashes in `kev-manifest.json`. If `--skip-nuclei` is used, setup
joins the catalog to an existing `nuclei-report.json`; when no such report is
available, it still freezes the public catalog but skips the join with an
explicit reason and does not treat that dependency skip as a setup failure.

When `bot-ranges.json` is present, hunt compares configured self-declared bot
User-Agents with the frozen operator-published ranges in the existing event
stream. An explicit `--bot-ranges <PATH>` overrides the default. Aggregate
operator/count/rate results enter the sanitized report; outside-range peer IPs
stay only in private `bot-range-observations.json`. Without a snapshot, hunt
prints a skip note and does not change CVE or Sigma metrics. An observed peer
outside a named operator's ranges is only outside that frozen list: published
ranges can be stale or incomplete, an intermediary can rewrite the peer, and
any client can set a User-Agent. It is not a determination of impersonation,
attack, or abuse. See [published bot ranges](published-bot-ranges.md).

Hunt also records these bot-range comparisons through the general
[declared-versus-observed consistency](declared-observed-consistency.md)
framework. Aggregate match, mismatch, and unavailable counts and the distinct
unavailable reasons are included in sanitized output; declaration and observed
values remain private in `declared-observed-observations.json`. Missing
reference data, an unsupported telemetry capability, and a missing event value
are each unavailable and are never converted into mismatches. Optional TLS
protocol/cipher fields exist in the normalized event model, but every current
profile leaves them unsupported and no current parser invents them.

By default `setup` writes to the standard data directory that `hunt`, `explain`,
and the other analysis commands read automatically. If you pass `--data-dir` to
write somewhere else, those commands do not look there by default, so pass the
matching `--nuclei-templates`, `--nuclei-report`, `--reputation-dataset`, and
`--asn-dataset` paths at analysis time. A partial failure (for example, one
temporarily unreachable list) still completes the other setup steps. Within the
reputation/ASN step, every configured public source is attempted independently:
successfully parsed records are written even when another source fails, while
`reputation-manifest.json` records each failed source and its reason. A source
failure is never hidden: setup prints its summary and exits non-zero. If all
reputation sources produce zero usable records, the reputation step fails; an
ASN failure likewise does not discard a successfully built reputation dataset.
The privacy guarantee that no customer data is transmitted holds on every
outcome.

If the direct peer is a known CDN, load balancer, or reverse proxy, supply every trusted proxy IP or CIDR explicitly to verify a forwarded end-client address. Shenron ignores `X-Forwarded-For` unless the observed direct peer is in this configured set: an untrusted peer can forge that header. Shenron evaluates a verified chain from right to left, removes only trusted proxy hops, and uses the first non-trusted address as `client_ip`. A missing, malformed, or all-trusted chain remains unavailable. Standard nginx/Apache Combined Log Format does not retain `X-Forwarded-For`, so it normally cannot provide `client_ip` even when `--trusted-proxy` is supplied.

```bash
cargo run --bin shenron -- hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --trusted-proxy 198.51.100.0/24 \
  --trusted-proxy 2001:db8:1234::/48
```

Restrict a hunt to an inclusive UTC time interval with RFC 3339 timestamps. The report records the selected interval and how many parseable events were excluded because they were outside the interval or had no timestamp.

```bash
cargo run --bin shenron -- hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --from 2026-04-01T00:00:00Z \
  --to 2026-04-30T23:59:59Z
```

Alongside the CVE-anchored Nuclei pass, `hunt` runs a generic **Sigma** detection pass **on by default**, in the same single stream over the corpus. It loads supported Sigma rules from `--rules <DIR>`, or from the prepared `<data-dir>/sigma-rules` when present; a missing rules directory is not an error (the hunt continues with Nuclei only), and `--no-sigma` disables the pass. Sigma covers generic request-pattern TTPs — for example secret-file path enumeration (`.env`, `/.aws/credentials`, `/.git/config`) — that map to no CVE template and are otherwise invisible to a CVE-only hunt. Sigma findings are kept fully distinct from the CVE track: every finding carries a `source` (`nuclei` or `sigma`), the sanitized report counts `sigma_matched_requests` (distinct requests with a Sigma detection), `sigma_rule_matches` (rule matches, which can exceed the request count because one request can match several rules), `distinct_sigma_rules`, and `sigma_rules_evaluated` separately from the CVE metrics, and Sigma findings never feed `candidate build` (candidates stay CVE- and Nuclei-IR-anchored). See [Sigma detection inside hunt](sigma-in-hunt.md).

For the bundled `shenron-secret-config-file-probe` rule, `hunt` additionally
labels matching requests by their observed response outcome. Sanitized metrics
contain only aggregate counts for all matches, 2xx responses, and unavailable
statuses; paths and peer IPs remain private. A 2xx match is highlighted as the
highest priority for human review in stdout and the private HTML report, but it
is not a hard filter and all matches remain stored and counted. A 2xx is only a
response status, not confirmation of file-content disclosure, attack,
exploitation, or compromise. An absent status remains unavailable and is never
treated as success.

Every hunt also measures [request concentration](request-concentration.md) in the
same stream, independently of Nuclei and Sigma. The sanitized report receives
counts and ratios only, while `request-concentration.json` is a private artifact
that contains paths and observed connection-peer IPs. Use the CTI-independent
`concentration` command when this volume context is needed without a
hunt. Neither command classifies concentration as a denial-of-service attempt,
attack, abuse, compromise, or attacker identity.

Use `concentration --path /example/path --show-source-ips` to
inspect deterministic request counts for observed connection peers on one exact
normalized path. The path and peer values remain private in
`request-concentration.json`; the sanitized report contains only aggregate
focus counts and rates. This is volume context only, never a DoS, attack,
abuse, compromise, or attribution determination.

Two related focuses build on the same private artifact. `--path-prefix /example`
analyzes a path and everything under it (segment-boundary matching, so
`/example` does not match `/examplex`); with `--show-paths` it lists the retained
sub-paths and their request counts, and with `--show-source-ips` the peers that
requested anything in the subtree. `--source-ip <IP>` reverses the view and
accepts one or more IPs, comma-separated or by repeating the flag: `--show-paths`
lists the union of URI paths those observed connection peers requested, and
`--show-source-ips` adds a private per-IP request breakdown for multiple selected
IPs. The three selector kinds are mutually exclusive; selected IPs, paths, and
breakdowns remain private, while the sanitized report still records only
aggregate counts and the focus kind. This is not attribution or a
DoS/attack/abuse determination. The private HTML report includes a per-IP chart
for a multiple-IP focus and retains the union path breakdown. See
[request concentration](request-concentration.md).

With `--show-source-ips`, the same private focus output also includes derived
network-prefix groups without replacing the individual peer-IP list. IPv4 uses
`/24` by default and `--ipv4-group-prefix` can change it; IPv6 uses `/48` by default
and `--ipv6-group-prefix` can change it. A shared prefix is not evidence of a
shared operator, owner, or actor.

Add `--asn-dataset <PATH>` to derive a second, private focus aggregation from a
local GeoLite2-ASN-compatible CSV or Shenron ASN range TSV. Under the same
`--show-source-ips` privacy gate it lists ASN, organization label, requests,
focused-request share, and distinct retained peers; unresolved peer and request
counts are disclosed. Prefix groups remain present. Without a dataset the run
succeeds and states that ASN grouping was omitted. An ASN is a routing-level
grouping: it does not establish that one operator controls the traffic and is
not attribution or a determination of a denial-of-service attempt, attack, or
abuse. ASN and organization values remain private and are not added to the
sanitized report.

## File-only CTI export

Convert an existing run without reprocessing logs using `shenron export
--results-dir <run-dir> --format stix|misp --output <file>`. The default reads
only sanitized aggregate results and includes no observed IP, URI path, host,
query, or header. `--include-observables` is an explicit private-data opt-in
that reads only observed peer IPs and URI paths from private findings. STIX
output always carries TLP marking (AMBER by default, RED when observables are
included); `--tlp` can override it. Export writes a local file only and never
pushes to TAXII or MISP. It creates no threat-actor or campaign assertion and
does not determine attack, exploitation, compromise, vulnerability, or
attribution. See [CTI export](cti-export.md).

## Private offline HTML report

Analyze raw logs and render the private report in the same hunt by adding
`--report`:

```bash
shenron hunt \
  --input ./logs \
  --format apache \
  --report \
  --report-lang ja
```

This writes the normal hunt artifacts and `<run-dir>/report.html` together;
`--report <path>` overrides the HTML destination. To rerender an existing hunt
or concentration run without reading or analyzing raw logs again, use
`shenron hunt --results-dir <run-dir> --report-lang ja`. Report generation is
the only action in `--results-dir` mode, and the default destination remains
`<run-dir>/report.html` even when `--report` is omitted.

The self-contained HTML uses inline CSS and server-generated inline SVG only:
there is no JavaScript, external resource, fetch, or network access. It combines
available aggregate provenance, private path/IP concentration and minute
timelines, focused-path prefix groups, the private hunt triage view, and an
observed-CVE table with matching Nuclei template IDs. Missing
artifacts are labeled unavailable, never inferred. The report is explicitly
private because it contains raw paths and observed peer IPs; it is not a
sanitized artifact. Every artifact-derived string is HTML-escaped. The charts
show volume and review priority only, not DoS, attack, exploitation, abuse,
compromise, probability of malice, or attribution. A report may be a file
inside the run directory (for example `<run-dir>/report.html`), since its source
is produced artifacts rather than raw logs; Shenron refuses to overwrite a
directory or a source artifact it reads. English is the default; `--report-lang ja`
localizes every human-readable report label and safety notice into Japanese.
Integer counts use three-digit comma grouping in both languages. See the full [HTML report
guide](html-report.md).

## Temporal comparison and retro-hunting

Compare two existing local run directories without re-streaming either corpus:

```bash
shenron compare \
  --baseline ./private-results/previous-run \
  --current ./private-results/current-run \
  --output ./private-results/comparison
```

The command writes sanitized `comparison-summary.json` and private
`comparison-detail.json`. Paths, connection-peer IPs, hosts, and JA4 values stay
private and print only with `--show-entities`, `--show-paths`, or
`--show-source-ips`. `hunt --baseline ./private-results/previous-run` writes the
same pair into the new hunt directory after the current artifact is complete.
First-seen and elevated-volume labels are triage context only; they are never a
determination of DoS, attack, abuse, exploitation, compromise, or attribution.

## Consolidated hunt triage view

Every `hunt` writes a consolidated connection/client-IP triage view
after its local matching pass. `triage-summary.json`
(`SANITIZED_HUNT_TRIAGE`) contains only aggregate cardinalities and a
behavior-priority tier histogram; `triage-view.json`
(`HUNT_TRIAGE_VIEW_PRIVATE`) contains the IP keys, identity labels, behavior
score, optional local ASN/reputation enrichment, and first-seen marker. The
normal hunt transcript prints only the sanitized counts. To intentionally view
the private ranked entries, pass `--show-triage`; `--limit` defaults to 20 and
accepts `0` to display all entries.

The ranking is deterministic: behavior score descending, then local
reputation score descending (no opinion last), then first-seen entities, then
the entity key. It uses the same local prepared ASN/reputation datasets as
`explain` when present and never performs an external lookup.
This is a **triage priority order for human review**, not threat severity or a
probability of malice. `first-seen` means new and worth review, never malicious;
neither it nor a score/reputation opinion determines attack, exploitation,
compromise, abuse, or attacker identity.

Long streaming commands (`hunt`, `ablation`, `replay`, `count-hypotheses`) emit a periodic progress heartbeat to stderr during a large scan. It reports only a running record count and a fixed command label — never a request value, IP address, or hostname — and stdout continues to carry findings and reports.

`--output` must be outside the raw-input tree. When omitted, hunt writes to `./private-results/hunt-<UTC timestamp>/`. The command writes `private-findings.jsonl` locally with investigation evidence, including fields that may be sensitive. `sanitized-research.json` has aggregate CVE/KEV counts, time ranges, WAF outcomes, cardinalities, and the sorted matching Nuclei `template_ids` for each observed CVE. Template IDs are public CTI metadata rather than customer data; no raw request values, IPs, hostnames, JA3/JA4 values, queries, or headers are included. The default `private-results/` location is ignored by Git, but that is only an additional safeguard and not a data-security boundary.

Every hunt also writes `run-manifest.json` beside the sanitized report. It records the Shenron version, generated time, telemetry profile, Nuclei report revision and provenance, optional KEV/Nuclei report byte lengths, trusted-proxy configuration, fixed triage baseline, time filters, and aggregate exclusion counts. The Nuclei report and, when supplied, the KEV report receive streaming SHA-256 values so reviewers can verify that frozen research inputs are identical; the templates directory remains identified by its pinned Nuclei revision rather than a directory-wide hash. This makes a run reviewable and reproducible without placing raw telemetry in the artifact: the manifest never contains raw request values, client or peer IP addresses, hosts, URI/query values, headers, or JA3/JA4 values.

Review the request-to-template mappings locally with `explain`. By default it hides only low-confidence display noise: findings that are both `response-unverified` and on a `generic` path such as `/robots.txt`. Pass `--include-generic` to restore every locally stored finding. This is a **display filter only**: it changes what is *listed* — the per-finding rows and the "Top request paths" summary — but it does **not** affect triage grouping or scoring. Entity grouping (IP/ASN/JA4) and the behavior priority score always see every finding that passed the `--waf-outcome` selection, so a source that mixes one distinctive probe with several generic ones still meets the repeated-pattern (breadth) basis. Because a group's observation and template counts are computed from all matching findings, they can exceed the rows shown; when low-confidence matches are hidden and a triage section is displayed, `explain` states this once in both text and JSON. `--include-generic` therefore changes only what is listed, never a group's score, observation count, or triage basis. Hunt records and sanitized reports always retain every match. The summary groups results by request method and path (up to 20 paths by default), bundling every distinct CVE and template that matched that path into one entry; this keeps paths shared by several CVEs readable. Each entry labels the path as `distinctive` or `generic`, and `--show-request` prints the deterministic path label for each individual matched method/path/query record. Generic paths, especially with response-unverified evidence, may be shared by unrelated applications and deserve closer review; the label is a triage heuristic only, never a precision, attack, exploitation, compromise, or vulnerable-product determination, and it never excludes a match. Add `--show-evidence` for all locally stored evidence, `--show-source-ips` for an IP-group summary, or `--show-fingerprints` for a JA4 client-fingerprint summary. Evidence labels distinguish the observed connection peer from a validated forwarded client IP. IP addresses and JA4 values are shown only from the local private findings file and are never added to the sanitized report. Use `--limit 0` only when intentionally reviewing every request path, IP address, and individual finding.

```bash
cargo run --bin shenron -- explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-request
```

```bash
# Triage client IPs only when a trusted forwarded chain was verified; otherwise
# the observed connection peer is used. The fixed breadth rule is at least
# three matching request observations and two template patterns. The fixed
# depth rule is at least ten matching request observations, including one-template repetition.
cargo run --bin shenron -- explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-source-ips
```

`requires investigation` means that breadth or depth of CVE-pattern behavior was observed for the selected grouping identity: `validated-client` where a trusted forwarded chain was verified, otherwise `observed-peer`. `validated-client` and `observed-peer` groups are intentionally never merged: if forwarded resolution works for only some requests, one actual sender can appear under both identities. `breadth` means several request observations across template patterns; `depth` means repeated observations even when only one template matched. It does **not** establish that the IP belongs to an attacker, that a vulnerability was exploited, or that a compromise occurred. An observed peer can be a proxy, CDN, load balancer, or NAT; monitoring and authorized vulnerability scanners can also produce either pattern. The default thresholds are fixed so the research baseline remains comparable and the CLI stays small.

The default triage policy is the fixed research baseline: breadth is three distinct request observations across two templates, and depth is ten distinct request observations. `explain` can explicitly override these with `--triage-breadth-observations`, `--triage-breadth-templates`, and `--triage-depth-observations`; any non-default value is labelled `CUSTOM` and is not comparable to the fixed baseline. Repeat `--triage-window` or comma-separate values (for example `--triage-window 10m,1h`) to evaluate the breadth/depth condition independently within several sliding windows. One supplied window retains the previous single-window behavior. Without a window, all observations remain eligible as before. Timestamp-less observations are excluded only from windowed evaluation and their count is shown for each group. Matching windows and their breadth/depth basis are listed deterministically.

[Ordered request sequences](request-sequences.md) add bounded timing and
ordering context to private entity triage. The default sequence window is ten
seconds and `--sequence-window` changes it. Sequence metrics do not change
matches, triage thresholds, or score points. `triage-view.json` keeps the raw
ordered patterns private, while `triage-summary.json` contains numeric counts
and seconds only. A short or regular sequence is an observation for review,
not a determination of automation, attack, abuse, compromise, or identity.

To retain recurring address-space observations across more than two runs,
explicitly opt in with `--observation-store <PATH>`. The [private append-only
observation memory](observation-store.md) records prefixes and optional locally
resolved ASNs, never individual IPs, and uses the run-manifest SHA-256 for
idempotency. It is not created when the option is absent, is never referenced
from sanitized output, and makes no network request.

`explain` writes the human-readable text report to stdout by default. Pass `--output-format json` to emit the same content — the path summary, the entity groupings with their behavior scores and score-component breakdowns, the triage basis, and (with `--show-*`) the requested private detail — as a machine-readable report carrying `report_kind: EXPLAIN_PRIVATE_TRIAGE`, and `--output <PATH>` to write it to a file. The JSON honors the identical privacy gates as the text: fields behind `--show-request`, `--show-evidence`, `--show-source-ips`, `--show-asn`, and `--show-fingerprints` stay gated, so no request value, IP, host, header, JA3/JA4, or request ID appears unless it was explicitly requested. Like the text report, the JSON is private analyst output and is never added to the sanitized report or run manifest.

## Behavior priority score

Each IP group (`--show-source-ips`) and JA4 fingerprint (`--show-fingerprints`) carries a **behavior priority score** in the range 0–100 with an `info`/`low`/`medium`/`high` tier. The score is a deterministic, transparent sum of capped contributions computed only from local hunt evidence:

- **template-breadth** (up to 24): distinct Nuclei template patterns matched.
- **cve-breadth** (up to 16): distinct CVEs matched.
- **observation-depth** (up to 16): distinct matching request observations, with repeated generic paths intentionally contributing only a small capped amount while distinctive-path observations contribute directly.
- **path-distinctiveness** (up to 4): distinct matching request observations on paths classified as `distinctive` by the documented transparent heuristic.
- **spread** (up to 20): for an IP group, distinct hosts targeted; for a JA4 fingerprint, the larger of separately counted validated-client and observed-peer identity populations. These identity types are never merged.
- **waf-unblocked** (up to 15): the fraction of deduplicated matched requests that the WAF recorded as `ALLOW` or `COUNT`, among requests with a known `BLOCK` / `ALLOW` / `COUNT` outcome. Unknown actions contribute neither numerator nor denominator.
- **windowed-burst** (5): added once when at least one `--triage-window` meets the breadth or depth condition. Additional matching windows are listed in the component detail but never add more points.

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

`explain --show-source-ips` can join the private IP groups to frozen local datasets without any HTTP request or external API call. `shenron-lab reputation update` can prepare public reputation and ASN inputs once; when `<data-dir>/reputation.jsonl` and/or `<data-dir>/asn-ranges.tsv` exist, `explain` automatically uses them unless an explicit `--reputation-dataset` or `--asn-dataset` path overrides them. The data directory is `SHENRON_DATA_DIR`, then `$XDG_DATA_HOME/shenron`, then `~/.local/share/shenron`. Explicit datasets also remain supported: `--asn-dataset ./GeoLite2-ASN-Blocks-CSV.csv` accepts a GeoLite2-ASN-compatible CSV, while the prepared `asn-ranges.tsv` is a sorted IPv4 `start_ip<TAB>end_ip<TAB>asn<TAB>org` file resolved by binary search. The JSONL dataset has one record per opinion, for example `{"scope":"ip","value":"203.0.113.7","score":90,"source":"example-feed","categories":["scanner"],"as_of":"2026-08-01"}`. `scope` is `ip`, `cidr`, or `asn`; scores are integer values from 0 through 100, categories default to an empty list, and ASN values can be strings or numbers.

```bash
cargo run --bin shenron -- explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-source-ips \
  --asn-dataset ./datasets/GeoLite2-ASN-Blocks-CSV.csv \
  --reputation-dataset ./datasets/reputation.jsonl
```

The display records each supplied dataset's path, streaming SHA-256, and record count. For connection/client IP groups, it retains all matching local opinions but selects the reputation headline from the most-specific available scope: IP first, then CIDR, then ASN (using the highest score within that scope). `validated-client` and `observed-peer` identities are never merged. Dataset values and private IPs are printed only in local `explain` output and are never copied to sanitized reports or run manifests. Reputation is a third-party opinion, not evidence of an attack, exploitation, compromise, vulnerable product, or attacker identity; all evaluation remains offline and no IP is sent outside Shenron.

### ASN grouping

Add `--show-asn` to group private findings by a locally resolved ASN. It uses the prepared default ASN file when available, or an explicit `--asn-dataset`; without either it prints a warning and no ASN groups. Like IP grouping, it keeps `validated-client` and `observed-peer` identities separate even when they resolve to the same ASN. Its spread is the number of distinct member IPs in the larger of those two separate identity populations; they are never merged. Findings whose selected client/peer IP is absent, malformed, or unresolved by the local ASN dataset are excluded from ASN aggregation and counted in the output.

```bash
cargo run --bin shenron -- explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-asn \
  --asn-dataset ./datasets/GeoLite2-ASN-Blocks-CSV.csv \
  --reputation-dataset ./datasets/reputation.jsonl
```

When a reputation dataset is also supplied, each ASN group displays only ASN-scoped opinions and the highest ASN score as its headline. ASN grouping and reputation are local analyst aids, not a determination of an attack, exploitation, compromise, or attacker identity. They make no network request, send no IP externally, and never add private values to sanitized artifacts.

The hunt rebuilds only request matchers whose template IDs have both `SUPPORTED` conversion and `passed` synthetic validation in the supplied frozen report. It uses the same normalization and matcher as the Nuclei validation pipeline; there is no simplified production matcher. A response-dependent generic root probe such as `GET {{BaseURL}}` is not converted into passive CVE-related request evidence: request logs alone cannot reproduce the response fingerprint that makes that probe meaningful. If its template also contains an explicit exploit path, query, or distinctive request header, that explicit alternative remains eligible. `--format nginx` parses standard Combined access logs. `--format apache` automatically recognizes standard Apache Combined and vhost-prefixed `other_vhosts_access.log` lines in the same input, preserving a vhost as `host` only when present; `--format apache-vhost` remains available to require the prefix strictly. These profiles do not expose WAF actions, so outcome and protection-gap metrics are explicitly unavailable for those sources.

Each CVE-related request match has a separate request-specificity label. `request-specific` means that the recovered Detection IR requires a query, URI fragment, or explicit header. `response-unverified` means that only method and path matched; even a familiar path such as `/.env` remains response-unverified because Nuclei's response confirmation cannot be reproduced from request telemetry alone. This label measures resistance to accidental request-side matches, not severity, attack confidence, exploitation success, compromise, or the presence of a vulnerable product. The `HIGH`/`MEDIUM`/`LOW` totals are template detectability only, never attack or compromise confidence. Sanitized hunt reports retain only per-CVE and aggregate `distinctive_path_matches` / `generic_path_matches` counts, never paths themselves; they label the same transparent path-distinctiveness heuristic used by `explain` and do not remove a match.

An `ALLOW` or `COUNT` result is reported as **not blocked according to available WAF action evidence** for a CVE-related request match. This is a protection gap, not evidence that exploitation succeeded. Non-terminating WAF matches are reported separately as COUNT-related evidence. Candidate WAF controls remain analyst-authored defensive hypotheses and must be replayed and reviewed before any deployment; Shenron does not generate or deploy blocking rules in this command.
