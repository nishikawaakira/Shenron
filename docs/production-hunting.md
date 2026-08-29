# Production AWS WAF hunting

Production hunting is read-only and local. Shenron never modifies source logs, calls AWS, creates a WAF rule, replays traffic, scans a target, or executes a Nuclei template. Use a local JSON, JSONL, gzip, or directory-tree export.

Inspect structure before a hunt. This command reports only counts, timestamps, and field availability; it never prints raw requests.

```bash
cargo run --bin shenron -- production inspect --input ./production-waf-logs --format aws-waf --sample 10000
```

Run a full hunt only with the pinned Nuclei template checkout and frozen reports that validated the detections:

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --nuclei-templates /path/to/nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --output ./private-results/hunt-2026-08-24
```

If the direct peer is a known CDN, load balancer, or reverse proxy, supply every trusted proxy IP or CIDR explicitly to verify a forwarded end-client address. Shenron ignores `X-Forwarded-For` unless the observed direct peer is in this configured set: an untrusted peer can forge that header. Shenron evaluates a verified chain from right to left, removes only trusted proxy hops, and uses the first non-trusted address as `client_ip`. A missing, malformed, or all-trusted chain remains unavailable. Standard nginx/Apache Combined Log Format does not retain `X-Forwarded-For`, so it normally cannot provide `client_ip` even when `--trusted-proxy` is supplied.

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --trusted-proxy 198.51.100.0/24 \
  --trusted-proxy 2001:db8:1234::/48 \
  --nuclei-templates /path/to/nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --output ./private-results/hunt-behind-proxy
```

Restrict a hunt to an inclusive UTC time interval with RFC 3339 timestamps. The report records the selected interval and how many parseable events were excluded because they were outside the interval or had no timestamp.

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --nuclei-templates /path/to/nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --from 2026-04-01T00:00:00Z \
  --to 2026-04-30T23:59:59Z \
  --output ./private-results/april-2026
```

`--output` must be outside the raw-input tree. The command writes `private-findings.jsonl` locally with investigation evidence, including fields that may be sensitive. `sanitized-research.json` has aggregate CVE/KEV counts, time ranges, WAF outcomes, and cardinalities only; it never includes raw request values, IPs, hostnames, JA3/JA4 values, queries, or headers. The default `private-results/` location is ignored by Git, but that is only an additional safeguard and not a data-security boundary.

Every hunt also writes `run-manifest.json` beside the sanitized report. It records the Shenron version, generated time, telemetry profile, Nuclei report revision and provenance, KEV/Nuclei report byte lengths, trusted-proxy configuration, fixed triage baseline, time filters, and aggregate exclusion counts. The Nuclei and KEV report files also receive streaming SHA-256 values so reviewers can verify that frozen research inputs are identical; the templates directory remains identified by its pinned Nuclei revision rather than a directory-wide hash. This makes a run reviewable and reproducible without placing raw telemetry in the artifact: the manifest never contains raw request values, client or peer IP addresses, hosts, URI/query values, headers, or JA3/JA4 values.

Review the request-to-template mappings locally with `production explain`. It displays a CVE/template summary (up to 20 mappings) by default so a large hunt remains readable; small demo hunts therefore display all their mappings just as before. Each summary includes `distinctive-path` and `generic-path` counts, and `--show-request` prints the deterministic path label for each individual matched method/path/query record. Generic paths, especially with response-unverified evidence, may be shared by unrelated applications and deserve closer review; the label is a triage heuristic only, never a precision, attack, exploitation, compromise, or vulnerable-product determination, and it never excludes a match. Add `--show-evidence` for all locally stored evidence, `--show-source-ips` for an IP-group summary, or `--show-fingerprints` for a JA4 client-fingerprint summary. Evidence labels distinguish the observed connection peer from a validated forwarded client IP. IP addresses and JA4 values are shown only from the local private findings file and are never added to the sanitized report. Use `--limit 0` only when intentionally reviewing every mapping, IP address, and individual finding.

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

## Behavior priority score

Each IP group (`--show-source-ips`) and JA4 fingerprint (`--show-fingerprints`) carries a **behavior priority score** in the range 0–100 with an `info`/`low`/`medium`/`high` tier. The score is a deterministic, transparent sum of capped contributions computed only from local hunt evidence:

- **template-breadth** (up to 24): distinct Nuclei template patterns matched.
- **cve-breadth** (up to 16): distinct CVEs matched.
- **observation-depth** (up to 20): distinct matching request observations.
- **spread** (up to 20): for an IP group, distinct hosts targeted; for a JA4 fingerprint, the larger of separately counted validated-client and observed-peer identity populations. These identity types are never merged.
- **waf-unblocked** (up to 15): the fraction of deduplicated matched requests that the WAF recorded as `ALLOW` or `COUNT`, among requests with a known `BLOCK` / `ALLOW` / `COUNT` outcome. Unknown actions contribute neither numerator nor denominator.
- **windowed-burst** (5): added when `--triage-window` is set and the group met the breadth or depth condition within a single sliding window.

The weights total 100 at saturation and each contribution is monotonic in its signal, so the number is auditable rather than an opaque model output. The output separately reports `request-specific` and `response-unverified` request observations. A group with only response-unverified (URI-only) evidence is capped at 74/100 (`medium`): Nuclei response confirmation cannot be reproduced from request telemetry. It ranks entities for human triage from observed request behavior only. It is **not** a probability of malice, a precision or true-/false-positive estimate, an exploitation, compromise, or vulnerable-product determination, or attacker attribution.

This behavioral score is intentionally computed offline and involves no network lookup. IP and ASN reputation enrichment is a separate local layer; it does not change behavior-score inputs, weights, or tiers.

## IP/ASN reputation enrichment (offline)

`production explain --show-source-ips` can join the private IP groups to analyst-supplied frozen datasets without any HTTP request or external API call. Add `--asn-dataset ./GeoLite2-ASN-Blocks-CSV.csv` for a GeoLite2-ASN-compatible CSV and `--reputation-dataset ./reputation.jsonl` for local third-party opinions. The ASN CSV accepts `network,autonomous_system_number,autonomous_system_organization` or `network,asn,as_org`/`as_name`; overlapping IPv4 and IPv6 CIDRs resolve by longest prefix. The JSONL dataset has one record per opinion, for example `{"scope":"ip","value":"203.0.113.7","score":90,"source":"example-feed","categories":["scanner"],"as_of":"2026-08-01"}`. `scope` is `ip`, `cidr`, or `asn`; scores are integer values from 0 through 100, categories default to an empty list, and ASN values can be strings or numbers.

```bash
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-source-ips \
  --asn-dataset ./datasets/GeoLite2-ASN-Blocks-CSV.csv \
  --reputation-dataset ./datasets/reputation.jsonl
```

The display records each supplied dataset's path, streaming SHA-256, and record count. For connection/client IP groups, it retains all matching local opinions but selects the reputation headline from the most-specific available scope: IP first, then CIDR, then ASN (using the highest score within that scope). `validated-client` and `observed-peer` identities are never merged. Dataset values and private IPs are printed only in local `explain` output and are never copied to sanitized reports or run manifests. Reputation is a third-party opinion, not evidence of an attack, exploitation, compromise, vulnerable product, or attacker identity; all evaluation remains offline and no IP is sent outside Shenron.

### ASN grouping

Add `--show-asn` with `--asn-dataset` to group private findings by a locally resolved ASN. `--show-asn` without the ASN dataset prints a warning and no ASN groups. Like IP grouping, it keeps `validated-client` and `observed-peer` identities separate even when they resolve to the same ASN. Its spread is the number of distinct member IPs in the larger of those two separate identity populations; they are never merged. Findings whose selected client/peer IP is absent, malformed, or unresolved by the local ASN CSV are excluded from ASN aggregation and counted in the output.

```bash
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-asn \
  --asn-dataset ./datasets/GeoLite2-ASN-Blocks-CSV.csv \
  --reputation-dataset ./datasets/reputation.jsonl
```

When a reputation dataset is also supplied, each ASN group displays only ASN-scoped opinions and the highest ASN score as its headline. ASN grouping and reputation are local analyst aids, not a determination of an attack, exploitation, compromise, or attacker identity. They make no network request, send no IP externally, and never add private values to sanitized artifacts.

The hunt rebuilds only request matchers whose template IDs have both `SUPPORTED` conversion and `passed` synthetic validation in the supplied frozen report. It uses the same normalization and matcher as the Nuclei validation pipeline; there is no simplified production matcher. A response-dependent generic root probe such as `GET {{BaseURL}}` is not converted into passive CVE-related request evidence: request logs alone cannot reproduce the response fingerprint that makes that probe meaningful. If its template also contains an explicit exploit path, query, or distinctive request header, that explicit alternative remains eligible. `--format nginx` and `--format apache` parse standard combined access logs into the same event model. Their standard profiles do not expose WAF actions, so outcome and protection-gap metrics are explicitly unavailable for those sources.

Each CVE-related request match has a separate request-specificity label. `request-specific` means that the recovered Detection IR requires a query, URI fragment, or explicit header. `response-unverified` means that only method and path matched; even a familiar path such as `/.env` remains response-unverified because Nuclei's response confirmation cannot be reproduced from request telemetry alone. This label measures resistance to accidental request-side matches, not severity, attack confidence, exploitation success, compromise, or the presence of a vulnerable product. The `HIGH`/`MEDIUM`/`LOW` totals are template detectability only, never attack or compromise confidence. Sanitized hunt reports retain only per-CVE and aggregate `distinctive_path_matches` / `generic_path_matches` counts, never paths themselves; they label the same transparent path-distinctiveness heuristic used by `explain` and do not remove a match.

An `ALLOW` or `COUNT` result is reported as **not blocked according to available WAF action evidence** for a CVE-related request match. This is a protection gap, not evidence that exploitation succeeded. Non-terminating WAF matches are reported separately as COUNT-related evidence. Candidate WAF controls remain analyst-authored defensive hypotheses and must be replayed and reviewed before any deployment; Shenron does not generate or deploy blocking rules in this command.
