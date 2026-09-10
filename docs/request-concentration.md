# Request concentration

## First path-segment diversity per observed source

Each retained source reports distinct first path segments across all requests
and across responses with status 404. The first segment is the text between
the initial slash and the next slash in `uri_path` (queries are excluded).
`/` contributes one empty segment. No percent-decoding, case folding, or other
normalization occurs: `/Images`, `/images`, and `/%69mages` differ. Missing
paths are excluded and counted. Missing status cannot contribute to the 404
set; profiles without status report the 404 metrics as unavailable.

The default is 256 retained segments **per source per set**, independently for
all requests and 404 responses (`ConcentrationLimits.max_source_segments`).
First-observed segments are retained; each observation of an unretained segment
beyond the cap is counted, including repeats. Sources with such omissions are
also counted. A capped cardinality is a lower bound, not an exact cardinality.
Source tracking itself still uses the existing source cap and disclosures.
Segment strings never enter artifacts. Private source records contain counts
and omissions; sanitized output contains only numeric summaries. `daily` adds
one summary line: maximum and median 404-segment count across all retained
sources, including zero counts. For an even number of sources the median is
the arithmetic mean of the two central sorted values. No retained sources
means unavailable maximum/median. When a source is capped, these aggregate
statistics describe retained lower bounds as well.

The number of distinct first path segments a source requested is a count of
what the log recorded. A high count can equally result from a crawler, a broken
link tree, a security scanner, an inventory tool, or a person browsing widely.
It is not a determination of probing, scanning, enumeration, an attack, or abuse.

`shenron concentration` measures the distribution of requests in a
local historical corpus without requiring Nuclei templates, KEV data, or any
network access:

```bash
shenron concentration \
  --input ./logs \
  --format apache \
  --output ./private-results/concentration
```

The command streams the input once and always prints aggregate-only volume
context: distinct tracked URI paths and source IPs, the leading path and top-ten
shares, distinct tracked source IPs for the leading path, peak and median
requests across simultaneous UTC bucket widths, plus every exclusion or
tracking-cap count. The deterministic defaults are `1m`, `10m`, `1h`, and `1d`;
repeat `--rate-window` (or comma-separate values) to select another exact set.
It
writes `sanitized-research.json`, which contains only counts, ratios, status
classes, and availability metadata, and `request-concentration.json`, a private
artifact containing URI paths and observed connection-peer IPs. The default
stdout never displays either private value; use `--show-paths` or
`--show-source-ips` deliberately when reviewing the private artifact.

The same aggregate runs as part of every `hunt`, independently of
Nuclei and Sigma matching. It therefore exposes volume shapes even if no CVE or
generic rule matches a request. Hunt writes the private concentration artifact
alongside `private-findings.jsonl`; its sanitized concentration summary is
embedded in `sanitized-research.json`.

## Lightweight daily summary

`shenron daily` runs the same bounded concentration accumulator but prints only
an aggregate summary suitable for cron or another monitoring system:

```bash
shenron daily --input /var/log/nginx --format nginx
shenron daily --input /var/log/nginx --format nginx --output-format json
```

The output includes total requests, retained distinct observed source IPs, the
leading path's share and retained source count, requests per distinct source,
and peak/median ratios for the configured simultaneous rate windows. It never
prints a URI path, IP address, or query value. By default it creates no run
directory or artifact. Supplying `--output <DIR>` explicitly writes the normal
private and sanitized concentration artifacts without changing the computed
numbers. Parse failures, time-range exclusions, undated exclusions, and every
tracking-cap omission remain visible in both text and JSON output.

The command applies no threshold and does not use its exit status to classify
traffic. Its values are measurements for downstream review, not alerts or
determinations of automation, denial of service, attack, abuse, compromise, or
attacker identity.

### Response outcome health measurements

The daily summary also reports corpus-wide 2xx, 3xx, ordinary 4xx, nginx 499,
and 5xx counts and shares. The added `client_closed_request_499` count is a
subset of the backward-compatible `client_error` total; displayed ordinary
4xx subtracts that subset so 499 is not hidden among other client-error
responses. These aggregate numeric values are also present in sanitized output.
If the selected telemetry profile cannot expose response status, the entire
response outcome is `null`/unavailable rather than a fabricated zero.

For each existing simultaneous rate window, Shenron uses the same admitted UTC
buckets to report the minimum 2xx share and maximum 5xx share. Buckets below
`--response-bucket-min-requests` are excluded and counted; the deterministic
default is 10 requests. Undated observations and records beyond the existing
bucket cap remain separately disclosed. This inclusion floor is configurable
for corpus scale, but it is not an alert threshold and produces no label or
special exit status.

### Locating response windows and separating individual codes

Each response window also records `minimum_success_bucket_start` and
`maximum_server_error_bucket_start` in UTC. Equal shares select the earliest
retained bucket, independently of event arrival order. The existing bucket
admission cap still follows input order. Missing timestamps are excluded and
counted, and sparse buckets remain excluded by `--response-bucket-min-requests`
(default 10). No eligible bucket means unavailable extrema and start times.

`daily` and `concentration` accept
`--response-success-share-threshold-percent <0..100>` (default **50**).
`buckets_below_success_threshold` counts eligible buckets with a success share
strictly below that percentage; equality is not included. This is a descriptive
count, not a label, alert, or special exit status. A count does not establish
that the buckets are consecutive or identify a continuous incident interval.
The configured percentage is recorded alongside the count. Older artifacts
without these additive fields remain readable; their start times and configured
percentage are unavailable rather than inferred.

`response_status_codes` contains the observed individual numeric HTTP codes,
including 401, 403, 429, 499, 502 and 504 when present, not a fixed list of codes.
The corpus, each retained path, each retained peer, and focus details have
separate maps. The default cap is **128 retained codes per aggregate/entity**,
configurable through `ConcentrationLimits.max_status_codes_per_entity` for
library callers. Maps admit the first observed codes and serialize in numeric
order. `maximum_codes` records the limit and `observations_beyond_cap` counts
every observation of an unretained code, including repeats. Retained codes
continue to accumulate; missing status remains `unavailable` in the existing
class counts, never a fabricated status code. With a nonzero omission count,
the code map is incomplete, even though the existing class totals stay exact
within that entity's retained scope. Statusless profiles use `null` code maps.

Private peer and focus-peer records include `response_outcomes` shares (all
requests for that peer in scope, including unavailable statuses, form the
denominator). Existing `client_error` still includes 499; ordinary 4xx subtracts
that subset, so reporting 499 separately does not double-count it. Focus
address blocks combine retained peers' class and code counts without new
streaming state. Block code admission follows the deterministic private source
order (requests descending, then IP ascending), then numeric code order, and
discloses both upstream omissions and its own code-cap omissions. Blocks cannot
recover peers omitted by the existing focus-source cap. A shared prefix does
not imply a shared operator, owner, or actor.

Use `--show-source-ips` to display peer/block distributions and shares;
`--show-paths` displays private per-path code detail. The private HTML report
shows code counts and response shares in chart details and UTC window starts.
Sanitized artifacts contain only numeric aggregate code counts, shares and
UTC window metadata, never a source-IP/status mapping or raw path/query value.

A rise in client-closed responses (499) alone does not identify a cause. The
same increase can result from a slow backend, an origin that stopped responding,
a client that abandons requests early, or automated collection that does not
wait for the full response. The presence or absence of gateway timeouts, the
individual status codes, and how the sources are distributed are separate
observations that a human can use to distinguish them. None of these is a
determination of an outage, degraded availability, automated collection, an
attack, or abuse. Standard combined logs suffice; no response time is inferred
and no additional log fields or network lookups are required.

Response outcome shares are counts of what the log recorded. A low success
share can equally result from redirect-heavy routing, authentication flows,
health checks, clients that disconnect early, a slow backend, or an unavailable
origin. It is not a determination of an outage, degraded availability, an
attack, or abuse.

In one four-site review, three comparison sites recorded 2xx shares of
77.0–99.7% and 499 shares of 0.0–0.5%. These are case-specific reference
observations only, not a threshold, baseline, or availability classification.

### Explicit processed-file index

Recurring `daily` or `concentration` runs may opt into whole-file skipping with
`--processed-index <PATH>`. The private index records each processed file's
local path, byte length, modification time, SHA-256, and deterministic
execution identifier. On a later run an unchanged matching entry is skipped;
each candidate is hashed so a size-preserving content change is still processed
in full. Use `--reprocess-all` with the index to ignore every prior entry.

Skipping is never enabled implicitly. Every indexed run reports the number of
files skipped, including zero, and states that its totals and concentration
shares cover **only files processed in that run**, not historical cumulative
traffic. A modified append-only file is processed in full, while unchanged
rotated files are skipped. The index is private because it contains local file
paths. Shenron neither estimates omitted traffic nor silently treats current
totals as cumulative.

When a cumulative multi-run view is required, keep ordinary run artifacts and
use temporal `compare` or the explicit private `--observation-store` workflow.
The processed-file index is an I/O optimization, not an aggregate store.

## Private path trend across existing runs

`shenron trend` extracts one explicitly selected URI path from multiple
existing `request-concentration.json` artifacts without reading raw logs:

```bash
shenron trend \
  --results-dir ./private-results/day-1 \
  --results-dir ./private-results/day-2 \
  --results-dir ./private-results/day-3 \
  --path /documents/example.pdf
```

Supplying `--path` is the explicit privacy opt-in: text and JSON output are
private and include that path plus local result-directory names. For each run,
the command reports request count, share, retained distinct observed source
IPs, requests per source, HTTP status-class counts, and retained-path rank.
Result directories are sorted and deduplicated for deterministic output.

An absent retained path is emitted as `observation: null` in JSON and "No
retained record" in text, never as a measured zero. The accompanying path-cap
count remains visible because a missing record can mean either no observation
or exclusion after the deterministic tracking cap. These measurements do not
determine denial of service, attack, abuse, compromise, or attacker identity.

## Requests per distinct source IP

Each retained path and optional focus reports
`requests_per_source_ip`, calculated as `requests / distinct_source_ips`.
The value is zero when no source IP was retained, so it never produces a
non-finite JSON number. If source-IP tracking reaches its disclosed cap, the
ratio uses the retained cardinality and must be read together with the cap
count. The value appears in both the private detail and the numeric-only
sanitized summary; neither sanitized location adds an IP address or path.

Requests per distinct source is a ratio of two observed counts. A high ratio
can equally result from a single client polling a resource, a proxy aggregating
many users behind one address, an embedded asset fetched repeatedly in one
session, or automated traffic. It is not a determination of automation, a
denial-of-service attempt, an attack, or abuse. Shenron applies no threshold or
classification to this ratio.

In one reviewed 14-day case, ordinary-day leading-path values were 4.2–7.4,
while two unusually concentrated high-volume days measured 1,456.9 and
3,107.7. These are case-specific reference observations, not a baseline,
threshold, or generalizable label.

## Query-shape measurements per path

Each retained path and each optional focus records three query-shape metrics in
the existing streaming pass: `requests_with_query`,
`distinct_query_strings`, and `distinct_query_keys`. The query attachment share
is `requests_with_query / requests`; the distinct-string ratio is
`distinct_query_strings / requests`. A ratio near 1.0 means that nearly every
request carried a different literal query string, such as a timestamp, UUID, or
nonce. In that shape, a cache or rate limit keyed on the full URL cannot reuse
many entries. A much smaller ratio means the observed query value space was
reused—for example, 1,000 retained strings over 761,978 requests leaves more
opportunity for reuse. Neither ratio identifies why the shape occurred.

Query strings and query values are never serialized into either the private or
sanitized artifact. Sanitized output contains counts and ratios only. Retained
literal query-key names are written to the private artifact and printed by the
CLI only behind `--show-paths`; without that opt-in, both artifacts contain
counts only because key names can themselves be sensitive. Hunt does not retain
query-key names in its private artifact.
Keys are measured literally before the first `=` in each `&`-separated
component, without decoding or semantic interpretation.

Exact query-string tracking is capped at 100,000 retained strings per path and
per focus; key-name tracking is separately capped at 10,000. When a cap is
reached, Shenron reports the retained cardinality as **at least** that value and
discloses the number of subsequent observations that were not admitted. It
does not estimate the missing cardinality and uses no approximate data
structure.

These are query-shape counts for one URI path. A high share of requests carrying
a query, or a high ratio of distinct query strings to requests, can equally
result from cache-control or asset-versioning parameters the site itself emits,
analytics parameters, pagination, search, or an attempt to avoid a cache or a
rate limit keyed on the full URL. This is a request-shape measurement for human
review, not a determination of cache evasion, a denial-of-service attempt, an
attack, abuse, or attacker identity.

This context also matters when reviewing a defensive candidate. A path-only
condition for `/.env`, for example, also matches `/.env?x=1`; review the query
attachment and cardinality measurements before choosing whether a candidate
needs path-only, query-aware, or other conditions. Shenron does not infer or
label the appropriate condition from these counts.

## Focus (`--path`, `--path-prefix`, `--source-ip`)

A focus narrows the private review to one selector kind. The three are mutually
exclusive: `--path` matches one exact normalized path, `--path-prefix` matches a
path and everything under it, and `--source-ip` selects one or more observed
connection peers and lists the union of paths they requested. Source IPs may be
comma-separated or supplied by repeating the flag; duplicates are removed and
the retained values are ordered deterministically. In every case the
analyst-supplied path or IPs and all per-key detail stay in
`request-concentration.json`;
`sanitized-research.json` records only aggregate counts and the focus kind, and
never a raw path or IP address.

### Exact path (`--path`)

For a local review of the observed connection peers that requested one exact
path, use `--path` with `concentration`:

```bash
shenron concentration \
  --input ./logs \
  --format apache \
  --output ./private-results/concentration \
  --path /example/path \
  --show-source-ips
```

Matching is exact against the normalized `uri_path`; query strings do not alter
the focused path. The normal transcript echoes the analyst-supplied focus path
and reports aggregate request/source-IP counts and per-minute statistics, but
does not print IPs unless `--show-source-ips` is supplied. The private
`request-concentration.json` contains the focus path and deterministic
per-peer request counts; `sanitized-research.json` contains only the aggregate
focus counts and never contains the path or an IP address. Focused source-IP
tracking has its own fixed cap, and the output discloses observations from new
peers that could not be retained after that cap.

When `--show-source-ips` is enabled, Shenron retains the individual peer-IP
list and also prints a derived address-block aggregation. IPv4 sources default
to `/24` groups; IPv6 sources default to `/48` groups. Use
`--ipv4-group-prefix <0..32>` to choose the IPv4 prefix length and
`--ipv6-group-prefix <0..128>` to choose the IPv6 length. The private focus
section of `request-concentration.json` contains each prefix, its request
count and share within the focused path, and its distinct retained peer-IP
count. Prefix strings are never added to the sanitized report.

Addresses are grouped by network prefix only. A shared prefix is not evidence
of a shared operator, owner, or actor: allocations can be split across tenants
and one operator can span many prefixes. This is an address-block aggregation
of observed request volume, not an attribution or a determination of a
denial-of-service attempt, attack, or abuse.

### Path subtree (`--path-prefix`)

To analyze a path and everything under it (a directory-style rollup), use
`--path-prefix`. Matching is on path segments, so `/wp-admin` covers `/wp-admin`
and `/wp-admin/...` but not `/wp-adminx`; a trailing slash on the prefix is
ignored, and `/` covers everything.

```bash
shenron concentration \
  --input ./logs \
  --format apache \
  --output ./private-results/concentration \
  --path-prefix /wp-admin \
  --show-paths \
  --show-source-ips
```

`--show-paths` lists the individual sub-paths under the prefix with their
request counts; `--show-source-ips` lists the observed peers that requested
anything in the subtree, plus the same address-block aggregation as an exact
path focus. The sanitized report adds only `distinct_uri_paths` and the
retained-path cap disclosure; the sub-paths themselves stay private. Distinct
focus paths are bounded by a fixed cap, and observations beyond it are disclosed
as a count.

### Source IP (`--source-ip`)

To review what one or more observed connection peers requested, use
`--source-ip`. This is the reverse of a path focus: it lists the union of URI
paths those peers sent, with request counts.

```bash
shenron concentration \
  --input ./logs \
  --format apache \
  --output ./private-results/concentration \
  --source-ip 198.51.100.7,198.51.100.8 \
  --show-paths
```

The equivalent repeated form is `--source-ip 198.51.100.7 --source-ip
198.51.100.8`. `--show-paths` prints the union of paths the selected peers
requested, most-requested first. When two or more IPs are selected,
`--show-source-ips` also prints the request-count breakdown for each selected
IP. The selected IPs, paths, and per-IP breakdown stay in
`request-concentration.json`; the sanitized report records only aggregate
counts and the `source-ip` focus kind. Each IP is an observed connection peer
and may be a CDN, load balancer, NAT, or proxy; this is request-volume context,
not attacker attribution. Address-block grouping flags do not apply to a
source-IP focus because its peer set is explicitly selected. A private HTML
report generated from this run shows the per-IP chart when multiple IPs were
selected, while preserving the existing path breakdown.

### Optional ASN enrichment

Pass `--asn-dataset <PATH>` with a focus selector and `--show-source-ips` to
display a private ASN aggregation beside the existing address-prefix groups.
The dataset may be a GeoLite2-ASN-compatible CSV or Shenron's prepared
`asn-ranges.tsv`. Each group reports the ASN, organization label, request count,
share of focused requests, and distinct retained peer IP count. Peers that are
invalid or unresolved are not inferred: their peer and request counts are
disclosed separately. Without `--asn-dataset`, concentration still succeeds
and states that ASN grouping was omitted.

ASN is the semantically appropriate routing unit when the question concerns a
possible shared network operator. Prefix aggregation remains a
local-dataset-free alternative, preserving concentration's ability to run
without CTI inputs. An ASN is nevertheless only a routing-level grouping. It
does not establish that one operator controls the traffic, and it is not
attribution or a determination of a denial-of-service attempt, attack, or
abuse. ASN numbers, organization labels, peers, prefixes, and paths stay in the
private artifact; sanitized output receives none of those values.

A focused peer is only the observed direct connection address. It may be a CDN,
load balancer, NAT, proxy, or other intermediary, and concentration on a path
does not determine a denial-of-service attempt, attack, abuse, exploitation,
compromise, or attacker identity. The output states only that an observed peer
requested the selected path a counted number of times.

## Interpretation boundary

This is a request-volume distribution only. It is not a determination of a
denial-of-service attempt, an attack, abuse, compromise, or an attacker
identity. High concentration on one path can result from a popular or embedded
resource, a misconfigured client, a crawler, a load test, or a denial-of-service
attempt. Distinguishing these possibilities requires human review and context
outside the access log. Shenron deliberately has no concentration threshold,
score, alert, candidate-generation path, or enforcement action.

The legacy `requests per minute` field is calculated from non-empty observed UTC
minute buckets and remains unchanged. The additive `request_rates` array reports
peak, median, peak-to-median ratio, undated observations, and bucket-cap
exclusions for every configured width. Events without timestamps are excluded
from every rate and counted explicitly. The same windows are evaluated for an
exact-path, path-prefix, or source-IP focus. These profiles describe request
volume shape only; they do not determine automation, denial of service, attack,
abuse, compromise, or identity.
Response-byte totals are reported only for telemetry profiles that record them;
AWS WAF marks them unavailable rather than replacing them with zero.

The private `request-concentration.json` also stores the retained global and,
when selected, focused-path minute buckets as an epoch-minute/request-count
series in ascending order. `hunt --results-dir <run-dir>` report rendering uses this series for its inline
SVG timeline. The series is never copied into `sanitized-research.json`. Minute
tracking is bounded at 1,000,000 distinct buckets for each global/focus map;
records in new buckets beyond that cap are counted and disclosed, while already
retained buckets continue to receive exact counts.

For every retained global minute, the private artifact also stores aggregate
request counts split into HTTP status classes 1xx, 2xx, 3xx, 4xx, and 5xx. The
HTML report renders these as five lines on a shared scale immediately after the
global request timeline. This status series follows the same minute-bucket cap
and deterministic order, is not copied into sanitized output, and contains no
raw path or IP values. Response status classes are observation context, not a
determination of attack, exploitation, or compromise.

The private artifact additionally records 1xx, 2xx, 3xx, 4xx, 5xx, other, and
unavailable response-status counts for every retained observed connection peer
and every retained focus peer. The HTML report renders the Top-N peer rows as a
stacked status-class graph while preserving the ordinary per-IP request chart.
Missing status is `unavailable`, never 2xx. Per-peer status distribution is
response context only, not a determination of a denial-of-service attempt,
attack, exploitation, abuse, compromise, or attacker identity; an observed peer
may be a CDN, load balancer, NAT, or proxy.

## Bounded tracking and reproducibility

The default exact key limits are 100,000 URI paths, 1,000,000 source IPs,
2,000,000 retained source/path pairs, 100,000 distinct query strings per path,
and 10,000 distinct query keys per path. New keys are admitted in input order until
a limit is reached; afterward, existing keys continue to receive exact counts
while new-key observations are omitted from the detailed maps. Shenron reports
`paths_beyond_tracking_cap`, `source_ips_beyond_tracking_cap`, and
`source_path_pairs_beyond_tracking_cap` so a reviewer can see when a displayed
distinct count or source convergence count is a lower bound. A source whose
path pairs are incomplete does not receive a claimed `most_requested_uri_path`
in the private artifact. No sketch or
probabilistic approximation is used.
