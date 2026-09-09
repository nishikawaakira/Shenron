# Request concentration

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
