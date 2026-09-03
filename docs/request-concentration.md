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
requests per observed minute, plus every exclusion or tracking-cap count. It
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

### Relationship to ASN enrichment

ASN is the semantically appropriate unit when the question concerns a possible
shared network operator. Shenron already supports this separately through
`AsnDatabase` and `explain --show-asn --asn-dataset`. Prefix
aggregation is a local-dataset-free alternative for `concentration`:
it keeps the command usable without CTI inputs or an ownership lookup. When a
local ASN dataset is available, ASN grouping is the more accurate choice for
operator-oriented analysis; prefix groups remain only address-block volume
aggregation.

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

`requests per minute` is calculated from non-empty observed UTC minute buckets;
events without timestamps are excluded from that rate and counted explicitly.
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

## Bounded tracking and reproducibility

The default exact key limits are 100,000 URI paths, 1,000,000 source IPs, and
2,000,000 retained source/path pairs. New keys are admitted in input order until
a limit is reached; afterward, existing keys continue to receive exact counts
while new-key observations are omitted from the detailed maps. Shenron reports
`paths_beyond_tracking_cap`, `source_ips_beyond_tracking_cap`, and
`source_path_pairs_beyond_tracking_cap` so a reviewer can see when a displayed
distinct count or source convergence count is a lower bound. A source whose
path pairs are incomplete does not receive a claimed `most_requested_uri_path`
in the private artifact. No sketch or
probabilistic approximation is used.
