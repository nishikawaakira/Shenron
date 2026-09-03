# Request concentration

`shenron production concentration` measures the distribution of requests in a
local historical corpus without requiring Nuclei templates, KEV data, or any
network access:

```bash
shenron production concentration \
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

The same aggregate runs as part of every `production hunt`, independently of
Nuclei and Sigma matching. It therefore exposes volume shapes even if no CVE or
generic rule matches a request. Hunt writes the private concentration artifact
alongside `private-findings.jsonl`; its sanitized concentration summary is
embedded in `sanitized-research.json`.

## Path focus (`--path`)

For a local review of the observed connection peers that requested one exact
path, use `--path` with `production concentration`:

```bash
shenron production concentration \
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
`--group-prefix <0..32>` to choose the IPv4 prefix length and
`--ipv6-group-prefix <0..128>` to choose the IPv6 length. The private focus
section of `request-concentration.json` contains each prefix, its request
count and share within the focused path, and its distinct retained peer-IP
count. Prefix strings are never added to the sanitized report.

Addresses are grouped by network prefix only. A shared prefix is not evidence
of a shared operator, owner, or actor: allocations can be split across tenants
and one operator can span many prefixes. This is an address-block aggregation
of observed request volume, not an attribution or a determination of a
denial-of-service attempt, attack, or abuse.

### Relationship to ASN enrichment

ASN is the semantically appropriate unit when the question concerns a possible
shared network operator. Shenron already supports this separately through
`AsnDatabase` and `production explain --show-asn --asn-dataset`. Prefix
aggregation is a local-dataset-free alternative for `production concentration`:
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
