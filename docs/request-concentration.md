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
