# Field frequency observations (stacking)

`shenron stack` counts values observed in a selected local corpus without CTI.
Rarity means only low observed frequency in that corpus, not maliciousness,
attack or automation. New clients and legitimate monitoring tools can have rare
values. Observed peers may be shared proxies, CDNs or NATs. Capped fields omit
unadmitted values, so their rare-value lists are incomplete.

```bash
shenron stack --input ./logs --format nginx --field user-agent --field method --output ./stack-run
shenron stack --input ./logs --format aws-waf --field query-key --rarest 50 --show-values
shenron stack --input ./logs --format aws-waf --field header-name,content-type --output-format json
```

The command uses shared input discovery, gzip magic-byte detection, parsers,
parse-quality counts and stored-byte SHA-256 fingerprints. Each input is read
once. Inclusive UTC `--from`/`--to` bounds exclude and disclose undated records
when bounds are present. Genuine read/gzip errors stop before artifacts are
written. No network lookup or CTI download occurs.

## Fields and extraction

`--field` accepts repeated flags or a comma-separated list. The default is
`method,user-agent,path-extension,query-key,status`. Explicit selection replaces
the default; repeated fields are counted once. Field keys use deterministic
alphabetical order.

| Field | Exact value definition |
| --- | --- |
| `method` | Recorded case-sensitive method token, including nonstandard tokens |
| `user-agent` | Complete recorded User-Agent spelling |
| `path-extension` | Lowercased Unicode extension after the final dot in the final `/`-delimited raw path segment. Empty basename/extension, a lone leading dot such as `.env`, and trailing `/` have `(none)`. `file.tar.GZ` yields `gz`. Query text is excluded. |
| `path-depth` | Number of nonempty `/`-delimited raw path segments; root is `0`. Repeated/trailing slashes add no depth. Dot segments are not resolved. |
| `query-key` | Nonempty raw text before the first `=` in each nonempty `&`-separated query part. Duplicate keys count once per request. Query values are never retained. No percent decoding, plus conversion or case folding occurs. |
| `header-name` | ASCII-lowercased header names, deduplicated per request. Header values are never retained for this field. Only arbitrary-header-capable profiles support it. |
| `content-type` | Full recorded request Content-Type, including parameters, from the explicit postdata column or arbitrary headers. Repeated equal values count once per request; no MIME inference or parameter stripping. |
| `status` | Recorded status code as a decimal value |
| `protocol` | Recorded HTTP protocol/version spelling, without rewriting between profile conventions |
| `host` | Recorded host spelling, including any recorded port; no DNS, case folding or port normalization |
| `ja3`, `ja4` | Recorded fingerprint spelling; no inference from TLS attributes |
| `tls-cipher`, `tls-protocol` | Recorded negotiated TLS attributes, not inferred from User-Agent |
| `country` | Recorded country spelling; no IP geolocation lookup |

Each request contributes at most once to each distinct value of a field.
Multi-valued fields can contribute to several values, so their value request
counts can sum to more than the corpus request count. Values are not decoded
again beyond normalization already performed by the shared parser. Empty,
`-` and `REDACTED` scalar fields are treated as unrecorded. Available fields
with no extracted values increment `requests_without_value`.

Availability follows `TelemetryProfile::capabilities()`, not whether one sample
happens to contain a value. Method, User-Agent, URI-derived fields, status, host,
fingerprints, country and TLS attributes use the corresponding capability.
Header names require `HeaderCapability::Arbitrary`; logged Referer/User-Agent
alone are insufficient. There is no separate content-type capability: arbitrary
headers or the explicit `nginx-postdata` column provide it. Structured HTTP
request support supplies protocol, for which the capability structure also has
no separate flag. Existing capability definitions and other command outputs
are unchanged.

For example, standard Combined has no arbitrary headers, host, JA3/JA4, country,
Content-Type or TLS attributes. AWS WAF can record arbitrary headers and
fingerprints but has no negotiated cipher/protocol fields. ALB/CloudFront expose
TLS fields but not arbitrary headers; `nginx-postdata` supplies Content-Type
and TLS while its optional host prefix is not a guaranteed host capability.
Unavailable fields have `availability: "unavailable"`, null distinct/histogram/
missing-value metrics, and `unavailable_requests`. They are not reported as
observed zero-frequency values. Available fields with no records instead have
zero distinct values and an empty histogram.

## Measurements and ordering

Every retained private value has:

- `requests`, counted exactly for that value.
- `distinct_sources`, based on canonical observed peer IPs. IPv4-mapped IPv6
  and equivalent IPv6 spellings merge. Unparseable/hostname peers do not trigger
  DNS; unavailable and invalid peer observations are disclosed.
- With explicit `--trusted-proxy`, separate `client_sources` metrics for verified
  clients. These never replace or merge with peer counts. Missing/unverified
  clients remain unavailable, including on formats lacking forwarded headers.
- UTC `first_seen` / `last_seen`, plus `requests_without_timestamp`. Bounds are
  null if no timestamps are recorded.
- `response_status_classes`, using shared 1xx–5xx counts plus other/unavailable
  counts and the existing 499 subset. These describe responses, not outcomes.

Missing source observations or source-pair rejections make the affected exact
`distinct_sources` null. `distinct_sources_at_least` remains the proven retained
count; corresponding unavailable/omitted observation counts are reported.

Per-field histograms count retained values with request counts of **1**, **2–9**,
**10–99**, **100–999** or **1000+**. `rarest` sorts by request count ascending,
then distinct peer count ascending, then value lexicographically. `top` sorts
by requests descending, then distinct peer count descending, then value
lexicographically. Unknown peer counts sort after known counts at the same
request frequency, with value spelling breaking ties. Client counts do not
change this ordering. Neither list is a security classification.

## Finite bounds and omissions

| Option | Default | Meaning |
| --- | ---: | --- |
| `--rarest` | 25 | Rare-value rows per field |
| `--top` | 10 | Frequent-value rows for comparison |
| `--max-values-per-field` | 200,000 | Distinct values retained per field |
| `--max-source-pairs-per-field` | 2,000,000 | Independent budget per field for value/peer and value/verified-client pairs |
| `--max-display-length` | 160 | Unicode character limit on terminal-safe values in stdout only |

All limits must be positive; zero does not mean unlimited. Admissions follow
sorted-file/physical-line order, then lexicographic per-request values. Peer
pairs are admitted before client pairs. Known values and source pairs keep
counting after a cap. Full private values are never truncated.

`requests_beyond_value_cap` counts requests with at least one rejected value
for that field. `value_observations_beyond_cap` counts rejected **per-request
unique value observations**. A repeatedly rejected value counts again on the
next request; this is not an estimate of globally distinct unseen values.
For example, a request rejecting two different keys adds one request omission
and two value omissions. Distinct totals become null after rejections, with
`distinct_values_at_least` giving the retained count. Histograms remain exact
for retained keys, not the complete field. Rare unadmitted values may be absent.

`retained_source_pairs`, `peer_observations_beyond_source_pair_cap` and
`client_observations_beyond_source_pair_cap` disclose source tracking. The
additional pair budget bounds memory even when one value has many sources.
No approximate counting structure is used. Raise insufficient bounds and rerun
the same frozen corpus; do not treat omissions as absence.

## Artifacts and stdout

With `--output`, the shared buffered, new-file-only batch writer creates:

- **Private** `stack.json`: all retained full values/metrics in lexicographic
  order, plus bounded `rarest` and `top` lists and their omitted-row counts.
- **Sanitized** `sanitized-stack.json`: fixed field names, distinct counts,
  histograms, availability/missing counts and omissions only. **No values are
  included**, even for method or status. Query-key/header-name extraction uses
  only parameter keys/header names; other selected fields use their own
  recorded attributes, such as User-Agent or Content-Type.
- **Private** `run-manifest.json`: profile, UTC bounds, trusted proxies, options,
  all limits, stored-byte corpus paths/hashes and skipped entries. No wall-clock
  generation timestamp is added.

Default text/JSON stdout contains aggregate metrics only. `--show-values`
reveals private rare/top values; text marks truncated values with `[truncated]`,
and JSON uses `value_truncated`. Both apply `--max-display-length` after the
shared terminal-safety conversion. Control characters are replaced for display.
This does not change the full private artifact. Duplicate rare/top entries can
appear in both lists. Same frozen inputs and options produce byte-identical
artifacts and stdout.

Comparison with previous runs (new-value detection) and per-host stacking are
future candidates; neither is implemented here. Current counts pool the whole
selected corpus, including its hosts.
