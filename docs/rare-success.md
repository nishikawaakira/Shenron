# Rare response-status patterns

`shenron rare-success` finds paths with successful response statuses observed
from few sources in a selected local corpus. It also records whether a dated
success followed that source's earliest observed 4xx while the shared
`probe-sources` classifier labeled the source `probe-shaped`.

These are observations for human review priority, not a security conclusion or
attribution. **Success means only a configured status class, not an application
outcome.** Administrative pages, internal APIs, new releases, monitoring and
legitimate integrations commonly have few requesting sources. A source can be
a CDN, NAT or shared proxy. Temporal order does not establish causation.

```bash
shenron rare-success --input ./logs --format nginx --output ./rare-run
shenron rare-success --input ./logs --format aws-waf --method POST --max-sources 1 --show-paths --show-source-ips
shenron rare-success --input ./logs --format nginx --success-status 2xx,3xx --exclude-extension ''
```

## Definitions and selection

The command reads each file **once** using shared discovery, magic-byte gzip
detection, parsers, physical line references and stored-byte SHA-256 fingerprints.
There is no network lookup or second pass. `--from` and `--to` are inclusive UTC
bounds. Undated records are excluded when a time bound is set, with a separate
count. Parse errors and skipped inputs follow the shared quality disclosures.
Existing parsers and other commands' results are unchanged.

- The path key is the query-free `uri_path`, across the selected corpus, including
  its virtual hosts. By default, each ID segment uses the exact existing
  `identifier-access` normalization: 1–20 ASCII digits become `{num}`, UUIDs
  become `{uuid}`, and ID-plus-alphanumeric-extension segments retain their
  extension (for example `{num}.json`). This prevents IDs alone from creating
  many literal rare paths. `--no-collapse-identifiers` retains literal paths.
  No case folding or percent decoding is performed on path keys.
- `--method` restricts **candidate path counting only**, including requesting/
  successful-source counts and success measurements, to exact, case-sensitive
  method tokens. Repeat it to select several; omit it to include all methods.
  Missing methods are excluded from candidates when a method filter is set.
  Probe classification and the earliest 4xx for temporal comparison use **all
  methods** within the UTC time window, including requests excluded from
  candidate counting. GET exploration can therefore precede a POST candidate.
- A success is a response in a selected `--success-status` class (default `2xx`).
  The comma-separated option accepts `1xx` through `5xx`. Missing statuses count
  as neither success nor failure; they remain requesting-source observations
  and are disclosed by `requests_without_status`.
- A reported path has at least one success, at most `--max-sources` successful
  source identities, and at most `--max-requesting-sources` total requesting
  source identities. These are inclusive upper bounds. Non-success and missing
  statuses still contribute to the latter count.
- Static exclusions compare the final raw path extension case-insensitively,
  before ID collapse. Query text is not an extension. The default list is
  `css,js,map,png,jpg,jpeg,gif,svg,ico,webp,woff,woff2,ttf`.
  `--exclude-extension ''` disables it. The manifest records the supplied
  options and the effective normalized extension list. These exclusions apply
  only to candidate paths; the shared probe classifier still sees these requests.
- Source identity and canonicalization are shared with `probe-sources`:
  IPv4-mapped/equivalent IP spellings merge internally, verified clients remain
  separate from observed peers, and syntactically valid hostname peers are
  grouped without DNS lookup. Display uses the lexicographically smallest
  recorded spelling. `source_kind` distinguishes `ip` and `hostname`.
  `--trusted-proxy` is opt-in; forwarded clients are otherwise ignored.

## Temporal observation

All **dated** events within the UTC time window go into the existing `probe_sources`
accumulator with its unchanged thresholds and catalog. The final Report's
`probe-shaped` labels are used directly; no classification logic is copied.
Method filters, ID collapse and extension exclusions do not alter the requests
seen by this classifier or the earliest-4xx tracking. `probe_classified_requests`
counts requests passed to the classifier. `selected_requests` and
`requests_excluded_by_method` still describe candidate path selection only.
Undated events do not enter the classifier or temporal join. Their in-window
count is `parseable_records - records_outside_time_range - probe_classified_requests`;
`requests_without_timestamp` counts only those selected for candidate counting.

A successful source has `preceded_by_probe_shape: true` when it has that shared
label and at least one dated success for the reported path has a timestamp
**strictly later** than its earliest observed 4xx anywhere in the selected
corpus. The path flag is true if any of its successful sources has that flag.
A success at the same time or earlier is insufficient. Input order does not
substitute for timestamps: success can appear earlier in a file and still be
later in time. A 4xx remains the temporal reference even if custom success
classes include `4xx`.

`false` means this conjunction was not demonstrated within the selected data
and bounds. It does not establish absence of earlier activity. Missing times,
probe tracking omissions and failure-time tracking omissions are disclosed;
no missing timestamp or probe label is inferred.

## Defaults and bounds

| Option | Default | Meaning |
| --- | ---: | --- |
| `--max-sources` | 2 | Inclusive maximum successful sources for a candidate |
| `--max-requesting-sources` | 5 | Inclusive maximum total requesting sources |
| `--success-status` | `2xx` | Observed status classes, not application outcomes |
| `--max-paths` | 1,000,000 | Retained normalized path keys |
| `--max-path-source-pairs` | 2,000,000 | Global retained path/source pairs, independent of probe bounds |
| `--max-examples` | 5 | Retained records per path, in sorted-file/physical-line order |
| `--limit` | 20 | Private path groups displayed, not an artifact tracking cap |
| `--min-distinct-paths` | 20 | Unchanged probe-sources threshold |
| `--min-client-error-share` | 80 | Unchanged probe-sources percentage threshold |
| `--min-catalog-paths` | 5 | Unchanged probe-sources alternative threshold |
| `--min-unserved-path-share` | 90 | Unchanged probe-sources alternative percentage threshold |

Two successful sources and five requesting sources provide a narrow starting
set for human review, not a statistical confidence claim or a recommended
control. The independent path/pair bounds and five examples provide finite
tracking. Probe thresholds retain their existing defaults so the two commands
use the same definition, rather than a new classifier tuned to this command.

The existing probe tracking flags are also available, with unchanged defaults:
`--max-source-ips` (100,000), `--max-paths-per-source` (5,000),
`--max-source-path-pairs` (2,000,000), `--max-success-paths` (1,000,000),
`--max-auxiliary-values` (1,440). Probe omissions appear as fixed numeric
`probe_omissions` counts. The failure-time map is separately bounded by
`--max-source-ips`; rejections are `failure_observations_beyond_source_cap`.
Per-path method maps and the reported-method union use `--max-auxiliary-values`,
with `method_observations_beyond_cap` and
`reported_method_observations_beyond_cap` disclosing rejected observations.
All count bounds must be positive; zero never means unlimited.

Known keys continue counting after a cap. Requests rejected by the new path and
pair bounds are `requests_beyond_path_cap` and
`requests_beyond_path_source_pair_cap`; these are request counts, not estimates
of omitted distinct values. `retained_paths` and `retained_path_source_pairs`
record admitted sizes. A retained path with rejected source pairs is counted in
`paths_with_incomplete_source_tracking` and **not reported as rare**: incomplete
source counts cannot prove an upper bound. A retained path with missing or
unusable source values is likewise excluded and counted in
`paths_with_unavailable_sources`. These two path counts can overlap.
Admission follows sorted input paths and physical line order. Raise insufficient
bounds and rerun the same frozen corpus rather than interpreting omissions as
absence. Selected-corpus rarity does not imply rarity outside that corpus.

## Artifacts and display

With `--output`, the shared buffered, new-file-only batch writer creates:

- **Private** `rare-success.json`: path observations in the review order below, with
  request/success totals, exact requesting/successful-source counts, methods,
  first/last timestamps, response-byte minimum/maximum, successful-source rows,
  temporal flags and bounded examples. Method counts, path first/last and byte
  ranges cover all retained requests for the path, not just successes. Unknown
  byte values do not become zero: ranges are null when none are recorded, and
  `response_bytes_unavailable` discloses missing observations. Successful-source
  `requests` and first/last cover that source's successful responses only.
  Examples contain file, physical line, timestamp, method and status; admission
  follows input order and need not select the earliest timestamps. Missing
  timestamps/methods/statuses remain null. `requests_without_method` discloses
  missing method counts per path.
- **Sanitized** `sanitized-rare-success.json`: only aggregate counts and the
  fixed safety note, including reported paths, method counts, path and
  path/source temporal counts, exclusions, quality and omissions. No paths,
  peer values, input filenames or examples are included. `methods` counts
  requests for reported paths using only the fixed, case-sensitive keys
  `GET HEAD POST PUT DELETE PATCH OPTIONS TRACE CONNECT PROPFIND PROPPATCH MKCOL
  COPY MOVE LOCK UNLOCK`; all other recorded method tokens are grouped under
  `(other)`. The same grouped counts appear in default text/JSON stdout;
  per-path private `methods` retain the raw tokens and existing tracking bounds.
  `preceded_by_probe_shape` counts reported paths,
  and `successful_sources_preceded_by_probe_shape` counts their path/source rows.
- **Private** `run-manifest.json`: profile, UTC bounds, trusted proxies, all
  options/bounds, effective extension list, shared probe catalog version/hash,
  input paths and stored-byte fingerprints, and skipped-entry reasons.

Private JSON and opt-in text/JSON detail use the same deterministic review order:

1. `preceded_by_probe_shape: true` first.
2. Fewer `distinct_successful_sources` first.
3. Fewer `distinct_requesting_sources` first.
4. Newer path `first_seen` first, with null timestamps last.
5. Path key in lexicographic order to break remaining ties.

This is a presentation order for review, not a security conclusion or evidence
of causation. `--limit` selects the first groups in this order.

Default text/JSON stdout contains aggregates only. `--show-paths` reveals path
keys and their bounded example references; `--show-source-ips` independently
reveals successful-source values with identity/kind and counts. Neither flag
implies the other. `--limit` bounds displayed groups; omitted group counts are
shown. These opt-ins make stdout private. Text values are terminal-escaped.
Same frozen inputs and options produce byte-identical artifacts and stdout;
no wall-clock generation timestamp is added.
