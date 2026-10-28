# Identifier-access observations

`identifier-access` counts requests that vary only at identifier positions,
independently of Nuclei, Sigma and hunt triage. It reads a frozen local corpus
once, without network access or response bodies.

```sh
shenron identifier-access --input ./logs --format auto --output ./private-identifiers
shenron identifier-access --input ./logs --format apache-vhost --output ./private-review \
  --corpus-label 'example.test review' --method GET --method HEAD \
  --show-paths --show-source-ips --limit 20
```

Use one site's corpus, or a host-bearing profile when separating hosts matters.
Standard combined logs do not contain a host; this is recorded as null rather
than inferred. Input discovery, gzip magic detection, inclusive UTC
`--from`/`--to`, and format autodetection use the existing production readers.
Undated requests are excluded and counted when a time bound is supplied.
Skipped paths/reasons are private; stdout discloses their counts by reason.

`--method TOKEN` is repeatable and selects entry methods by exact, case-sensitive
comparison. Without it, all methods remain eligible. For reviewing reads, use
`--method GET --method HEAD`: creation APIs can return the same-size 200 response
for many IDs, which the size heuristic counts as rejected without judging what
the API did. Filtering lets the operator review reads separately.
Excluded methods create no entries and consume no entry slots, but exact
POST/PUT/PATCH/DELETE requests still feed the independently bounded write history.
`requests_excluded_by_method` counts ID-containing requests excluded by this
selection once per request, not per ID position (zero without a filter).
With a filter, an absent method also cannot match a selected token.
Request-level counts and the corpus timestamp span still describe the selected
time range before method filtering; entry totals, minimum counts, share bands
and ordering describe only the filtered entries. Sanitized output contains the
exclusion count, never method tokens; the private manifest records the method list.

## Identifier extraction and identity

- An ID is 1–20 ASCII digits or a UUID with exactly 8-4-4-4-12 hexadecimal
  characters. Case, leading zeroes and spelling are retained; ID values are not
  decoded or case-folded.
- In path segments, `<ID>.<1–10 ASCII alphanumeric characters>` also qualifies.
  The extension is preserved in the template but removed from the ID value:
  `/receipts/5001.json` becomes `/receipts/{num}.json`, with ID `5001`.
- Every path ID is replaced by `{num}` or `{uuid}`. Each ID position produces
  a separate entry keyed by identity/source, method, host, template and position.
  `path:N` uses the zero-based result of splitting on `/`, including empty
  segments (the first segment after a leading slash has index 1).
- Query values use the same ID grammar, without the extension exception.
  Position is `query:<literal name>`; the template is the replaced path, without
  query values. Split on literal `&` and the first `=`; do not percent-decode.
  The first qualifying occurrence of a repeated name is counted per request;
  later qualifying occurrences are disclosed separately.
- `--exclude-query-param NAME` is repeatable, literal and case-sensitive. There
  are no default exclusions or inferences from parameter names.
- IP identity uses canonical addresses internally, including IPv4-mapped IPv6.
  Output retains the lexicographically smallest raw spelling per entry.
  Non-IP source strings retain literal identity without DNS resolution.
  Missing sources or methods are counted and excluded from entries.
  Optional `--trusted-proxy` uses existing forwarded-client verification:
  validated clients and observed peers remain separate populations.

## Measurements

All shares are fractions from 0 to 1, not percentages. Arrival order means sorted
input-file path order, then physical record order; timestamps do not reorder
requests. Each entry exposes requests, exact `distinct_ids`, status classes
(including 499 within 4xx and separately), and first/last recorded UTC timestamps.

`dominant_2xx_response_bytes` is computed per entry: each size gets one vote
per distinct ID that received that size, regardless of repeated requests.
The greatest vote count wins; ties choose the smaller size. If no size appeared
for at least two distinct IDs, it is null and all observed 2xx sizes count as
content. An ID is in `content_ids` if it has any non-dominant 2xx response;
otherwise it is in `rejected_ids` only if it received a dominant-size 2xx or
a 4xx/5xx response. `redirect_only_ids` counts IDs whose recorded statuses are
exclusively 1xx/3xx; despite the field name, informational-only IDs are included.
Missing-status observations do not change that classification. These IDs enter
neither content nor rejected counts and are excluded from the share denominator.
Other status codes remain in `status_classes.other` but alone establish neither
content nor rejection; they also prevent an ID from being called 1xx/3xx-only.
`rejected_id_share` divides rejected IDs by content plus rejected IDs.
An empty denominator yields null. `redirect_only_ids` is null whenever outcome
measurements are unavailable, including missing successful-response bytes.
IDs with no status are not in that denominator. These are operational field
names, not claims about the response body or whether access was authorized.

`repeated_content_ids` counts IDs with at least two content responses;
`stable_size_ids` counts those whose content responses always had one size.
Dominant-size responses are not included in that stability calculation.
Missing status yields null outcome measurements, not zero. If any successful
response lacks bytes, or ID/size tracking omitted data, the content/rejection
measurements are unavailable rather than inferred from incomplete sizes.
Missing status, bytes and timestamps have explicit observation counts.

`adjacent_step_share` uses consecutive pairs where both values fit u64 and
counts absolute differences 1 or 2. Overflow values are counted separately;
they break adjacency rather than bridging to an earlier value.
`prefix_extension_share` uses every consecutive value pair and counts unequal
values where either is a literal prefix of the other. Both expose denominators.
`timestamp_like_share` counts numeric ID observations (including repetitions)
whose integer value, interpreted as seconds or milliseconds, lies in the
selected corpus's earliest timestamp minus one day through latest plus one day.
No timestamps or no numeric values means null; nothing is automatically excluded.

`self_reference_segment` records the nearest preceding path segment equal to
`me`, `my`, `self`, `mine` or `current`, case-insensitively, preserving its
original spelling. For query IDs all path segments precede the position.
This is a string observation, not an interpretation of endpoint semantics.

`ids_written_by_same_peer` counts retained IDs also used by the same identity
in exactly POST, PUT, PATCH or DELETE (case-sensitive), across templates and hosts
in the selected corpus, even when excluded by `--method`. Other method tokens
produce entries only when selected and never
contribute write history. It does not require a successful write response and does not
establish ownership. `ids_written_before_first_content` additionally requires a
strictly earlier recorded write timestamp than the first content timestamp.
Both counts exclude writes from the evaluated entry's own full Key, including
its identity/source, method, host, template and ID position. Only other Keys
contribute the earliest write timestamp. Each retained ID keeps at most two
distinct origin Keys with the earliest recorded timestamps; dated origins precede
undated ones and full Key order breaks ties. This suffices to exclude any single
Key, even with out-of-order timestamps, without changing the per-peer ID/peer
caps or treating discarded redundant origin records as missing history.
An undated content response prevents this temporal conclusion for that ID.
Undated writes do not establish ordering. When content measurements themselves
are unavailable, the before-first-content count is null.
`write_history_incomplete` discloses partial histories; reported write-match
counts then describe retained evidence only, and zero does not establish absence
of a prior write.

## Bounds and output

| Option | Default | Scope |
| --- | ---: | --- |
| `--min-distinct-ids` | 20 | Minimum retained distinct IDs for reporting |
| `--max-entries` | 1,000,000 | Entry keys; independently also write-history peers |
| `--max-ids-per-entry` | 100,000 | Distinct ID strings per entry |
| `--max-reported-ids-per-entry` | 10,000 | Content ID strings in each private row |
| `--max-written-ids-per-peer` | 100,000 | Write ID strings per identity |
| `--max-response-size-pairs-per-entry` | 100,000 | Distinct (ID, 2xx size) pairs per entry |

All bounds must be positive; there is no unlimited tracking mode. Raising limits
raises memory use. Admission follows arrival order, with no eviction. Existing
retained keys continue accumulating after caps fill. Rejected observations,
not estimated distinct values, are counted by reason. Report truncation does not
change measurements; content ID values are emitted in lexical order.

When an entry's ID cap actually rejects observations, `distinct_ids` is null
and `distinct_ids_at_least` gives the retained lower bound. Otherwise,
`distinct_ids` is exact and `distinct_ids_at_least` is null. Such incomplete entries remain
in private output even below the reporting minimum, with a sanitized count of
affected entries. Merely filling a cap without rejection does not make data
incomplete. `total_entries` is null when the entry cap omitted observations;
`retained_entries` remains exact. Threshold counts use proven retained counts,
not guesses about omitted IDs. Complete entries below the minimum are counted
in `entries_below_minimum` and not reported. Entries with ID omissions whose
retained count is below the minimum are instead counted in
`entries_below_minimum_unproven` and reported as exceptions.
`entries_at_or_above_minimum + entries_below_minimum_unproven == reported_entries`.
These unproven exceptions do not contribute to `sources_at_or_above_minimum`.

The private `identifier-access.json` orders entries by rejected IDs descending,
then retained distinct IDs descending, then lexical key order. Unknown rejected
counts follow measured counts. This highlights combinations with many recorded
non-content IDs rather than simply high request volume; synthetic sweep and
prior-write fixtures demonstrate why raw breadth alone is insufficient.
It is an inspection order, not a score or a classification.

`sanitized-identifier-access.json` contains only aggregate counts, without
sources, hosts, templates, ID values or labels. Share bands (null, <0.3,
[0.3,0.5), [0.5,0.8), >=0.8), and timestamp/prefix shares >=0.5 describe
reported entries, including incomplete entries. They never filter or classify.
`run-manifest.json` is private: it records all options, time bounds, trusted
proxies, skipped inputs, and sorted corpus path/byte length/SHA-256 provenance.
`--corpus-label` is recorded verbatim only there as an analyst annotation.
No wall-clock generation time enters these outputs; identical input bytes and
configuration produce identical artifact bytes. Existing outputs are refused.
If a later artifact write fails, completed files created by this batch are
removed; the failing write handles its own partial file. Files that prevented
creation are not removed. An already absent cleanup target is success; other
cleanup failures add path/reason context while preserving the original error.

Internal lookups borrow composite keys and reuse the previous-ID string buffer;
owned keys are created only for new retained records and shared with write
origins. The canonical-address helper still produces the canonical source value.
These implementation choices do not alter admission order, lexical output
ordering, raw display spelling or measurements. Status-class accounting and
address normalization use the same helpers as the other analysis commands.

Stdout shows the safety note, aggregate `  Name: value` lines and a fixed-width
table with one line per entry for the top `--limit` rows (default 20, zero means
all). Columns are `# requests ids content rejected share dom_bytes adjacent
prefix timestamp written_before`, followed by optional `source` and optional
`method position template` (template last). `ids` shows the exact count, or
`>=` followed by the retained lower bound when observations were omitted.
Null measurements appear as `-`, shares have two decimal places, and counts
have no thousands separators. Unknown total entries are shown as `unknown`.
The table retains the private artifact's inspection order, not a judgment or
score. Suppressed rows are counted in the final `Entries not displayed` line. Only
`--show-source-ips` exposes source values; only `--show-paths` exposes templates,
positions and methods. Hosts, literal IDs and self-reference strings stay private.
These display gates do not affect private artifacts.

## Safety and limits

Identifier-access measurements are not a determination of an attack, an
authorization flaw or information disclosure. Content and rejected are
status/size-based observations, not response-body or access-control findings.
A high rejected-ID share may reflect requests for absent IDs; it does not
establish why. Observed peers may be proxies or NATs. Prior writes do not
establish ownership or successful creation. Uniform legitimate payloads,
variable error pages, public data access and ordinary searches can exhibit
these shapes. No alert, blocking recommendation or hunt score is produced.
