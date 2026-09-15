# From a finding to an investigation

Start with `daily` and `compare` to inspect coverage and observed changes. Use
`hunt` to retain evidence, then `explain` for review. A match is a starting point,
not evidence of exploitation or an identified actor.

## Non-matching request context and original records

`hunt --input ./logs --output ./private-results/run --include-source-references`
adds an input-file/physical-line reference to each private finding. The run
manifest identifies the complete stored file bytes by SHA-256. Lines are one-based
in decoded text (including blank and malformed lines); gzip offsets are not byte
offsets. Omit the flag to preserve the existing artifact format.
References are valid only for the frozen corpus identified by that SHA-256, not
a live log path. Appends change the fingerprint, while rotation, truncation or
replacement can also shift or reassign physical line numbers; verify the frozen
bytes before following a reference.
Concatenated gzip members are decoded as one continuous log stream, with line
numbers continuing across member boundaries. Fingerprints cover all stored members.

```sh
shenron context --input ./logs --source-ip 198.51.100.1 --show-request
shenron context --input ./logs --source-ip 198.51.100.1 \
  --from 2026-08-24T11:15:00Z --to 2026-08-24T11:25:00Z
shenron context --input ./logs --source-ip 198.51.100.1 \
  --from 2026-08-24T11:15:00Z --to 2026-08-24T11:25:00Z \
  --show-request --output ./private-context.json
```

Context includes all requests from the selected observed peers within any supplied
inclusive UTC bounds, whether or not they matched Nuclei/Sigma. No intelligence inputs or
network access are required. Peers can represent CDN/LB/NAT/proxies, not actors.
Default stdout contains counts only. `--show-request` opts into private records;
`--show-query` additionally includes sensitive query and Referer values, including
any query values in the Referer URL. Private output never
becomes sanitized merely because it is JSON. No query values are retained in the
context artifact by default. The original logs and ordinary hunt findings retain
their existing privacy contract.
The private context artifact also records `selected_source_ips` as a sorted,
deduplicated selection, including peers with no retained records. This preserves
the selection when there are no matches or the record cap is reached; it is never
included in default counts-only stdout.

Private records also include Host, User-Agent, country, JA3/JA4, WAF action and
WAF labels when the selected telemetry profile supports them and the request
records them. `field_availability` records that profile's capabilities, not
per-request populated counts. Unsupported or unrecorded new fields are omitted;
Referer is additionally omitted without `--show-query`. WAF action is the recorded
string, not an interpretation of whether a request reached the origin or a control
succeeded. An absent field does not establish that a control did not act. No field
is inferred from another field, and these details never enter counts-only stdout.

Both time bounds are optional: `--from` alone retains requests at or after that
instant, `--to` alone retains requests at or before it, and omitting both applies
no time filter. Supplying both preserves the closed interval and rejects reversed
bounds. Missing timestamps are always excluded and counted in
`selected_without_timestamp`, even with no window. No preliminary pass is made to
discover the corpus period. Omitted bounds are absent from the private JSON.

`counts.earliest_retained` and `counts.latest_retained` in private output describe
the actual retained UTC span (unavailable when no records are retained). They do
not describe omitted records. Counts-only stdout retains its previous shape and
does not include these private time bounds. With cap omissions, the retained span
is only a lower bound on the observed span; stderr reports the omitted count and
suggests narrowing the window or raising `--max-records`. The default remains
10,000 records. For a bounded follow-up, use the retained times as explicit
`--from`/`--to` values, while accounting for the disclosed cap omissions.

The default finite cap is 10,000 eligible records (`--max-records`). The first
eligible records in sorted file/physical-line order are retained, then displayed
in UTC/file/line order. This is not necessarily the earliest time subset when
capped. Counts disclose parse errors, other peers, missing time, outside-window
records and cap omissions. Input read errors abort rather than silently omit
evidence. The corpus hashes are computed in the same read, including stored gzip
bytes. This is a bounded review view, not a reconstruction of unlogged activity.

## Scoped analyst opinions and review deadlines

```sh
shenron disposition set --store ./private-opinions.jsonl --corpus-scope site-a \
  --source nuclei --template-id example --method GET --path /robots.txt \
  --disposition expected --reviewer analyst --evidence-run ./private-results/run \
  --nuclei-revision frozen-revision --review-after 2026-10-01T00:00:00Z
shenron explain --findings ./private-results/run --disposition-store ./private-opinions.jsonl \
  --disposition-scope site-a --disposition-as-of 2026-10-01T00:00:00Z
shenron disposition read --store ./private-opinions.jsonl --disposition-scope site-a
```

`hunt` also accepts `--disposition-scope` and `--disposition-as-of` with an
explicit disposition store. Scope identifiers are private, verbatim analyst
choices, never inferred host identities. Exact scope matching has no fallback:
unscoped legacy opinions apply only when no scope is selected. Selection reports
the number of store entries excluded for scope mismatch, not a finding count.

Reviewer, evidence-run and template revision are private analyst annotations,
not independently verified evidence. Review deadlines are evaluated only at an
explicit RFC 3339 time, including equality. A due opinion remains the original
analyst opinion: it is not silently changed, suppressed or made into a Shenron
finding. The numeric deadline summary counts selected store entries, not matches;
`disposition read` exposes the private entries for manual re-review. To accept a
new decision or deadline, explicitly append it with `disposition set`. Identical
opinions and metadata are idempotent; changed metadata appends a new entry.
Default stores remain absent, and all CVE/Sigma counts remain independent of
these opinions. No wall clock is read during lookup or deadline evaluation.
With an explicit evaluation time, hunt/explain also report the number of matching
findings whose unchanged opinions are due for re-review. Scope, evaluation time
and the loaded store's SHA-256 enter the private hunt manifest when this metadata
is used; keep the corresponding append-only snapshot for reproducibility. Only
the additional matching count enters sanitized metrics, never the scope or
reviewer/evidence annotations.

## Compare measurement conditions before interpreting differences

`compare --baseline ./previous --current ./current --output ./comparison
--compare-conditions` adds numeric coverage and recorded-setting signatures to
the comparison artifact and prints their differences. It does not change legacy
comparability flags, CVE deltas or comparison points. Without the flag the old
comparison artifact is unchanged.

Review window duration and UTC alignment, observed timestamp span, malformed and
excluded counts, processed-file skips, field/status availability, caps and
evaluated template/rule counts. Recorded CTI and proxy/triage/selection settings
are compared by hashes; their private values and source paths are not copied.
Signatures reflect the recorded representation (including selection-file paths
where recorded), not a proof of semantic equivalence. Missing older metadata,
implicit limits or unrecorded rule identities stay unavailable; equal rule counts
do not establish identical rules. Differences are disclosed, not automatically
classified or excluded. Operators must establish that runs concern the same
corpus/service; labels and matching numeric conditions cannot establish that.

## Evaluate candidates on separate corpora

Use a private JSON plan and a frozen candidate:

```json
{"corpora":[
  {"input":"logs/development.log.gz","telemetry_profile":"apache-combined","role":"development","label":"construction day"},
  {"input":"logs/reference.log.gz","telemetry_profile":"apache-combined","role":"reference","label":"operator-reviewed ordinary period"},
  {"input":"logs/holdout.log.gz","telemetry_profile":"apache-combined","role":"holdout","label":"not used to build the condition"}
]}
```

```sh
shenron candidate evaluate --candidate ./candidate.json --plan ./cohorts.json \
  --output ./private-evaluation.json --limit 20
```

Paths resolve relative to the plan. At least two explicit cohorts are required.
The plan order and sorted input traversal determine output; nothing runs in
parallel. Candidate/plan hashes and single-pass stored-file fingerprints freeze
what was evaluated. Optional `expected_corpus` entries have the same
`path`/`byte_length`/`sha256` structure and must exactly match current provenance;
drift aborts evaluation. The output is new, private, and must be outside inputs.

Review per-cohort match counts/shares, malformed records, absent condition fields,
source-address exclusions, matching response distribution and retained top paths
and peers. Match-share denominator is all parseable records, including records
excluded for an unavailable/invalid required source address (also counted).
An absent leaf does not necessarily make an OR/NOT expression indeterminate;
matching uses exactly the established candidate predicate/replay semantics.
Compatibility limitations are recorded, not assumed away. Standard concentration
caps apply to matched detail and are disclosed; `--limit` additionally bounds
displayed retained paths/peers. Query keys/values are not added to this report.

Roles and labels are analyst declarations, not verified benign/malicious labels.
Identical whole files shared across plan entries are counted, not excluded.
Zero shared file hashes cannot prove independent traffic (partial overlap remains
possible). Select truly separate representative dates/services yourself. No
false-positive rate or threat coverage is inferred from unlabeled data.
Evaluation does not modify the candidate or set `replay_completed`. The existing
explicit replay, backend-fidelity and COUNT-only export gates remain mandatory;
no network calls or deployment are performed.

## Explicit multiple-run reference distributions

```sh
shenron compare --baseline ./runs/previous-monday --current ./runs/current-monday \
  --reference-run ./runs/two-mondays-ago --reference-run ./runs/three-mondays-ago \
  --compare-conditions --output ./private-comparison
```

The primary baseline plus each `--reference-run` form an explicit, equal-weight
set. Select the same corpus and representative same-weekday/time windows yourself;
the tool never infers dates from directory names, schedules work, or chooses a
"normal" period. Original two-run comparison and point semantics are unchanged.
Without extra references this additional output is absent.

Eight measurements use the same definitions as the daily comparison: total
requests, retained sources, top path share and requests/source, corpus-wide
requests/source, and 2xx/499/5xx shares. Each reports current value, min/median/max,
delta and ratio to the median, contributing run count, and unavailable counts and
reasons. Even-sized medians average the central two values; zero denominators and
empty sets are unavailable, not zero. Missing status is never a measured 0%.
Caps still make retained counts lower bounds. Each run's recorded measurement
conditions and artifact hashes accompany the numeric distribution for review.

Canonical directory aliases are deduplicated with a count. Distinct directories
remain separate operator selections even if their artifacts are identical; do
not copy one run into multiple directories to weight the reference set. References
are sorted by canonical path for stable order. The current run cannot also be a
reference. No logs are read and no IPs, paths, labels or request values are copied
into this additional aggregate section. This is descriptive context, not an
alert, an anomaly score or a determination of an outage, attack or abuse.
