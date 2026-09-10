# Private observation memory

`shenron hunt --observation-store <PATH>` explicitly opts a completed run into
an append-only private memory store. No store is created by default. The file
contains address prefixes and, when a local ASN dataset is available, ASNs; it
never stores individual source IPs. It is local-only and no network lookup or
upload occurs.

```bash
shenron hunt \
  --input ./logs \
  --format apache \
  --output ./private-results/today \
  --corpus-label 'Analyst corpus label' \
  --observation-store ./private-results/observation-memory.jsonl
```

IPv4 prefixes default to `/24` and IPv6 prefixes to `/48`. Explicit
`--ipv4-group-prefix` and `--ipv6-group-prefix` values apply only when the store
is enabled. `--asn-dataset` selects a local dataset; otherwise Shenron uses the
prepared default dataset when present. Invalid source IPs and observations that
cannot be admitted after a fixed cap are counted and disclosed rather than
inferred or approximated.

Each append records an aggregate entry snapshot with the first and last
observed epoch minute, first and last run ID, number of distinct runs, and the
ordered run IDs. The run ID is the SHA-256 of the existing `run-manifest.json`;
submitting the same completed run twice is idempotent. The store is bounded to
1,000,000 distinct prefix/ASN entries, 10,000,000 appended entry snapshots, and
100,000 run records. Existing entries remain exact; anything omitted at a cap
is reported numerically.

The store is a private artifact and starts with a safety note. A prefix observed
across several runs is a recurring observation of address space, not evidence
that one operator, owner, or actor is responsible. Address space is reassigned,
shared across tenants, and reused. This is not attribution or a determination
of a campaign.

## Read recurrence without reprocessing logs

```bash
shenron observation-store read --store ./private-results/observation-memory.jsonl --limit 20
```

This prints **private JSON** with a safety note. It reads only the selected
store, never changes it, and performs no log parsing or network access. Entries
are ordered by `runs_observed` descending, then `entity_kind` and `value`
ascending. `--limit 0` includes all entries; other limits disclose
`entries_omitted_by_limit`. Recorded cap exclusions and invalid-address
exclusions are carried forward as counts. Recurrence remains an observation,
not an inference about probing, scanning, coordination, attack, or abuse.

New RUN records copy the optional `corpus_label` from the private run manifest
verbatim. Readout associates each entry's opaque run IDs with available labels
and counts runs without labels. Historical unlabeled stores remain readable;
no label is inferred or backfilled. Labels are analyst annotations, not Shenron
determinations, and can contain private information. Keep both the store and
its readout private. No labels or prefixes are added to sanitized artifacts.

## Explicit non-destructive compaction

```bash
shenron observation-store compact \
  --store ./private-results/observation-memory.jsonl \
  --output ./private-results/observation-memory.compacted.jsonl
```

The destination must not exist. The source is never overwritten, and
compaction never runs implicitly during updates. The last appended snapshot
of each entity is cumulative and retains its full `run_ids`, `runs_observed`,
first/last observation times, and first/last run IDs. Compaction keeps that
snapshot, the store header/cap settings and all run metadata (including labels
and exclusion counts). Output order is header, entities sorted by kind/value,
then runs sorted by run index and ID. It adds no current time or randomness;
repeating compaction from the same source produces identical bytes. The
summary discloses total records and entry snapshots before/after compaction.

Readout is identical before and after compaction. Review the compacted file
before explicitly selecting it for future `--observation-store` updates; the
old file remains available. Compaction reduces historical snapshot records,
not the number of distinct entities or their run histories. Updates and
compaction still read the store, and run-ID lists still grow with recurrence;
this is not an unbounded-memory or constant-time storage design.
