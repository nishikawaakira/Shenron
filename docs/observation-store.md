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
