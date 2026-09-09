# Analyst dispositions

Shenron can remember an analyst-authored review state for a recurring finding
pattern in a private, append-only JSONL store. This is explicit opt-in state:
no store is created or read unless `--disposition-store` is supplied. A key is
the detection source, template ID, method, literal path, and optional literal
query, which is stable across daily runs without depending on an individual
request ID.

Record an opinion explicitly:

```sh
shenron disposition set \
  --store ./private-results/dispositions.jsonl \
  --source nuclei \
  --template-id CVE-2023-33960 \
  --method GET \
  --path /robots.txt \
  --disposition expected \
  --comment "Reviewed crawler traffic in this environment"
```

The dispositions are `reviewed`, `expected`, and `needs-review`. Repeating the
same key, disposition, and comment is idempotent. Changing an opinion appends a
new record, and the last record for a key is effective. `hunt
--disposition-store ...` and `explain --disposition-store ...` report separate
counts for matching opinions and unclassified findings. They do not delete,
filter, or change any finding, CVE match count, Sigma match count, or behavior
score.

The store is **private**: its stable keys contain raw request paths and may
contain query strings, and comments are analyst-authored. Do not share it
without review. A disposition is an analyst opinion, not a Shenron
determination of attack, exploitation, compromise, or benignness. Sanitized
outputs contain only optional disposition counts when a store is used; they
never contain store keys, request values, or comments.
