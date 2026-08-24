# Loop engineering

The permanent loop is **generate → validate → diagnose → fix → add regression → rerun**. A deterministic validation failure is never resolved by weakening its truth record or skipping a supported rule.

The first loop found a schema/normalization issue during corpus implementation: AWS WAF writes the query string in `httpRequest.args`, independently from `httpRequest.uri`. The prior parser only split a `?` embedded in `uri`, so rules using `cs-uri-query` could miss valid WAF events. The fix normalizes `args` into `uri_query` and recombines it for `cs-uri`; [the regression fixture](../tests/regressions/issue-uri-query-alias/) locks this behavior down.

Exit criteria for the project-owned deterministic and mutation corpora are exact expected findings, exact expected non-findings, expected parser-error count, zero panics, and no existing test regressions. Unsupported upstream syntax remains explicit validation output; it is not silently ignored or relabelled to make a test pass.

The CI workflow and `make validate` run formatting, Clippy with warnings denied, and all tests. Large performance runs are intentionally manual so ordinary CI stays lightweight.
