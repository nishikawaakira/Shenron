# Changelog

Notable, operator-facing changes. Dates are UTC. Analysis stays offline by
default and COUNT-only; see the README for the full invariants.

## [Unreleased]

### Fixed

- Nuclei conversion now shares the generic-path heuristic with explain, preserving traversal-shaped paths and generic paths with query/header conditions; rerun `shenron nuclei update` to regenerate the frozen report.
- Corrected the context retained-span addition: aggregate UTC bounds now appear in default counts-only stdout when records are retained, without requiring `--show-request`.
- Concatenated gzip input is now fully decoded. Previously a `.gz` file holding
  more than one gzip member (for example rotated logs appended together) had only
  its first member parsed while later members were silently dropped, even though
  the corpus fingerprint still covered every byte. All members are now read
  across `hunt`, `concentration`, and `context`, and a truncated later member is
  an error rather than a silent stop.

### Added

- Bundled Sigma rules now include AI developer tooling configuration requests and expanded secret/configuration paths; public Firebase initialization, AI-crawler convention files and standalone `/mcp` remain excluded. Matches do not establish an attack, compromise or a vulnerable product.
- `context` records now include capability-gated host, user agent, country,
  JA3/JA4, WAF action and labels, and (behind `--show-query`) Referer, with the
  telemetry profile's `field_availability` reported so an absent field is
  distinguishable from an unsupported one. Time bounds are optional, and the
  retained-record span is disclosed as a lower bound when the cap is reached.

## [0.4.0] - 2026-09-13

All additions are private-only with sanitized output kept to aggregate counts,
deterministic, non-asserting, and COUNT-only where they touch candidates. New
serialized fields are additive, so older artifacts and default runs are
unchanged.

### Changed

- **`hunt` now writes `private-findings.jsonl.gz` (gzip) by default** instead of
  `private-findings.jsonl`. Compression is lossless and deterministic (fixed
  level, gzip mtime 0), and Shenron's own readers (`explain`, `compare`,
  `export`, the HTML report, the observation store) read both the compressed
  and plaintext forms automatically. **Migration:** external tooling that
  hard-codes the plaintext filename should either pass `--uncompressed-findings`
  to keep the old `.jsonl` output, or `gunzip` the file first. A run whose output
  directory already holds the opposite-extension findings file is refused rather
  than silently mixed.
- Human-readable hunt, `explain`, and HTML timeline timestamps are explicitly
  labelled UTC; stored RFC 3339 values are unchanged and rendering ignores the
  host timezone.

### Added

- `context`: a private, read-only, peer/time-window timeline of all accesses
  including non-matching ones (method, path, status, response bytes), with the
  query gated behind `--show-request` / `--show-query`. Findings can carry an
  opt-in private file-and-line source reference bound to the run's corpus
  SHA-256. Rows are bounded and omissions disclosed.
- `compare --compare-conditions`: surfaces measurement-condition deltas (window
  length, UTC weekday/hour, recorded-status share, parse-error rate, tracking
  caps and overflow, processed-index skips, template/rule settings) beside the
  metric deltas without auto-refusing or classifying runs; private and config
  values are compared as SHA-256 signatures. Explicit same-cohort reference-run
  median/range is also available.
- Analyst dispositions gain an explicit corpus scope so opinions never cross
  corpora, plus review run/revision, an advisory (never auto-suppressing)
  re-review deadline, rationale, and evidence references.
- Candidate evaluation across two or more explicit frozen corpora with
  operator-declared roles/labels (never inferred), showing a private per-path and
  per-time expansion breakdown. It stays COUNT-only, grants no replay or export,
  and reuses the existing matcher and concentration aggregation.
- Response-outcome health in `concentration`/`hunt`: 2xx/3xx/4xx (with nginx 499
  separated)/5xx shares and counts, per-window minimum-success and maximum-
  server-error extrema with earliest-tie bucket timestamps, and a configurable
  success-share comparison count. Buckets with no recorded status are excluded
  and disclosed rather than read as zero success.
- Exact per-entity HTTP status-code counts (bounded, overflow disclosed) beside
  the status-class tallies.
- Per-source first-segment diversity for 404 and 4xx client errors, with distinct
  all-source and error-bearing-source medians and disclosed caps.
- Configurable concentration tracking limits (`--max-paths`, `--max-source-ips`,
  `--max-source-path-pairs`, `--max-source-segments`) for `hunt`, `concentration`,
  and `daily`; positive counts only, recorded in the private run manifest when
  overridden.
- `daily`: a lightweight aggregate-only volume summary, and opt-in daily metric
  comparison points on `compare` (descriptive delta/ratio thresholds, never
  alerts or classifications).
- Corpus fingerprints (path, byte length, SHA-256) in the private run manifests
  of both `hunt` and `concentration`; optional private analyst corpus labels.
- Bounded, capability-aware WAF observation aggregates in `concentration`/`hunt`:
  sanitized output carries a fixed action vocabulary and value cardinalities
  only; raw JA3/JA4, WAF labels, and country values stay in private artifacts.
  Profiles without a WAF outcome report the summary as unavailable rather than
  fabricating zeros.
- Opt-in frozen source-address candidate conditions (`--source-address-set`,
  with `--source-ip-set-v4/v6-arn`). Candidates remain COUNT-only and export as
  an AWS WAF `IPSetReferenceStatement` by ARN — no inline addresses leave the
  private candidate artifact. The address snapshot is fingerprinted and a drifted
  snapshot cannot replay or export. A source-address match is operator-selected
  context, never identity, ownership, attack, or abuse.
