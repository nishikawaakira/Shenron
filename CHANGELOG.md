# Changelog

Notable, operator-facing changes. Dates are UTC. Analysis stays offline by
default and COUNT-only; see the README for the full invariants.

## [Unreleased]

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

### Added

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
