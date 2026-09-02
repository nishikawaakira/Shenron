# Temporal comparison and retro-hunting (design proposal)

Status: **proposal**. This document records the design decisions before any code
is written, so that the implementation stays inside Shenron's pillars. It is not
yet a settled specification; the open decisions at the end must be resolved
first.

## Why

Shenron answers "what does public CTI find in my history, right now." It does not
yet answer two questions that materially help threat hunting:

1. **What is new since last time?** A source IP, ASN, JA4, path, or CVE match that
   appears in the current window but was absent from a baseline window is the
   signal most worth a human's attention — new scanner infrastructure, a newly
   probed path, a first appearance of a known-bad ASN.
2. **What can we now detect that we could not before?** When the Nuclei
   templates or the CISA KEV catalog are updated, re-running over an *unchanged*
   historical window can surface probes that were invisible at the original run
   because no template covered them yet. This is **retro-hunting**, and it is the
   most CTI-aligned form of temporal comparison — it is `replay` framed across
   two CTI revisions rather than two calendar windows.

Both are behavioural/temporal, orthogonal to the CVE-per-request matching. They
extend the CTI-independent volume track that `production concentration` opened,
plus the CTI track via retro-hunting; they do not change how a single run works.

## The comparison modes

All four operate by **diffing two already-produced run artifacts**. Shenron does
not gain a live rolling database; a comparison is a read-only function of two
frozen inputs, exactly like a single run is a read-only function of one corpus.

1. **First-seen entities.** Entities present in the current run's private
   artifacts but absent from the baseline's: source/peer IPs, resolved ASNs, JA4
   fingerprints, hosts, and request paths. Requires the **private** artifacts
   (`private-findings.jsonl`, `request-concentration.json`) because those hold
   the entity values; the *count* of new entities per class is sanitizable, the
   *list* stays private behind `--show-*` gates.
2. **CVE finding diff.** New CVEs observed, CVEs that disappeared, and per-CVE
   deltas in `request_count`, `unique_source_clusters`, `unique_ja4_fingerprints`,
   and `protection_gap_rate`. This is computable entirely from the **sanitized**
   `cve_findings` (CVE identifiers are CTI, not customer data), so it needs no
   private input and its output is sanitizable.
3. **Concentration delta.** Per-path and per-source changes in request share and
   requests-per-minute versus the baseline, plus movement of the top-N. Path/IP
   detail comes from the private `request-concentration.json`; the aggregate
   shape (how much mass shifted, how many paths newly crossed a share threshold)
   is sanitizable.
4. **Retro-hunt.** Re-run the *same* corpus window under a newer Nuclei/KEV
   revision and diff the `cve_findings` against the earlier run. New matches are
   "probes we can now attribute to a CVE we could not before." The two runs'
   `run-manifest.json` records (Nuclei revision, report SHA-256, KEV SHA-256)
   distinguish a CTI-revision diff from a calendar-window diff; both are the same
   diff machinery.

## Design decisions

- **No new long-lived store.** A baseline is just a prior run's artifact
  directory. Shenron never accumulates raw telemetry across time; retention is
  whatever the operator keeps of past run outputs. This keeps the privacy surface
  identical to today's (per-run private vs. sanitized split) and avoids a
  standing database of customer request values.
- **Frozen, reproducible inputs.** A comparison records, in its own manifest,
  the identity of both compared runs: their `run-manifest` fields where present
  (Shenron version, telemetry profile, time filter, Nuclei revision and report
  SHA-256), plus a SHA-256 of each consumed artifact file. Re-running the
  comparison over the same two run directories is byte-for-byte reproducible.
- **New / spike is described, never asserted.** A first-seen entity or a volume
  spike is triage context, not a determination of an attack, exploitation,
  abuse, compromise, or attacker identity. A path can be new because of a
  legitimate deploy; a spike can be a popular resource, a crawler, a load test,
  or a misconfigured client. Every comparison output carries the same
  non-assertion register as `concentration` and the behavior score, and the
  documentation states the benign explanations explicitly.
- **Robust baselines, not naive deltas.** Week-over-week volume varies by base
  rate and seasonality, so a raw "increased since last week" is a false-positive
  generator. Volume deltas are expressed relative to a robust baseline statistic
  (for example a ratio to the baseline window's median or an interquartile
  reference), never a single prior point, and the baseline definition is recorded
  so the number is auditable. First-seen and CVE-appearance signals are set
  membership, which is robust by construction; the seasonality caveat is a
  volume-delta concern.
- **Privacy separation is preserved exactly.** The comparison writes the same
  two-artifact split as a hunt: a **sanitized** report (counts, ratios,
  cardinalities, CVE identifiers — no paths, IPs, hosts, headers, JA3/JA4, or
  request values) and a **private** artifact (the first-seen entity lists and
  per-path/per-source detail). Private detail prints only behind explicit
  `--show-*` gates, mirroring `explain` and `concentration`. No private value is
  ever written to a sanitized artifact or a manifest.
- **Comparable windows only, stated when not.** Two runs are cleanly comparable
  when their telemetry profile and triage baseline match; a comparison across
  different profiles or a `CUSTOM` triage policy is still produced but is labeled
  as not baseline-comparable, rather than silently mixed. Time-window overlap and
  length differences are reported, not hidden.
- **Missing inputs are reported, not approximated.** If a compared run lacks a
  private artifact (for example a sanitized-only export), the entity-level modes
  are reported as unavailable for that pair with a reason, and only the
  sanitizable modes run. Nothing is inferred to fill the gap.

## Proposed command shape

A single read-only command that consumes two run directories:

```
shenron production compare \
  --baseline ./private-results/hunt-2026-08-01T.../ \
  --current  ./private-results/hunt-2026-08-08T.../ \
  --output   ./compare-2026-08-08/
```

- Reads each side's `sanitized-research.json`, and (when present and permitted)
  `private-findings.jsonl` and `request-concentration.json`.
- Writes a **sanitized** `comparison-summary.json`
  (`report_kind: SANITIZED_TEMPORAL_COMPARISON`) and a **private**
  `comparison-detail.json` (`report_kind: TEMPORAL_COMPARISON_PRIVATE`).
- `--show-entities` / `--show-paths` / `--show-source-ips` gate the private lists
  on stdout, exactly as `explain` and `concentration` do; `--limit` bounds
  displayed rows.
- Retro-hunt is the same command with two runs over the same corpus window under
  different Nuclei/KEV revisions; the summary labels the pair as a CTI-revision
  diff when the time filters match but the Nuclei revisions differ.

No network access, no template execution, no AWS calls, COUNT-only downstream —
unchanged. The comparison is pure aggregation over local files.

## Report contents (sketch)

Sanitized `comparison-summary.json`:

- provenance of both runs (versions, profiles, time filters, Nuclei revisions,
  artifact SHA-256s) and a comparability label,
- CVE diff: newly observed / disappeared CVE identifiers, and per-CVE deltas in
  request count, distinct source clusters, JA4, and protection-gap rate,
- first-seen **counts** per entity class (new source IPs, ASNs, JA4, hosts,
  paths),
- concentration deltas: aggregate mass shift, count of paths newly crossing a
  share threshold, peak-rpm change, each expressed against the robust baseline.

Private `comparison-detail.json` (paths + connection-peer IPs + JA4):

- the actual first-seen entity lists,
- per-path and per-source concentration deltas.

## Explicit non-goals

- **Not** anomaly scoring or ML baselining. The value is a transparent,
  deterministic set-and-ratio diff a human reads, not a model output.
- **Not** a streaming or scheduled monitor. Shenron stays a batch, read-only
  tool; scheduling and retention are the operator's, outside the binary.
- **Not** a claim that new or spiking traffic is malicious. See the
  non-assertion decision above.
- **Not** a new telemetry store. Baselines are prior run outputs the operator
  already chose to keep.

## Open decisions to resolve before implementation

1. **Baseline robustness statistic.** Which reference for volume deltas — ratio
   to baseline-window median, an interquartile band, or both — and the exact
   thresholds for "newly concentrated." These must be fixed and documented like
   the triage baseline so runs stay comparable.
2. **Multi-baseline vs. single-baseline.** Start with one baseline vs. one
   current (simplest, fully deterministic), or accept several baseline runs to
   damp seasonality. Recommendation: ship single-vs-single first; add
   multi-baseline only if the single-baseline false-positive rate warrants it.
3. **Entity identity across runs.** Source IP, ASN, JA4, host, and path are
   stable keys; whether "first-seen" should also consider verified `client_ip`
   when a trusted-proxy chain was configured (it is only available on some runs)
   needs a rule for mixed availability.
4. **Retro-hunt window pinning.** Whether `compare` should re-run the corpus
   itself under a new revision, or only diff two pre-existing runs the operator
   produced. Recommendation: diff pre-existing runs only, so `compare` stays a
   pure function of local files and never re-streams a corpus.
5. **Where the first-seen counts live.** Confirm that per-class new-entity counts
   are safe for the sanitized report (they are cardinalities, not values) and
   that only the lists are private.

## Fit with the pillars

Static (no execution), offline (no network), fidelity made explicit (deltas are
transparent counts and ratios with a stated baseline), reproducible (both runs
pinned by SHA-256), and never asserting an attack, exploitation, compromise, or
attacker identity. Temporal comparison adds a time axis to the same evidence
Shenron already produces, without changing what that evidence is or how it is
gated.
