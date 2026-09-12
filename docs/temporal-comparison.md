# Temporal comparison and retro-hunting (design proposal)

Status: **implemented (Parts A and B)**. This document records the design
decisions before any code is written, so that the implementation stays inside
Shenron's pillars. The formerly open decisions on the robust statistic and the
retro-hunt scope are now settled (see "Settled decisions"); the delivery is a
single-pass command rather than a family of subcommands (see "One command, not a
family").

Part A implements the artifact comparison engine, `compare`, and
`hunt --baseline`. It writes `comparison-summary.json`
(`SANITIZED_TEMPORAL_COMPARISON`) and `comparison-detail.json`
(`TEMPORAL_COMPARISON_PRIVATE`). Part B implements the consolidated
behavior-score and reputation triage view emitted by every `hunt`.

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
extend the CTI-independent volume track that `concentration` opened,
plus the CTI track via retro-hunting; they do not change how a single run works.

## The comparison modes

### Opt-in daily measurement deltas and comparison points

```bash
shenron compare --baseline ./private-results/day-1 --current ./private-results/day-2 \
  --output ./private-results/day-diff --comparison-points
shenron compare --baseline ./private-results/day-1 --current ./private-results/day-2 \
  --output ./private-results/custom-diff --comparison-points ./comparison-points.json
```

`--comparison-points [PATH]` explicitly enables the additive
`concentration_delta.daily_metrics` section in `comparison-summary.json` and
the aggregate-only daily lines on stdout. Without this option, existing
comparison bytes, labels, and fixed `elevated_*` / `low_baseline_*` /
`median_rpm_elevated` behavior are unchanged. This also leaves automatic
`hunt --baseline` comparisons unchanged; run `compare` on the completed runs
to request these additional measurements. No log files are read again, no
network access occurs, and the exit code reflects processing success only.

The section includes baseline, current, and signed current-minus-baseline
values for all eight metrics below, plus current/baseline ratios. Total
requests and retained distinct sources also have exact integer `NumericDelta`
counts. Ratios below one express decreases and ratios above one express
increases; no directional finding or flag is created. A baseline of zero
makes a multiplicative ratio unavailable, not infinite. Its additive count
delta remains available. Changes outside the signed 64-bit count-delta range
are rejected with an explicit error rather than wrapped or approximated.

| Metric key | Measurement | Default comparison point when opted in |
| --- | --- | --- |
| `total_requests` | All analyzed requests | None |
| `distinct_source_ips` | Retained distinct observed sources | None |
| `top_path_share` | Each run's retained top path requests / total requests | Delta at least `0.20` (+20 percentage points) |
| `top_path_requests_per_source_ip` | That path's requests / its distinct observed sources | Current/baseline ratio at least `10.0` |
| `corpus_requests_per_source_ip` | Total requests / retained distinct observed sources | None |
| `success_share` | Corpus 2xx share | Delta at most `-0.25` (-25 percentage points) |
| `client_closed_request_499_share` | Corpus 499 share | Delta at least `0.10` (+10 percentage points) |
| `server_error_share` | Corpus 5xx share | None |

The boundary is inclusive (`>=` or `<=`): a value exactly at a comparison
point counts as crossing it. Computation uses unrounded values, not the
displayed precision. Point order and crossed-point lists follow the fixed
metric order in this table. There is no score, classification, warning,
notification, or recommended response attached to the count.

A JSON file accepts a `points` object with one point per metric. Each point
has `basis` (`delta` or `ratio`), `relation` (`at_least` or `at_most`), and a
finite numeric `value`. Ratio points must be nonnegative. Share deltas use
fractions, not percentage-point integers: use `0.20`, not `20`. The supplied
map **replaces**, rather than merges with, the four defaults. `{}` selects
the defaults; `{"points": {}}` requests all measurements with no points.
Unknown names or fields are errors, preventing silently ignored settings.
For example, independently count a decline in total recorded requests and
an increase in corpus-wide requests per retained source:

```json
{
  "points": {
    "total_requests": { "basis": "ratio", "relation": "at_most", "value": 0.01 },
    "distinct_source_ips": { "basis": "ratio", "relation": "at_most", "value": 0.2 },
    "corpus_requests_per_source_ip": { "basis": "ratio", "relation": "at_least", "value": 9.0 }
  }
}
```

The resolved settings are stored alongside all original measurements and
each point's `crossed: true | false | null`, the ordered crossed-point list,
and configured/evaluated/unavailable/crossed counts. An unavailable point
includes its reason and is not counted as false. The source settings file's
path is not copied into sanitized output; the resolved numeric settings are
sufficient to repeat the evaluation.

#### Denominators, missing values, and retained coverage

- Corpus requests/source and top-path requests/source are independent. On
  a distributed site, the first can change substantially while the second
  stays nearly constant. The selected top path can differ between runs;
  this measures each run's maximum retained share, not a fixed path's trend.
- Total requests include observations without a source. The corpus ratio
  divides that total by **retained** distinct sources, preserving the stated
  definition. Zero source counts make requests/source unavailable. Source
  caps can make this denominator a lower bound. Path caps can affect which
  path is selected. Both runs disclose missing-path/source counts and
  path/source/pair cap omissions, plus top-path request/source denominators.
- Status shares remain divided by **all** response observations, including
  missing status. Missing profile support or missing historical fields,
  an empty corpus, and a corpus with no recorded status yield unavailable
  2xx/499/5xx comparisons, never a fabricated zero. Partial status coverage
  keeps the existing shares and discloses total/unavailable response counts.
- Missing concentration artifacts are reported per side, not replaced with
  zero. If private concentration detail is absent, a valid sanitized hunt or
  concentration summary can supply the aggregate-only daily measurements.
  Legacy private-detail comparisons remain unavailable in that case.
- The operator selects two runs of the **same corpus** and appropriate time
  windows. Shenron does not infer common host identity or orchestrate hosts.
  Counts describe each run's processed scope, not an accumulated history;
  different windows, caps, missing telemetry, or processed-file selections
  affect comparability. Existing comparability notes remain visible.

> A comparison point is a value the operator chose, not a finding. Crossing one means the measurement moved by at least that much between two runs of the same corpus. Traffic changes for many reasons: a campaign, a release, a holiday, a crawler arriving or leaving, an upstream change in how client addresses are presented. None of this is a determination of an outage, degraded availability, an attack, or abuse.

### Existing comparison tracks

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
4. **Retro-hunt.** After the operator re-runs `hunt` over the *same* corpus
   window under a newer Nuclei/KEV revision, diff that run's `cve_findings`
   against the earlier one. New matches are "probes we can now attribute to a CVE
   we could not before." Shenron does not re-stream the corpus itself for this;
   it diffs two runs the operator already produced (see the retro-hunt decision).
   The two runs' `run-manifest.json` records (Nuclei revision, report SHA-256,
   KEV SHA-256) distinguish a CTI-revision diff from a calendar-window diff; both
   are the same diff machinery.

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
  generator. The rule is fixed and documented, in the same spirit as the triage
  baseline's fixed 3/2/10 constants — no dynamic thresholds, no model:
  - The headline for a volume delta is the **ratio of the current value to the
    baseline window's median** (median, not mean, so a single outlier minute or
    day cannot move it), computed per path and per source and for the
    per-minute rate. The raw ratio is always shown.
  - A delta is labeled **`elevated`** only when `ratio >= 3.0` (a fixed constant,
    not a CLI knob, so runs stay comparable).
  - A **minimum-baseline floor** guards against tiny denominators: a path or
    source whose baseline count is below **30 requests in the baseline window**
    does not get a ratio at all; it is labeled **`low-baseline`** (effectively a
    near-first-seen), because "1 request last week, 5 this week" is not a
    meaningful 5x.
  - First-seen and CVE-appearance signals are **set membership**, robust by
    construction; the seasonality caveat applies only to volume deltas.
  The two fixed constants (`elevated` ratio `3.0`, baseline floor `30`) are part
  of the recorded, comparable baseline, exactly like the triage thresholds.
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

## One command, not a family

The primary path is a **single command that already does most of this**:
`hunt` runs Nuclei, Sigma, and concentration in one pass over the
corpus. Rather than add a family of comparison subcommands the analyst must
orchestrate, temporal comparison is folded into that one pass, and a single
consolidated view is added, in the spirit of a one-command tool like Hayabusa —
"run once, get everything worth looking at first" — while keeping Shenron's
non-assertion register.

Two additions:

1. **`hunt --baseline <prior-run-dir>` (optional).** When supplied, the same hunt
   pass also emits the temporal diff (first-seen entities, CVE finding diff,
   concentration delta) against the baseline run. The baseline is only **read**
   from its existing artifacts — it is never re-streamed — so the comparison
   stays cheap and the corpus is scanned exactly once. Without `--baseline`, hunt
   behaves exactly as today.
2. **A consolidated triage view.** Instead of making the analyst run `explain`
   separately, hunt writes a single prioritized view that ranks entities by the
   existing **behavior priority score**, layered with reputation and a
   first-seen flag, alongside the aggregate counts. This is the "one prioritized
   output" a Hayabusa-style timeline provides — but it is a **triage ordinal
   (the order a human should look), not a threat severity or a probability of
   malice**, and a first-seen mark means "new, worth review", never "new,
   therefore malicious". The consolidated view contains paths and IPs, so it is a
   **private** artifact printed only behind the existing `--show-*` gates; the
   sanitized report stays aggregate.

The focused subcommands stay available for re-analysis rather than being the
common path:

- `explain`, `concentration` — unchanged, for deep dives.
- `compare --baseline <run-A> --current <run-B> --output <dir>` — the
  same diff over two arbitrary pre-existing runs, for when neither is the run you
  just produced. It is a **pure read-only function of two local run directories**
  and **never re-streams a corpus** (see the retro-hunt decision).

### Artifacts and gating

Whether the diff is produced by `hunt --baseline` or by `compare`, it writes the
same two-artifact split:

- a **sanitized** comparison summary (`report_kind:
  SANITIZED_TEMPORAL_COMPARISON`) — counts, ratios, cardinalities, CVE
  identifiers, comparability label; no paths, IPs, hosts, headers, JA3/JA4, or
  request values;
- a **private** comparison detail (`report_kind: TEMPORAL_COMPARISON_PRIVATE`) —
  the first-seen entity lists and per-path/per-source deltas.

`--show-entities` / `--show-paths` / `--show-source-ips` gate the private lists on
stdout exactly as `explain` and `concentration` do; `--limit` bounds displayed
rows. No network access, no template execution, no AWS calls, COUNT-only
downstream — unchanged. The comparison is pure aggregation over local files.

### Consolidated triage view (Part B)

Every `hunt` also re-reads its local `private-findings.jsonl` after
the streaming pass and writes two additional artifacts:

- `triage-summary.json` (`SANITIZED_HUNT_TRIAGE`) contains only entity counts,
  the behavior-priority tier histogram, the count requiring investigation, and
  the count marked first-seen. It contains no IP addresses, paths, hosts,
  request values, JA3/JA4 values, or reputation values.
- `triage-view.json` (`HUNT_TRIAGE_VIEW_PRIVATE`) contains the ranked
  connection/client-IP entries, their grouping identity, behavior score,
  optional local ASN/reputation enrichment, and first-seen marker.

Hunt's normal stdout prints only the aggregate summary. Pass `--show-triage`
to print private ranked entries, and use hunt's `--limit` (default 20; `0` for
all) to bound that listing. Entries sort deterministically by behavior score
descending, then locally supplied reputation score descending (missing opinion
last), then first-seen first, then key. ASN and reputation inputs use the same
prepared local datasets as `explain`; no external lookup occurs.

This is a **triage priority order — which entity a person reviews first — not a
threat severity or a probability of malice**. A first-seen marker means new and
worth review, never malicious. Neither the view nor its first-seen/reputation
context determines an attack, exploitation, compromise, abuse, or attacker
identity.

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

## Settled decisions

1. **Baseline robustness statistic — fixed.** Volume deltas use the ratio to the
   baseline window's **median**; a delta is labeled `elevated` at `ratio >= 3.0`;
   a baseline count below **30 requests in the window** is labeled `low-baseline`
   and gets no ratio. First-seen and CVE-appearance are set membership. Both
   constants (`3.0`, `30`) are fixed and part of the recorded, comparable
   baseline — no CLI knobs, no dynamic thresholds. (See "Robust baselines" above.)
2. **Single baseline first.** One baseline run vs. one current run — the simplest
   fully deterministic form. Multi-baseline seasonality damping is deferred and
   added only if the single-baseline false-positive rate warrants it.
3. **Retro-hunt = diff pre-existing runs only.** Neither `hunt --baseline` nor
   `compare` re-streams a corpus under a new revision. Retro-hunting is "run
   `hunt` again after `nuclei update`/`kev` refresh, then diff the two run
   directories." The diff stays a pure, fast function of local files; a
   CTI-revision diff is distinguished from a calendar-window diff by the two
   `run-manifest` records (matching time filters, differing Nuclei revisions).
4. **Delivery = one command, plus focused re-analysis.** `hunt --baseline` folds
   the diff and a consolidated triage view into the single existing pass;
   `compare` handles two arbitrary prior runs. (See "One command, not a family".)

## Settled implementation details

1. **Entity identity across runs.** Verified `client_ip` is compared only when
   both runs recorded it; otherwise that class is reported unavailable. The
   consolidated hunt view uses the existing per-finding identity rule:
   validated client when available, otherwise observed peer, without merging
   the two identities.
2. **First-seen privacy boundary.** Per-class first-seen cardinalities are in
   the sanitized comparison report. Entity lists remain exclusively in the
   private comparison detail and private triage view.
3. **Consolidated view shape.** Hunt ranks connection/client-IP groups by
   behavior score, then local reputation score, then first-seen marker, then
   key, with `--limit 20` by default. The order is deliberately a triage
   ordinal only; concentration's `elevated`/`low-baseline` labels remain in the
   separate temporal comparison detail rather than being folded into this view.

## Fit with the pillars

Static (no execution), offline (no network), fidelity made explicit (deltas are
transparent counts and ratios with a stated baseline), reproducible (both runs
pinned by SHA-256), and never asserting an attack, exploitation, compromise, or
attacker identity. Temporal comparison adds a time axis to the same evidence
Shenron already produces, without changing what that evidence is or how it is
gated.
