# Daily threat-hunting runbook

How a security researcher would run Shenron day to day — and **why** each step
is shaped this way. Shenron is a passive, offline-by-default evidence-and-candidate engine:
it turns public CTI plus your own historical logs into confidence-labeled
evidence, triage priorities, and COUNT-only WAF rule candidates. It never
asserts an attack, never blocks traffic, and never touches the source logs. The
analyst stays in the loop; Shenron does the correlation, labeling, and
bookkeeping.

An optional post-hunt Slack notification is the only analysis-side network
exception. It is disabled unless `SHENRON_SLACK_WEBHOOK` is set and sends only
sanitized aggregate counters, never IPs, paths, hosts, headers, log values, or
private findings.

The companion driver is [`scripts/daily-hunt.sh`](../scripts/daily-hunt.sh).

## Prerequisites

- The single `shenron` binary.
- System `curl` only when the optional Slack notification is enabled.
- `git` on the PATH — `shenron setup` clones the public
  `projectdiscovery/nuclei-templates` repository (a `--filter=blob:none
  --no-checkout` partial clone). **Why git is a good choice here:** it is
  near-universal in security-engineering environments, it lets you pin an exact
  template revision (`--nuclei-revision`) so a hunt is reproducible, and it
  updates incrementally instead of re-downloading a tarball. In an air-gapped or
  no-git host, prepare `nuclei-templates/` + `nuclei-report.json` elsewhere and
  pass them with `--nuclei-templates` / `--nuclei-report`.

## Cadence: prepare deliberately, hunt daily

Split the work into an occasional **prepare** step and a frequent **hunt** step.

### Prepare (weekly, or when you deliberately refresh CTI)

```bash
shenron setup     # downloads Nuclei, CISA KEV, reputation, ASN, Sigma, bot-ranges
```

**Why not daily:** CTI freshness matters, but changing the templates mid-window
changes your results. Refresh on a schedule you control, note the pinned Nuclei
revision, and hunt a stable window against that frozen snapshot. Reproducibility
(same inputs → same output, recorded with SHA-256) is a core Shenron property;
don't undermine it by moving the ground under an active investigation.

### Hunt (daily)

```bash
nice -n 10 shenron hunt --input /var/log/nginx --format nginx --since 24h --output "./private-results/hunt-$(date -u +%Y%m%dT%H%M%SZ)" --baseline-latest ./private-results --report --lang ja
```

This single command is suitable for cron. The optional
[`scripts/daily-hunt.sh`](../scripts/daily-hunt.sh) wrapper only supplies these
arguments from environment variables and lowers the process priority; Shenron
itself selects the prior run and prints the aggregate review signals.

To add an aggregate-only daily Slack notification, place the webhook and an
optional catalog-severity threshold in the cron environment rather than on the
command line:

```bash
SHENRON_SLACK_WEBHOOK='https://hooks.slack.com/services/REDACTED' \
SHENRON_SLACK_MIN_SEVERITY=high \
nice -n 10 shenron hunt --input /var/log/nginx --format nginx --since 24h \
  --output "./private-results/hunt-$(date -u +%Y%m%dT%H%M%SZ)" \
  --baseline-latest ./private-results --report --lang ja
```

The message contains sanitized severity/CVE/KEV/Sigma, sensitive-file 2xx,
concentration, and optional baseline-delta counts plus local artifact paths.
It never contains raw IPs, paths, hosts, headers, log values, or private
findings. The threshold also permits a notification for any observed KEV CVE
or sensitive-file/config 2xx response. Delivery uses `curl` and is best effort:
a missing executable, timeout, or non-2xx response is disclosed without the
webhook URL and does not fail the completed hunt. Catalog severity and these
aggregates remain review context, not determinations of attack, exploitation,
compromise, or attacker identity.

Slack, baseline comparison, HTML reports, and the observation store require a
run directory, so daily operation always supplies `--output`. An ad hoc hunt
without `--output` instead creates no files and streams private findings only
to stdout; any configured Slack notification is explicitly skipped.
For a setup-free Sigma-only check, add `--no-nuclei --rules <DIR>`; use the
retained `validate-rules` command to inspect rule compatibility. Nuclei and
Sigma cannot both be disabled.

## The daily loop

### 1. Point at the log directory and bound the window

Daily files are not required. Point `--input` at a log directory and Shenron
streams its supported files recursively, including rotated `.gz` files.
`--since 24h` keeps only events from the 24 hours before the run starts. Use an
explicit `--from` and `--to` instead when an audit needs fixed, exactly
reproducible UTC boundaries. Shenron remains read-only and never modifies the
source files.

### 2. One hunt pass, diffed against yesterday

```bash
shenron hunt --input /var/log/nginx --format nginx --since 24h \
  --output ./private-results/hunt-<UTC> \
  --baseline-latest ./private-results \
  --report --lang ja
```

A single pass runs, in one stream over the corpus: the CVE-anchored Nuclei
matchers, the Sigma pass (secret/config-file probes and other generic TTPs),
request-concentration, published bot-range comparison, declared-vs-observed
consistency checks, and the sensitive-file 2xx highlight. `--baseline-latest`
selects the lexicographically greatest prior child directory containing a
`run-manifest.json` (excluding the current output) and adds the same temporal
diff as an explicit `--baseline`; sortable `hunt-<UTC>` names therefore select
the latest run without relying on filesystem modification times. If no prior
run exists, the first hunt continues and states that comparison was skipped.
`--report` writes a self-contained, offline HTML report.

The resolved `--since` start boundary is recorded as `filter_from` in both the
sanitized report and `run-manifest.json`, making that individual run
self-describing. The boundary itself necessarily depends on the execution
time; use fixed `--from/--to` timestamps when rerunning the exact same window.

**Why this shape:**

- **One pass, many lenses.** Re-reading a large corpus is the expensive part;
  doing every check in one stream keeps daily cost down.
- **Diff, don't re-survey.** Daily hunting is about *what changed* — newly
  observed CVEs, first-seen source IPs/hosts/paths/JA4, elevated-volume paths.
  The baseline diff is what turns a full scan into a short, actionable delta.
- **The report is the review surface.** It is private (raw IPs and paths) and is
  meant for your eyes, not for sharing.
- **The stdout block is the daily index.** It summarizes only existing
  aggregate counts: observed CVEs, sensitive-file/config responses, Sigma
  matches, concentration, and (when available) the baseline delta. These are
  review priorities, not determinations of attack, exploitation, compromise,
  or attacker identity.

## Appended and rotated logs

Shenron is stateless: it records no file offset or checkpoint between runs.
Each invocation re-streams the selected corpus and applies the timestamp
window before matching. This means an appended file or a directory containing
current and rotated logs can be used directly without creating a separate
daily file. A single run does not duplicate a finding merely because an event
was read from a larger corpus; events outside the window and events without a
timestamp are excluded and their counts are disclosed.

The tradeoff is I/O proportional to the corpus scanned, even when most events
fall outside the requested window. For a very large append-only file, use log
rotation or narrow `--input` to the recent files while retaining immutable
copies for fixed-window audit runs. Directory-tree and gzip streaming are
supported; no log content is sent over the network.

### 3. Triage: prioritize by behavior, add context

```bash
shenron explain --findings ./private-results/hunt-<UTC>/private-findings.jsonl \
  --show-source-ips --show-asn --show-request
```

`explain` groups findings by connection/client IP, ASN, or JA4, and ranks them
with an offline behavior-priority score (from observed request behavior only).
Add `--reputation-dataset` / `--asn-dataset` for local enrichment.

**Why:** volume alone is noisy. You want the few entities that combine breadth
(many distinct probes), depth, and distinctiveness — and you want ASN,
reputation, and request-sequence/rate context to tell a short spike apart from
sustained activity. The score is a *review priority*, never a probability of
malice.

### 4. Read the incident signals (leads, not verdicts)

Open `report.html` and look, in rough priority order, at:

1. **Sensitive file/config access with a 2xx response** — a request for `.env`,
   `/.git/config`, `/.aws/credentials` etc. that returned success. The most
   alarming daily signal: the file may actually have been served. Confirm with
   `response_bytes` / `response_status` on the finding.
2. **Request-concentration spikes** — a path or source with sharply elevated
   per-minute volume (the status-class timeline separates 2xx/4xx/5xx over time).
3. **Baseline delta** — first-seen entities and elevated-volume paths/IPs vs
   yesterday (`comparison-summary.json` / the report's compare view).
4. **Declared-vs-observed mismatches** — e.g. a `Googlebot` User-Agent whose
   observed peer is outside Google's published ranges.
5. **Protection-gap** — a CVE-related request that available WAF evidence shows
   was not blocked.

**Why each is only a lead:** every one has innocent explanations (a decoy file,
a CDN/NAT peer, a popular resource, a stale published range, a crawler). Shenron
labels and prioritizes; *you* decide whether it is an incident. That non-
assertion discipline is deliberate — it keeps false certainty out of your day.

### 5. Act: turn a confirmed finding into a COUNT-only WAF rule

```bash
shenron candidate build  --from-findings <private-findings.jsonl> \
  --output cand.json --telemetry apache
shenron candidate replay --candidate cand.json --input ./logs/today \
  --output cand-replayed.json
shenron candidate export --candidate cand-replayed.json \
  --backend aws-waf-json --priority 100 --output rule.json
```

**Why this three-step gate:**

- **build** creates a *narrow* condition from the evidence (AWS WAF BLOCK-already
  and URI-only response-unverified findings are excluded by default — you opt in
  to the weaker ones only after review).
- **replay** simulates the candidate across your full history and reports how
  many requests it would have matched — your false-positive check *before*
  anything is deployed.
- **export** emits the rule with its initial action fixed to **COUNT** (observe,
  never block) plus a sanitized evidence sidecar. A human reviews the COUNT
  observations in production and promotes it to BLOCK. Backends:
  `aws-waf-json`, `terraform-aws-waf`, `ossec`.

Shenron never deploys, never emits BLOCK, and cannot infer WebACL priority — so
`--priority` is required and deployment stays a human, out-of-band action.

### 6. Keep memory for tomorrow

- A valid prior run under the run root is selected by tomorrow's
  `--baseline-latest`; `--baseline <dir>` remains available when an analyst
  needs to pin a particular comparison explicitly.
- Opt in to an append-only observation store to track *recurring* address space
  across weeks (prefixes/ASNs only, never individual IPs):

  ```bash
  shenron hunt --input ./logs/today \
    --output ./private-results/hunt-<UTC> \
    --observation-store ./private-results/observation-memory.jsonl
  ```

**Why:** a single day rarely proves anything. Persistence across days
(baseline deltas) and across weeks (observation store) is what separates
background noise from a source that keeps coming back.

## Privacy and retention

Run directories, `private-findings.jsonl`, `request-concentration.json`,
`bot-range-observations.json`, and the HTML report are **private** — they
contain raw IPs and request paths. Keep them access-controlled and unshared.
What you share (after review) is the sanitized research output or a
sanitized-only STIX/MISP export (`shenron export`, TLP-marked, file-only). Raw
values enter an export only behind an explicit `--include-observables` opt-in.

## What this workflow does *not* do

Set expectations honestly:

- **No automated incident detection or alerting.** Shenron surfaces prioritized
  evidence; a human finds the incident. It is not a SIEM/IDS and has no daemon,
  threshold, or alert.
- **Bounded detection.** Coverage is the Nuclei literal-request IR plus the
  supported Sigma subset (extend it with `setup --sigma-source
  https://github.com/SigmaHQ/sigma.git`, supported subset only), concentration,
  bot-range, and consistency checks — not general behavioral/anomaly detection.
- **Request-side confidence only.** Nuclei matches are labeled
  `request-specific` vs `response-unverified`; there is no response-body/OAST
  confirmation. Confirm true positives yourself using breadth, first-seen, and
  the response status/bytes context.
- **COUNT-only output.** Promotion to BLOCK is always a reviewed human decision.
