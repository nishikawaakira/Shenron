# Case study: Turning public CTI into honest, *validated* detection evidence

*Sanitized case study for a FIRST CTI CFP submission. All figures are aggregate and
anonymized: site identities are replaced with Site A/B/C, and no domains, hostnames,
source IPs, or raw request values appear. CVE identifiers, CISA KEV metadata, Nuclei
template paths, and scanner network prefixes are public information.*

---

## Proposed talk

**Title (draft):** *Background radiation vs. real intent: operationalizing public CTI
into reproducible detection evidence — and proving how much of it is noise.*

**Abstract (draft, ~215 words):**

Public threat intelligence — Nuclei templates and the CISA Known Exploited
Vulnerabilities (KEV) catalog — is abundant, but turning it into trustworthy evidence
on your own telemetry is hard. Naïve matching drowns analysts in false positives:
"we detected CVE-X 12,984 times" is worthless when 12,984 of those are crawler hits
on `/robots.txt`.

We present a passive method (and an open-source tool, Shenron) that statically converts
public Nuclei detections into literal request matchers and replays them across historical
web logs. The analysis probes nothing, deploys nothing, and transmits none of your logs,
findings, or IPs; its only network use is downloading public CTI (Nuclei templates, CISA
KEV) to prepare inputs. Its core contribution is to **quantify the fidelity of every
match** along two transparent axes: request-specificity and path-distinctiveness.

We evaluate on four real datasets: three internet-facing sites (spanning two weeks,
three months, and a **full year**) and a high-interaction honeypot with TLS
fingerprints and per-request IDs. The fidelity classifier discriminates cleanly: the
distinctive-match share is 7–19% on noise-dominated production sites but 54% on the
honeypot. We **validate the axes against the honeypot's own independent detector** —
Shenron's high-fidelity classes agree 97–99%, while the generic-path class (where
false positives live) drops to 79%. We also show longitudinal shifts (a KEV entering
the scanning rotation mid-year) and a scanner network probing two of three sites but
not the third. Measured fidelity, reproducibility, and a strict "never claim
exploitation" stance are what make CTI operationalization safe and credible.

---

## 1. Problem

Two failure modes dominate CTI operationalization against real logs:

1. **False confidence from volume.** A detector matching a request path alone fires on
   every legitimate request to that path. Counts become meaningless and the KEV that
   matters is buried under noise.
2. **Unsafe validation.** Confirming a finding usually means *sending* a probe — which
   is intrusive, changes state, and cannot be done against historical traffic at all.

The analyst's real question is not "did a pattern match?" but "**which of these are
worth my time, and how sure can I honestly be?**"

## 2. Method

Shenron implements a passive workflow — **FIND → EXPLAIN → PIVOT → ACT → VALIDATE**. The
analysis never executes a template, probes a monitored site, deploys a control, changes a
cloud account, or transmits your logs, findings, or IPs. Its only network use is an
explicit, download-only step that fetches public Nuclei templates and the CISA KEV catalog
to prepare inputs; customer data is never uploaded.

- **Static conversion.** Public Nuclei YAML is parsed (never executed) into a literal
  request subset (method, path, query, fragment, headers). Anything requiring payload
  expansion, multi-request state, response/OAST confirmation, or bodies is rejected
  with a stable reason — not silently approximated.
- **Two fidelity axes, surfaced not hidden.**
  - *Request-specificity:* `request-specific` (a distinctive query/fragment/header was
    required) vs. `response-unverified` (only method + path matched).
  - *Path-distinctiveness:* a transparent, deterministic `distinctive`/`generic` label
    (`/robots.txt`, `/login`, `/` are generic; `/.env`, `/remote/login`,
    `/wp-json/<plugin>/...` are distinctive). Matches are **labeled, never dropped.**
- **Reproducibility.** Every run pins a Nuclei revision and a KEV snapshot and records
  SHA-256 hashes of the frozen inputs. Sanitized reports contain only counts, CVE IDs,
  and ratios — never IPs, hosts, queries, or headers.
- **Epistemic discipline.** No output claims an attack, exploitation, compromise,
  attacker attribution, or a vulnerable product. Coverage is a conservative lower
  bound, not a precision or true-positive rate.

## 3. Datasets (sanitized)

| | Site A | Site B | Site C | Honeypot |
|---|---|---|---|---|
| Nature | internet-facing | internet-facing | internet-facing | high-interaction |
| Window | ~2 weeks | **~1 year** | ~3 months | 200k-request slice |
| Format | Apache vhost | Apache vhost (portless) | Apache combined | rich JSONL |
| Parseable requests | 122,071 | 827,095 | 94,742 | 200,000 |
| Telemetry richness | path/query/host/method | same | same | + JA3/JA4, per-request ID, full headers |

The honeypot is converted to an AWS WAF-shaped schema before analysis; the conversion
carries request-side evidence, JA3/JA4, and the per-request ID, and deliberately does
**not** synthesize a WAF action (a honeypot makes no block/allow decision).

## 4. Findings

### 4.1 The fidelity classifier discriminates across all four datasets

| Metric | Site A | Site B | Site C | Honeypot |
|---|---:|---:|---:|---:|
| CVE-related matches | 3,409 | 17,508 | 2,091 | 5,212 |
| request-specific (high fidelity) | 62 | 244 | 30 | 438 |
| Unique CVEs | 51 | 56 | 26 | 58 |
| CISA KEVs | 12 | 4 | 6 | 18 |
| **Distinctive-path share** | **12%** | **19%** | **7%** | **54%** |

The same deterministic rule reports very different stories: **7–19% distinctive on
noise-dominated production sites, 54% on an attack-dense honeypot.** On every
production site the single generic path `/robots.txt` (Nuclei template CVE-2023-33960,
confirmed only by a response) dominates: **71% of matches on Site A, 74% on Site B,
89% on Site C — all labeled generic (0 distinctive).**

### 4.2 Counts mislead; fidelity fixes it — even for KEVs

The top KEV across sites, CVE-2022-42475 (Fortinet FortiOS), illustrates why raw counts
cannot be trusted:

| | matches | distinctive | interpretation |
|---|---:|---:|---|
| Site A | 140 | 3 | 137 generic `/login`; real signal ≈ 3 |
| Site B | 284 | 0 | all generic `/login` (103 clusters) |
| Site C | 15 | 1 | mostly generic |
| Honeypot | 633 | 39 | genuine `/remote/login` targeting |

The honeypot draws real FortiOS SSL-VPN probing (39 distinctive); the production sites
mostly see generic `/login` that any application serves. Same CVE, opposite meaning —
made visible only by the distinctiveness axis.

### 4.3 Longitudinal and cross-site signal (only visible across datasets)

- **A KEV entering the rotation.** Over Site B's full year, FortiOS CVE-2022-42475 is
  probed continuously (2025-08 → 2026-08, 103 clusters), while Gogs CVE-2025-8110
  first appears **2025-11** and persists — a new KEV joining the scanning rotation,
  visible only with long-window data.
- **A single-day edge-device sweep.** On Site C, four edge/appliance KEVs — F5 BIG-IP
  (CVE-2022-1388), Ivanti Connect Secure (CVE-2025-0282, CVE-2025-22457), and PAN-OS
  (CVE-2026-0257) — appear on the *same day* (2026-06-20), each once, each distinctive:
  one actor's targeted sweep, cleanly separated from the noise floor.
- **A site-selective scanner network.** A single hosting-range /24 (185.177.72.0/24)
  probes Site A (58 matches) and Site B (96 matches) with breadth+depth across many CVE
  templates — but is **absent from Site C (0)**. Meanwhile the highest-*volume* sources
  on every site are benign crawlers (Googlebot, SEO bots) hitting `/robots.txt`.
  **Volume ≠ threat**; behavior score + path-distinctiveness separate crawlers from real
  scanners, and cross-site correlation surfaces an adversary a single log would hide.
  (Site B is highly distributed: 6,005 sources, top 10 = only 9% of matches.)

### 4.4 The key result: fidelity validated against an independent detector

The honeypot runs its **own** request classifier (rule matches / severity), independent
of Shenron and of Nuclei. Joining by per-request ID, we compare Shenron's fidelity
class to whether the honeypot itself flagged the same request:

| Shenron fidelity class | Requests | Also flagged by honeypot | Agreement |
|---|---:|---:|---:|
| request-specific (highest) | 285 | 278 | **97.5%** |
| distinctive-path | 2,148 | 2,119 | **98.6%** |
| generic-path | 1,777 | 1,403 | **79.0%** |

An independent detector confirms **97–99%** of what Shenron labels high-fidelity, and
markedly less (79%) of the generic-path class — precisely where false positives are
expected. This is quantitative, label-based evidence that the transparent fidelity axes
mean what they claim, on real adversarial traffic.

## 5. Why this matters / what is new

- **Fidelity as a first-class, *validated* output** — two transparent axes turn
  thousands of raw matches into an honest triage surface, an independent detector
  agrees, and the pattern holds across four datasets.
- **Safe by construction.** No template execution, no probing of monitored sites, no
  deployment, and no egress of your logs, findings, or IPs — validation happens against
  *historical* traffic. The only network use is a download-only fetch of public CTI.
- **Reproducible CTI.** Pinned Nuclei revision + KEV snapshot + content hashes make a
  finding auditable and repeatable.
- **Honesty as a feature.** Never claiming exploitation keeps output trustworthy; the
  classifier labels noise instead of hiding or dropping it.

## 6. Limitations (stated up front)

- Matches are **probe/scan attempts**, never evidence of successful exploitation or
  compromise.
- The honeypot's classifier is a *weak* ground truth (its own rules/severity), an
  independent second opinion, not adjudicated labels.
- The three production datasets carry no WAF decision or TLS fingerprint, so
  protection-gap and fingerprint analysis use the honeypot/AWS-WAF path; the tool
  supports richer telemetry when available.
- Path-distinctiveness is a transparent, auditable, deliberately tunable heuristic —
  not ground truth.
- Four datasets from one operator; not a multi-organization study.

## 7. Reproducibility

- Open-source tool (Rust); passive analysis with no customer-data egress. Its only network
  use is a download-only fetch of public Nuclei templates and the KEV catalog to prepare inputs.
- Frozen inputs: Nuclei revision `48a4f865…` (13,613 templates; 1,577 validated request
  branches), CISA KEV snapshot `2026-08-21`.
- Bespoke telemetry (the honeypot's schema) is adapted to a supported format with a
  thin external converter; the tool itself stays on standard formats (AWS WAF, nginx,
  Apache/vhost).
- Sanitized machine-readable reports carry input SHA-256 values; private evidence is
  written to a separate local file that never leaves the host.

---

*Prepared with Shenron. Nothing in this document asserts an attack, exploitation,
compromise, attacker identity, or the presence of a vulnerable product.*
