# Private offline HTML report

`shenron hunt` can analyze raw logs and render a report in one invocation:

```bash
shenron hunt \
  --input ./logs \
  --format apache \
  --report \
  --report-lang ja
```

The hunt writes its normal artifacts and then renders
`<run-dir>/report.html`. Pass a path to `--report` to override that location.
To rerender an existing hunt or concentration run without re-streaming or
re-analyzing raw logs, use the same command with the distinct results input:

```bash
shenron hunt \
  --results-dir ./private-results/hunt-20260901T120000Z \
  --report-lang ja
```

Report rendering uses whichever of these artifacts are present and labels
missing sections unavailable rather than estimating them:

- `sanitized-research.json` for aggregate counts;
- `run-manifest.json` for the telemetry profile, time range, Shenron version,
  and pinned Nuclei revision. Both `hunt` and `concentration` write this
  manifest, so provenance is populated for either run; a `concentration` run has
  no Nuclei pass, so its Nuclei revision reads as not applicable;
- `request-concentration.json` for private paths, observed connection-peer IPs,
  prefix groups, tracking-cap disclosures, the minute-resolution request
  timeline, and aggregate minute-by-HTTP-status-class counts;
- `triage-view.json` for the ranked private behavior-priority view.

The report shows aggregate cards, Top-N path and peer-IP bars, global and
focused-path request timelines, a five-line global timeline split into HTTP
status classes 1xx through 5xx, focused-path network-prefix bars when present,
the hunt triage table, and a sanitized aggregate row for each observed CVE. The
Observed CVEs summary card links to that final section when CVE rows exist. It
lists the matching Nuclei template IDs, catalog KEV membership, and
detectability alongside aggregate request, path-distinctiveness, time-range,
and protection-gap fields. Template IDs are public CTI metadata and are also
stored in each sanitized CVE finding as the sorted `template_ids` array; this
adds no customer telemetry value. These fields remain catalog and matcher-volume
context, not an exploitation, compromise, or attacker-identity determination.
`--limit` defaults to 20 and controls private
path, IP, prefix, and triage rows; `0` shows all. The CVE list remains complete.
The timeline uses at most 240 points.
Longer minute series are deterministically downsampled into equal-width minute
spans whose request counts are summed. Retained-bucket and key-tracking caps are
disclosed; omitted data is never approximated. Human-readable labels default to
English; pass `--report-lang ja` for Japanese. Integer counts use three-digit comma
grouping in either language. Older artifacts without a retained minute series
show guidance to rerun `hunt` or `concentration` with the current build.

The status-class timeline uses the same retained minute admission and
deterministic downsampling as the global request timeline. Its five lines share
one scale so 1xx, 2xx, 3xx, 4xx, and 5xx volumes remain directly comparable.
The series contains aggregate counts only and is stored only in the private
`request-concentration.json`; it is not copied into sanitized output. HTTP
response classes are context, not a determination of attack, exploitation, or
compromise. Other or unavailable status values are not plotted.

Timeline columns contain visible CSS-only hover readouts showing the UTC minute
and request count; native SVG `<title>` elements remain as a fallback. Hovering
a bar likewise exposes the full path or peer address with its count. These
interactions use no JavaScript. Long provenance labels and values wrap inside
their cards. Charts and triage tables are placed in independent horizontal and
bounded vertical scroll containers, so wide labels and high row counts do not
force page-level horizontal scrolling or become unreachable. When a run
recorded no explicit filter window, the provenance time range is the observed
span of retained minute buckets, and the report says so.

The triage table omits the Reputation opinion or Resolved ASN column when every
entity lacks that enrichment. If either value exists for at least one entity,
its column remains visible and unavailable rows are labelled individually. The
always-present entity, identity, behavior-priority, basis, observed-breadth, and
first-seen columns are unchanged.

## Privacy and offline guarantees

The HTML is a **private artifact**. It contains raw request paths and observed
IP addresses and begins with this banner:

> PRIVATE — contains raw IP addresses and request paths. Do not share.

Do not publish or attach the report as if it were sanitized research output.
Shenron also prints the private warning to stderr when generating it. In
`--results-dir` mode the input is already-produced artifacts, so the report
defaults to `<run-dir>/report.html`; Shenron refuses to overwrite a directory
or one of the source artifacts it reads. In raw `--input` mode the report also
remains separate from the raw-input tree.

The document contains inline CSS and server-side generated inline SVG only. It
has no JavaScript, external CSS, fonts, images, CDN links, fetches, or other
network references, so opening it performs no external communication. Every
artifact-derived string is escaped for HTML/SVG (`&`, `<`, `>`, quotes, and
apostrophes) before rendering to prevent log-derived markup injection.

The visualizations state observed counts and concentration only. They do not
determine a denial-of-service attempt, attack, exploitation, abuse, compromise,
or attacker identity. Source IPs are observed connection peers and may be a
CDN, load balancer, NAT, or proxy. Behavior scores are human-review priorities,
not threat severity or probabilities of malice. First-seen means worth review,
not malicious.
