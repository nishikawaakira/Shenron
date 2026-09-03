# Private offline HTML report

`shenron production report` renders an existing hunt or concentration run as a
single self-contained HTML file. It reads only local artifacts and does not
re-stream the original logs:

```bash
shenron production report \
  --input ./private-results/hunt-20260901T120000Z \
  --output ./private-results/hunt-20260901T120000Z-report.html \
  --lang ja
```

The input is a run directory. Shenron uses whichever of these artifacts are
present and labels missing sections unavailable rather than estimating them:

- `sanitized-research.json` for aggregate counts;
- `run-manifest.json` for the telemetry profile, time range, Shenron version,
  and pinned Nuclei revision;
- `request-concentration.json` for private paths, observed connection-peer IPs,
  prefix groups, tracking-cap disclosures, and minute-resolution timelines;
- `triage-view.json` for the ranked private behavior-priority view.

The report shows aggregate cards, Top-N path and peer-IP bars, global and
focused-path request timelines, focused-path network-prefix bars when present,
and the hunt triage table. `--limit` defaults to 20 and controls private path,
IP, prefix, and triage rows; `0` shows all. `--timeline-points` defaults to 240.
Longer minute series are deterministically downsampled into equal-width minute
spans whose request counts are summed. Retained-bucket and key-tracking caps are
disclosed; omitted data is never approximated. Human-readable labels default to
English; pass `--lang ja` for Japanese. Integer counts use three-digit comma
grouping in either language. Older artifacts without a retained minute series
show guidance to rerun `hunt` or `concentration` with the current build.

## Privacy and offline guarantees

The HTML is a **private artifact**. It contains raw request paths and observed
IP addresses and begins with this banner:

> PRIVATE — contains raw IP addresses and request paths. Do not share.

Do not publish or attach the report as if it were sanitized research output.
Shenron also prints the private warning to stderr when generating it. Because
the input is already-produced artifacts rather than raw logs, the report may be
written inside its own run directory (for example
`--output <run-dir>/report.html`); Shenron only refuses to overwrite a
directory or one of the source artifacts it reads.

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
