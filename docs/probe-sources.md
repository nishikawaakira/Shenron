# Probe-source request shapes

`probe-sources` describes wide requests to catalog paths or paths with no
observed success. It does not depend on Nuclei, CVE coverage, or Sigma findings,
and does not modify `hunt`, existing scores, candidates, or sanitized schemas.
Analysis and the embedded catalog are entirely offline.

```sh
shenron probe-sources --input ./logs --format nginx --output ./private-probes
shenron probe-sources --input ./logs --format nginx --show-source-ips --show-paths --limit 10
shenron probe-sources --input ./logs --format aws-waf --output-format json
```

Use the same input formats, discovery rules (including extensionless and rotated
logs), gzip magic detection and inclusive UTC `--from` / `--to` bounds as `hunt`.
Skipped input counts/reasons and parse failures are disclosed; skipped paths
appear only in the private manifest. Undated rows are excluded when either time
bound is set and counted separately. Input bytes are hashed in the same streaming
read, including compressed bytes and unread suffixes.

## Measurements and conditions

Each identity/address has requests, retained distinct URI paths, catalog requests
and distinct paths (also by category), recorded 4xx and 404 counts and percentage
shares, and distinct paths returning 404. Here **4xx means 400 through 499**, not
just 404: a 499 or 403 does not establish that a page is absent. Shares use all
requests from the identity as denominator, including missing statuses, whose
count is always recorded. No recorded status means unavailable (`null`), not zero.

`unserved_path_share` is the percentage of retained distinct paths for which no
2xx was recorded **anywhere in the selected corpus**, including requests from
untracked sources. It is not a statement that those paths do not exist. The
success set is completed before any source is evaluated. Keep a corpus scoped to
one site: hostnames are not correlated or separated by this command. Routing,
authentication, partial status telemetry, and the selected time bounds can all
affect this observation.

The label `probe-shaped` requires all of:

1. `distinct_paths >= --min-distinct-paths` (default **20**).
2. `client_error_share >= --min-client-error-share` (default **80**, percent).
   This gate is explicitly not applied when that identity has no recorded status;
   `client_error_condition_applied` is false and the criterion remains unavailable.
3. `catalog_distinct_paths >= --min-catalog-paths` (default **5**) **or**
   `unserved_path_share >= --min-unserved-path-share` (default **90**, percent).
   Without status, the latter alternative is unavailable, so catalog evidence is
   required. Unavailable evidence never passes an alternative.

Every criterion exposes its measured value, inclusive minimum, `met` (true,
false, or null), and an unavailable reason. These operator-adjustable defaults
are review filters, not calibrated probabilities or a claim about intent. The
synthetic tests include a wide mostly-404 source, a mostly-200/301 crawler-shaped
source, a small browser-shaped source, and a few broken-link requests. Only the
first meets the defaults; UA names do not grant or deny an exemption.

Also recorded: earliest/latest timestamp (UTC), observed active UTC days, peak
requests in a UTC-aligned minute, methods, requests containing a nonempty query
and their percentage, and distinct User-Agents. Missing fields are counted. Query
values are never retained. Time measurements describe timestamped observations
only, not an inferred continuous duration or response time.

## Identity and display

Addresses use `event::canonical_ip`: IPv4-mapped IPv6 and alternative IPv6
spellings aggregate together. The observed-peer representative is the lexicographically
smallest original spelling; verified clients retain the existing resolver's canonical
spelling. With `--trusted-proxy IP_OR_CIDR` (repeatable), an
event with a verified forwarded client belongs to `validated-client`; otherwise
it belongs to `observed-peer`, following triage's identity policy. These are
separate populations even if their address is equal. Untrusted forwarded values
are ignored. Invalid and missing address observations are counted, not guessed.

Syntactically valid hostname peers are also evaluated, separately as `hostname-peer`:
ASCII letters/digits, hyphens and dots only, at most 253 characters, labels of
1–63 characters, and at least one letter. A final dot is removed and case is
folded only for the internal key; display retains the lexicographically smallest
raw spelling. Empty values and `-` are missing; other invalid values are counted
as invalid. Hostname peers never establish CIDR proxy trust, and forwarded client
values are ignored for them. **No DNS query is made**: a hostname and an IP that
happen to refer to the same peer remain different sources. Sanitized output adds
only evaluated and labeled counts per identity, never hostname strings.

Private JSON and displayed JSON source rows use `source` for the raw representative
spelling and `source_kind` (`ip` or `hostname`) to distinguish address values from
names. `identity` remains `observed-peer`, `validated-client`, or `hostname-peer`;
only the last has `source_kind: "hostname"`. Such a `source` is not an IP address
and has not been resolved. These rows do not use a `source_ip` key.

Default text/JSON stdout contains counts and the safety note only. Raw addresses
require `--show-source-ips`; example paths additionally require `--show-paths`.
UA values remain private-artifact-only. Display order is labeled rows first,
then retained path count descending, requests descending, identity and raw
representative ascending; this is an inspection order, not a severity score.
`--limit` defaults to 20. Suppressed rows and examples are disclosed.
Text uses a summary followed by two lines per displayed source (measurements,
then criteria), plus indented examples when requested. Only individual raw values
are terminal-sanitized, so control characters cannot alter the layout. JSON
stdout uses the same `source`, `source_kind`, and `identity` fields as private JSON.

## Embedded catalog

`probe-paths/probe-paths.yaml` version 2 contains 68 entries in four categories:

| Category | Entries | Matching |
| --- | ---: | --- |
| webshell-or-backdoor-names | 50 | Exact final path component, at any depth |
| wordpress-paths | 5 | Exact root path or slash-delimited subtree |
| config-or-secret-files | 8 | Exact full path |
| admin-or-installer-paths | 5 | Exact root path or slash-delimited subtree |

Matching is case-sensitive, with no URL decoding, dot resolution, or wildcard
expansion. The parser's query-free `uri_path` is used; query changes do not add
paths. A path can contribute to multiple categories, but is counted once in the
overall catalog total. `/robots.txt`, `/favicon.ico`, `/sitemap.xml`, and
`/.well-known` and its subtree are expressly excluded.

The basename vocabulary is selected verbatim from the public
[SecLists filename list](https://github.com/danielmiessler/SecLists/blob/master/Web-Shells/backdoor_list.txt),
not operational logs. The 44 additional names include `r57shell.php`,
`php-reverse-shell.php` and `jspspy_k8.jsp`; generic `index.php`, `admin.php` and
`test.php` are excluded. SecLists is distributed under the MIT License,
Copyright (c) 2018 Daniel Miessler; the complete notice is preserved in
[`probe-paths/SECLISTS-LICENSE.txt`](../probe-paths/SECLISTS-LICENSE.txt).
Loading validates nonempty, unique patterns per category and mode-specific path
syntax. Version 2 and the hash of the exact embedded YAML bytes are recorded in
the manifest. WordPress vocabulary refers to the public
[WordPress tree](https://github.com/WordPress/WordPress).
Secret/config paths use the same vocabulary as the bundled
`sigma-rules/secret-and-config-file-probe.yml`, with stricter exact-path matching;
the existing Sigma matcher is unchanged. Administrative/installer names are
generic [forced-browsing vocabulary](https://owasp.org/www-community/attacks/Forced_browsing),
not evidence that any particular software is deployed. Catalog entries are
observable names, not malicious-file determinations.

## Bounds and limitations

| Option | Default | Retained items |
| --- | ---: | --- |
| `--max-source-ips` | 100,000 | Identity/canonical-address pairs |
| `--max-paths-per-source` | 5,000 | Distinct paths per identity/address |
| `--max-source-path-pairs` | 2,000,000 | Paths across all identities/addresses |
| `--max-success-paths` | 1,000,000 | Corpus paths with any observed 2xx |
| `--max-auxiliary-values` | 1,440 | Independently: minute bins, UTC days, methods, UAs per source |

All limits are positive and finite. First observations are admitted until a cap;
already retained keys continue to accumulate exact counts. Every rejected
observation is disclosed, separately by reason (not an estimated distinct count).
Memory also depends on string lengths; increasing limits increases memory use.
Input order can affect retained sets after a cap. Re-run the same frozen corpus
with larger caps if necessary.

Retained path and catalog-distinct counts become lower bounds after path omissions.
A lower bound reaching a minimum can pass; a lower bound below it is unavailable,
not evidence of failure. Missing paths or either source-path cap make that
source's unserved share unavailable. Any global successful-path rejection makes
**all** unserved shares unavailable. A source with no status cannot use it either.
Day/minute/UA measurements become unavailable if their own tracking cap rejects
observations. Retained methods and UA frequencies are lower bounds when capped;
these supplemental measurements are never label conditions.

Without catalog matches, a source can qualify only through width, recorded
client-error share and the corpus-relative no-observed-2xx share. Catch-all 200
responses, uncatalogued requests, missing statuses, shared proxies, and incomplete
corpora limit visibility. Legitimate assessments, monitoring, and crawlers cannot
be distinguished by these measurements alone.

## Artifacts and safety

`--output` writes private `probe-sources.json` (all retained sources, at most 20
lexicographic example paths and 10 top retained UAs per source, with omitted
counts), `probe-source-ips.txt`, and `run-manifest.json`. The IP list is plain
text with one canonical IP per line, deduplicated and sorted in address order
(IPv4 before IPv6), with **no comments**. It contains only labeled observed-peer
IPs, never hostnames or validated clients. With `--trusted-proxy`, validated
client IPs are written separately to `probe-source-validated-client-ips.txt` in
the same format. Each enabled list is an empty file when it has no matches;
without trusted proxies no client list is created. Keep runs in separate output
directories when changing proxy configuration. The conditions and safety note
are in both the private report and manifest: consult them before consuming the
plain lists, which are not block recommendations or verified IOC feeds.
The manifest records thresholds, effective bounds, trusted proxies,
catalog version/SHA-256, exact corpus path/length/SHA-256 and skipped inputs.
No wall-clock generation time is inserted, so the same input and configuration
produce identical bytes. Existing output files may be replaced.

`sanitized-research.json` contains counts only: evaluated/labeled identities,
criterion met/unavailable counts, missing observations and cap omissions. No
address, path, User-Agent, private configuration or corpus filename appears there.

> Probe-shaped describes an observed request pattern for review priority, not a
> determination of an attack, compromise, malicious intent or attacker identity,
> and not a recommendation to block. Observed peers may be CDNs, load balancers,
> NATs or proxies. Legitimate monitoring, security assessments and crawlers can
> have the same shape. No observed 2xx does not establish that a path does not exist.
