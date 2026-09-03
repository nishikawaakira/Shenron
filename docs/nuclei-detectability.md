# Nuclei detectability

Shenron statically analyzes local, untrusted Nuclei YAML. It never executes templates, evaluates arbitrary template DSL, sends requests, contacts targets, or performs OAST interactions. The output describes request characteristics relevant to CVE-oriented investigation; it never establishes an attack, successful exploitation, compromise, or the presence of a vulnerable product.

## Updating public template inputs

`shenron-lab nuclei update` is the only Nuclei-template command that uses the
network. It invokes system `git` to download public Nuclei templates into a
local checkout. It never uploads or transmits customer logs, findings, IP
addresses, request values, or any other customer data. The analysis binary
`shenron`, including its production and candidate commands, remains offline
during analysis.

Run this once to use the standard local layout. It writes the checkout to
`$SHENRON_DATA_DIR/nuclei-templates`, or to
`$XDG_DATA_HOME/shenron/nuclei-templates` / `~/.local/share/shenron/nuclei-templates`
when the override is absent, and generates the matching frozen coverage report
at `nuclei-report.json` in the same data directory:

```bash
shenron-lab nuclei update
```

Pin a reviewed commit when reproducibility matters. `--templates` and `--report`
can override the standard locations:

```bash
shenron-lab nuclei update \
  --revision <full-commit-sha> \
  --templates ./nuclei-templates \
  --report ./research/nuclei/<full-commit-sha>/final.json
```

When `--revision` is omitted, the command checks out the current remote default
branch tip, prints its resolved full SHA, and writes a frozen report generated
by the same coverage logic as `shenron-lab nuclei coverage`. After either form,
hunt uses the default prepared inputs without repeating their paths:

```bash
shenron hunt \
  --input ./historical-logs --format aws-waf
```

The update command downloads public intelligence only. Coverage, inventory,
matchers, and all production analysis remain local; matchers in particular do
not access the network or execute templates.

## Updating public reputation and ASN inputs

`shenron-lab reputation update` is a separate, explicit preparation command. It
uses system `curl` only to download public Spamhaus DROP, FireHOL level 1, CINS
Army, blocklist.de, and iptoasn IPv4 data; it never uploads customer logs,
findings, observed IPs, request values, or any other customer data. The command
writes local `reputation.jsonl`, `asn-ranges.tsv`, and
`reputation-manifest.json` files under `SHENRON_DATA_DIR` (or the standard
XDG/home data directory), recording source URLs, retrieval time, output hashes,
and record counts. The main `shenron` binary remains offline and automatically
uses those local files during `explain` when no explicit dataset
paths are supplied.

```bash
shenron-lab reputation update
shenron explain --findings ./private-findings.jsonl --show-source-ips --show-asn
```

The generated opinions are third-party context, not a determination of attack,
exploitation, compromise, or attribution. Review and comply with the terms of
use for each source before downloading or relying on its list.

`shenron-lab nuclei coverage` includes a template capability funnel: all CVE templates, HTTP CVE templates, templates with supported request IR, and the resulting IR alternatives split into `request-specific` and `response-unverified`. This separates the request-feature distribution of the convertible template corpus from the limitations of a selected telemetry source. It is not a field precision, true-positive-rate, attack, exploitation, compromise, or vulnerability-presence measurement; the funnel contains no ground truth.

**Report kinds.** Every report names its shape in a `report_kind` field. `shenron-lab nuclei coverage` **without** `--telemetry`, and `shenron-lab nuclei update`, write the frozen coverage report (`report_kind: NUCLEI_COVERAGE_REPORT`) — the only shape `hunt`/`ablation`/`replay`/`count-hypotheses` and `kev coverage` accept as a frozen input. `shenron-lab nuclei coverage --telemetry <profile>` writes a per-profile detectability assessment (`report_kind: NUCLEI_TELEMETRY_COVERAGE`) whose templates carry `level`/`convertible`/`validated` rather than `protocol`/`conversion_status`/`validation_status`; it is an **analysis-only artifact and is not a frozen hunt input**. `--telemetry` accepts `aws-waf`, `nginx`, `apache`, and `apache-vhost`, so lab-side analysis can target the same vhost profile a hunt uses. If a telemetry report (or any other kind) is passed where a frozen input is required, the loader checks `report_kind` before deserializing the body and fails with a message that names the file, the kind found, the kind required, and the command to regenerate it, rather than an opaque serde field error. A report written before `report_kind` existed carries none and is accepted as a frozen input for backward compatibility.

| Level | Meaning |
| --- | --- |
| `HIGH` | A literal, distinctive request path, query, or header is observable in supported logs. |
| `MEDIUM` | A useful request-side signal exists, but response/OAST/body/state context is unavailable. |
| `LOW` | The observable request is too generic to be a meaningful attempt signature by itself. |
| `UNDETECTABLE` | No supported HTTP request-side signal exists. |
| `UNKNOWN` | Shenron cannot safely interpret the template syntax or variable behavior. |

Detectability and conversion are deliberately separate. For example, a distinctive raw HTTP request can be detectable in principle while unsupported by a limited parser. The converter supports one literal structured request with one or more literal alternative paths, or one simple raw request, plus method, path, query, URI fragment, and literal headers. It rejects payload expansion, attack modes, multi-request flows, unresolved variables/helpers, OAST-required verification, and body-dependent logic with stable reason identifiers.

AWS WAF logs do not provide complete arbitrary request bodies for this engine, so body-dependent characteristics are never silently converted into a WAF detection.

## Path distinctiveness

Every literal Detection IR path and every locally displayed finding path receives a
deterministic `generic` or `distinctive` label. This is a transparent triage
heuristic only: it does not remove a match and is not a precision, ground-truth,
attack, exploitation, compromise, or vulnerable-product determination. Shenron
trims and lowercases the path, ignores empty `/` segments, and labels the root
path as `generic`. It also labels these generic basenames as `generic`:
`robots.txt`, `favicon.ico`, `sitemap.xml`, `security.txt`, `ads.txt`,
`humans.txt`, `crossdomain.xml`, `index.html`, `index.htm`, `index.php`,
`index.asp`, `index.jsp`, `default.aspx`, and `apple-touch-icon.png`. Otherwise,
a path is `generic` only when every segment is one of the documented generic
application terms: `login`, `signin`, `sign-in`, `logout`, `admin`,
`administrator`, `user`, `users`, `account`, `accounts`, `api`, `auth`, `oauth`,
`settings`, `setting`, `config`, `configuration`, `health`, `healthz`, `status`,
`dashboard`, `home`, `index`, `search`, `about`, `contact`, `help`, `support`,
`profile`, `register`, `signup`, `web`, `app`, `portal`, `console`, `v1`, `v2`,
`v3`, `public`, or `static`. All other paths are `distinctive`; for example,
`.env` and product-specific nested paths remain distinctive. The complete,
auditable lists are the `GENERIC_BASENAMES` and `GENERIC_SEGMENTS` constants in
`src/nuclei.rs`.

## Matcher codebook listing

`shenron-lab nuclei matchers` lists the literal method, path, query, fragment,
headers, request-specificity, and path-distinctiveness for every Detection IR alternative that hunt
can use. With `--report`, it applies the same frozen-report gates as hunt:
`SUPPORTED` conversion, `passed` validation, and a non-empty CVE list. Without
`--report`, it lists every supported literal Detection IR in the local checkout.

```bash
shenron-lab nuclei matchers \
  --templates ./nuclei-templates \
  --revision <pinned-revision> \
  --report ./research/nuclei/<revision>/final.json \
  --output ./research/matchers.json
```

This is a read-only local codebook aid: it lists what hunt literally compares
without executing a template or making a network request. It can be used for
manual precision-codebook review, including checking whether a path is a
legitimate application route (step 2) and whether the matched literal content
represents an attack-like request (step 3). The command supplies no labels or
precision estimate; those judgments remain with the reviewer.
