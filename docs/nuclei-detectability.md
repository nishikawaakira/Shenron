# Nuclei detectability

Shenron statically analyzes local, untrusted Nuclei YAML. It never executes templates, evaluates arbitrary template DSL, sends requests, contacts targets, or performs OAST interactions. The output describes request characteristics relevant to CVE-oriented investigation; it never establishes an attack, successful exploitation, compromise, or the presence of a vulnerable product.

`shenron-lab nuclei coverage` includes a template capability funnel: all CVE templates, HTTP CVE templates, templates with supported request IR, and the resulting IR alternatives split into `request-specific` and `response-unverified`. This separates the request-feature distribution of the convertible template corpus from the limitations of a selected telemetry source. It is not a field precision, true-positive-rate, attack, exploitation, compromise, or vulnerability-presence measurement; the funnel contains no ground truth.

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
