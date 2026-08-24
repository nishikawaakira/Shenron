# Nuclei test generation

`shenron-lab nuclei inventory --templates ./nuclei-templates` reads Nuclei YAML as static data and reports feature usage. `shenron-lab nuclei coverage` additionally converts the literal supported subset to an internal request-side detection, generates in-memory AWS WAF-shaped events, and runs exact and mutation checks locally.

```bash
cargo run --bin shenron-lab -- nuclei inventory \
  --templates ./nuclei-templates --revision <pinned-revision> --report inventory.json
cargo run --bin shenron-lab -- nuclei coverage \
  --templates ./nuclei-templates --revision <pinned-revision> --report coverage.json
```

The machine-readable reports retain template ID, explicitly sourced CVEs, relative template path, protocol, detectability, stable reasons, observable/unavailable fields, conversion status, and synthetic exact/mutation/near-miss validation status. CVEs are extracted only from explicit ID, tags, references, classification, or metadata values; Shenron never guesses a CVE from request resemblance.

Supported conversion is intentionally narrow: one structured `http`/legacy `requests` item with a literal `method`, one or more literal alternative `path` values, optional literal query or URI fragment, and literal headers; or one simple literal raw HTTP request. `{{BaseURL}}`, `{{RootURL}}`, and raw `{{Hostname}}` are target placeholders, not attack signatures. Any other variable/helper, payload expansion, attack mode, multi-request flow, required body, or OAST verification is reported rather than executed or approximated.

Response matchers are inventory evidence only. They cannot prove successful exploitation from WAF logs, and they are never translated into request-side detection conditions.
