# Cross-telemetry comparison

## Provenance

- Nuclei repository: `https://github.com/projectdiscovery/nuclei-templates.git`
- Exact revision: `48a4f865127cb9e6b113c6bb493c984978009fd4`
- Checkout verification: `git -C /private/tmp/shenlon-nuclei-exact-checkout rev-parse HEAD` returned that exact SHA.
- Method: passive static template analysis and local synthetic parsing only. No Nuclei template was executed and no target was contacted.

The dataset contained 13,657 templates, 4,488 CVE templates, and 4,347 HTTP CVE templates. The AWS WAF row reproduces the frozen checkpoint exactly; the frozen artifact itself was not modified.

| Telemetry | HTTP CVE templates | Observable | Convertible | Validated |
| --- | ---: | ---: | ---: | ---: |
| AWS WAF | 4,347 | 2,622 | 1,577 | 1,577 |
| nginx combined | 4,347 | 2,198 | 1,474 | 1,469 |
| Apache combined | 4,347 | 2,198 | 1,474 | 1,469 |

nginx and Apache standard combined logs lose observability for 425 templates that require arbitrary request headers. Five additional source-compatible templates did not pass deterministic combined-log synthetic validation because their request targets are deliberately rejected as malformed by the parser (unencoded whitespace or invalid percent encoding). These are reported separately as implementation/validation limits, not silently counted as validated.

The comparison JSON includes per-template assessments and the analysis-only `nginx-combined+host` and `nginx-security` counterfactuals. Those counterfactuals are not parser implementations and must not be interpreted as a recommendation to log credentials, cookies, tokens, passwords, or complete request bodies.

## Reproduce

```bash
git init --bare /private/tmp/shenlon-nuclei-exact.git
git -C /private/tmp/shenlon-nuclei-exact.git fetch --no-tags --depth=1 \
  https://github.com/projectdiscovery/nuclei-templates.git \
  48a4f865127cb9e6b113c6bb493c984978009fd4
git --git-dir=/private/tmp/shenlon-nuclei-exact.git worktree add --detach \
  /private/tmp/shenlon-nuclei-exact-checkout \
  48a4f865127cb9e6b113c6bb493c984978009fd4
git -C /private/tmp/shenlon-nuclei-exact-checkout rev-parse HEAD

cargo run --release --bin webhunt-lab -- nuclei compare-telemetry \
  --templates /private/tmp/shenlon-nuclei-exact-checkout \
  --revision 48a4f865127cb9e6b113c6bb493c984978009fd4 \
  --report research/telemetry/48a4f865127cb9e6b113c6bb493c984978009fd4/comparison.json
```
