# Nuclei detectability

Shenron statically analyzes local, untrusted Nuclei YAML. It never executes templates, evaluates arbitrary template DSL, sends requests, contacts targets, or performs OAST interactions. The output describes request characteristics consistent with an exploitation attempt; it never establishes successful exploitation.

| Level | Meaning |
| --- | --- |
| `HIGH` | A literal, distinctive request path, query, or header is observable in supported logs. |
| `MEDIUM` | A useful request-side signal exists, but response/OAST/body/state context is unavailable. |
| `LOW` | The observable request is too generic to be a meaningful attempt signature by itself. |
| `UNDETECTABLE` | No supported HTTP request-side signal exists. |
| `UNKNOWN` | Shenron cannot safely interpret the template syntax or variable behavior. |

Detectability and conversion are deliberately separate. For example, a distinctive raw HTTP request can be detectable in principle while unsupported by a limited parser. The converter supports one literal structured request with one or more literal alternative paths, or one simple raw request, plus method, path, query, URI fragment, and literal headers. It rejects payload expansion, attack modes, multi-request flows, unresolved variables/helpers, OAST-required verification, and body-dependent logic with stable reason identifiers.

AWS WAF logs do not provide complete arbitrary request bodies for this engine, so body-dependent characteristics are never silently converted into a WAF detection.
