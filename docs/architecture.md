# Architecture

```text
AWS WAF JSONL / .gz → streaming parser → WebEvent → compiled Sigma subset → Finding → JSONL / CSV
```

The source parser owns vendor details; the matcher only reads normalized aliases. Rules are parsed and compiled once before input files are opened. Findings keep analyst-relevant evidence and a request ID, while `WebEvent` retains raw input for later pivots without copying raw logs into every finding.

Future hunting, candidate generation, and replay should consume `WebEvent` and `Finding` without coupling themselves to AWS JSON layout.

Nuclei analysis is a separate static-input adapter: it turns a literal, single-request HTTP subset into one or more alternative request-side detections over the same `WebEvent`. Multiple literal paths in one request are alternatives, not a stateful flow. Sigma keeps its condition AST because its named selections and boolean expressions are not losslessly equivalent to a Nuclei request. Both paths share source-neutral field normalization; neither executes template code or treats response matchers as request evidence.
