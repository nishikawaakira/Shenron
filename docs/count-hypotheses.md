# COUNT hypothesis ladder

`shenron production count-hypotheses` evaluates broad-to-narrow validated Nuclei Detection IR predicates as **local COUNT-mode simulations**. It does not create an AWS rule, call AWS, deploy a control, execute a template, or contact a network. Its purpose is to give an analyst the measurements needed to choose whether a condition is appropriate for a separate human-reviewed COUNT-only export.

```bash
shenron production count-hypotheses \
  --input ./historical-logs \
  --format aws-waf \
  --nuclei-templates ./nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --findings ./private-results/hunt/private-findings.jsonl \
  --output ./research/count-hypotheses.json
```

For every observed CVE, the report lists this broad-to-narrow predicate ladder:

1. `path_only`
2. `path_and_query`
3. `path_query_headers`
4. `nuclei_ir`
5. `nuclei_ir_request_specific`

Each rung reports matched event volume, conservative known-finding re-observation coverage, other matches split by request-ID availability, and the logged WAF outcome context. The figures expose the coverage-versus-collateral trade-off, but Shenron deliberately does **not** select or recommend a best rung. The analyst must review the evidence and, if appropriate, use the existing COUNT-only export workflow separately.

Coverage is based only on re-observed source-finding request IDs and is a conservative lower bound. It is not precision, recall, accuracy, ground truth, attack evidence, exploitation success, compromise evidence, or proof of a vulnerable product. Other matches may represent additional relevant attempts or accidental matches, so they require review. `BLOCK`, `ALLOW`/`COUNT`, and unknown outcomes are historical context only, not exploitation outcomes.

The JSON report is sanitized aggregate output: it contains hashes of frozen local inputs and counts only, never IP addresses, hosts, URIs, queries, headers, raw requests, or request IDs. This differs from [detection-strategy ablation](ablation.md), which compares only aggregate predicate volume across the corpus. COUNT hypotheses add per-CVE conservative coverage, other-match, and WAF-outcome measurements while remaining non-deploying and offline.
