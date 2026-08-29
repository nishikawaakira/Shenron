# Threat-hunting workflow

The workflow is **FIND → EXPLAIN → PIVOT → ACT → VALIDATE**. It matches known request-side indicators in historical telemetry and intentionally does not infer compromise or generate deployable blocks.

Implemented so far:

- **FIND** — `production hunt` matches validated Nuclei request matchers against historical logs and writes separate private and sanitized artifacts.
- **EXPLAIN / PIVOT** — `production explain` groups matches by CVE/template and by connection/client IP, locally resolved ASN, or JA4 fingerprint, applies breadth/depth/windowed triage, and assigns an offline [behavior priority score](production-hunting.md#behavior-priority-score). It can also enrich displayed IP and ASN groups from analyst-supplied frozen [local ASN and reputation datasets](production-hunting.md#ipasn-reputation-enrichment-offline), without external calls. `production ablation` compares aggregate match volume across a predicate ladder derived from one validated Detection IR without writing private findings.
- **ACT** — the `candidate` commands build, evaluate, review, and export analyst-authored defensive hypotheses. Shenron never deploys a control.

Planned: WAF-condition hypotheses in COUNT mode and full historical replay to measure threat coverage and other historical matches.

No finding proves successful exploitation. A lack of findings does not prove that an application was not attacked or compromised.
