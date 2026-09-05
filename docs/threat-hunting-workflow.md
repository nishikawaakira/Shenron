# Threat-hunting workflow

The workflow is **FIND → EXPLAIN → PIVOT → ACT → VALIDATE**. It matches known request-side indicators in historical telemetry and intentionally does not infer compromise or generate deployable blocks.

Implemented so far:

- **FIND** — `hunt` matches validated Nuclei and/or Sigma request matchers against historical logs. With `--output` it writes separate private and sanitized artifacts; without it, private findings stream to stdout and no files are created.
- **EXPLAIN / PIVOT** — `explain` groups matches by CVE/template and by connection/client IP, locally resolved ASN, or JA4 fingerprint, applies breadth/depth/windowed triage, and assigns an offline [behavior priority score](production-hunting.md#behavior-priority-score). It can also enrich displayed IP and ASN groups from analyst-supplied frozen [local ASN and reputation datasets](production-hunting.md#ipasn-reputation-enrichment-offline), without external calls. `ablation` compares aggregate match volume across a predicate ladder derived from one validated Detection IR without writing private findings.
- **ACT** — `count-hypotheses` measures broad-to-narrow WAF-condition hypotheses as local [COUNT simulations](count-hypotheses.md); the `candidate` commands build, evaluate, review, and export analyst-authored defensive hypotheses. Shenron never deploys a control.
- **VALIDATE** — `replay` replays every validated Nuclei matcher across the complete local corpus and writes a sanitized [historical coverage report](historical-replay.md). It is distinct from the per-candidate replay export gate.

No finding proves successful exploitation. A lack of findings does not prove that an application was not attacked or compromised.
