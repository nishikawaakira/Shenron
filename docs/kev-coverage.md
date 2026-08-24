# CISA KEV Coverage

`shenron-lab kev coverage` joins two local, untrusted-data inputs: an official CISA KEV JSON snapshot and a Shenron Nuclei coverage report. It does not download data, execute templates, scan targets, or evaluate payloads.

```bash
cargo run --bin shenron-lab -- kev coverage \
  --kev ./known_exploited_vulnerabilities.json \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --report ./research/kev/<snapshot-date>/coverage.json
```

Web relevance is conservative and evidence-based. A KEV is `WEB_RELEVANT` only when CISA's short description explicitly mentions HTTP/HTTPS/web transport or a Nuclei HTTP template exists. It is `NOT_WEB_RELEVANT` only when Nuclei evidence exists and all associated templates are non-HTTP. Otherwise it is `UNKNOWN`. Missing Nuclei data is not evidence that a KEV is undetectable.

The join preserves every KEV CVE, concise CISA metadata, web-relevance reasons, all matching Nuclei template summaries, and a strongest-state aggregate. The aggregate preference is validated, then converted, then observable-but-unsupported, then HTTP-not-observable, non-HTTP, and no Nuclei evidence. A future Sigma intersection can use the same CVE-keyed results without changing this measurement.
