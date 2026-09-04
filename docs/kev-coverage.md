# CISA KEV Coverage

`shenron-lab kev coverage` joins two local, untrusted-data inputs: an official CISA KEV JSON snapshot and a Shenron Nuclei coverage report. It does not download data, execute templates, scan targets, or evaluate payloads.

`shenron-lab setup` can perform the public download and this local join in one
preparation step. It stores `known_exploited_vulnerabilities.json`,
`kev-report.json`, and `kev-manifest.json` in the Shenron data directory. The
manifest records the public source URL, retrieval time, SHA-256 values, and
record counts; no customer data is transmitted. Use `--skip-kev` to omit this
step. With `--skip-nuclei`, an existing frozen Nuclei report is reused; without
one, only the join is skipped and the reason is reported.

```bash
cargo run --bin shenron-lab -- kev coverage \
  --kev ./known_exploited_vulnerabilities.json \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --report ./research/kev/<snapshot-date>/coverage.json
```

Web relevance is conservative and evidence-based. A KEV is `WEB_RELEVANT` only when CISA's short description explicitly mentions HTTP/HTTPS/web transport or a Nuclei HTTP template exists. It is `NOT_WEB_RELEVANT` only when Nuclei evidence exists and all associated templates are non-HTTP. Otherwise it is `UNKNOWN`. Missing Nuclei data is not evidence that a KEV is undetectable.

The join preserves every KEV CVE, concise CISA metadata, web-relevance reasons, all matching Nuclei template summaries, and a strongest-state aggregate. The aggregate preference is validated, then converted, then observable-but-unsupported, then HTTP-not-observable, non-HTTP, and no Nuclei evidence. A future Sigma intersection can use the same CVE-keyed results without changing this measurement.
