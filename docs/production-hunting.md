# Production AWS WAF hunting

Production hunting is read-only and local. Shenron never modifies source logs, calls AWS, creates a WAF rule, replays traffic, scans a target, or executes a Nuclei template. Use a local JSON, JSONL, gzip, or directory-tree export.

Inspect structure before a hunt. This command reports only counts, timestamps, and field availability; it never prints raw requests.

```bash
cargo run --bin shenron -- production inspect --input ./production-waf-logs --format aws-waf --sample 10000
```

Run a full hunt only with the pinned Nuclei template checkout and frozen reports that validated the detections:

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --nuclei-templates /path/to/nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --output ./private-results/hunt-2026-08-24
```

If the direct peer is a known CDN, load balancer, or reverse proxy, supply every trusted proxy IP or CIDR explicitly to verify a forwarded end-client address. Shenron ignores `X-Forwarded-For` unless the observed direct peer is in this configured set: an untrusted peer can forge that header. Shenron evaluates a verified chain from right to left, removes only trusted proxy hops, and uses the first non-trusted address as `client_ip`. A missing, malformed, or all-trusted chain remains unavailable. Standard nginx/Apache Combined Log Format does not retain `X-Forwarded-For`, so it normally cannot provide `client_ip` even when `--trusted-proxy` is supplied.

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --trusted-proxy 198.51.100.0/24 \
  --trusted-proxy 2001:db8:1234::/48 \
  --nuclei-templates /path/to/nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --output ./private-results/hunt-behind-proxy
```

Restrict a hunt to an inclusive UTC time interval with RFC 3339 timestamps. The report records the selected interval and how many parseable events were excluded because they were outside the interval or had no timestamp.

```bash
cargo run --bin shenron -- production hunt \
  --input ./production-waf-logs \
  --format aws-waf \
  --nuclei-templates /path/to/nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --from 2026-04-01T00:00:00Z \
  --to 2026-04-30T23:59:59Z \
  --output ./private-results/april-2026
```

`--output` must be outside the raw-input tree. The command writes `private-findings.jsonl` locally with investigation evidence, including fields that may be sensitive. `sanitized-research.json` has aggregate CVE/KEV counts, time ranges, WAF outcomes, and cardinalities only; it never includes raw request values, IPs, hostnames, JA3/JA4 values, queries, or headers. The default `private-results/` location is ignored by Git, but that is only an additional safeguard and not a data-security boundary.

Review the request-to-template mappings locally with `production explain`. It displays a CVE/template summary (up to 20 mappings) by default so a large hunt remains readable; small demo hunts therefore display all their mappings just as before. Add `--show-request` for individual matched method/path/query records, `--show-evidence` for all locally stored evidence, or `--show-source-ips` for an IP-group summary. Evidence labels distinguish the observed connection peer from a validated forwarded client IP. IP addresses are shown only from the local private findings file and are never added to the sanitized report. Use `--limit 0` only when intentionally reviewing every mapping, IP address, and individual finding.

```bash
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-request
```

```bash
# Triage client IPs only when a trusted forwarded chain was verified; otherwise
# the observed connection peer is used. The fixed breadth rule is at least
# three matching request observations and two template patterns. The fixed
# depth rule is at least ten matching request observations, including one-template repetition.
cargo run --bin shenron -- production explain \
  --findings ./private-results/hunt-2026-08-24/private-findings.jsonl \
  --show-source-ips
```

`requires investigation` means that breadth or depth of CVE-pattern behavior was observed for the selected grouping identity: `validated-client` where a trusted forwarded chain was verified, otherwise `observed-peer`. `validated-client` and `observed-peer` groups are intentionally never merged: if forwarded resolution works for only some requests, one actual sender can appear under both identities. `breadth` means several request observations across template patterns; `depth` means repeated observations even when only one template matched. It does **not** establish that the IP belongs to an attacker, that a vulnerability was exploited, or that a compromise occurred. An observed peer can be a proxy, CDN, load balancer, or NAT; monitoring and authorized vulnerability scanners can also produce either pattern. These thresholds are deliberately fixed rather than hunt options, so results stay comparable and the CLI stays small.

The hunt rebuilds only request matchers whose template IDs have both `SUPPORTED` conversion and `passed` synthetic validation in the supplied frozen report. It uses the same normalization and matcher as the Nuclei validation pipeline; there is no simplified production matcher. A response-dependent generic root probe such as `GET {{BaseURL}}` is not converted into passive CVE-related request evidence: request logs alone cannot reproduce the response fingerprint that makes that probe meaningful. If its template also contains an explicit exploit path, query, or distinctive request header, that explicit alternative remains eligible. `--format nginx` and `--format apache` parse standard combined access logs into the same event model. Their standard profiles do not expose WAF actions, so outcome and protection-gap metrics are explicitly unavailable for those sources.

Each CVE-related request match has a separate request-specificity label. `request-specific` means that the recovered Detection IR requires a query, URI fragment, or explicit header. `response-unverified` means that only method and path matched; even a familiar path such as `/.env` remains response-unverified because Nuclei's response confirmation cannot be reproduced from request telemetry alone. This label measures resistance to accidental request-side matches, not severity, attack confidence, exploitation success, compromise, or the presence of a vulnerable product. The `HIGH`/`MEDIUM`/`LOW` totals are template detectability only, never attack or compromise confidence.

An `ALLOW` or `COUNT` result is reported as **not blocked according to available WAF action evidence** for a CVE-related request match. This is a protection gap, not evidence that exploitation succeeded. Non-terminating WAF matches are reported separately as COUNT-related evidence. Candidate WAF controls remain analyst-authored defensive hypotheses and must be replayed and reviewed before any deployment; Shenron does not generate or deploy blocking rules in this command.
