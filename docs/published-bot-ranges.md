# Self-declared bot User-Agents and published ranges

Shenron can compare a crawler/operator name declared in a User-Agent with a
frozen local copy of that operator's published IP ranges. This is an offline,
labeled observation: it is not reverse-DNS verification and does not determine
impersonation, attack, abuse, compromise, vulnerability, or attacker identity.

Prepare the snapshot explicitly with either:

```bash
shenron-lab bot-ranges update
# or as part of all public-input preparation
shenron-lab setup
```

The preparation command downloads only public JSON range files. It does not
receive or upload logs, findings, observed IPs, User-Agents, paths, or any other
customer data. The normalized `bot-ranges.json` records each source URL,
retrieval time, SHA-256, accepted range count, and invalid-record exclusion
count. Operator names, User-Agent substring patterns, and source URLs live in
the reviewable `data/bot-range-sources.json` catalog rather than matching code;
`--catalog <PATH>` can supply an alternative local catalog. Review each
publisher's terms and update policy before relying on the snapshot.

`hunt` automatically uses `<data-dir>/bot-ranges.json` when it exists, or an
explicit `--bot-ranges <PATH>`. Evaluation happens in the existing event stream
and causes no additional I/O or network access. For every configured operator,
the sanitized report records the number of User-Agent declarations, requests
inside and outside the published ranges, distinct peer counts, unavailable-peer
count, and the outside-range volume ratio. Raw outside-range peer IPs are kept
only in the private `bot-range-observations.json`. If no snapshot exists, hunt
prints one skip note and leaves every CVE and Sigma metric unchanged.

A request whose User-Agent names an operator but whose observed peer is outside
that operator's published ranges is only that: outside the published ranges.
Published ranges can be incomplete or stale, an intermediary can rewrite the
peer address, and a User-Agent string is freely settable by any client. The
observed peer can itself be a CDN, load balancer, NAT, or proxy. This is a
labeled observation for human review, never a determination of impersonation,
attack, abuse, compromise, or attribution.
