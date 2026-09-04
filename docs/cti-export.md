# File-only STIX 2.1 and MISP export

`shenron export` converts an existing hunt run into a local STIX 2.1 bundle or
MISP event JSON. It does not re-read source logs, contact TAXII or MISP, open a
socket, or upload anything.

The safe default reads only `sanitized-research.json`:

```bash
shenron export \
  --results-dir ./private-results/hunt-20260904T120000Z \
  --format stix \
  --output ./shenron-sanitized.stix.json
```

The bundle includes a Shenron identity, an explicit TLP marking, observed CVE
aggregate objects, public Nuclei template IDs, counts, source telemetry profile,
and frozen Nuclei revision where available. The equivalent `--format misp`
writes a non-published, organization-only MISP event. Neither format creates a
threat actor or campaign or determines attack, exploitation, compromise,
vulnerability, or attribution. Request specificity, response-unverified counts,
detectability, and path-distinctiveness counts stay machine-readable as
Shenron-labeled aggregate properties; they are not ground truth.

By default, no observed IP address, URI path, host, query, or header is read or
written. To deliberately include observed connection-peer IPs and URI paths
from `private-findings.jsonl`, opt in:

```bash
shenron export \
  --results-dir ./private-results/hunt-20260904T120000Z \
  --format stix \
  --include-observables \
  --output ./shenron-private.stix.json
```

The default marking is TLP:AMBER for sanitized-only output and TLP:RED when
private observables are included. `--tlp clear|green|amber|red` explicitly
overrides it. The marking does not itself make an output safe to share: review
local policy and the artifact before transfer. An observed connection peer can
be a CDN, load balancer, NAT, or proxy and is not attacker attribution. Relative
URI paths are represented as a custom STIX cyber-observable because Shenron
does not invent a scheme or hostname absent from telemetry.

IDs and object order are derived deterministically from frozen input content.
Malformed private-finding lines and invalid IP values are skipped and disclosed
as aggregate exclusion counts rather than guessed. No export command sends a
file to a remote endpoint; sharing remains a separate human-controlled action.
