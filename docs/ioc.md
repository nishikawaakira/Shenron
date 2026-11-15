# Retrospective IOC observations

`ioc` matches operator-provided local indicators against frozen historical logs.
It does not require Nuclei, Sigma, KEV or reputation inputs. Indicator files and
log values are never sent anywhere; no DNS, HTTP or TAXII lookup is performed.

```sh
shenron ioc --input ./logs --format nginx --indicators ./iocs.tsv --output ./ioc-run
shenron ioc --input ./logs --format aws-waf --indicators ./bundle.json --indicators ./more.tsv --show-matches --limit 20
```

The existing input discovery, gzip magic detection, stored-byte fingerprinting
and physical-line reference stream are reused. Paths are scanned in sorted
order. Skipped inputs and parse errors are disclosed, with skipped paths confined
to the private manifest. Inclusive UTC `--from` and `--to` behave as in other
analysis commands; undated records are counted and excluded when a bound is set.
Reader failures stop the run rather than silently accepting an incomplete input.
Gzip evidence line numbers refer to decompressed lines; SHA-256 covers stored
compressed bytes, including all members and unread suffixes, in the same pass.

## TSV indicators

Each record is `type<TAB>value[<TAB>label]`, without a header row. Lines beginning
with `#` and whitespace-only lines are counted as comments/empty records. Values
and labels retain their spelling; no inline comment syntax is applied.

| Type | Match |
| --- | --- |
| `ip` | Exact canonical address, including IPv4-mapped IPv6 equivalence |
| `cidr` | Address membership; host bits are truncated |
| `path` | Exact query-free `uri_path` |
| `path-prefix` | Literal prefix of query-free `uri_path`, including partial segments |
| `user-agent` | Exact recorded User-Agent |
| `ja3` | Recorded JA3; input must have 32 hexadecimal digits, folded to lowercase |
| `ja4` | Exact recorded JA4; nonempty ASCII without whitespace/control characters |
| `host` | Host equality after ASCII case folding, numeric-port removal and removal of one trailing dot |

Paths must start with `/` and cannot contain `?` or `#`. Paths, prefixes and UAs
are case-sensitive and are not URL-decoded. Host/domain indicators and event
hosts are compared after removing an explicit numeric port (including from
`[IPv6]:port`), removing one trailing dot and folding ASCII case. An unbracketed
IPv6 tail is never interpreted as a port. This changes matching keys only;
indicator values and recorded evidence retain their spelling. No DNS resolution
is performed. Missing fields do not match; a source
hostname is not parsed as an address. `observations_without_field` reports counts
for fixed field names, not an indicator-specific claim of absence from the site.
An IP or host match does not establish that any particular software is present.

IP lookup uses a hash index. CIDRs use IPv4/IPv6 hash tables keyed by network
address and existing prefix lengths, with at most 33/129 lengths per address;
there is no per-event scan over all CIDRs. All matching networks count, not only
the longest. Membership follows the existing mapped-address policy: native IPv4
can match mapped IPv6 networks at /96 or longer, but is not expanded into `::/0`.
Hash-table iteration never determines admission, output order or an identifier.
Path-prefix lookup tests only byte lengths present in admitted prefix indicators,
and only at UTF-8 character boundaries; with no prefix indicators it is skipped.
It does not hash every possible substring of each event path.

## Narrow STIX 2.1 subset

One initial UTF-8 BOM (`EF BB BF`) is removed before format detection, for either
TSV or JSON, and each private manifest file entry records `utf8_bom: true/false`.
This flag is absent from sanitized output and stdout. BOM removal does not alter
physical row numbers, and stored-byte length/SHA-256 still cover the BOM. A BOM
anywhere else is not removed.
Files are sniffed by their first non-whitespace byte: `{` selects a JSON bundle;
otherwise the file is TSV. Both may be gzip-compressed. A bundle must have
`type: "bundle"` and an `objects` array. Objects are read one at a time, rather
than retaining the whole bundle. Non-indicator objects are counted as ignored.
Only `indicator` objects with `pattern_type: "stix"` are eligible; explicit
`spec_version` or `pattern_version` values other than `2.1` are rejected. This is
a narrow importer, not full STIX schema validation or a source trust assessment.
An indicator with `revoked: true` is rejected as `revoked`; a non-boolean
`revoked` is rejected as `invalid-revoked`. False or absent values allow the
existing pattern/validity checks to proceed. The existing cap-first omission
rule still applies once the indicator limit is full.

Supported patterns contain one bracketed observation with one equality or
equalities of the same observable type joined by uppercase `OR`:

```text
[ipv4-addr:value = '192.0.2.7']
[ipv4-addr:value = '192.0.2.0/24' OR ipv4-addr:value = '198.51.100.7']
[ipv6-addr:value = '2001:db8::/32']
[domain-name:value = 'example.test']
[url:value = 'https://example.test/review/items']
```

Address families must match the STIX observable type. Domain values match host.
HTTP/HTTPS URLs match their normalized host and path. Only the scheme's default
port is removed from an indicator (`http:80`, `https:443`); an omitted/default
port compares with the event host after port removal. A non-default indicator
port is retained and matches only when the event host explicitly records that
port; portless vhost telemetry cannot establish it. Event matching tries both
the normalized host and, when available, its explicitly recorded port. Scheme
itself is not tested because the requested observation is host/path equality.
An absent URL path means `/`. Query-bearing URLs are rejected, as are fragments
and userinfo; none is silently discarded. Event queries do not change `uri_path`.
Single-quoted STIX strings support escaped quote/backslash only.

The **entire indicator** is rejected if any branch cannot be represented.
There is no partial OR, AND weakening, wildcard expansion or operator emulation.
Stable rejection codes include:

| Reason | Examples |
| --- | --- |
| `unsupported-operator` | AND, NOT, MATCHES, LIKE, WITHIN, unsupported property/syntax |
| `compound-observation` | Multiple bracketed observations, including FOLLOWEDBY |
| `mixed-observation-types` | OR combining IPv4 with a domain or IPv6 observable |
| `unsupported-object-type` | Other observable types, or unknown TSV types |
| `unsupported-pattern-type` | Indicator using a pattern language other than STIX |
| `unsupported-stix-version` | Explicit non-2.1 version |
| `revoked` | Indicator explicitly has `revoked: true` |
| `invalid-revoked` | Indicator's `revoked` value is not boolean |
| `invalid-pattern`, `invalid-value`, `address-family-mismatch` | Invalid grammar/value/family |
| `url-query-unsupported`, `url-fragment-unsupported`, `unsupported-url` | URL components outside the subset |
| `invalid-validity` | Malformed dates or `valid_until <= valid_from` |
| `invalid-tsv-record`, `invalid-utf8`, `indicator-too-large` | Malformed TSV/encoding or a TSV record/STIX pattern over 65,536 bytes |

`valid_from` and `valid_until` are preserved as UTC. An absent boundary is
unbounded. Validity uses `[valid_from, valid_until)`: matches before the start or
at/after the end remain counted and have `outside_validity: true`. If a bounded
indicator matches an undated event, this flag is null and
`validity_unavailable_matches` is incremented; no time is inferred. Invalid
bundle JSON fails the run with a file context, rather than reporting a partial
import as successful. Other STIX metadata is not interpreted. An indicator's
optional `name` becomes its private label; its ID is not needed for matching.
No STIX ID, name, value or label enters sanitized output.

## Identity, accounting and limits

Observed `source_ip` is always evaluated. `--trusted-proxy IP_OR_CIDR` optionally
enables the existing forwarded-client verifier. Only a verified `client_ip` is
also evaluated; untrusted forwarded values are ignored. `source_ip_matches` and
`client_ip_matches` count these matches independently. Individual records expose
`matched_on`; path/UA/fingerprint/host/URL conditions refer to request fields.
Raw source spellings remain in private records, while distinct sources use
canonical observed IPs. Validated clients and observed peers are never presented
as one identity population, and neither is an attribution.

One indicator/event pair counts once even if several OR branches or both address
identities match. `indicator_matches` counts these pairs; `matched_requests`
counts each input event once across all indicators. Outside-validity event and
pair totals are also separate. An event is a physical input record: overlapping
input files are not deduplicated as traffic. First/last seen summarize all
timestamped matches, including matches whose evidence was not retained.

| Option | Default | Meaning |
| --- | ---: | --- |
| `--max-indicators` | 1,000,000 | Accepted unique indicator rows |
| `--max-records-per-indicator` | 100 | Retained evidence records per indicator |
| `--max-sources-per-indicator` | 100,000 | Retained distinct canonical observed sources per indicator |

All limits must be positive. Files are processed in path order, records in
arrival order; retained keys continue accumulating after caps fill. Raising
limits increases memory use. OR expressions expand into multiple indexed terms,
bounded per pattern by the 65,536-byte pattern limit. No preallocation to the
configured maxima or approximate counting is used.

Identical normalized matcher sets with identical validity boundaries are
duplicates even if labels differ. The first admitted row supplies private
spelling, label and source file. OR terms are deduplicated internally.
Versions with the same STIX `id` are not selected by `modified`; identical
normalized atoms and validity boundaries count as duplicates across versions.
TSV `ip` and single-host `cidr` remain different matcher kinds. Once the indicator
cap is full, later candidate records are counted as `records_beyond_indicator_cap`
without interpreting their pattern/value or classifying duplicates/rejections.
Comments and non-indicator STIX objects are still counted separately. Reading
continues to count exclusions and fingerprint every file; omitted indicators
are never indexed. Per-file record counts include comments/ignored objects.

Private rows report `records_omitted`. Distinct-source admission failures count
observations, not estimated new sources. With any such failure,
`distinct_source_ips` is null and `distinct_source_ips_at_least` gives the
retained lower bound. Missing/invalid observed addresses are counted separately
and never inserted into the distinct-source set. No automatic eviction occurs.

## Outputs and safety

With `--output`, the command writes three new-only files, refusing existing
outputs. Failed batches clean up only files created by that batch:

- `ioc-matches.json`: **private**, all admitted indicators including zero-match
  rows, labels, source files, validity, match counts, distinct sources, UTC span,
  and bounded evidence (time, input file, physical line, method, query-free path,
  status, raw observed peer and verified client). Query/UA/header values are not
  copied into evidence; a UA used as an indicator remains a private indicator.
- `sanitized-ioc.json`: counts only, including fixed type/reason counts, matched
  indicators/events/pairs, validity exclusions, missing fields and cap omissions.
- `run-manifest.json`: **private**, indicator file paths, stored-byte SHA-256 and
  byte lengths, per-file accounting, corpus provenance, skipped inputs, telemetry
  profile, time bounds, trusted proxies and effective limits. Updating indicator
  files changes matching and provenance. There is no wall-clock generation time.

Default stdout contains the safety note and aggregates only. `--show-matches`
opts into private values/labels and retained record evidence; `--limit` defaults
to 20, with zero meaning all retained evidence. Display omissions are counted.
Values are terminal-escaped. Display settings do not change artifacts. These
files may contain restricted or TLP-marked CTI; sanitized output deliberately
excludes indicator strings, including STIX IDs and names. Existing outputs are
never overwritten. Identical input bytes and configuration give identical bytes.

> A match records only that an observed request matched an operator-provided
> indicator. It is not a determination of compromise, an attack, attacker
> identity, intent or a shared operator. CDN, NAT and shared-cloud addresses can
> also match unrelated users. Indicator values and labels may be sensitive CTI;
> review private artifacts before sharing. Analysis is local and offline; no
> blocking or deployment is performed.

The supported grammar is intentionally narrower than
[STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).
There is no explain/candidate integration, CTI export round trip or TAXII fetch.
