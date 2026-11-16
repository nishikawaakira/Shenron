# Request spelling observations

`shenron request-anomalies` counts logged encoding shapes and request-line forms.
These are string observations, not a determination of attack, successful
exploitation, compromise, intent or identity. Client bugs, multilingual filenames,
old proxies, legitimate proxy use, diagnostics and health checks can produce
the same shapes. An observed 2xx response does not establish exploitation.

```bash
shenron request-anomalies --input ./logs --format nginx --output ./anomaly-run
shenron request-anomalies --input ./logs --format apache --show-examples
shenron request-anomalies --input ./logs --format nginx --show-source-ips --limit 20
shenron request-anomalies --input ./logs --format aws-waf --output-format json
```

Discovery, skipped-input disclosures, gzip magic-byte detection, physical line
references, inclusive UTC `--from`/`--to` and stored-byte SHA-256 fingerprints
use shared production machinery. Standard nginx/Apache Combined is ambiguous
under `--format auto`; select it explicitly. Recovery does not change auto
detection or another command's parser.

## Inspection and decoding

Inspection uses logged spellings, not inferred original wire content. For
Combined records, logger escapes `\"`, `\\` and `\xNN` are unescaped once by
this command. Invalid UTF-8 is never repaired with replacement characters:
invalid bytes in private JSON evidence are displayed as `\xNN`.

Percent decoding then runs **at most twice**, byte by byte. Valid `%HH` becomes
one byte; malformed escapes stay literal. Hex digits are case-insensitive.
`+` always stays literal, including query strings and form bodies. There is no
third pass, Unicode normalization, `%uXXXX` decoding, overlong repair, case
folding or application emulation. The byte helper is shared with response-sizes,
whose separate plus policy and existing outputs are unchanged.

Byte features inspect the target and available body. A known path can still be
inspected when the full target is unavailable. Non-HTTP request-line bytes are
also inspected, including when no target can be identified. Path features use
the logged path, excluding query/fragment **before** decoding. Body content is
not guessed to be a path or parsed as JSON, multipart or form fields.

Each feature counts a request once, even if it occurs repeatedly, in several
fields, or at both decoding depths. Requests may have multiple features, so
feature totals must not be summed as distinct requests.

## Exact feature definitions

| ID | Observation |
| --- | --- |
| `double-encoding` | Literal `%25` immediately followed by two hex digits, such as `%252e`. `%2e`, `%25` and `%25zz` do not meet this definition. |
| `overlong-utf8` | Literally or after either pass: C0/C1 plus a continuation byte; E0 followed by 80–9F and a continuation; F0 followed by 80–8F and two continuations. These non-shortest 2/3/4-byte shapes are not repaired into characters. |
| `overlong-traversal` | After the first or second percent-decoding pass, an adjacent dot + dot + separator byte sequence using the exact spellings below, with at least one non-shortest/explicit legacy token. Counts byte shapes in inspected targets/bodies/request lines, not a normalized server path; no character substitution or third pass. |
| `nul-byte` | Byte 00 literally or after either pass. |
| `crlf` | Byte 0A or 0D literally or after either pass. |
| `control-char` | C0 bytes 01–09, 0B–0C, 0E–1F, or DEL 7F, literally or after either pass. NUL and CR/LF are separate features. |
| `traversal` | Raw path segment exactly `..`, delimited by `/`, `\` or path boundaries. `...` is not a match. |
| `traversal-encoded` | Such a segment after one/two passes where a dot or its delimiting separator came from percent decoding. Encoding elsewhere is insufficient. A mixed path may have both traversal features. |
| `path-parameter-traversal` | In the raw path or after one/two passes, a `/`- or `\`-delimited segment contains `;` and the part before its first `;` is exactly `..`, including `..;jsessionid=x`, `%2e%2e;` and `..%3b`. Counted independently of `traversal` / `traversal-encoded`; query/body occurrences do not match. |
| `backslash-path` | A path backslash literally or after one/two passes, including `%5c` and `%255c`. Query/body backslashes do not match. |
| `iis-unicode` | `%u` or `%U` followed by four hex digits. It records spelling, not decoded characters. |
| `iis-unicode-ascii` | Literal `%u` or `%U` followed by four hex digits whose code-unit value is U+0000–U+007F or one of U+FF0E, U+FF0F, U+FF3C, U+2215, U+2216. Hex case is ignored. Records spelling only; `%uXXXX` is never replaced with a character. |
| `invalid-utf8` | The bytes after the second pass fail strict UTF-8 validation. Valid multilingual UTF-8 alone does not match. |
| `long-target` | Target byte length after logger unescaping and before percent decoding is strictly greater than `--max-target-length` (2048). Body length is not used. |
| `absolute-form` | Request target begins with `http://` or `https://` (case-insensitive). Its authority is excluded from path features. |
| `authority-form` | CONNECT with a nonempty target containing a colon, including `CONNECT example.test:443`. A shape test, not DNS resolution or authority validation. |
| `asterisk-form` | Target exactly `*`. |
| `invalid-percent-escape` | Literal percent in inspected target/body bytes is not followed by two hex digits. `%uXXXX` also matches. Malformed escapes created only by decoding do not. |
| `non-http-request-line` | Unescaped request line contains control/non-ASCII bytes, lacks exactly three whitespace-separated tokens ending with an `HTTP/` protocol token, or has an otherwise unrecognized target form; also an ALB event with neither method nor target (request placeholder, original line unavailable). No TLS handshake is interpreted. |
| `empty-request` | Request field empty/whitespace-only or `-`. |

Forms can overlap: CONNECT without a protocol token also has
`non-http-request-line`. A literal multilingual request line may have this
shape even if the regular parser accepted it. It does not establish malicious
behavior. Overlong and IIS spellings are not substituted for dots in traversal.

The `..;` feature observes a string shape, not a successful routing or access-control
bypass or an attack. Legitimate applications also use `;jsessionid=` path parameters.
Sanitized feature counts always include `path-parameter-traversal`, even at zero.

The exact byte tokens for `overlong-traversal` are:

| Token | ASCII | Non-shortest / explicit legacy spellings |
| --- | --- | --- |
| Dot | `2E` | `C0 AE`, `E0 80 AE`, `F0 80 80 AE`, and the explicit legacy spelling `C0 2E` |
| Separator | `2F`, `5C` | `C0 AF`, `C1 9C`, `E0 80 AF`, `E0 81 9C`, `F0 80 80 AF` |

Two dot tokens must be followed immediately by a separator token, with at least
one token from the last column. A lone `C0 AE` or ordinary ASCII `../` is
insufficient. `C0 2E` is deliberately included as a spelling exception: `2E`
is not a UTF-8 continuation byte, and this match does not assert decoder
acceptance. Existing `overlong-utf8`, `invalid-utf8`, `traversal` and
`traversal-encoded` definitions and counts are unchanged. Neither narrower
feature substitutes characters for `%uXXXX` or repairs UTF-8; a match does not
establish a successful traversal.
Both new feature keys always appear in sanitized counts, including at zero.

## Legacy Japanese encodings and interpretation

On EUC-JP and Shift_JIS sites, the broad `overlong-utf8` and `invalid-utf8`
features can count ordinary text rather than an encoding anomaly for that
site. EUC-JP search text such as `%C0%B8`, and even an isolated `%C0%AE`, does
not meet the narrower dot + dot + separator definition. Ordinary legacy text
can still satisfy that shape, however: in EUC-JP, `C0 AE` is 成 and `C0 AF` is
政, so `..政` (`..%C0%AF`), `成./` (`%C0%AE./`) and `成成政`
(`%C0%AE%C0%AE%C0%AF`) match `overlong-traversal`; in Shift_JIS, half-width
`..ﾀｯ` (`..%C0%AF`) has the same bytes. Review query-string and body matches
with the site's character encoding in mind. Japanese `%u30af`
matches `iis-unicode` but not `iis-unicode-ascii`. JavaScript's legacy
[`escape()`](https://tc39.es/ecma262/multipage/additional-ecmascript-features-for-web-browsers.html#sec-escape-string)
also produces `%uXXXX` for code units above U+00FF; the shape does not identify
a client implementation or its intent.

As operator-reported context, an sctx measurement dated 2026-11-14 across
3,201 hosts counted `%u` plus four hex digits on 17 hosts / 1,573 requests.
The operator associated 15 of those hosts with ASP.NET-related Japanese text
spellings. C0/C1 plus continuation-byte shapes appeared on 41 hosts / 16,172
requests, many associated with EUC-JP search terms. These are observations from
that corpus, not validation results for Shenron or general detection rates.
The narrower features provide separate counts for review; they do not turn
either broad family, or a narrower match, into an attack or intent conclusion.

## Profile support and unavailable fields

| Profile | Logged target/query | Body | Command-local request-line recovery |
| --- | --- | --- | --- |
| `nginx`, `apache`, `apache-vhost` | Available when recorded, within an intact Combined envelope | Unavailable | Yes; outer timestamp, peer and recorded status shape are required |
| `nginx-postdata` | Same, within the existing prefix/postdata envelope | Logged body, including known empty bodies | Yes within a complete envelope; cut bodies are not repaired |
| `aws-waf` | Logged JSON URI and args spellings; missing/`REDACTED` fields unavailable | Unavailable | Unavailable: no original request line |
| `alb` | Existing parser's normalized logged URL target | Unavailable | Unavailable; `"- - - "` placeholders retain peer/status without a target and receive `non-http-request-line` |
| `cloudfront` | Existing parser's logged URI stem/query | Unavailable | Unavailable: no original request line |

The synthetic WAF fixture checks that `%252e`, `%2500` and `+` in
`httpRequest.uri` and `args` survive the existing parser unchanged. This
verifies Shenron's handling of the supplied JSON spelling, not a service's or
collector's original wire bytes. See AWS's
[URI/query log-field definitions](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html).
No missing/redacted value is reconstructed. A redacted query makes the complete
target unavailable, while a separately known path can still be inspected.
Upstream normalization cannot be reversed or established from these logs.

For ALB/CloudFront the existing parser remains authoritative: rejected fields
remain parse errors. Headers, TLS, cookies and arbitrary raw-record fields are
not inspection inputs. Counterfactual profiles are not production parsers.

ALB's single `"-"` request placeholder has the same parsed representation as
`"- - - "` and receives the same feature. These are ordinary ALB parse successes:
`rescued_records` does not increase and no original request line is reconstructed.

`targets_unavailable`, `paths_unavailable`, `request_bodies_unavailable`,
`request_lines_unavailable` and `sources_unavailable` count missing inspection
data among analyzed requests. A zero count for a feature does not establish its
absence in unrecorded/uninspected fields.

## Quality and recovery

`parseable_records` counts ordinary parse successes; `rescued_records` counts
records recovered only by this command. `parse_errors` counts unrescued
rejections. These disjoint quality counts cover nonblank input before filtering;
`analyzed_requests` and feature measurements follow the time filter. Explicit
UTC bounds exclude and disclose undated observations.

Recovery requires a recognizable outer envelope and valid timestamp. Rejected
request fields can retain absolute-form, CONNECT, asterisk, malformed escapes,
empty or binary content. Format errors caused by control/binary/empty request
content are recoverable only with an intact envelope. Unrelated malformed
records and invalid timestamps remain parse errors. The existing 64 KiB
Combined line cap applies; oversized lines are disclosed. Genuine read/gzip
errors fail before artifacts are written. Cut records/bodies are not completed
by guessing. `hunt` still rejects/counts the same rows: integrating recovery
there would be a separate design change.

## Metrics, bounds and privacy

Each feature reports requests, distinct sources/paths, status classes, UTC
first/last, undated counts and `responses_2xx` (not an exploitation result).
Missing status is unavailable; first/last are null without dated observations.
Distinct paths are case-sensitive, query-free raw spellings, not merged after
percent decoding. IP sets canonicalize mapped IPv4/equivalent spellings;
display selects the lexicographically smallest recorded spelling. Unparseable
peer strings use raw equality, without DNS. All sources are observed peers and
may be proxies, CDNs or NATs.

All limits are positive finite counts; zero is rejected:

| Option | Default | Meaning |
| --- | ---: | --- |
| `--max-target-length` | 2048 | Strict length threshold for `long-target` |
| `--max-examples` | 10 | Retained examples per feature |
| `--max-source-ips` | 100000 | Global source rows and distinct sources per feature |
| `--max-paths-per-feature` | 100000 | Distinct raw paths per feature |
| `--limit` | 20 | Top source rows in private output/display |

Known keys keep counting at capacity. Rejected new-key requests are disclosed
as observation counts, not estimated distinct values. `distinct_sources` and
`distinct_paths` become null when observations lack that field or their sets reject new keys; corresponding
`_at_least` counts remain proven lower bounds. Global source-row omissions
are `requests_beyond_source_tracking_cap`. `sources_not_reported` counts
retained rows omitted by `--limit`. Source rows count requests with any feature,
sorted by that count descending, then canonical/raw key ascending.
`examples_omitted` reports each feature's example overflow.

Examples are admitted in sorted-file/physical-line order, then sorted by UTC,
file and line. Capped examples need not be the earliest by time.

With `--output`:

- **Private** `request-anomalies.json` contains summary, bounded examples and
  top sources. Examples have file, physical decoded line, timestamp, recorded
  peer and raw target; rescued rows also retain their logged request line.
  `observed_in` identifies inspected parts. Body values are never copied;
  inspect immutable source references locally if needed.
- **Sanitized** `sanitized-request-anomalies.json` contains aggregate counts
  and distributions only: no target, path, IP, peer string or filename.
- **Private** `run-manifest.json` records corpus paths, stored-byte SHA-256,
  profile, UTC bounds, limits, skipped entries, depth and literal-plus policy.
  Gzip references are decoded physical lines; hashes identify original
  compressed bytes. Existing outputs are not overwritten.

Default stdout (text/JSON) is aggregate-only. `--show-examples` reveals private
evidence but hides its peer unless `--show-source-ips` is also set. The latter
independently shows retained source rows. Strings are terminal-escaped. These
flags make stdout private: filenames/targets themselves may be sensitive.
Same frozen inputs/options produce byte-identical artifacts and stdout;
manifests do not add wall-clock generation times.
