# Response-size observations

`shenron production response-sizes` (also `shenron response-sizes`) compares
request-adjusted response sizes in a frozen local corpus. It does not reconstruct
response content, establish access authorization, or determine disclosure.
All analysis is offline. Standard Combined inputs remain supported by existing
commands; body-dependent analysis requires the explicitly selected extended format.

```sh
shenron production response-sizes --input ./logs --format nginx-postdata --output ./private-sizes
shenron response-sizes --input ./logs --format nginx-postdata --output ./private-review \
  --from 2026-01-01T00:00:00Z --to 2026-01-01T23:59:59Z \
  --show-source-ips --show-expressions --limit 20
```

## Explicit nginx-postdata input

After the standard Combined fields, the format requires quoted content type,
quoted TLS protocol, quoted cipher, request duration in seconds, and
`postdata[<body>]`. The final `]` closes the body; intermediate `]` characters
are retained. An empty `postdata[]` is no body. A duration of `-` is unavailable;
otherwise it must be finite and nonnegative. No timing-based conclusions are made.

An optional prefix of the following shape is removed before parsing:

```text
2026 Jan 01 00:00:01 (fixture) 192.0.2.1->/var/log/nginx/example.test_access_443.log
```

For response-sizes, the prefix is removed whenever its filename ends in `.log`.
Host is extracted only from `<host>_access.log` or `<host>_access_<digits>.log`;
all other filenames, including `error.log` and `example.test_error_443.log`,
leave host null. Error-log classification uses the remaining line's shape,
never the filename: an access record under an error-log filename is still read.
This broader prefix handling is limited to this command; other commands and
auto detection keep their existing parsing behavior. Without this prefix, host
is null, not inferred from a request or file path. Use one site's corpus when host is absent: null-host
requests cannot be separated into different sites. Forwarded clients are used
only under the existing `--trusted-proxy` verification; this format itself
does not record forwarded headers. Observed peers and validated clients are
different identities, and address comparisons canonicalize IPv4-mapped peers.

Host extraction uses the filename before `_access`, so `ssl_access.log` and
`other_vhosts_access.log` yield `ssl` and `other_vhosts`. Do not use this host
value to distinguish sites when the filename does not identify the site.

The event stores `request_body` in its logged spelling, `request_time_seconds`,
and `content_type`. All three remain absent in serialized events from existing
formats. The new profile declares response-byte and recorded TLS capabilities.
Host is recorded only when a prefix is present, so `host` capability is false;
response-sizes still groups on the actual `event.host` value. The body is read
directly from `WebEvent::request_body` by response-sizes, not available through
rule field matching, so `request_body` capability is also false. It is
**never selected by `--format auto`**.
The existing line-size bound and gzip magic detection apply, with parse failures
counted. Within `parse_errors`, `truncated_body` counts lines containing
`postdata[` but missing the final `]`; they are never repaired or analyzed.
`error_log_lines` counts lines beginning with `YYYY/MM/DD HH:MM:SS [level] `
after removal of a recognized prefix, and takes precedence over truncated-body
classification. `invalid_utf8_lines` counts byte records that cannot be decoded
as UTF-8; they are rejected without replacement characters, and subsequent
records are still read. All three counts are subsets of `parse_errors` and also
appear in sanitized output. Remaining parse errors are
`parse_errors - truncated_body - error_log_lines - invalid_utf8_lines`. Actual
reader errors, including incomplete gzip streams, still stop the run before
artifacts are written. The line-size bound still prevents analysis of oversized
records, including complete bodies.
Common discovery excludes unsupported/hidden entries with reasons;
their paths appear only in the private manifest.

## Paired size estimates

For recognizing request shapes, nginx `\xHH` escapes are decoded to bytes, then
percent escapes are decoded at most twice. Before the first percent-decoding
pass only, literal `+` becomes a space in the target after `?`, in body spans
starting at `?` and ending at the next double quote, ASCII whitespace or end of
body, and throughout an `application/x-www-form-urlencoded` body (media type
is case-insensitive and may have parameters). Boundaries are located after
nginx unescaping, so `\x22` is a double quote. Elsewhere, including JSON values
outside query spans and ordinary multipart content, `+` stays literal. A plus
produced from `%2B` or a second decoding pass is never converted to a space.
Both control recognition and shape comparison use this decoded text.
Non-UTF-8 decoded text is excluded and counted rather than replaced. This decoded
text is used only for recognition and shape comparison. The sent byte count is
the target plus body with each valid `\xHH` counted as one byte; **percent escapes
remain encoded for this count**. Invalid escape sequences remain literal.

Supported wrappers are `HEX(CAST((<expression>) AS CHAR))` (multiplier 2) and
`CAST((<expression>) AS CHAR)` (multiplier 1). Recognition is ASCII-case-insensitive
and permits whitespace, including no whitespace before `AS`. Balanced parentheses
retain nested expressions; quoted parentheses do not close a subquery.
This is deliberately limited syntax recognition, not a general SQL interpreter.

Each control group has identical host, canonical source/identity, method, path,
status, and decoded target/body with only the expression replaced by a marker.
Path and shape comparisons fold ASCII case but do not remove other differences.
The wrapper, surrounding whitespace, inner endpoint and request framing remain
part of the shape. Methods remain exact. Target and body stay separate so their
boundary cannot introduce an accidental match. CAST matches starting inside an
accepted wrapper belong to its expression and do not form independent shapes.
If an outer wrapper is invalid, an inner valid wrapper can still be recognized.
Independent wrappers, multiple character-read shapes, or a mixture of wrapper
and character-read shapes in one request are excluded with a count.

The earliest timestamped known constant in each group is the control; equal
timestamps use sorted input-file order, then physical record order. A later
file record can therefore supply an earlier control. Supported constants:

- `SELECT <ASCII digits>`: number of digits. A multi-digit value starting with
  zero is not a known control because SQL can remove leading zeros; `SELECT 0`
  remains a one-byte control.
- `SELECT 0x<hex>`: half the hex-digit count, requiring a nonempty even count.
- `SELECT '<string>'`: ASCII byte count, with doubled single quotes counted once.
  Non-ASCII strings are not known controls: character count is not byte count,
  and the connection encoding can affect response bytes. Backslash-dependent
  SQL string escapes are also not accepted as known controls.

Every other retained request, including another constant, is compared with that
control. Groups without a control contribute only to `groups_without_control`
and `requests_without_control`, not estimates. Missing source, method, path,
status, response bytes or timestamp prevents comparison and is counted separately.

```text
response_byte_delta = response_bytes - control.response_bytes
request_byte_delta  = sent_request_bytes - control.sent_request_bytes
adjusted_delta      = response_byte_delta - request_byte_delta
candidate_length   = adjusted_delta / multiplier + control.constant_length
```

If the adjusted delta is not divisible by the multiplier, the outcome is
`not_fitting` and `estimated_length` is null. Otherwise a negative candidate is
`negative_estimate`: the response shrank by more than the control value's
contribution. A missing row, different response template or noise may account
for this; it is not an identification of SQL NULL. A zero candidate is
`empty_or_null`: an empty value and SQL NULL cannot be distinguished by size.
Both outcomes have null `estimated_length` and add nothing to `estimated_lengths`.
Only a positive candidate produces outcome `length` and a numeric
`estimated_length`. Signed arithmetic is used even for decreasing sizes.

Private paired rows also contain `negative_candidates`, an ascending array of
distinct negative values with their request counts, for example
`[{"value": -2, "requests": 3}]`. These are candidate values, never members of
`estimated_lengths`. Repeated negative values could be explained by a
NULL-sensitive `CONCAT(..., HEX(CAST((...) AS CHAR)), ...)` wrapper: a NULL
value can make the entire concatenation NULL, removing the surrounding literal
contributions as well as the value. This is a possible explanation, not a NULL
determination; a changed response template or noise can also change sizes.

Results aggregate by host and normalized expression (whitespace collapsed to
one space and ASCII case folded). Private rows contain request count, distinct
source/identity count, sorted unique positive `estimated_lengths`, outcome
counts, first/last timestamps, and per-request evidence with the control time,
length, multiplier and both deltas. No response value is reconstructed.
Per-host `fitting`, `not_fitting` and `fit_rate` cover **HEX-wrapped reads only**.
`fit_rate` is fitting / (fitting + not_fitting), a parity check of the adjusted
delta, including zero and negative even candidates. CAST-only reads have no
divisibility check and are counted separately in `parity_unchecked_reads`.
With no HEX reads (including a CAST-only or control-only host), fit rate is null,
not 1.0. The host and these expression-level details are private. A high fit
rate does not validate the underlying assumptions or establish disclosure.

## Character-position observations

Recognized shapes are `ASCII` or `ORD` around `SUBSTRING`, `SUBSTR` or `MID`
with a positive integer position and a final argument of `1`. The first argument
may be `(SELECT ...)`, `COALESCE((SELECT ...), fallback)`, or
`IFNULL(CAST((SELECT ...) AS NCHAR), fallback)`. The single innermost SELECT is
retained; independent innermost subqueries are ambiguous and not recognized.
Expressions aggregate with the same host/normalization rules as paired estimates.

Rows report requests, distinct sources, `positions_probed` (distinct positions),
`max_position`, first/last timestamps, and the three most frequent response sizes
per status. Ties choose the smaller size. Counts beyond those three appear in
`response_size_requests_not_displayed_by_status`; these are display omissions,
not analysis exclusions. Position counts are **not lengths**: a client may test
beyond a value's end, repeat positions, or stop early.

## Bounds, outputs and reproducibility

`--max-observations` defaults to 1,000,000 matching requests with required fields,
shared by both analysis modes. It must be positive; it bounds retained records,
not log reading. Later eligible requests are counted in `observations_beyond_cap`.
An omitted request might have supplied an earlier control or new evidence, so
capped results describe retained observations only; raise the bound and rerun
the same frozen corpus for a complete comparison. Higher bounds use more memory.
No eviction, sampling, wall-clock generation time or random ordering is used.

- `response-sizes.json`: private expression details, source addresses, timestamps
  and host fit rates. Rows follow host/expression order, with null host first;
  evidence follows group-key order and input order within a group.
- `sanitized-response-sizes.json`: counts only, including parse failures, time
  exclusions, unmatched/ambiguous shapes, missing fields, decoding failures,
  cap omissions and outcome totals. It contains no hosts, expressions, paths,
  source values or timestamps.
- `run-manifest.json`: private options/time range, trusted proxies, input paths,
  stored byte lengths/SHA-256 and discovery exclusions. Hashing reuses the read
  path, including stored gzip bytes. Existing files are never overwritten;
  failed multi-file writes clean up outputs created by that batch.

Default stdout is aggregate `  Name: value` lines plus the safety note. Major
counts are always shown; exclusions, missing fields and cap omissions are shown
only when nonzero. `--show-source-ips`
exposes sources, `--show-expressions` exposes expressions independently. Expressions
are terminal-escaped and limited to 300 displayed characters. `--limit` defaults
to 20 expression rows; zero displays all. Paired rows precede character rows
with continuous numbering. Lengths are comma-separated without thousands
separators, or `-` when none; after ten values, `,... (+N)` discloses the remaining
count. With `--show-expressions`, negative candidates are shown alongside lengths
as `negative: -2 x3`; without that opt-in, their individual values are not shown.
Omitted expression row counts are also disclosed. These display options
do not change files.

## Safety note

Response-size estimates describe lengths, never content, and are not a determination of data disclosure. They assume the response is not compressed, does not vary over time, and repeats the request in the same way for the control and the read. fit_rate checks only parity for HEX-wrapped reads; CAST-only reads are unchecked. Positions probed by character-by-character reads are not lengths.
