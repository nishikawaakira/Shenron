# Local malformed request-target results

Tested on 2026-08-24 using isolated `nginx:alpine` and `httpd:2.4-alpine` containers bound only to `127.0.0.1`. Each container received the same five raw request lines. Responses establish request acceptance/rejection only; no application or CVE behavior was exercised.

| Template | Characteristic | nginx status | Apache status | Observation |
| --- | --- | --- | --- | --- |
| CVE-2023-33568 | trailing bare `%` | 204 | 404 | Both servers accepted the request line; Apache recorded the target in its access output. |
| CVE-2023-39600 | unencoded whitespace | 400 | 400 | Both rejected it. Apache's log contains the request only up to the first invalid whitespace. |
| CVE-2023-32235 | incomplete percent-encoded sequence | 400 | 400 | Both rejected it; Apache emitted an `invalid URI path` error. |
| CVE-2015-6544 | literal `%%` before an encoded value | 204 | 404 | Both accepted the request line; Apache recorded the target. |
| CVE-2020-9054 | unencoded whitespace | 400 | 400 | Both rejected it. |

This validates that the current strict combined-log parser is conservative for the first and fourth cases: real servers can log them. It is not changed automatically in this research phase. Any future parser policy change must retain explicit raw-target safety tests and re-run the cross-telemetry benchmark as a new, non-frozen revisioned artifact.
