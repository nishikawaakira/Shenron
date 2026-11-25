# Telemetry capabilities

Shenron normalizes every supported source into `WebEvent`, but detectability is assessed against the source’s actual capabilities. A missing field is not a parser failure when the selected telemetry profile does not log it.

| Capability | AWS WAF | nginx combined | Apache combined | Apache vhost combined | ALB | CloudFront legacy |
| --- | --- | --- | --- | --- | --- | --- |
| Source IP, timestamp, method, path/query | Yes | Yes | Yes | Yes | Yes | Yes |
| Status / response bytes | Status only | Yes | Yes | Yes | Yes | Yes |
| Referer / User-Agent | Yes | Yes | Yes | Yes | User-Agent only | Yes |
| Arbitrary request headers / Host | Yes | No by default | No by default | Host only | Host only | Host only |
| JA3 / JA4 | Optional | No by default | No by default | No by default | No | No |
| TLS protocol / cipher | No | No | No | No | Yes, when TLS | Yes, when TLS |
| WAF action, labels, rule IDs | Yes | No | No | No | No | No |
| Request body | No | No | No | No | No | No |

ALB and CloudFront also record client ports and request identifiers. Capability
means the format can express a value, not that every record contains it. ALB
uses the request URL's host; CloudFront uses `x-host-header`. Neither profile
records arbitrary headers or supports WAF outcome scoring. CloudFront can
supply a forwarded client only under explicit trusted-proxy configuration,
never as a default capability. ALB's three timing fields are not synthesized
into `request_time_seconds`; missing fields remain unavailable. CloudFront
Cookies are redacted even from retained raw records. See the full
[normalization and privacy rules](production-hunting.md#alb-and-legacy-cloudfront-inputs).


nginx documents its built-in `combined` format as `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`; Apache documents the equivalent `combined` `LogFormat` with `%h`, `%t`, `%r`, `%>s`, `%b`, Referer, and User-Agent. Neither standard form includes arbitrary request headers, a Host value, JA3/JA4, the negotiated TLS protocol/cipher, WAF metadata, or request bodies. See [nginx log module documentation](https://nginx.org/en/docs/http/ngx_http_log_module.html) and [Apache 2.4 log documentation](https://httpd.apache.org/docs/current/logs.html).

Log-reading commands default to `--format auto`. Auto mode safely identifies
AWS WAF JSON, ALB records, headered legacy CloudFront files and vhost-prefixed Apache Combined records. Standard nginx and
Apache Combined records are structurally identical, so auto mode deliberately
does not infer either source. In that case Shenron reports:

```text
Could not determine the input format safely.
Pass --format aws-waf, nginx, apache, or apache-vhost.
```

Auto mode uses shared input discovery, including extensionless and numeric
rotations, and detects gzip by magic bytes. CloudFront is identified only when
the first two lines are `#Version: 1.0` and `#Fields: ...`; headerless TSV
requires `--format cloudfront`. ALB requires a recognized request type and UTC
ISO 8601 timestamp prefix. Explicit `--format alb` / `--format cloudfront`
select the parsers without inference.

Select the source explicitly for standard Combined or when strict parsing is
desired:

```bash
shenron hunt --input ./logs --format nginx --rules ./sigma-rules/ --no-nuclei
shenron hunt --input ./logs --format apache --rules ./sigma-rules/ --no-nuclei
shenron hunt --input ./logs --format apache-vhost --rules ./sigma-rules/ --no-nuclei
shenron hunt --input ./logs --format apache ...
shenron hunt --input ./other_vhosts_access.log --format apache ...
shenron nuclei compare-telemetry --templates ./nuclei-templates --revision <sha>
```

Every hunt summarizes populated-field counts and input quality over all
parseable events in the selected time range, including parse errors and the
earliest/latest timestamps. The same aggregate-only counts are stored in
`sanitized-research.json`; no IP, path, host, header, or other observed value is
included. This is useful for checking a new source or a suspected format
mismatch. A verified forwarded client IP is counted only when an explicit
`--trusted-proxy` configuration permits safe resolution.

The combined parser does not guess arbitrary custom formats. `apache` first recognizes standard Apache Combined and then falls back to Apache's `other_vhosts_access.log` shape on a per-line basis. The vhost prefix accepts either `%v:%p` (with port) or `%v` (without port) and is normalized to `host`; events record the format that actually matched. `apache-vhost` remains the strict mode when every line must contain that prefix. The telemetry comparison also includes analysis-only counterfactuals: `nginx-combined+host` and `nginx-security`. The latter models a reviewed custom format with Host and explicitly selected, non-sensitive request headers; it is not a recommendation to log credentials, cookies, tokens, or request bodies, and it is not yet a custom-format parser. In particular, it does not currently carry TLS protocol or cipher values. Capability-aware consistency checks therefore label those facts `unavailable` rather than guessing them or treating absence as a mismatch. See [declared-versus-observed consistency](declared-observed-consistency.md).

For combined, ALB and CloudFront logs, WAF outcome is unavailable. A hunt therefore never calculates a WAF protection-gap rate from nginx or Apache evidence alone.
