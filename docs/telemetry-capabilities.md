# Telemetry capabilities

Shenron normalizes every supported source into `WebEvent`, but detectability is assessed against the source’s actual capabilities. A missing field is not a parser failure when the selected telemetry profile does not log it.

| Capability | AWS WAF | nginx combined | Apache combined | Apache vhost combined |
| --- | --- | --- | --- | --- |
| Source IP, timestamp, method, path/query | Yes | Yes | Yes | Yes |
| Status / response bytes | Status only | Yes | Yes | Yes |
| Referer / User-Agent | Yes | Yes | Yes | Yes |
| Arbitrary request headers / Host | Yes | No by default | No by default | Host only |
| JA3 / JA4 | Optional | No by default | No by default | No by default |
| WAF action, labels, rule IDs | Yes | No | No | No |
| Request body | No | No | No | No |

nginx documents its built-in `combined` format as `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`; Apache documents the equivalent `combined` `LogFormat` with `%h`, `%t`, `%r`, `%>s`, `%b`, Referer, and User-Agent. Neither standard form includes arbitrary request headers, a Host value, JA3/JA4, WAF metadata, or request bodies. See [nginx log module documentation](https://nginx.org/en/docs/http/ngx_http_log_module.html) and [Apache 2.4 log documentation](https://httpd.apache.org/docs/current/logs.html).

Log-reading commands default to `--format auto`. Auto mode safely identifies
AWS WAF JSON and vhost-prefixed Apache Combined records. Standard nginx and
Apache Combined records are structurally identical, so auto mode deliberately
does not infer either source. In that case Shenron reports:

```text
Could not determine the input format safely.
Pass --format aws-waf, nginx, apache, or apache-vhost.
```

Auto mode samples input files with a recognized extension (`.json`, `.jsonl`,
`.log`, `.txt`, `.gz`); a directory of only differently named rotations (for
example `access.log.1`) yields no sample and reports the message above. The
scan itself still reads every file once the format is known, so passing an
explicit `--format` resolves that case.

Select the source explicitly for standard Combined or when strict parsing is
desired:

```bash
shenron scan --input ./logs --format nginx --rules ./rules
shenron scan --input ./logs --format apache --rules ./rules
shenron scan --input ./logs --format apache-vhost --rules ./rules
shenron inspect --input ./logs --format nginx
shenron hunt --input ./logs --format apache ...
shenron hunt --input ./other_vhosts_access.log --format apache ...
shenron-lab nuclei compare-telemetry --templates ./nuclei-templates --revision <sha>
```

The combined parser does not guess arbitrary custom formats. `apache` first recognizes standard Apache Combined and then falls back to Apache's `other_vhosts_access.log` shape on a per-line basis. The vhost prefix accepts either `%v:%p` (with port) or `%v` (without port) and is normalized to `host`; events record the format that actually matched. `apache-vhost` remains the strict mode when every line must contain that prefix. The telemetry comparison also includes analysis-only counterfactuals: `nginx-combined+host` and `nginx-security`. The latter models a reviewed custom format with Host and explicitly selected, non-sensitive request headers; it is not a recommendation to log credentials, cookies, tokens, or request bodies, and it is not yet a custom-format parser.

For combined logs, WAF outcome is unavailable. A hunt therefore never calculates a WAF protection-gap rate from nginx or Apache evidence alone.
