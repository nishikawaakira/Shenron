# Telemetry capabilities

Shenron normalizes every supported source into `WebEvent`, but detectability is assessed against the source’s actual capabilities. A missing field is not a parser failure when the selected telemetry profile does not log it.

| Capability | AWS WAF | nginx combined | Apache combined |
| --- | --- | --- | --- |
| Source IP, timestamp, method, path/query | Yes | Yes | Yes |
| Status / response bytes | Status only | Yes | Yes |
| Referer / User-Agent | Yes | Yes | Yes |
| Arbitrary request headers / Host | Yes | No by default | No by default |
| JA3 / JA4 | Optional | No by default | No by default |
| WAF action, labels, rule IDs | Yes | No | No |
| Request body | No | No | No |

nginx documents its built-in `combined` format as `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`; Apache documents the equivalent `combined` `LogFormat` with `%h`, `%t`, `%r`, `%>s`, `%b`, Referer, and User-Agent. Neither standard form includes arbitrary request headers, a Host value, JA3/JA4, WAF metadata, or request bodies. See [nginx log module documentation](https://nginx.org/en/docs/http/ngx_http_log_module.html) and [Apache 2.4 log documentation](https://httpd.apache.org/docs/current/logs.html).

Use explicit source selection:

```bash
shenron scan --input ./logs --format nginx --rules ./rules
shenron scan --input ./logs --format apache --rules ./rules
shenron production inspect --input ./logs --format nginx
shenron production hunt --input ./logs --format apache ...
shenron-lab nuclei compare-telemetry --templates ./nuclei-templates --revision <sha>
```

The combined parser is intentionally limited to standard combined records. Custom formats are not guessed. The telemetry comparison also includes analysis-only counterfactuals: `nginx-combined+host` and `nginx-security`. The latter models a reviewed custom format with Host and explicitly selected, non-sensitive request headers; it is not a recommendation to log credentials, cookies, tokens, or request bodies, and it is not yet a custom-format parser.

For combined logs, WAF outcome is unavailable. A production hunt therefore never calculates a WAF protection-gap rate from nginx or Apache evidence alone.
