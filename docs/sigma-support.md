# Sigma support (MVP)

Supported logsource: `category: webserver`, optionally narrowed to `product: aws` and `service: waf`. A generic `webserver` rule can evaluate against AWS WAF; non-webserver or non-AWS-WAF-specific rules are simply inapplicable to this source.

| Sigma field | Normalized field |
| --- | --- |
| `cs-method`, `method` | HTTP method |
| `cs-uri`, `uri` | URI |
| `cs-uri-stem`, `uri_path` | URI path |
| `cs-uri-query`, `uri_query` | URI query |
| `cs-host`, `host` | Host header |
| `cs-user-agent`, `c-useragent`, `user_agent` | User-Agent |
| `cs-referer`, `referer` | Referer |
| `c-ip`, `source_ip` | client IP |
| `sc-status`, `status` | `responseCodeSent`, when present |
| `ja3`, `ja4` | AWS WAF TLS fingerprints |
| `waf_action`, `waf_rule_id`, `waf_labels` | AWS WAF fields |

Selections support case-insensitive string equality; a list is OR by default. `|contains` is supported, and `|all` makes all list values mandatory. `keywords` searches a documented concatenation of method, host, URI, headers, and raw JSON. Conditions support named selections, parentheses, `and`, `or`, and `not`.

Rejected with a validation reason: correlation rules, wildcard values, regexes, other modifiers, numeric/structured values, `1 of`/`all of` wildcard conditions, placeholders, and unknown aliases. These are planned compatibility work, not silently downgraded behavior.
