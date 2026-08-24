# AWS WAF schema handling

`WebEvent` stores the raw JSON and normalized source IP, country, headers, host, method, URI/path/query/fragment, User-Agent, Referer, protocol, request ID, action, terminating-rule fields, labels, non-terminating rule IDs, JA3, and JA4. AWS WAF stores a request's query string in `httpRequest.args`; the parser maps it to `uri_query` and reconstructs `uri` as `path?args` for `cs-uri` matching. AWS WAF's top-level `fragment` is preserved as `uri_fragment`. Missing fields remain `None`/empty rather than causing a scan failure.

The parser accepts newline-delimited JSON and `.gz` variants. It reports malformed records and continues. See [the AWS logging-field reference](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html) for the complete provider schema and optionality.
