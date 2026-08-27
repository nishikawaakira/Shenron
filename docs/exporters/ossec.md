# OSSEC exporter

`shenron candidate export --backend ossec` generates an OSSEC XML **detection** rule. It is not a WAF rule and cannot block an HTTP request.

For standard nginx or Apache combined logs, Shenron emits one PCRE2 rule over the raw access-log representation with `category` `web-log`. This avoids assuming that a local OSSEC decoder exposes Shenron's normalized fields. The output requires local decoder/category validation with `ossec-logtest` before use.

Only a faithful AND combination of method, URI path, query, and User-Agent conditions is emitted. Host, arbitrary headers, JA3/JA4, OR, and NOT are refused for raw combined logs; a missing JA4 in nginx/Apache is reported as unavailable telemetry, never silently removed. Default rule ID is `99001`, within OSSEC's documented 100–99999 range.

Sources checked 2026-08-25: [OSSEC rules syntax](https://www.ossec.net/docs/docs/syntax/head_rules.html), [rule matching](https://www.ossec.net/docs/docs/manual/rules-decoders/rule-matching.html), and [Wazuh decoder field documentation](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html) for the decoder-dependency rationale.
