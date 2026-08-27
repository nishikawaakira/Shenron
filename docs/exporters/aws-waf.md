# AWS WAF JSON exporter

`shenron candidate export --backend aws-waf-json` writes a review-only AWS WAF v2 **rule** JSON artifact and a sanitized evidence sidecar. It never calls AWS or deploys a Web ACL.

The exporter emits `Count` only. It requires `--priority` and recorded historical replay evidence, and refuses `PARTIALLY_SUPPORTED` or `UNSUPPORTED` candidates rather than dropping conditions.

AWS WAF v2 `ByteMatchStatement` is used with `TextTransformations: [{"Priority": 0, "Type": "NONE"}]`, preserving the literal candidate semantics. URI path, query string, method, single headers, AND/OR/NOT, JA3, and JA4 are mapped only when faithful.

JA3/JA4 are `EXACTLY` byte matches with `FallbackBehavior: NO_MATCH`. AWS documents them as available only for CloudFront and ALB, and requires exact string matching. The target resource remains a reviewer decision.

Sources checked 2026-08-25: [AWS WAF FieldToMatch](https://docs.aws.amazon.com/waf/latest/APIReference/API_FieldToMatch.html), [request components](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields-list.html), and [Statement API](https://docs.aws.amazon.com/waf/latest/APIReference/API_Statement.html).
