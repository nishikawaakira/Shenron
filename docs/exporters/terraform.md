# Terraform AWS WAF exporter

`shenron candidate export --backend terraform-aws-waf` generates an HCL `rule { ... }` fragment for manual integration into an existing `aws_wafv2_web_acl`. It does not generate a complete Web ACL and does not run Terraform.

The fragment is COUNT-only, requires `--priority`, and has the same replay and faithful-compatibility requirements as the AWS WAF JSON exporter. Shenron cannot know an organization's Web ACL ordering, so it never invents a priority.

The generated HCL uses the current HashiCorp AWS provider's `byte_match_statement`, `field_to_match`, logical statement blocks, and required text transformation. JA3/JA4 fields include `fallback_behavior = "NO_MATCH"`.

Source checked 2026-08-25: [HashiCorp AWS `aws_wafv2_web_acl_rule`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_rule).
