# Minimum security access-log profile

This is an example configuration for human review, derived from the pinned minimum-telemetry benchmark. It is not a deployment instruction.

The recommended additions to standard combined access logging are request `Content-Type`, `Accept`, `Accept-Encoding`, `SOAPAction`, and `Accept-Language`. The benchmark does not recommend raw `Authorization`, `Cookie`, API-key, token, or request-body logging.

## nginx

```nginx
# Example configuration for human review.
log_format shenron_security
  '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
  '"$http_referer" "$http_user_agent" '
  'ct="$http_content_type" accept="$http_accept" '
  'accept_encoding="$http_accept_encoding" soapaction="$http_soapaction" '
  'accept_language="$http_accept_language"';
```

## Apache HTTP Server

```apache
# Example configuration for human review.
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{Content-Type}i\" \"%{Accept}i\" \"%{Accept-Encoding}i\" \"%{SOAPAction}i\" \"%{Accept-Language}i\"" shenron_security
```

These examples intentionally use selected protocol/content-negotiation fields only. Review retention, access controls, downstream redaction, and tenant-specific privacy requirements before deployment.
