# AWS WAF `args` query alias

AWS WAF represents the URI and query string separately. This regression verifies that `args` populates `uri_query` and is recombined for `cs-uri` matching without modifying the raw event.
