# Declared-versus-observed consistency

Shenron can compare a self-declared request attribute with an independently
observed fact in the same offline hunt stream. Each check records the declared
attribute, the observed fact, and one of `match`, `mismatch`, or `unavailable`.
An unavailable result has one explicit reason: the frozen reference data is
missing, the telemetry profile does not expose the required fact, or the
particular event has no usable observed value. Unavailable observations are
never counted as mismatches.

The first check implemented through this framework is the existing comparison
of a crawler operator named by its User-Agent with that operator's frozen,
published address ranges. Its existing aggregate and private bot-range report
remain unchanged. The generalized aggregate is added to
`sanitized-research.json`; declaration and observation values are written only
to the private `declared-observed-observations.json` artifact. Both paths are
deterministic and perform no network access during analysis.

`WebEvent` also has optional normalized `tls_protocol` and `tls_cipher` fields.
All currently implemented telemetry profiles declare both capabilities as
unavailable: AWS WAF and standard nginx/Apache logs do not populate them, and
the analysis-only `nginx-security` profile is still not a custom-format parser.
Consequently, a browser-family-versus-cipher check is reported as unavailable
for current inputs. Shenron does not infer a cipher from a User-Agent, and it
does not classify a pair without an explicit frozen reference table. A future
custom parser may populate these fields only when the source actually records
them.

A mismatch between a self-declared attribute and an observed one is a labeled
observation. Declarations are freely settable, reference data can be incomplete
or stale, and intermediaries can rewrite both. It is not a determination of
impersonation, automation, attack, abuse, compromise, or attacker identity.

