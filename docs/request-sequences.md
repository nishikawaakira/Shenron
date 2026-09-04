# Ordered request sequences

Entity triage derives a bounded, deterministic sequence view from the private
findings already stored by a hunt. `shenron explain --show-source-ips` reports
the maximum distinct request patterns, and the subset on distinctive paths,
within a ten-second sliding window by default. Use `--sequence-window 1m` (or
another positive `s`, `m`, `h`, or `d` duration) to change that reporting
window. This setting does not change detection matches, triage thresholds, or
the behavior-priority score.

For every entity, timestamped observations are ordered by UTC time. The private
`triage-view.json` stores the ordered method/path/query pattern, timestamp, and
path-distinctiveness label, plus minimum and median intervals between retained
observations. The corresponding `triage-summary.json` contains only numeric
counts and seconds: raw entity keys and request patterns are never copied into
the sanitized summary. Timestamp-less observations are excluded from ordering
and disclosed as a count.

Tracking retains and displays request patterns for up to 100,000 distinct
logged requests per entity. New observations beyond the cap are not
approximated and are disclosed in both the private entity entry and aggregate
numeric summary. The distinct-request tracking used to detect that cap still
grows with the input, like the other per-entity distinct-value sets; the
100,000 limit is therefore not a hard bound on all per-entity memory. Retained
observations are the first 100,000 in input order, which is deterministic for a
fixed input but does not necessarily mean the chronologically earliest 100,000.
Multiple findings for the same request ID contribute one sequence observation.

An ordered request sequence is an observation of what was requested and when.
Regular intervals or a short span can result from automation, a crawler, a page
that issues several subresource requests, or a person clicking quickly. This is
a labeled observation for review, not a determination of automation, attack,
abuse, compromise, or attacker identity.
