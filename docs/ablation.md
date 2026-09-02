# Detection-strategy ablation

`shenron production ablation` compares aggregate match volume for several
predicates derived from the same validated Nuclei Detection IR. It reads local
historical telemetry and frozen Nuclei/KEV reports, but it never writes private
findings or request evidence.

```bash
shenron production ablation \
  --input ./historical-logs --format aws-waf \
  --nuclei-templates ./nuclei-templates \
  --nuclei-report ./research/nuclei/<revision>/final.json \
  --kev-report ./research/kev/<snapshot>/coverage.json \
  --output ./research/ablation-volume.json
```

`--from` and `--to` use the same inclusive RFC 3339 time filter as
`production hunt`. The optional output is an aggregate-only JSON report.

## Ladder

Every strategy is evaluated against the same parseable events and the same
validated Detection IR. An event counts once per strategy if it matches one or
more detections. The report also shows distinct event × CVE matches.

1. `path_only`: the normalized URI path equals a detection path.
2. `path_and_query`: path equality, plus a required query substring where the
   Detection IR has one. A detection with no query condition passes this rung
   exactly as it passes `path_only`, so the rung cannot narrow it. The report
   therefore states how many of the validated detections have no query condition
   (`path_and_query_detections_without_query_condition` of `validated_detections`);
   this is the honest reason `path_and_query` often adds almost nothing over
   `path_only`, rather than it being an independent narrowing step.
3. `path_query_headers`: path/query conditions, plus every explicit Detection
   IR header condition.
4. `nuclei_ir`: the full request-side IR, including method and fragment
   conditions.
5. `nuclei_ir_request_specific`: a full IR match only when its detection also
   requires a query, fragment, or explicit header.

The predicates are intentionally nested: full IR matches are a subset of the
preceding stages, so matched-event counts should be non-increasing down the
ladder. `nuclei_ir_behavior_triaged` is deliberately deferred until behavior
triage is shared as library logic.

## Interpretation limits

This is a comparison of match volume only. The reported volume rate is
`matched events / total events evaluated`; it is not precision, recall,
accuracy, a true- or false-positive rate, or any other performance estimate.
The command creates no ground-truth labels and does not determine attacks,
exploitation, compromise, or vulnerable-product presence. It is suitable for
showing how adding validated request constraints narrows the volume relative to
a URI-only predicate, while leaving assessment of individual matches to human
review.

The report contains aggregate counts, selected time filters, telemetry profile,
and parse/exclusion counts only. It never includes raw request values, client
or peer IP addresses, hostnames, headers, queries, or private findings.
