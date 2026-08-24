# Threat-hunting workflow

This first slice implements **FIND**: matching known request-side indicators in historical telemetry. It intentionally does not infer compromise or generate deployable blocks.

The planned workflow is: **FIND → EXPLAIN → PIVOT → ACT → VALIDATE**. The next phases add grouping and pivots, then WAF-condition hypotheses in COUNT mode, then full historical replay to measure threat coverage and other historical matches.

No finding proves successful exploitation. A lack of findings does not prove that an application was not attacked or compromised.
