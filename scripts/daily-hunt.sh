#!/usr/bin/env bash
# Optional thin wrapper for one read-only, offline Shenron daily hunt.
# Artifact-dependent comparison/reporting requires the explicit run directory
# created below; Shenron selects the prior valid run and prints review signals.
# See docs/daily-hunting-runbook.md for interpretation and retention guidance.
set -euo pipefail

LOG_INPUT="${LOG_INPUT:-./logs/today}"
RUN_ROOT="${RUN_ROOT:-./private-results}"
FORMAT="${FORMAT:-auto}"
REPORT_LANG="${REPORT_LANG:-ja}"
SHENRON="${SHENRON:-shenron}"
NICE_LEVEL="${NICE_LEVEL:-10}"
SINCE="${SINCE:-24h}"

# Shenron remains single-threaded. Lower process priority preserves resources
# for interactive applications without changing analysis results.
if command -v nice >/dev/null 2>&1; then
  RUNNER=(nice -n "$NICE_LEVEL" "$SHENRON")
else
  RUNNER=("$SHENRON")
fi

mkdir -p "$RUN_ROOT"
run_dir="$RUN_ROOT/hunt-$(date -u +%Y%m%dT%H%M%SZ)"

"${RUNNER[@]}" hunt \
  --input "$LOG_INPUT" \
  --format "$FORMAT" \
  --since "$SINCE" \
  --output "$run_dir" \
  --baseline-latest "$RUN_ROOT" \
  --report \
  --lang "$REPORT_LANG"
