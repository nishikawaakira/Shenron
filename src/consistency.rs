//! Deterministic comparison of self-declared attributes with observed facts.
//!
//! A mismatch is a labeled observation only. Declarations are freely settable,
//! reference data can be incomplete or stale, and intermediaries can rewrite
//! both sides. Results do not determine impersonation, automation, attack,
//! abuse, compromise, or identity.

use std::collections::BTreeMap;

use serde::Serialize;

pub const DEFAULT_MAX_PRIVATE_CONSISTENCY_OBSERVATIONS: usize = 1_000_000;
pub const CONSISTENCY_SAFETY_NOTE: &str = "A mismatch between a self-declared attribute and an observed one is a labeled observation. Declarations are freely settable, reference data can be incomplete or stale, and intermediaries can rewrite both. It is not a determination of impersonation, automation, attack, abuse, compromise, or attacker identity.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComparisonOutcome {
    Match,
    Mismatch,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnavailableReason {
    ReferenceDataMissing,
    TelemetryDoesNotExpose,
    ObservedValueMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparisonResult {
    pub outcome: ComparisonOutcome,
    pub unavailable_reason: Option<UnavailableReason>,
}

/// Evaluate a declared attribute against a set of accepted observed values.
/// Capability and value absence are checked before reference absence so every
/// unavailable result has one precise, auditable reason.
pub fn compare_declared_with_observed(
    telemetry_exposes_observed: bool,
    observed: Option<&str>,
    accepted_observed_values: Option<&[String]>,
) -> ComparisonResult {
    if !telemetry_exposes_observed {
        return unavailable(UnavailableReason::TelemetryDoesNotExpose);
    }
    let Some(observed) = observed.filter(|value| !value.is_empty()) else {
        return unavailable(UnavailableReason::ObservedValueMissing);
    };
    let Some(accepted) = accepted_observed_values else {
        return unavailable(UnavailableReason::ReferenceDataMissing);
    };
    ComparisonResult {
        outcome: if accepted.iter().any(|value| value == observed) {
            ComparisonOutcome::Match
        } else {
            ComparisonOutcome::Mismatch
        },
        unavailable_reason: None,
    }
}

pub fn compare_boolean_fact(
    telemetry_exposes_observed: bool,
    observed_available: bool,
    reference_available: bool,
    matches: bool,
) -> ComparisonResult {
    if !telemetry_exposes_observed {
        unavailable(UnavailableReason::TelemetryDoesNotExpose)
    } else if !observed_available {
        unavailable(UnavailableReason::ObservedValueMissing)
    } else if !reference_available {
        unavailable(UnavailableReason::ReferenceDataMissing)
    } else {
        ComparisonResult {
            outcome: if matches {
                ComparisonOutcome::Match
            } else {
                ComparisonOutcome::Mismatch
            },
            unavailable_reason: None,
        }
    }
}

fn unavailable(reason: UnavailableReason) -> ComparisonResult {
    ComparisonResult {
        outcome: ComparisonOutcome::Unavailable,
        unavailable_reason: Some(reason),
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UnavailableReasonCounts {
    pub reference_data_missing: u64,
    pub telemetry_does_not_expose: u64,
    pub observed_value_missing: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ConsistencyCheckSummary {
    pub check_id: String,
    pub matches: u64,
    pub mismatches: u64,
    pub unavailable: u64,
    pub unavailable_reasons: UnavailableReasonCounts,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ConsistencySummary {
    pub checks: Vec<ConsistencyCheckSummary>,
    pub private_observations_beyond_cap: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateConsistencyObservation {
    pub check_id: String,
    pub declared_attribute: String,
    pub declared_value: String,
    pub observed_attribute: String,
    pub observed_value: Option<String>,
    pub outcome: ComparisonOutcome,
    pub unavailable_reason: Option<UnavailableReason>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateConsistencyReport {
    pub report_kind: String,
    pub safety_note: String,
    pub observations: Vec<PrivateConsistencyObservation>,
    pub observations_beyond_cap: u64,
}

#[derive(Debug, Default)]
struct CheckAccumulator {
    matches: u64,
    mismatches: u64,
    unavailable: u64,
    reasons: UnavailableReasonCounts,
}

pub struct ConsistencyAccumulator {
    checks: BTreeMap<String, CheckAccumulator>,
    private: Vec<PrivateConsistencyObservation>,
    private_cap: usize,
    private_beyond_cap: u64,
}

impl Default for ConsistencyAccumulator {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PRIVATE_CONSISTENCY_OBSERVATIONS)
    }
}

impl ConsistencyAccumulator {
    pub fn new(private_cap: usize) -> Self {
        Self {
            checks: BTreeMap::new(),
            private: Vec::new(),
            private_cap,
            private_beyond_cap: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        check_id: &str,
        declared_attribute: &str,
        declared_value: &str,
        observed_attribute: &str,
        observed_value: Option<&str>,
        result: ComparisonResult,
    ) {
        let summary = self.checks.entry(check_id.to_owned()).or_default();
        match result.outcome {
            ComparisonOutcome::Match => summary.matches += 1,
            ComparisonOutcome::Mismatch => summary.mismatches += 1,
            ComparisonOutcome::Unavailable => {
                summary.unavailable += 1;
                match result
                    .unavailable_reason
                    .expect("unavailable comparisons carry a reason")
                {
                    UnavailableReason::ReferenceDataMissing => {
                        summary.reasons.reference_data_missing += 1
                    }
                    UnavailableReason::TelemetryDoesNotExpose => {
                        summary.reasons.telemetry_does_not_expose += 1
                    }
                    UnavailableReason::ObservedValueMissing => {
                        summary.reasons.observed_value_missing += 1
                    }
                }
            }
        }
        if self.private.len() < self.private_cap {
            self.private.push(PrivateConsistencyObservation {
                check_id: check_id.to_owned(),
                declared_attribute: declared_attribute.to_owned(),
                declared_value: declared_value.to_owned(),
                observed_attribute: observed_attribute.to_owned(),
                observed_value: observed_value.map(str::to_owned),
                outcome: result.outcome,
                unavailable_reason: result.unavailable_reason,
            });
        } else {
            self.private_beyond_cap += 1;
        }
    }

    pub fn reports(self) -> (ConsistencySummary, PrivateConsistencyReport) {
        let checks = self
            .checks
            .into_iter()
            .map(|(check_id, item)| ConsistencyCheckSummary {
                check_id,
                matches: item.matches,
                mismatches: item.mismatches,
                unavailable: item.unavailable,
                unavailable_reasons: item.reasons,
            })
            .collect();
        (
            ConsistencySummary {
                checks,
                private_observations_beyond_cap: self.private_beyond_cap,
            },
            PrivateConsistencyReport {
                report_kind: "DECLARED_OBSERVED_CONSISTENCY_PRIVATE".to_owned(),
                safety_note: CONSISTENCY_SAFETY_NOTE.to_owned(),
                observations: self.private,
                observations_beyond_cap: self.private_beyond_cap,
            },
        )
    }
}

/// Extract a coarse self-declared browser family for a TLS consistency check.
/// No comparison is attempted without an explicit reference table.
pub fn declared_browser_family(user_agent: Option<&str>) -> Option<&'static str> {
    let user_agent = user_agent?;
    if user_agent.contains("Firefox/") {
        Some("firefox")
    } else if user_agent.contains("Chrome/") || user_agent.contains("Chromium/") {
        Some("chromium")
    } else if user_agent.contains("Safari/") {
        Some("safari")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::TelemetryProfile;

    #[test]
    fn distinguishes_each_unavailable_reason_without_counting_a_mismatch() {
        let missing_reference = compare_declared_with_observed(true, Some("fact"), None);
        let missing_capability = compare_declared_with_observed(false, Some("fact"), None);
        let missing_value = compare_declared_with_observed(true, None, Some(&[]));
        assert_eq!(
            missing_reference.unavailable_reason,
            Some(UnavailableReason::ReferenceDataMissing)
        );
        assert_eq!(
            missing_capability.unavailable_reason,
            Some(UnavailableReason::TelemetryDoesNotExpose)
        );
        assert_eq!(
            missing_value.unavailable_reason,
            Some(UnavailableReason::ObservedValueMissing)
        );

        let mut accumulator = ConsistencyAccumulator::default();
        for result in [missing_reference, missing_capability, missing_value] {
            accumulator.record("test", "declared", "value", "observed", None, result);
        }
        let (summary, _) = accumulator.reports();
        assert_eq!(summary.checks[0].mismatches, 0);
        assert_eq!(summary.checks[0].unavailable, 3);
        assert_eq!(
            summary.checks[0].unavailable_reasons.reference_data_missing,
            1
        );
        assert_eq!(
            summary.checks[0]
                .unavailable_reasons
                .telemetry_does_not_expose,
            1
        );
        assert_eq!(
            summary.checks[0].unavailable_reasons.observed_value_missing,
            1
        );
    }

    #[test]
    fn tls_check_is_unavailable_when_the_profile_does_not_expose_tls() {
        let capabilities = TelemetryProfile::AwsWaf.capabilities();
        assert!(!capabilities.tls_cipher);
        let result = compare_declared_with_observed(
            capabilities.tls_cipher,
            Some("TLS_AES_128_GCM_SHA256"),
            Some(&["TLS_AES_128_GCM_SHA256".to_owned()]),
        );
        assert_eq!(result.outcome, ComparisonOutcome::Unavailable);
        assert_eq!(
            result.unavailable_reason,
            Some(UnavailableReason::TelemetryDoesNotExpose)
        );
    }
}
