//! Deterministic request-volume distribution measurement for local WebEvent streams.
//!
//! These aggregates are triage context only. They do not determine a denial-of-service
//! attempt, attack, abuse, compromise, or attacker identity. Tracking is exact for
//! retained keys and deliberately stops admitting new keys at fixed caps; every such
//! omission is reported as a count rather than approximated.

mod accumulate;
mod focus;
mod rates;
mod types;

pub use accumulate::RequestConcentration;
pub use focus::{
    add_focus_asn_groups, add_focus_prefix_groups, FocusPrefixLengths, FocusSelector,
    DEFAULT_FOCUS_IPV4_GROUP_PREFIX, DEFAULT_FOCUS_IPV6_GROUP_PREFIX,
};
pub(crate) use rates::record_status_class;
pub use types::*;

#[cfg(test)]
mod tests;
