//! Bounded observational WAF counts. Raw categorical values remain private.
use crate::event::{TelemetryCapabilities, WebEvent};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const WAF_OBSERVATION_NOTE: &str = "A TLS fingerprint groups clients that negotiated the same way. It is not an identity: unrelated deployments of the same library share one, and a single actor can present several. A WAF action records what the edge decided, not whether a request succeeded or whether anything was compromised. None of these is a determination of automation, probing, an attack, or abuse.";

/// Fixed action vocabulary prevents arbitrary log strings entering sanitized JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct WafActionCounts {
    pub allow: u64,
    pub block: u64,
    pub count: u64,
    pub captcha: u64,
    pub challenge: u64,
    pub other: u64,
    pub unavailable: u64,
}
impl WafActionCounts {
    pub fn record(&mut self, value: Option<&str>) {
        match value {
            Some("ALLOW") => self.allow += 1,
            Some("BLOCK") => self.block += 1,
            Some("COUNT") => self.count += 1,
            Some("CAPTCHA") => self.captcha += 1,
            Some("CHALLENGE") => self.challenge += 1,
            Some(_) => self.other += 1,
            None => self.unavailable += 1,
        }
    }
    pub fn entries(&self) -> [(&'static str, u64); 7] {
        [
            ("ALLOW", self.allow),
            ("BLOCK", self.block),
            ("COUNT", self.count),
            ("CAPTCHA", self.captcha),
            ("CHALLENGE", self.challenge),
            ("other", self.other),
            ("unavailable", self.unavailable),
        ]
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ValueCounts {
    pub distinct_values: usize,
    pub values: BTreeMap<String, u64>,
    pub observations_beyond_cap: u64,
    pub observations_without_value: u64,
    pub maximum_values: usize,
}
impl ValueCounts {
    fn record(&mut self, value: Option<&str>, maximum: usize) {
        self.maximum_values = maximum;
        let Some(value) = value else {
            self.observations_without_value += 1;
            return;
        };
        if let Some(count) = self.values.get_mut(value) {
            *count += 1;
        } else if self.values.len() < maximum {
            self.values.insert(value.to_owned(), 1);
            self.distinct_values = self.values.len();
        } else {
            self.observations_beyond_cap += 1;
        }
    }
    fn summary(&self) -> ValueCountSummary {
        ValueCountSummary {
            distinct_values: self.values.len(),
            retained_occurrences: self.values.values().sum(),
            observations_beyond_cap: self.observations_beyond_cap,
            observations_without_value: self.observations_without_value,
            maximum_values: self.maximum_values,
        }
    }
}

/// Cardinalities are exact for retained values; omissions are observations,
/// never estimates of omitted distinct values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ValueCountSummary {
    pub distinct_values: usize,
    pub retained_occurrences: u64,
    pub observations_beyond_cap: u64,
    pub observations_without_value: u64,
    pub maximum_values: usize,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WafSummary {
    pub actions: Option<WafActionCounts>,
    pub ja3: Option<ValueCountSummary>,
    pub ja4: Option<ValueCountSummary>,
    pub labels: Option<ValueCountSummary>,
    pub countries: Option<ValueCountSummary>,
    pub ja4_sources: Option<Ja4SourceSummary>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PrivateWafSummary {
    pub actions: Option<WafActionCounts>,
    pub ja3: Option<ValueCounts>,
    pub ja4: Option<ValueCounts>,
    pub labels: Option<ValueCounts>,
    pub countries: Option<ValueCounts>,
}

#[derive(Debug, Default)]
pub struct WafEntityAccumulator {
    actions: WafActionCounts,
    ja3: ValueCounts,
    ja4: ValueCounts,
    labels: ValueCounts,
    countries: ValueCounts,
}
impl WafEntityAccumulator {
    pub fn set_maximum(&mut self, maximum: usize) {
        for counts in [
            &mut self.ja3,
            &mut self.ja4,
            &mut self.labels,
            &mut self.countries,
        ] {
            counts.maximum_values = maximum;
        }
    }
    pub fn observe(
        &mut self,
        event: &WebEvent,
        capabilities: TelemetryCapabilities,
        maximum: usize,
    ) {
        self.set_maximum(maximum);
        if capabilities.waf_action {
            self.actions.record(event.waf_action.as_deref());
        }
        if capabilities.ja3 {
            self.ja3.record(event.ja3.as_deref(), maximum);
        }
        if capabilities.ja4 {
            self.ja4.record(event.ja4.as_deref(), maximum);
        }
        if capabilities.country {
            self.countries.record(event.country.as_deref(), maximum);
        }
        if capabilities.waf_labels {
            if event.waf_labels.is_empty() {
                self.labels.record(None, maximum);
            }
            for label in &event.waf_labels {
                self.labels.record(Some(label), maximum);
            }
        }
    }
    pub fn private(&self, caps: TelemetryCapabilities) -> PrivateWafSummary {
        PrivateWafSummary {
            actions: caps.waf_action.then(|| self.actions.clone()),
            ja3: caps.ja3.then(|| self.ja3.clone()),
            ja4: caps.ja4.then(|| self.ja4.clone()),
            labels: caps.waf_labels.then(|| self.labels.clone()),
            countries: caps.country.then(|| self.countries.clone()),
        }
    }
    pub fn summary(&self, caps: TelemetryCapabilities) -> WafSummary {
        WafSummary {
            actions: caps.waf_action.then(|| self.actions.clone()),
            ja3: caps.ja3.then(|| self.ja3.summary()),
            ja4: caps.ja4.then(|| self.ja4.summary()),
            labels: caps.waf_labels.then(|| self.labels.summary()),
            countries: caps.country.then(|| self.countries.summary()),
            ja4_sources: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Ja4SourceSummary {
    pub distinct_ja4: usize,
    pub maximum_distinct_sources: usize,
    pub retained_associations: usize,
    pub observations_beyond_fingerprint_cap: u64,
    pub observations_beyond_association_cap: u64,
    pub observations_without_source: u64,
    pub observations_without_fingerprint: u64,
    pub maximum_fingerprints: usize,
    pub maximum_associations: usize,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateJa4Sources {
    pub ja4: String,
    pub distinct_source_ips: usize,
}
#[derive(Debug, Default)]
pub struct Ja4SourceAccumulator {
    sources: BTreeMap<String, BTreeSet<String>>,
    summary: Ja4SourceSummary,
}
impl Ja4SourceAccumulator {
    pub fn observe(
        &mut self,
        event: &WebEvent,
        maximum_fingerprints: usize,
        maximum_associations: usize,
    ) {
        self.summary.maximum_fingerprints = maximum_fingerprints;
        self.summary.maximum_associations = maximum_associations;
        let Some(ja4) = event.ja4.as_deref() else {
            self.summary.observations_without_fingerprint += 1;
            return;
        };
        let Some(source) = event.source_ip.as_deref() else {
            self.summary.observations_without_source += 1;
            return;
        };
        if !self.sources.contains_key(ja4) {
            if self.sources.len() >= maximum_fingerprints {
                self.summary.observations_beyond_fingerprint_cap += 1;
                return;
            }
            self.sources.insert(ja4.to_owned(), BTreeSet::new());
        }
        let sources = self.sources.get_mut(ja4).expect("admitted fingerprint");
        if sources.contains(source) {
            return;
        }
        if self.summary.retained_associations >= maximum_associations {
            self.summary.observations_beyond_association_cap += 1;
            return;
        }
        sources.insert(source.to_owned());
        self.summary.retained_associations += 1;
    }
    pub fn summary(&self) -> Ja4SourceSummary {
        Ja4SourceSummary {
            distinct_ja4: self.sources.len(),
            maximum_distinct_sources: self.sources.values().map(BTreeSet::len).max().unwrap_or(0),
            ..self.summary.clone()
        }
    }
    pub fn private(&self) -> Vec<PrivateJa4Sources> {
        let mut values: Vec<_> = self
            .sources
            .iter()
            .map(|(ja4, sources)| PrivateJa4Sources {
                ja4: ja4.clone(),
                distinct_source_ips: sources.len(),
            })
            .collect();
        values.sort_by(|left, right| {
            right
                .distinct_source_ips
                .cmp(&left.distinct_source_ips)
                .then_with(|| left.ja4.cmp(&right.ja4))
        });
        values
    }
}
