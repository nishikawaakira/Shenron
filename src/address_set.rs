//! Frozen private address membership, not identity or ownership inference.
use crate::production::{read_fingerprinted_input, PathProvenance};
use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr, path::Path};

pub const ADDRESS_SET_NOTE: &str = "Frozen source-address membership is operator-selected context, not identity, ownership, intent, attack, or abuse. Replay covers only this snapshot. Remote IP sets must contain exactly the recorded subsets and use the same observed-peer semantics; Shenron does not verify or modify remote sets. Review legitimate shared-cloud users and crawlers before any manual policy change. COUNT only; no deployment.";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FrozenAddressSet {
    pub provenance: PathProvenance,
    #[serde(with = "network_strings")]
    pub networks: Vec<IpNet>,
    pub invalid_records: u64,
    pub duplicate_records: u64,
    pub comment_or_empty_records: u64,
    pub ipv4_arn: Option<String>,
    pub ipv6_arn: Option<String>,
}

impl FrozenAddressSet {
    pub fn load(path: &Path, ipv4_arn: Option<String>, ipv6_arn: Option<String>) -> Result<Self> {
        // Absolute input reference remains stable if replay runs elsewhere.
        let path = path
            .canonicalize()
            .with_context(|| format!("locating frozen address input {}", path.display()))?;
        let (bytes, provenance) = read_fingerprinted_input(&path)?;
        let text = std::str::from_utf8(&bytes).context("address set must be UTF-8")?;
        let mut networks = BTreeSet::new();
        let (mut invalid_records, mut duplicate_records, mut comment_or_empty_records) = (0, 0, 0);
        for line in text.lines() {
            let value = line.split('#').next().unwrap_or_default().trim();
            if value.is_empty() {
                comment_or_empty_records += 1;
                continue;
            }
            let parsed = value
                .parse::<IpNet>()
                .ok()
                .or_else(|| value.parse::<IpAddr>().ok().map(IpNet::from));
            match parsed {
                Some(network) => {
                    if !networks.insert(network.trunc()) {
                        duplicate_records += 1;
                    }
                }
                None => invalid_records += 1,
            }
        }
        if networks.is_empty() {
            bail!("address set has no usable networks (invalid records: {invalid_records}; comment/empty records: {comment_or_empty_records})");
        }
        Ok(Self {
            provenance,
            networks: networks.into_iter().collect(),
            invalid_records,
            duplicate_records,
            comment_or_empty_records,
            ipv4_arn,
            ipv6_arn,
        })
    }
    pub fn validate_snapshot(&self) -> Result<()> {
        let loaded = Self::load(
            Path::new(&self.provenance.path),
            self.ipv4_arn.clone(),
            self.ipv6_arn.clone(),
        )?;
        if &loaded != self {
            bail!("frozen source-address snapshot or normalized contents changed; rebuild and replay the candidate");
        }
        Ok(())
    }
    pub fn matches(&self, source: &str) -> bool {
        source
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|ip| self.networks.iter().any(|network| network.contains(&ip)))
    }
    pub fn has_v4(&self) -> bool {
        self.networks.iter().any(|net| matches!(net, IpNet::V4(_)))
    }
    pub fn has_v6(&self) -> bool {
        self.networks.iter().any(|net| matches!(net, IpNet::V6(_)))
    }
    pub fn references(&self) -> Vec<&str> {
        self.ipv4_arn
            .as_deref()
            .filter(|_| self.has_v4())
            .into_iter()
            .chain(self.ipv6_arn.as_deref().filter(|_| self.has_v6()))
            .collect()
    }
    pub fn compatibility_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.networks.iter().any(|net| net.prefix_len() == 0) {
            reasons.push("AWS WAF IP sets cannot faithfully represent /0 ranges".to_owned());
        }
        for (family, present, arn) in [
            ("IPv4", self.has_v4(), &self.ipv4_arn),
            ("IPv6", self.has_v6(), &self.ipv6_arn),
        ] {
            if present && !arn.as_deref().is_some_and(valid_ip_set_arn) {
                reasons.push(format!(
                    "{family} requires an operator-supplied WAFv2 IP set ARN"
                ));
            }
        }
        if self.has_v4() && self.has_v6() && self.ipv4_arn == self.ipv6_arn {
            reasons.push("IPv4 and IPv6 require distinct single-family IP sets".to_owned());
        }
        if self.has_v4() && self.has_v6() {
            if let (Some(v4), Some(v6)) = (&self.ipv4_arn, &self.ipv6_arn) {
                if v4.split("/ipset/").next() != v6.split("/ipset/").next() {
                    reasons.push(
                        "IPv4 and IPv6 IP set references must share account, region, and scope"
                            .to_owned(),
                    );
                }
            }
        }
        reasons
    }
}

fn valid_ip_set_arn(value: &str) -> bool {
    // Reject HCL interpolation and control characters before rendering an
    // operator reference into either backend's string syntax.
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'/' | b'-' | b'_'))
    {
        return false;
    }
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6
        || parts[0] != "arn"
        || !parts[1].starts_with("aws")
        || parts[2] != "wafv2"
        || parts[3].is_empty()
        || parts[4].len() != 12
        || !parts[4].bytes().all(|v| v.is_ascii_digit())
    {
        return false;
    }
    let resource: Vec<_> = parts[5].split('/').collect();
    resource.len() == 4
        && matches!(resource[0], "regional" | "global")
        && resource[1] == "ipset"
        && resource[2..].iter().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

mod network_strings {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        networks: &[IpNet],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<IpNet>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| value.parse().map_err(serde::de::Error::custom))
            .collect()
    }
}
