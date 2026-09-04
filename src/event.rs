use std::{fmt, net::IpAddr, str::FromStr};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// A configured proxy network that is permitted to supply a forwarded client
/// address. Parsing accepts either a single IP address or a CIDR network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxy(IpNet);

impl fmt::Display for TrustedProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for TrustedProxy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse::<IpNet>().map(Self).or_else(|_| {
            value
                .parse::<IpAddr>()
                .map(|address| {
                    let prefix = if address.is_ipv4() { 32 } else { 128 };
                    Self(
                        IpNet::new(address, prefix)
                            .expect("an IP address always has a valid host prefix"),
                    )
                })
                .map_err(|_| format!("{value:?} is not a valid IP address or CIDR network"))
        })
    }
}

/// Immutable trusted-proxy configuration. With an empty set, forwarded headers
/// are deliberately ignored because an untrusted peer can forge them.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxySet {
    proxies: Vec<TrustedProxy>,
}

impl TrustedProxySet {
    pub fn new(proxies: Vec<TrustedProxy>) -> Self {
        Self { proxies }
    }

    /// Analyzer-supplied trusted proxy networks, suitable for reproducibility
    /// metadata. These are configuration values, never recovered client IPs.
    pub fn configured_proxy_networks(&self) -> Vec<String> {
        self.proxies.iter().map(ToString::to_string).collect()
    }

    /// Populate `WebEvent::client_ip` only when the observed direct peer is a
    /// configured proxy and the forwarded chain can be validated from right to
    /// left. Invalid or incomplete chains are treated as unavailable.
    pub fn resolve_client_ip(&self, event: &mut WebEvent) {
        event.client_ip =
            self.validated_client_from_headers(event.source_ip.as_deref(), &event.headers);
    }

    fn validated_client_from_headers(
        &self,
        observed_peer: Option<&str>,
        headers: &[HttpHeader],
    ) -> Option<String> {
        // Multiple same-name header fields are equivalent to one comma-joined
        // field. Preserve observed order before evaluating the chain right to left.
        let forwarded_for = headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("x-forwarded-for"))
            .map(|header| header.value.as_str())
            .collect::<Vec<_>>();
        let forwarded_for = (!forwarded_for.is_empty()).then(|| forwarded_for.join(", "));
        self.validated_forwarded_client_ip(observed_peer, forwarded_for.as_deref())
    }

    fn validated_forwarded_client_ip(
        &self,
        observed_peer: Option<&str>,
        forwarded_for: Option<&str>,
    ) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }
        let peer = observed_peer?.parse::<IpAddr>().ok()?.to_canonical();
        if !self.contains(peer) {
            return None;
        }
        let chain = forwarded_for?
            .split(',')
            .map(|value| {
                value
                    .trim()
                    .parse::<IpAddr>()
                    .ok()
                    .map(|address| address.to_canonical())
            })
            .collect::<Option<Vec<_>>>()?;
        chain
            .into_iter()
            .rev()
            .find(|address| !self.contains(*address))
            .map(|address| address.to_string())
    }

    fn contains(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        self.proxies.iter().any(|proxy| proxy.0.contains(&address))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    AwsWaf,
    NginxCombined,
    ApacheCombined,
    ApacheVhostCombined,
}

impl LogSource {
    /// The telemetry profile whose capabilities describe this source. Used to
    /// bound the reachable behavior-score maximum for the source that actually
    /// produced a finding, so absent capabilities do not depress the score.
    pub fn telemetry_profile(self) -> TelemetryProfile {
        match self {
            Self::AwsWaf => TelemetryProfile::AwsWaf,
            Self::NginxCombined => TelemetryProfile::NginxCombined,
            Self::ApacheCombined => TelemetryProfile::ApacheCombined,
            Self::ApacheVhostCombined => TelemetryProfile::ApacheVhostCombined,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetryProfile {
    #[default]
    AwsWaf,
    NginxCombined,
    ApacheCombined,
    /// Apache `other_vhosts_access.log` / vhost-prefixed Combined Log Format.
    ApacheVhostCombined,
    /// Counterfactual analysis only: standard nginx combined plus an
    /// intentionally configured Host field.
    NginxCombinedHost,
    /// Counterfactual analysis only: a reviewed nginx security format with
    /// Host and selected request-header logging. It does not imply bodies,
    /// WAF metadata, or TLS fingerprints are present.
    NginxSecurity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HeaderCapability {
    Arbitrary,
    RefererAndUserAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TelemetryCapabilities {
    pub timestamp: bool,
    pub source_ip: bool,
    /// Whether a verified end-client IP can be populated. Standard combined
    /// logs do not contain forwarded chains. AWS WAF may expose one in a
    /// header, but availability still depends on trusted-proxy configuration.
    pub client_ip: bool,
    pub host: bool,
    pub method: bool,
    pub uri_path: bool,
    pub uri_query: bool,
    pub headers: HeaderCapability,
    pub user_agent: bool,
    pub referer: bool,
    pub status: bool,
    pub response_bytes: bool,
    pub ja3: bool,
    pub ja4: bool,
    /// Whether the source records the negotiated TLS protocol version.
    pub tls_protocol: bool,
    /// Whether the source records the negotiated TLS cipher suite.
    pub tls_cipher: bool,
    pub waf_action: bool,
    pub waf_labels: bool,
    pub request_body: bool,
}

impl Default for TelemetryCapabilities {
    fn default() -> Self {
        TelemetryProfile::AwsWaf.capabilities()
    }
}

impl TelemetryCapabilities {
    /// Combine two capability sets by keeping any capability either source can
    /// express. A hunt over one format yields a single profile; Apache's
    /// per-line auto-detection can mix standard and vhost lines, so the union
    /// reflects what the corpus as a whole could record.
    pub fn union(self, other: Self) -> Self {
        let headers = match (self.headers, other.headers) {
            (HeaderCapability::Arbitrary, _) | (_, HeaderCapability::Arbitrary) => {
                HeaderCapability::Arbitrary
            }
            _ => HeaderCapability::RefererAndUserAgent,
        };
        Self {
            timestamp: self.timestamp || other.timestamp,
            source_ip: self.source_ip || other.source_ip,
            client_ip: self.client_ip || other.client_ip,
            host: self.host || other.host,
            method: self.method || other.method,
            uri_path: self.uri_path || other.uri_path,
            uri_query: self.uri_query || other.uri_query,
            headers,
            user_agent: self.user_agent || other.user_agent,
            referer: self.referer || other.referer,
            status: self.status || other.status,
            response_bytes: self.response_bytes || other.response_bytes,
            ja3: self.ja3 || other.ja3,
            ja4: self.ja4 || other.ja4,
            tls_protocol: self.tls_protocol || other.tls_protocol,
            tls_cipher: self.tls_cipher || other.tls_cipher,
            waf_action: self.waf_action || other.waf_action,
            waf_labels: self.waf_labels || other.waf_labels,
            request_body: self.request_body || other.request_body,
        }
    }
}

impl TelemetryProfile {
    pub fn capabilities(self) -> TelemetryCapabilities {
        match self {
            Self::AwsWaf => TelemetryCapabilities {
                timestamp: true,
                source_ip: true,
                // X-Forwarded-For is only usable after a caller supplies
                // trusted-proxy configuration, so it is not a profile-default capability.
                client_ip: false,
                host: true,
                method: true,
                uri_path: true,
                uri_query: true,
                headers: HeaderCapability::Arbitrary,
                user_agent: true,
                referer: true,
                status: true,
                response_bytes: false,
                ja3: true,
                ja4: true,
                tls_protocol: false,
                tls_cipher: false,
                waf_action: true,
                waf_labels: true,
                request_body: false,
            },
            Self::NginxCombined | Self::ApacheCombined => TelemetryCapabilities {
                timestamp: true,
                source_ip: true,
                client_ip: false,
                host: false,
                method: true,
                uri_path: true,
                uri_query: true,
                headers: HeaderCapability::RefererAndUserAgent,
                user_agent: true,
                referer: true,
                status: true,
                response_bytes: true,
                ja3: false,
                ja4: false,
                tls_protocol: false,
                tls_cipher: false,
                waf_action: false,
                waf_labels: false,
                request_body: false,
            },
            Self::ApacheVhostCombined => TelemetryCapabilities {
                host: true,
                ..Self::ApacheCombined.capabilities()
            },
            Self::NginxCombinedHost => TelemetryCapabilities {
                host: true,
                ..Self::NginxCombined.capabilities()
            },
            Self::NginxSecurity => TelemetryCapabilities {
                host: true,
                headers: HeaderCapability::Arbitrary,
                ..Self::NginxCombined.capabilities()
            },
        }
    }
}

/// A source-neutral request representation. New observable attributes can be
/// added without changing the matcher interface: aliases resolve through
/// [`WebEvent::field_values`].
#[derive(Debug, Clone, Serialize)]
pub struct WebEvent {
    pub timestamp: Option<DateTime<Utc>>,
    /// Observed direct connection peer. This may be a CDN, load balancer, NAT,
    /// or proxy and is not attacker attribution.
    pub source_ip: Option<String>,
    /// End-client IP verified from a forwarded chain under an explicit trusted
    /// proxy configuration. It is unavailable by default.
    pub client_ip: Option<String>,
    pub source_port: Option<u16>,
    pub country: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub uri_path: Option<String>,
    pub uri_query: Option<String>,
    pub uri_fragment: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub status: Option<u16>,
    pub response_bytes: Option<u64>,
    pub protocol: Option<String>,
    pub request_id: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    /// TLS protocol version observed by the telemetry source. Existing source
    /// profiles do not expose this value, so parsers leave it unavailable.
    pub tls_protocol: Option<String>,
    /// TLS cipher suite observed by the telemetry source. It is never inferred
    /// from a User-Agent or another request attribute.
    pub tls_cipher: Option<String>,
    pub waf_action: Option<String>,
    pub waf_rule_id: Option<String>,
    pub waf_rule_type: Option<String>,
    pub waf_labels: Vec<String>,
    pub waf_non_terminating_rule_ids: Vec<String>,
    pub log_source: LogSource,
    /// The unmodified JSON record, for analyst follow-up rather than repeat
    /// parsing of the source file.
    pub raw: String,
}

impl WebEvent {
    pub fn field_values(&self, field: &str) -> Option<Vec<String>> {
        let one = |value: &Option<String>| value.clone().map(|v| vec![v]);
        match field.to_ascii_lowercase().as_str() {
            "cs-method" | "method" => one(&self.method),
            "cs-uri" | "uri" => one(&self.uri),
            "cs-uri-stem" | "uri_path" => one(&self.uri_path),
            "cs-uri-query" | "uri_query" => one(&self.uri_query),
            "uri_fragment" => one(&self.uri_fragment),
            "cs-host" | "host" => one(&self.host),
            "cs-user-agent" | "c-useragent" | "user_agent" => one(&self.user_agent),
            "cs-referer" | "referer" => one(&self.referer),
            "c-ip" | "source_ip" => one(&self.source_ip),
            "client_ip" => one(&self.client_ip),
            "sc-status" | "status" => self.status.map(|value| vec![value.to_string()]),
            "ja3" => one(&self.ja3),
            "ja4" => one(&self.ja4),
            "tls_protocol" | "ssl_protocol" => one(&self.tls_protocol),
            "tls_cipher" | "ssl_cipher" => one(&self.tls_cipher),
            "waf_action" => one(&self.waf_action),
            "waf_rule_id" => one(&self.waf_rule_id),
            "waf_labels" => Some(self.waf_labels.clone()),
            _ => None,
        }
    }

    /// A stable documented request representation for Sigma `keywords`.
    pub fn keyword_haystack(&self) -> String {
        let mut haystack = String::with_capacity(
            self.method.as_ref().map_or(0, String::len)
                + self.host.as_ref().map_or(0, String::len)
                + self.uri.as_ref().map_or(0, String::len)
                + self.raw.len()
                + self
                    .headers
                    .iter()
                    .map(|header| header.name.len() + header.value.len() + 3)
                    .sum::<usize>()
                + 4,
        );
        haystack.push_str(self.method.as_deref().unwrap_or_default());
        haystack.push('\n');
        haystack.push_str(self.host.as_deref().unwrap_or_default());
        haystack.push('\n');
        haystack.push_str(self.uri.as_deref().unwrap_or_default());
        haystack.push('\n');
        for (index, header) in self.headers.iter().enumerate() {
            if index != 0 {
                haystack.push('\n');
            }
            haystack.push_str(&header.name);
            haystack.push_str(": ");
            haystack.push_str(&header.value);
        }
        haystack.push('\n');
        haystack.push_str(&self.raw);
        haystack
    }
}

#[cfg(test)]
mod tests {
    use super::TrustedProxy;
    use super::TrustedProxySet;

    fn proxies(values: &[&str]) -> TrustedProxySet {
        TrustedProxySet::new(
            values
                .iter()
                .map(|value| value.parse::<TrustedProxy>().unwrap())
                .collect(),
        )
    }

    #[test]
    fn resolves_client_from_a_trusted_peer_and_forwarded_chain() {
        let proxies = proxies(&["198.51.100.0/24"]);
        assert_eq!(
            proxies.validated_forwarded_client_ip(
                Some("198.51.100.10"),
                Some("203.0.113.25, 198.51.100.20"),
            ),
            Some("203.0.113.25".to_owned())
        );
    }

    #[test]
    fn combines_multiple_forwarded_headers_in_observed_order() {
        let proxies = proxies(&["198.51.100.0/24"]);
        let headers = [
            super::HttpHeader {
                name: "X-Forwarded-For".to_owned(),
                value: "203.0.113.25".to_owned(),
            },
            super::HttpHeader {
                name: "x-forwarded-for".to_owned(),
                value: "198.51.100.20".to_owned(),
            },
        ];
        assert_eq!(
            proxies.validated_client_from_headers(Some("198.51.100.10"), &headers),
            Some("203.0.113.25".to_owned())
        );
    }

    #[test]
    fn resolves_ipv4_mapped_peer_against_an_ipv4_trusted_proxy_network() {
        let proxies = proxies(&["198.51.100.0/24"]);
        assert_eq!(
            proxies.validated_forwarded_client_ip(
                Some("::ffff:198.51.100.10"),
                Some("203.0.113.25, 198.51.100.20"),
            ),
            Some("203.0.113.25".to_owned())
        );
    }

    #[test]
    fn ignores_forwarded_chain_from_an_untrusted_peer() {
        let proxies = proxies(&["198.51.100.0/24"]);
        assert_eq!(
            proxies.validated_forwarded_client_ip(Some("203.0.113.10"), Some("192.0.2.1")),
            None
        );
    }

    #[test]
    fn ignores_forwarded_chain_without_trusted_proxy_configuration() {
        assert_eq!(
            TrustedProxySet::default()
                .validated_forwarded_client_ip(Some("198.51.100.10"), Some("192.0.2.1")),
            None
        );
    }

    #[test]
    fn leaves_client_unavailable_when_every_forwarded_hop_is_trusted() {
        let proxies = proxies(&["198.51.100.0/24"]);
        assert_eq!(
            proxies.validated_forwarded_client_ip(
                Some("198.51.100.10"),
                Some("198.51.100.11, 198.51.100.20"),
            ),
            None
        );
    }

    #[test]
    fn rejects_invalid_trusted_proxy_values() {
        assert!("not-an-address".parse::<TrustedProxy>().is_err());
    }
}
