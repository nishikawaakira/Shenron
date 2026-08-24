use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    AwsWaf,
    NginxCombined,
    ApacheCombined,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetryProfile {
    #[default]
    AwsWaf,
    NginxCombined,
    ApacheCombined,
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
    pub waf_action: bool,
    pub waf_labels: bool,
    pub request_body: bool,
}

impl Default for TelemetryCapabilities {
    fn default() -> Self {
        TelemetryProfile::AwsWaf.capabilities()
    }
}

impl TelemetryProfile {
    pub fn capabilities(self) -> TelemetryCapabilities {
        match self {
            Self::AwsWaf => TelemetryCapabilities {
                timestamp: true,
                source_ip: true,
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
                waf_action: true,
                waf_labels: true,
                request_body: false,
            },
            Self::NginxCombined | Self::ApacheCombined => TelemetryCapabilities {
                timestamp: true,
                source_ip: true,
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
                waf_action: false,
                waf_labels: false,
                request_body: false,
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
    pub source_ip: Option<String>,
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
            "sc-status" | "status" => self.status.map(|value| vec![value.to_string()]),
            "ja3" => one(&self.ja3),
            "ja4" => one(&self.ja4),
            "waf_action" => one(&self.waf_action),
            "waf_rule_id" => one(&self.waf_rule_id),
            "waf_labels" => Some(self.waf_labels.clone()),
            _ => None,
        }
    }

    /// A stable documented request representation for Sigma `keywords`.
    pub fn keyword_haystack(&self) -> String {
        let headers = self
            .headers
            .iter()
            .map(|header| format!("{}: {}", header.name, header.value))
            .collect::<Vec<_>>()
            .join("\n");
        [
            self.method.as_deref().unwrap_or_default(),
            self.host.as_deref().unwrap_or_default(),
            self.uri.as_deref().unwrap_or_default(),
            &headers,
            self.raw.as_str(),
        ]
        .join("\n")
    }
}
