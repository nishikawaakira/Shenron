use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::{
    access_log::{
        apache_vhost_combined_regex, combined_regex, parse_combined_line_with_raw_retention,
        AccessLogFormat, AccessLogParseError,
    },
    event::{LogSource, RawRetention, TelemetryProfile, WebEvent},
    percent_encoding::hex_pair,
};

use super::features::{mark, Feature, Observations};

pub(super) struct Observation {
    pub timestamp: Option<DateTime<Utc>>,
    pub source: Option<String>,
    pub status: Option<u16>,
    pub target: Option<Vec<u8>>,
    pub path: Option<Vec<u8>>,
    pub body: Option<Vec<u8>>,
    pub request_line: Option<String>,
    pub rescued: bool,
    pub features: Observations,
}

/// Display invalid bytes without replacement characters; corpus references
/// remain authoritative for the original byte spelling.
pub(super) fn byte_spelling(mut bytes: &[u8]) -> String {
    let mut result = String::new();
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                result.push_str(text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if let Ok(text) = std::str::from_utf8(&bytes[..valid]) {
                    result.push_str(text);
                }
                let length = error.error_len().unwrap_or(bytes.len() - valid);
                for byte in &bytes[valid..valid + length] {
                    result.push_str(&format!("\\x{byte:02x}"));
                }
                bytes = &bytes[valid + length..];
            }
        }
    }
    result
}

pub(super) fn log_bytes(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'x' && i + 3 < bytes.len() {
                if let Some(value) = hex_pair(bytes[i + 2], bytes[i + 3]) {
                    result.push(value);
                    i += 4;
                    continue;
                }
            }
            if matches!(bytes[i + 1], b'\\' | b'"') {
                result.push(bytes[i + 1]);
                i += 2;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    result
}

pub(super) fn format(profile: TelemetryProfile) -> Option<AccessLogFormat> {
    match profile {
        TelemetryProfile::NginxCombined => Some(AccessLogFormat::NginxCombined),
        TelemetryProfile::NginxPostdata => Some(AccessLogFormat::NginxPostdata),
        TelemetryProfile::ApacheCombined => Some(AccessLogFormat::ApacheCombined),
        TelemetryProfile::ApacheVhostCombined => Some(AccessLogFormat::ApacheVhostCombined),
        _ => None,
    }
}

fn envelope(raw: &str, format: AccessLogFormat) -> Option<(&str, Option<&str>)> {
    if format != AccessLogFormat::NginxPostdata {
        return Some((raw, None));
    }
    static PREFIX: OnceLock<Regex> = OnceLock::new();
    static RECORD: OnceLock<Regex> = OnceLock::new();
    let prefix = PREFIX.get_or_init(|| Regex::new(r"^\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} \([^)]*\) \S+->\S*/[^/ ]+?_access(?:_\d+)?\.log ").expect("valid anomaly postdata prefix"));
    let line = prefix.find(raw).map_or(raw, |prefix| &raw[prefix.end()..]);
    let record = RECORD.get_or_init(|| Regex::new(r#"^(?P<combined>\S+ \S+ \S+ \[[^\]]+\] "(?:\\.|[^"])*" (?:\d{3}|-) (?:\d+|-) "(?:\\.|[^"])*" "(?:\\.|[^"])*") "(?:\\.|[^"])*" "(?:\\.|[^"])*" "(?:\\.|[^"])*" \S+ postdata\[(?P<body>.*)\]$"#).expect("valid anomaly postdata envelope"));
    let captures = record.captures(line)?;
    Some((
        captures.name("combined")?.as_str(),
        captures.name("body").map(|body| body.as_str()),
    ))
}

fn absolute_prefix_length(target: &[u8]) -> Option<usize> {
    [b"http://".as_slice(), b"https://".as_slice()]
        .into_iter()
        .find(|scheme| {
            target
                .get(..scheme.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
        })
        .map(<[u8]>::len)
}

fn request_parts(request: &[u8]) -> (Option<Vec<u8>>, Observations) {
    let mut found = Observations::new();
    let parts = request
        .split(u8::is_ascii_whitespace)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() || parts == [b"-".as_slice()] {
        mark(&mut found, Feature::EmptyRequest, "request-line");
        return (None, found);
    }
    let has_controls = request
        .iter()
        .any(|b| b.is_ascii_control() || !b.is_ascii());
    let http = parts.len() == 3 && parts[2].starts_with(b"HTTP/");
    if has_controls || !http {
        mark(&mut found, Feature::NonHttpRequestLine, "request-line");
    }
    let target = parts.get(1).map(|target| target.to_vec());
    if let Some(target) = &target {
        if absolute_prefix_length(target).is_some() {
            mark(&mut found, Feature::AbsoluteForm, "request-line");
        } else if parts[0] == b"CONNECT" && !target.is_empty() && target.contains(&b':') {
            mark(&mut found, Feature::AuthorityForm, "request-line");
        } else if target == b"*" {
            mark(&mut found, Feature::AsteriskForm, "request-line");
        } else if !target.starts_with(b"/") {
            mark(&mut found, Feature::NonHttpRequestLine, "request-line");
        }
    }
    (target, found)
}

pub(super) fn path_from_target(target: &[u8]) -> Option<Vec<u8>> {
    let target = if let Some(authority) = absolute_prefix_length(target) {
        let offset = target[authority..]
            .iter()
            .position(|b| matches!(*b, b'/' | b'?' | b'#'))?;
        &target[authority + offset..]
    } else {
        target
    };
    if !target.starts_with(b"/") {
        return None;
    }
    Some(target.split(|b| matches!(*b, b'?' | b'#')).next()?.to_vec())
}

pub(super) fn combined(raw: &[u8], format: AccessLogFormat) -> Result<Observation, &'static str> {
    let projected = byte_spelling(raw);
    let (combined, body) = envelope(&projected, format).ok_or("invalid-format")?;
    let captures = match format {
        AccessLogFormat::ApacheVhostCombined => apache_vhost_combined_regex().captures(combined),
        AccessLogFormat::ApacheCombined => combined_regex()
            .captures(combined)
            .or_else(|| apache_vhost_combined_regex().captures(combined)),
        _ => combined_regex().captures(combined),
    }
    .ok_or("invalid-format")?;
    let timestamp = DateTime::parse_from_str(&captures["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        .map_err(|_| "invalid-timestamp")?
        .with_timezone(&Utc);
    let request = log_bytes(&captures["request"]);
    let (target, features) = request_parts(&request);
    let normal = parse_combined_line_with_raw_retention(&projected, format, RawRetention::Drop);
    let rescued = match normal {
        Ok(_) => std::str::from_utf8(raw).is_err(),
        Err(AccessLogParseError::Request) => true,
        Err(AccessLogParseError::Format)
            if features.contains_key(&Feature::NonHttpRequestLine)
                || features.contains_key(&Feature::EmptyRequest) =>
        {
            true
        }
        Err(_) => return Err("invalid-format"),
    };
    Ok(Observation {
        timestamp: Some(timestamp),
        source: Some(captures["source_ip"].to_owned()),
        status: captures["status"].parse().ok(),
        path: target.as_deref().and_then(path_from_target),
        target,
        body: body.map(log_bytes),
        request_line: Some(captures["request"].to_owned()),
        rescued,
        features,
    })
}

pub(super) fn event(event: WebEvent) -> Observation {
    let mut features = Observations::new();
    if event.log_source == LogSource::Alb && event.method.is_none() && event.uri.is_none() {
        mark(&mut features, Feature::NonHttpRequestLine, "request-line");
    }
    // These are the logged spellings, not reconstructed original wire bytes.
    // A redacted WAF query makes the complete target unavailable; its known path
    // can still be inspected independently without guessing the redacted value.
    let known_path = event
        .uri_path
        .as_deref()
        .filter(|value| *value != "REDACTED");
    let target = if event.uri_query.as_deref() == Some("REDACTED")
        || event.uri_path.as_deref() == Some("REDACTED")
    {
        None
    } else {
        event.uri.as_ref().map(|value| value.as_bytes().to_vec())
    };
    Observation {
        timestamp: event.timestamp,
        source: event.source_ip,
        status: event.status,
        path: known_path.map(|value| value.as_bytes().to_vec()),
        target,
        body: event.request_body.as_deref().map(log_bytes),
        request_line: None,
        rescued: false,
        features,
    }
}
