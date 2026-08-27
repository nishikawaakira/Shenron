//! Streaming nginx and Apache Combined Log Format parsing.
//!
//! Standard nginx/Apache formats have the same field shape. Apache's
//! `other_vhosts_access.log` vhost-prefixed Combined Log Format is an explicit
//! additional source, because it supplies a server host that standard Combined
//! logs do not contain.

use std::{
    io::{BufRead, BufReader, Read},
    sync::OnceLock,
};

use chrono::DateTime;
use regex::Regex;
use thiserror::Error;

use crate::event::{HttpHeader, LogSource, WebEvent};

/// Standard combined logs are line-oriented. Rejecting unusually long records
/// keeps a corrupt or attacker-influenced access log from dominating a scan.
pub const MAX_COMBINED_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLogFormat {
    NginxCombined,
    ApacheCombined,
    ApacheVhostCombined,
}

#[derive(Debug, Error)]
pub enum AccessLogParseError {
    #[error("line is not standard combined access-log format")]
    Format,
    #[error("invalid access-log timestamp")]
    Timestamp,
    #[error("invalid access-log request line")]
    Request,
}

pub fn parse_combined_line(
    raw: &str,
    format: AccessLogFormat,
) -> Result<WebEvent, AccessLogParseError> {
    let captures = match format {
        AccessLogFormat::NginxCombined | AccessLogFormat::ApacheCombined => combined_regex(),
        AccessLogFormat::ApacheVhostCombined => apache_vhost_combined_regex(),
    }
    .captures(raw)
    .ok_or(AccessLogParseError::Format)?;
    let field = |name| {
        captures
            .name(name)
            .map(|capture| capture.as_str())
            .ok_or(AccessLogParseError::Format)
    };
    let timestamp = DateTime::parse_from_str(field("timestamp")?, "%d/%b/%Y:%H:%M:%S %z")
        .map_err(|_| AccessLogParseError::Timestamp)?
        .with_timezone(&chrono::Utc);
    let request = decode_log_value(field("request")?).ok_or(AccessLogParseError::Format)?;
    let mut parts = request.split_whitespace();
    let method = parts.next().ok_or(AccessLogParseError::Request)?;
    let target = parts.next().ok_or(AccessLogParseError::Request)?;
    let protocol = parts.next().ok_or(AccessLogParseError::Request)?;
    if parts.next().is_some()
        || !protocol.starts_with("HTTP/")
        || !target.starts_with('/')
        || !valid_percent_escapes(target)
    {
        return Err(AccessLogParseError::Request);
    }
    let (uri_path, uri_query, uri_fragment) = split_target(target);
    let status = parse_optional(field("status")?);
    let response_bytes = parse_optional(field("response_bytes")?);
    let referer = value_or_none(field("referer")?).and_then(|value| decode_log_value(&value));
    let user_agent = value_or_none(field("user_agent")?).and_then(|value| decode_log_value(&value));
    let host = match format {
        AccessLogFormat::ApacheVhostCombined => parse_vhost(field("vhost")?)?,
        AccessLogFormat::NginxCombined | AccessLogFormat::ApacheCombined => None,
    };
    // These are the only request headers represented by the standard combined
    // format. Keeping them as headers lets the shared Detection IR evaluate
    // User-Agent/Referer requirements without pretending arbitrary headers
    // were recorded.
    let mut headers = Vec::new();
    if let Some(value) = &referer {
        headers.push(HttpHeader {
            name: "Referer".to_owned(),
            value: value.clone(),
        });
    }
    if let Some(value) = &user_agent {
        headers.push(HttpHeader {
            name: "User-Agent".to_owned(),
            value: value.clone(),
        });
    }
    Ok(WebEvent {
        timestamp: Some(timestamp),
        source_ip: Some(field("source_ip")?.to_owned()),
        client_ip: None,
        source_port: None,
        country: None,
        host,
        method: Some(method.to_owned()),
        uri: Some(target.to_owned()),
        uri_path: Some(uri_path),
        uri_query,
        uri_fragment,
        headers,
        user_agent,
        referer,
        status,
        response_bytes,
        protocol: Some(protocol.to_owned()),
        request_id: None,
        ja3: None,
        ja4: None,
        waf_action: None,
        waf_rule_id: None,
        waf_rule_type: None,
        waf_labels: Vec::new(),
        waf_non_terminating_rule_ids: Vec::new(),
        log_source: match format {
            AccessLogFormat::NginxCombined => LogSource::NginxCombined,
            AccessLogFormat::ApacheCombined => LogSource::ApacheCombined,
            AccessLogFormat::ApacheVhostCombined => LogSource::ApacheVhostCombined,
        },
        raw: raw.to_owned(),
    })
}

fn combined_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>(?:\\.|[^"])*)" (?P<status>\d{3}|-) (?P<response_bytes>\d+|-) "(?P<referer>(?:\\.|[^"])*)" "(?P<user_agent>(?:\\.|[^"])*)"$"#,
        )
        .expect("valid combined log regex")
    })
}

fn apache_vhost_combined_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"^(?P<vhost>\S+) (?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>(?:\\.|[^"])*)" (?P<status>\d{3}|-) (?P<response_bytes>\d+|-) "(?P<referer>(?:\\.|[^"])*)" "(?P<user_agent>(?:\\.|[^"])*)"$"#,
        )
        .expect("valid Apache vhost combined log regex")
    })
}

fn parse_vhost(value: &str) -> Result<Option<String>, AccessLogParseError> {
    let (host, port) = value.rsplit_once(':').ok_or(AccessLogParseError::Format)?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(AccessLogParseError::Format);
    }
    Ok(Some(host.to_owned()))
}

fn parse_optional<T: std::str::FromStr>(value: &str) -> Option<T> {
    (value != "-").then(|| value.parse().ok()).flatten()
}
fn value_or_none(value: &str) -> Option<String> {
    (value != "-").then(|| value.to_owned())
}

fn decode_log_value(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character.is_control() {
            return None;
        }
        if character == '\\' {
            match characters.next()? {
                '"' => decoded.push('"'),
                '\\' => decoded.push('\\'),
                other => {
                    decoded.push('\\');
                    decoded.push(other);
                }
            }
        } else {
            decoded.push(character);
        }
    }
    Some(decoded)
}

fn valid_percent_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn split_target(target: &str) -> (String, Option<String>, Option<String>) {
    let (target, fragment) = target.split_once('#').map_or_else(
        || (target, None),
        |(before, after)| (before, (!after.is_empty()).then(|| after.to_owned())),
    );
    target.split_once('?').map_or_else(
        || (target.to_owned(), None, fragment.clone()),
        |(path, query)| {
            (
                path.to_owned(),
                (!query.is_empty()).then(|| query.to_owned()),
                fragment.clone(),
            )
        },
    )
}

pub struct AccessLogLines<R: Read> {
    reader: BufReader<R>,
    line: String,
    format: AccessLogFormat,
}
impl<R: Read> AccessLogLines<R> {
    pub fn new(reader: R, format: AccessLogFormat) -> Self {
        Self {
            reader: BufReader::new(reader),
            line: String::new(),
            format,
        }
    }
}
impl<R: Read> Iterator for AccessLogLines<R> {
    type Item = Result<WebEvent, AccessLogParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line.clear();
            match self.reader.read_line(&mut self.line) {
                Ok(0) => return None,
                Ok(_) if self.line.trim().is_empty() => continue,
                Ok(_) if self.line.len() > MAX_COMBINED_LINE_BYTES => {
                    return Some(Err(AccessLogParseError::Format));
                }
                Ok(_) => return Some(parse_combined_line(self.line.trim_end(), self.format)),
                Err(_) => return Some(Err(AccessLogParseError::Format)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_combined_uri_query_and_optional_fields() {
        let event = parse_combined_line(r#"203.0.113.4 - - [24/Aug/2026:11:20:30 +0000] "GET /foo/bar?id=123&x=test HTTP/1.1" 404 123 "-" "example-agent""#, AccessLogFormat::NginxCombined).unwrap();
        assert_eq!(event.uri_path.as_deref(), Some("/foo/bar"));
        assert_eq!(event.uri_query.as_deref(), Some("id=123&x=test"));
        assert_eq!(event.user_agent.as_deref(), Some("example-agent"));
        assert_eq!(event.response_bytes, Some(123));
    }

    #[test]
    fn separates_a_fragment_when_a_raw_request_target_contains_one() {
        let event = parse_combined_line(
            r#"203.0.113.4 - - [24/Aug/2026:11:20:30 +0000] "GET /foo?q=one#anchor HTTP/1.1" 200 1 "-" "-""#,
            AccessLogFormat::NginxCombined,
        )
        .unwrap();
        assert_eq!(event.uri_path.as_deref(), Some("/foo"));
        assert_eq!(event.uri_query.as_deref(), Some("q=one"));
        assert_eq!(event.uri_fragment.as_deref(), Some("anchor"));
    }

    #[test]
    fn nginx_and_apache_normalize_common_fields_equivalently() {
        let line = r#"198.51.100.9 - - [24/Aug/2026:11:20:30 +0000] "GET /foo/bar?id=123 HTTP/1.1" 200 42 "https://example.test/" "example-agent""#;
        let nginx = parse_combined_line(line, AccessLogFormat::NginxCombined).unwrap();
        let apache = parse_combined_line(line, AccessLogFormat::ApacheCombined).unwrap();
        assert_eq!(nginx.timestamp, apache.timestamp);
        assert_eq!(nginx.source_ip, apache.source_ip);
        assert_eq!(nginx.method, apache.method);
        assert_eq!(nginx.uri_path, apache.uri_path);
        assert_eq!(nginx.uri_query, apache.uri_query);
        assert_eq!(nginx.user_agent, apache.user_agent);
    }

    #[test]
    fn parses_apache_vhost_combined_and_preserves_host() {
        let event = parse_combined_line(
            r#"api.example.test:443 198.51.100.9 - - [24/Aug/2026:11:20:30 +0000] "GET /foo/bar?id=123 HTTP/1.1" 200 42 "https://example.test/" "example-agent""#,
            AccessLogFormat::ApacheVhostCombined,
        )
        .unwrap();
        assert_eq!(event.host.as_deref(), Some("api.example.test"));
        assert_eq!(event.source_ip.as_deref(), Some("198.51.100.9"));
        assert_eq!(event.uri_path.as_deref(), Some("/foo/bar"));
        assert_eq!(event.uri_query.as_deref(), Some("id=123"));
        assert_eq!(event.log_source, LogSource::ApacheVhostCombined);
    }

    #[test]
    fn rejects_malformed_combined_lines() {
        for line in [
            "truncated",
            r#"203.0.113.4 - - [bad] "GET / HTTP/1.1" 200 1 "-" "-""#,
            r#"203.0.113.4 - - [24/Aug/2026:11:20:30 +0000] GET / HTTP/1.1 200 1 "-" "-""#,
            r#"203.0.113.4 - - [24/Aug/2026:11:20:30 +0000] "GET invalid HTTP/1.1" 200 1 "-" "-""#,
        ] {
            assert!(parse_combined_line(line, AccessLogFormat::NginxCombined).is_err());
        }
    }

    #[test]
    fn retains_only_standard_selected_headers() {
        let event = parse_combined_line(
            r#"203.0.113.4 - - [24/Aug/2026:11:20:30 +0000] "GET / HTTP/1.1" 200 1 "https://example.test/" "example-agent""#,
            AccessLogFormat::NginxCombined,
        )
        .unwrap();
        assert_eq!(event.headers.len(), 2);
        assert!(event.headers.iter().any(|header| header.name == "Referer"));
        assert!(event
            .headers
            .iter()
            .any(|header| header.name == "User-Agent"));
    }

    #[test]
    fn decodes_quoted_user_agent_and_rejects_malformed_percent_encoding() {
        let event = parse_combined_line(
            r#"2001:db8::1 - - [24/Aug/2026:11:20:30 +0000] "PATCH /ok%20path HTTP/1.1" 201 1 "-" "agent \"quoted\"""#,
            AccessLogFormat::ApacheCombined,
        )
        .unwrap();
        assert_eq!(event.source_ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(event.user_agent.as_deref(), Some("agent \"quoted\""));
        assert!(parse_combined_line(
            r#"203.0.113.4 - - [24/Aug/2026:11:20:30 +0000] "GET /bad%zz HTTP/1.1" 200 1 "-" "-""#,
            AccessLogFormat::NginxCombined,
        )
        .is_err());
    }
}
