//! Offline ALB and legacy CloudFront access-log normalization.

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read},
    net::IpAddr,
};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    access_log::{split_target, valid_percent_escapes, MAX_COMBINED_LINE_BYTES},
    event::{HttpHeader, LogSource, RawRetention, WebEvent},
};

/// AWS's legacy standard-log field order, used only without a #Fields header.
pub const CLOUDFRONT_DEFAULT_FIELDS: &str = "date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status cs(Referer) cs(User-Agent) cs-uri-query cs(Cookie) x-edge-result-type x-edge-request-id x-host-header cs-protocol cs-bytes time-taken x-forwarded-for ssl-protocol ssl-cipher x-edge-response-result-type cs-protocol-version fle-status fle-encrypted-fields c-port time-to-first-byte x-edge-detailed-result-type sc-content-type sc-content-len sc-range-start sc-range-end";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsAccessLogFormat {
    Alb,
    CloudFront,
}

/// Fixed-name parsing diagnostics stored alongside private corpus provenance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputParsingProvenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudfront_default_fields: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alb_unparsed_requests: Option<u64>,
    pub parse_error_reasons: BTreeMap<String, u64>,
}

#[derive(Debug, Error)]
pub enum AwsAccessLogParseError {
    #[error("invalid AWS access-log field layout")]
    Format,
    #[error("invalid AWS access-log timestamp")]
    Timestamp,
    #[error("invalid AWS access-log request target")]
    Request,
    #[error("invalid AWS access-log numeric field")]
    Number,
    #[error("invalid AWS access-log client address")]
    Address,
    #[error("invalid CloudFront percent encoding")]
    Encoding,
    #[error("invalid CloudFront fields header")]
    Fields,
    #[error("invalid UTF-8 AWS access-log line")]
    InvalidUtf8,
    #[error("AWS access-log line exceeds the byte limit")]
    LineTooLong,
}

impl AwsAccessLogParseError {
    fn reason(&self) -> &'static str {
        match self {
            Self::Format => "invalid-format",
            Self::Timestamp => "invalid-timestamp",
            Self::Request => "invalid-request",
            Self::Number => "invalid-number",
            Self::Address => "invalid-address",
            Self::Encoding => "invalid-encoding",
            Self::Fields => "invalid-fields",
            Self::InvalidUtf8 => "invalid-utf8",
            Self::LineTooLong => "line-too-long",
        }
    }
}

fn optional(value: &str) -> Option<String> {
    (!value.is_empty() && value != "-").then(|| value.to_owned())
}

fn number<T: std::str::FromStr>(value: &str) -> Result<Option<T>, AwsAccessLogParseError> {
    if value == "-" {
        Ok(None)
    } else {
        value
            .parse()
            .map(Some)
            .map_err(|_| AwsAccessLogParseError::Number)
    }
}

fn empty_event(log_source: LogSource) -> WebEvent {
    WebEvent {
        timestamp: None,
        source_ip: None,
        client_ip: None,
        source_port: None,
        country: None,
        host: None,
        method: None,
        uri: None,
        uri_path: None,
        uri_query: None,
        uri_fragment: None,
        headers: Vec::new(),
        user_agent: None,
        referer: None,
        status: None,
        response_bytes: None,
        request_body: None,
        request_time_seconds: None,
        content_type: None,
        protocol: None,
        request_id: None,
        ja3: None,
        ja4: None,
        tls_protocol: None,
        tls_cipher: None,
        waf_action: None,
        waf_rule_id: None,
        waf_rule_type: None,
        waf_labels: Vec::new(),
        waf_non_terminating_rule_ids: Vec::new(),
        log_source,
        raw: String::new(),
    }
}

fn set_target(event: &mut WebEvent, target: &str) -> Result<(), AwsAccessLogParseError> {
    if !target.starts_with('/') || !valid_percent_escapes(target) {
        return Err(AwsAccessLogParseError::Request);
    }
    let (path, query, fragment) = split_target(target);
    event.uri = Some(target.to_owned());
    event.uri_path = Some(path);
    event.uri_query = query;
    event.uri_fragment = fragment;
    Ok(())
}

fn add_header(event: &mut WebEvent, name: &str, value: Option<String>) {
    if let Some(value) = value {
        event.headers.push(HttpHeader {
            name: name.to_owned(),
            value,
        });
    }
}

fn alb_fields(raw: &str) -> Result<Vec<String>, AwsAccessLogParseError> {
    let mut chars = raw.chars().peekable();
    let mut fields = Vec::new();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let quoted = chars.peek() == Some(&'"');
        if quoted {
            chars.next();
        }
        let mut value = String::new();
        let mut closed = !quoted;
        while let Some(c) = chars.next() {
            if quoted && c == '"' {
                closed = true;
                break;
            }
            if !quoted && c.is_ascii_whitespace() {
                break;
            }
            if quoted && c == '\\' && chars.peek().is_some_and(|c| matches!(c, '"' | '\\')) {
                value.push(chars.next().ok_or(AwsAccessLogParseError::Format)?);
            } else {
                value.push(c);
            }
        }
        if !closed || (quoted && chars.peek().is_some_and(|c| !c.is_ascii_whitespace())) {
            return Err(AwsAccessLogParseError::Format);
        }
        fields.push(value);
        if fields.len() == 18 {
            break;
        }
    }
    Ok(fields)
}

/// Normalize an ALB record, accepting absent or additional trailing fields.
pub fn parse_alb_line(
    raw: &str,
    retention: RawRetention,
) -> Result<WebEvent, AwsAccessLogParseError> {
    let f = alb_fields(raw)?;
    if f.len() < 18
        || !matches!(
            f[0].as_str(),
            "http" | "https" | "h2" | "grpcs" | "ws" | "wss"
        )
    {
        return Err(AwsAccessLogParseError::Format);
    }
    let mut event = empty_event(LogSource::Alb);
    event.timestamp = Some(
        DateTime::parse_from_rfc3339(&f[1])
            .map_err(|_| AwsAccessLogParseError::Timestamp)?
            .with_timezone(&Utc),
    );
    if f[3] != "-" {
        let (ip, port) = f[3]
            .rsplit_once(':')
            .ok_or(AwsAccessLogParseError::Address)?;
        let ip = ip
            .strip_prefix('[')
            .and_then(|ip| ip.strip_suffix(']'))
            .unwrap_or(ip);
        ip.parse::<IpAddr>()
            .map_err(|_| AwsAccessLogParseError::Address)?;
        event.source_ip = Some(ip.to_owned());
        event.source_port = number(port)?;
    }
    event.status = number(&f[8])?;
    event.response_bytes = number(&f[11])?;
    let parts = f[12].split_whitespace().collect::<Vec<_>>();
    if f[12] != "-" && parts != ["-", "-", "-"] {
        if parts.len() != 3 || !parts[2].starts_with("HTTP/") {
            return Err(AwsAccessLogParseError::Request);
        }
        let (_, rest) = parts[1]
            .split_once("://")
            .filter(|(scheme, _)| matches!(*scheme, "http" | "https" | "ws" | "wss" | "grpcs"))
            .ok_or(AwsAccessLogParseError::Request)?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        if authority.is_empty() || authority.contains('@') {
            return Err(AwsAccessLogParseError::Request);
        }
        let host = if authority.starts_with('[') {
            let end = authority.find(']').ok_or(AwsAccessLogParseError::Request)?;
            let host = &authority[1..end];
            host.parse::<std::net::Ipv6Addr>()
                .map_err(|_| AwsAccessLogParseError::Request)?;
            let suffix = &authority[end + 1..];
            if !suffix.is_empty() {
                suffix
                    .strip_prefix(':')
                    .ok_or(AwsAccessLogParseError::Request)?
                    .parse::<u16>()
                    .map_err(|_| AwsAccessLogParseError::Request)?;
            }
            host
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            port.parse::<u16>()
                .map_err(|_| AwsAccessLogParseError::Request)?;
            host
        } else {
            authority
        };
        if host.is_empty() {
            return Err(AwsAccessLogParseError::Request);
        }
        event.host = Some(host.to_owned());
        event.method = Some(parts[0].to_owned());
        event.protocol = Some(parts[2].to_owned());
        let target = &rest[end..];
        if target.starts_with('/') {
            set_target(&mut event, target)?;
        } else {
            set_target(&mut event, &format!("/{target}"))?;
        }
    }
    event.user_agent = optional(&f[13]);
    event.tls_cipher = optional(&f[14]);
    event.tls_protocol = optional(&f[15]);
    event.request_id = optional(&f[17]);
    add_header(&mut event, "User-Agent", optional(&f[13]));
    event.raw = retention.capture(raw);
    Ok(event)
}

fn decode_once(value: &str) -> Result<Option<String>, AwsAccessLogParseError> {
    if value == "-" {
        return Ok(None);
    }
    if !valid_percent_escapes(value) {
        return Err(AwsAccessLogParseError::Encoding);
    }
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b.to_ascii_lowercase() - b'a' + 10
                }
            };
            decoded.push(hex(bytes[i + 1]) * 16 + hex(bytes[i + 2]));
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded)
        .map(Some)
        .map_err(|_| AwsAccessLogParseError::Encoding)
}

/// A per-file reader: CloudFront headers and physical line references never
/// carry over to another input. Cookies are redacted before raw retention.
pub struct AwsAccessLogLines<R: Read> {
    reader: BufReader<R>,
    buffer: Vec<u8>,
    format: AwsAccessLogFormat,
    retention: RawRetention,
    fields: BTreeMap<String, usize>,
    field_count: usize,
    explicit_fields: bool,
    invalid_fields: bool,
    line_number: u64,
    io_error: Option<String>,
    parsing: InputParsingProvenance,
}

impl<R: Read> AwsAccessLogLines<R> {
    pub fn new(reader: R, format: AwsAccessLogFormat, retention: RawRetention) -> Self {
        let names = CLOUDFRONT_DEFAULT_FIELDS
            .split_whitespace()
            .collect::<Vec<_>>();
        Self {
            reader: BufReader::new(reader),
            buffer: Vec::new(),
            format,
            retention,
            fields: names
                .iter()
                .enumerate()
                .map(|(i, name)| ((*name).to_owned(), i))
                .collect(),
            field_count: names.len(),
            explicit_fields: false,
            invalid_fields: false,
            line_number: 0,
            io_error: None,
            parsing: InputParsingProvenance {
                cloudfront_default_fields: (format == AwsAccessLogFormat::CloudFront)
                    .then_some(false),
                alb_unparsed_requests: (format == AwsAccessLogFormat::Alb).then_some(0),
                ..Default::default()
            },
        }
    }
    pub fn line_number(&self) -> u64 {
        self.line_number
    }
    pub fn io_error(&self) -> Option<&str> {
        self.io_error.as_deref()
    }
    pub fn parsing_provenance(&self) -> InputParsingProvenance {
        self.parsing.clone()
    }

    fn parse_cloudfront(&mut self, raw: &str) -> Result<WebEvent, AwsAccessLogParseError> {
        if self.invalid_fields {
            return Err(AwsAccessLogParseError::Fields);
        }
        if !self.explicit_fields {
            self.parsing.cloudfront_default_fields = Some(true);
        }
        let values = raw.split('\t').collect::<Vec<_>>();
        if self.explicit_fields && values.len() != self.field_count {
            return Err(AwsAccessLogParseError::Format);
        }
        let get = |name: &str| {
            self.fields
                .get(name)
                .and_then(|index| values.get(*index))
                .copied()
                .unwrap_or("-")
        };
        let mut event = empty_event(LogSource::CloudFront);
        let timestamp = format!("{} {}", get("date"), get("time"));
        event.timestamp = Some(
            NaiveDateTime::parse_from_str(&timestamp, "%Y-%m-%d %H:%M:%S")
                .map_err(|_| AwsAccessLogParseError::Timestamp)?
                .and_utc(),
        );
        if let Some(ip) = optional(get("c-ip")) {
            ip.parse::<IpAddr>()
                .map_err(|_| AwsAccessLogParseError::Address)?;
            event.source_ip = Some(ip);
        }
        event.source_port = number(get("c-port"))?;
        event.method = optional(get("cs-method"));
        event.host = optional(get("x-host-header"));
        if let Some(stem) = optional(get("cs-uri-stem")) {
            let target =
                optional(get("cs-uri-query")).map_or(stem.clone(), |q| format!("{stem}?{q}"));
            set_target(&mut event, &target)?;
        }
        event.status = number(get("sc-status"))?;
        event.response_bytes = number(get("sc-bytes"))?;
        event.user_agent = decode_once(get("cs(User-Agent)"))?;
        event.referer = decode_once(get("cs(Referer)"))?;
        event.protocol = optional(get("cs-protocol-version"));
        event.tls_protocol = optional(get("ssl-protocol"));
        event.tls_cipher = optional(get("ssl-cipher"));
        event.request_id = optional(get("x-edge-request-id"));
        let agent = event.user_agent.clone();
        let referer = event.referer.clone();
        add_header(&mut event, "User-Agent", agent);
        add_header(&mut event, "Referer", referer);
        add_header(
            &mut event,
            "X-Forwarded-For",
            optional(get("x-forwarded-for")),
        );
        if self.retention == RawRetention::Keep {
            let cookie = self.fields.get("cs(Cookie)").copied();
            event.raw = values
                .iter()
                .enumerate()
                .map(|(i, v)| if Some(i) == cookie { "-" } else { *v })
                .collect::<Vec<_>>()
                .join("\t");
        }
        Ok(event)
    }
}

impl<R: Read> Iterator for AwsAccessLogLines<R> {
    type Item = Result<WebEvent, AwsAccessLogParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.io_error.is_some() {
            return None;
        }
        loop {
            self.buffer.clear();
            match self.reader.read_until(b'\n', &mut self.buffer) {
                Ok(0) => return None,
                Err(error) => {
                    self.io_error = Some(error.to_string());
                    return Some(Err(AwsAccessLogParseError::Format));
                }
                Ok(_) => self.line_number += 1,
            }
            let bytes = std::mem::take(&mut self.buffer);
            let result = if bytes.len() > MAX_COMBINED_LINE_BYTES {
                Err(AwsAccessLogParseError::LineTooLong)
            } else if let Ok(line) = std::str::from_utf8(&bytes) {
                let raw = line.trim_end_matches(['\r', '\n']);
                if raw.trim().is_empty() {
                    self.buffer = bytes;
                    continue;
                }
                if self.format == AwsAccessLogFormat::CloudFront && raw.starts_with('#') {
                    if let Some(fields) = raw.strip_prefix("#Fields:") {
                        let names = fields.split_whitespace().collect::<Vec<_>>();
                        self.fields = names
                            .iter()
                            .enumerate()
                            .map(|(i, name)| ((*name).to_owned(), i))
                            .collect();
                        self.field_count = names.len();
                        self.explicit_fields = true;
                        self.invalid_fields = self.fields.len() != names.len()
                            || ["date", "time", "c-ip", "cs-method", "cs-uri-stem"]
                                .iter()
                                .any(|name| !self.fields.contains_key(*name));
                        if self.invalid_fields {
                            Err(AwsAccessLogParseError::Fields)
                        } else {
                            self.buffer = bytes;
                            continue;
                        }
                    } else {
                        self.buffer = bytes;
                        continue;
                    }
                } else {
                    match self.format {
                        AwsAccessLogFormat::Alb => parse_alb_line(raw, self.retention),
                        AwsAccessLogFormat::CloudFront => self.parse_cloudfront(raw),
                    }
                }
            } else {
                Err(AwsAccessLogParseError::InvalidUtf8)
            };
            self.buffer = bytes;
            if let Err(error) = &result {
                *self
                    .parsing
                    .parse_error_reasons
                    .entry(error.reason().to_owned())
                    .or_default() += 1;
            }
            if let (Some(count), Ok(event)) = (&mut self.parsing.alb_unparsed_requests, &result) {
                *count += u64::from(event.method.is_none());
            }
            return Some(result);
        }
    }
}
