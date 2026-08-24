use std::io::Write;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{event::WebEvent, sigma::CompiledRule};

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub timestamp: Option<DateTime<Utc>>,
    pub level: Option<String>,
    pub rule_title: String,
    pub rule_id: String,
    pub cves: Vec<String>,
    pub source_ip: Option<String>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub waf_action: Option<String>,
    pub waf_rule_id: Option<String>,
    pub waf_labels: Vec<String>,
    pub log_source: String,
    pub request_id: Option<String>,
}

impl Finding {
    pub fn from_rule_and_event(rule: &CompiledRule, event: &WebEvent) -> Self {
        Self {
            timestamp: event.timestamp,
            level: rule.level.clone(),
            rule_title: rule.title.clone(),
            rule_id: rule.id.clone(),
            cves: rule.cves.clone(),
            source_ip: event.source_ip.clone(),
            method: event.method.clone(),
            host: event.host.clone(),
            uri: event.uri.clone(),
            ja3: event.ja3.clone(),
            ja4: event.ja4.clone(),
            waf_action: event.waf_action.clone(),
            waf_rule_id: event.waf_rule_id.clone(),
            waf_labels: event.waf_labels.clone(),
            log_source: "aws_waf".to_owned(),
            request_id: event.request_id.clone(),
        }
    }
}

pub enum FindingWriter<W: Write> {
    Jsonl(W),
    Csv(Box<csv::Writer<W>>, bool),
}

impl<W: Write> FindingWriter<W> {
    pub fn jsonl(writer: W) -> Self {
        Self::Jsonl(writer)
    }
    pub fn csv(writer: W) -> Self {
        Self::Csv(Box::new(csv::Writer::from_writer(writer)), false)
    }
    pub fn write(&mut self, finding: &Finding) -> anyhow::Result<()> {
        match self {
            Self::Jsonl(writer) => {
                serde_json::to_writer(&mut *writer, finding)?;
                writer.write_all(b"\n")?;
            }
            Self::Csv(writer, _) => {
                writer.write_record([
                    finding
                        .timestamp
                        .map(|timestamp| timestamp.to_rfc3339())
                        .unwrap_or_default(),
                    finding.level.clone().unwrap_or_default(),
                    finding.rule_title.clone(),
                    finding.rule_id.clone(),
                    finding.cves.join(";"),
                    finding.source_ip.clone().unwrap_or_default(),
                    finding.method.clone().unwrap_or_default(),
                    finding.host.clone().unwrap_or_default(),
                    finding.uri.clone().unwrap_or_default(),
                    finding.ja3.clone().unwrap_or_default(),
                    finding.ja4.clone().unwrap_or_default(),
                    finding.waf_action.clone().unwrap_or_default(),
                    finding.waf_rule_id.clone().unwrap_or_default(),
                    finding.waf_labels.join(";"),
                    finding.log_source.clone(),
                    finding.request_id.clone().unwrap_or_default(),
                ])?;
            }
        }
        Ok(())
    }

    pub fn write_header(&mut self) -> anyhow::Result<()> {
        if let Self::Csv(writer, header_written) = self {
            if !*header_written {
                writer.write_record([
                    "Timestamp",
                    "Level",
                    "RuleTitle",
                    "RuleID",
                    "CVE",
                    "SourceIP",
                    "Method",
                    "Host",
                    "URI",
                    "JA3",
                    "JA4",
                    "WAFAction",
                    "WAFRuleID",
                    "WAFLabels",
                    "LogSource",
                    "RequestID",
                ])?;
                *header_written = true;
            }
        }
        Ok(())
    }
    pub fn finish(mut self) -> anyhow::Result<()> {
        if let Self::Csv(writer, _) = &mut self {
            writer.flush()?;
        }
        Ok(())
    }
}
