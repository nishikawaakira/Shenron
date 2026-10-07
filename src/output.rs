use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{event::WebEvent, sigma::CompiledRule};

/// Write `value` as pretty JSON through a buffered writer and flush it
/// explicitly, so write errors surface instead of being lost on drop.
pub fn write_json_pretty(path: impl AsRef<Path>, value: &impl Serialize) -> anyhow::Result<()> {
    let path = path.as_ref();
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    write_json_pretty_buffered(file, path, value)
}

/// Write pretty JSON without replacing a file created before or during this call.
pub fn write_json_pretty_new(path: impl AsRef<Path>, value: &impl Serialize) -> anyhow::Result<()> {
    let path = path.as_ref();
    write_new_output(path, |file| write_json_pretty_buffered(file, path, value))
}

fn write_new_output(
    path: &Path,
    write: impl FnOnce(&mut File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    // Never attempt cleanup unless this call successfully created the file.
    let mut file = create_new_output(path)?;
    let result = write(&mut file);
    drop(file);
    if let Err(error) = result {
        if let Err(cleanup_error) = fs::remove_file(path) {
            // An absent file already satisfies the cleanup goal; do not report
            // a cleanup failure when another actor has removed it first.
            if cleanup_error.kind() == io::ErrorKind::NotFound {
                return Err(error);
            }
            // Preserve the original write/flush error as the cause; cleanup
            // failure adds context rather than replacing the primary failure.
            return Err(error.context(format!(
                "could not remove incomplete output {}: {cleanup_error}",
                path.display()
            )));
        }
        return Err(error);
    }
    Ok(())
}

fn create_new_output(path: &Path) -> anyhow::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            let message = if error.kind() == io::ErrorKind::AlreadyExists {
                format!("refusing to overwrite existing output: {}", path.display())
            } else {
                format!("creating {}", path.display())
            };
            anyhow::Error::new(error).context(message)
        })
}

/// Write already-rendered bytes without replacing an existing output.
pub(crate) fn write_bytes_new(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    write_new_output(path, |file| {
        file.write_all(contents)
            .with_context(|| format!("writing {}", path.display()))?;
        file.flush()
            .with_context(|| format!("flushing {}", path.display()))
    })
}

fn write_json_pretty_buffered(
    writer: impl Write,
    path: &Path,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    let mut writer = BufWriter::new(writer);
    serde_json::to_writer_pretty(&mut writer, value)
        .with_context(|| format!("writing JSON to {}", path.display()))?;
    writer
        .flush()
        .with_context(|| format!("flushing JSON to {}", path.display()))
}

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

#[cfg(test)]
mod json_tests {
    use super::*;
    use std::{fs, io};

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeStruct;
            let mut record = serializer.serialize_struct("Partial", 2)?;
            // Exceed the buffer so this failure follows actual file writes.
            record.serialize_field("text", &"x".repeat(32_768))?;
            record.serialize_field("count", &1)?;
            Err(serde::ser::Error::custom("injected serialize failure"))
        }
    }

    #[test]
    fn new_pretty_json_removes_partial_serialization_and_allows_retry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial.json");
        let error = write_json_pretty_new(&path, &FailingSerialize).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("writing JSON to {}", path.display())
        );
        assert!(format!("{error:#}").contains("injected serialize failure"));
        assert!(!path.exists());
        write_json_pretty_new(&path, &true).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"true");
    }

    #[test]
    fn new_output_removes_partial_bytes_and_allows_retry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial.txt");
        let error = write_new_output(&path, |file| {
            file.write_all(b"partial")?;
            assert_eq!(file.metadata()?.len(), 7);
            anyhow::bail!("injected write failure");
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "injected write failure");
        assert!(!path.exists());
        write_bytes_new(&path, b"complete\n").unwrap();
        assert_eq!(fs::read(path).unwrap(), b"complete\n");
    }

    #[test]
    fn new_output_creation_failure_never_runs_writer_or_removes_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing.txt");
        fs::write(&path, b"existing\n").unwrap();
        let error = write_new_output(&path, |_| panic!("writer must not run")).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("refusing to overwrite existing output: {}", path.display())
        );
        assert_eq!(fs::read(path).unwrap(), b"existing\n");
    }

    #[cfg(unix)]
    #[test]
    fn new_output_already_removed_returns_only_original_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial.txt");
        let error = write_new_output(&path, |file| {
            file.write_all(b"partial")?;
            // Unix permits unlinking an open file; cleanup is already complete.
            fs::remove_file(&path)?;
            Err(io::Error::other("injected write failure").into())
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "injected write failure");
        assert!(!format!("{error:#}").contains("could not remove incomplete output"));
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::Other
        );
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn new_output_cleanup_failure_preserves_original_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial.txt");
        let replacement_content = path.join("keep.txt");
        let error = write_new_output(&path, |file| {
            file.write_all(b"partial")?;
            // A nonempty replacement directory cannot be removed with
            // remove_file, even as root. Never remove it recursively.
            fs::remove_file(&path)?;
            fs::create_dir(&path)?;
            fs::write(&replacement_content, b"replacement content\n")?;
            Err(io::Error::other("injected write failure").into())
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(&format!(
            "could not remove incomplete output {}:",
            path.display()
        )));
        assert!(message.contains(&fs::remove_file(&path).unwrap_err().to_string()));
        assert!(message.contains("injected write failure"));
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().to_string(),
            "injected write failure"
        );
        assert!(path.is_dir());
        assert_eq!(
            fs::read(replacement_content).unwrap(),
            b"replacement content\n"
        );
    }

    #[test]
    fn new_pretty_json_preserves_serialized_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("new.json");
        let value =
            serde_json::json!({"rows": (0..2000).collect::<Vec<_>>(), "text": "\"line\"\n日本語"});
        write_json_pretty_new(&path, &value).unwrap();
        assert_eq!(
            fs::read(path).unwrap(),
            serde_json::to_vec_pretty(&value).unwrap()
        );
    }

    #[test]
    fn new_pretty_json_refuses_a_file_created_after_preflight() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("new.json");
        assert!(!path.exists());
        // Simulate another writer winning between preflight and atomic creation.
        fs::write(&path, b"existing content\n").unwrap();
        let error = write_json_pretty_new(&path, &true).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("refusing to overwrite existing output: {}", path.display())
        );
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(path).unwrap(), b"existing content\n");
    }

    #[test]
    fn new_output_creation_errors_include_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("absent-parent/new.json");
        let error = write_json_pretty_new(&path, &true).unwrap_err();
        assert_eq!(error.to_string(), format!("creating {}", path.display()));
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn new_rendered_output_preserves_bytes_and_refuses_a_preflight_race() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.tf");
        let rendered = b"rule {\n    action { count {} }\n}";
        write_bytes_new(&path, rendered).unwrap();
        assert_eq!(fs::read(&path).unwrap(), rendered);
        let raced = directory.path().join("raced.tf");
        assert!(!raced.exists());
        fs::write(&raced, b"existing content\n").unwrap();
        let error = write_bytes_new(&raced, rendered).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("refusing to overwrite existing output: {}", raced.display())
        );
        assert_eq!(fs::read(raced).unwrap(), b"existing content\n");
    }

    #[test]
    fn buffered_pretty_json_preserves_bytes_across_buffer_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        let value = serde_json::json!({
            "empty": [], "missing": null, "enabled": true, "count": 12345,
            "share": 0.125, "escaped": "\"quoted\"\n日本語\\path",
            "rows": (0..2000).collect::<Vec<_>>(),
        });
        let expected = serde_json::to_vec_pretty(&value).unwrap();
        assert!(expected.len() > 8192);
        fs::write(&path, vec![b'x'; expected.len() + 100]).unwrap();
        write_json_pretty(&path, &value).unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected);
        // Repeated writes preserve formatting, truncation and no final newline.
        write_json_pretty(&path, &value).unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert_eq!(expected.last(), Some(&b'}'));
    }

    #[test]
    fn pretty_json_create_failure_includes_path() {
        let directory = tempfile::tempdir().unwrap();
        // A directory cannot be opened as a file, including when run as root.
        let error = write_json_pretty(directory.path(), &()).unwrap_err();
        assert!(error
            .to_string()
            .contains(&directory.path().display().to_string()));
        assert!(error.to_string().contains("creating"));
    }

    struct FailingWriter {
        fail_write: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                Err(io::Error::other("injected write failure"))
            } else {
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected flush failure"))
        }
    }

    #[test]
    fn pretty_json_reports_buffered_write_failures_during_explicit_flush() {
        // This small value stays buffered until the explicit flush.
        let error = write_json_pretty_buffered(
            FailingWriter { fail_write: true },
            Path::new("private/report.json"),
            &true,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("flushing JSON to private/report.json"));
        assert!(message.contains("injected write failure"));
    }

    #[test]
    fn pretty_json_reports_underlying_flush_failures() {
        let error = write_json_pretty_buffered(
            FailingWriter { fail_write: false },
            Path::new("private/report.json"),
            &true,
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("flushing JSON to private/report.json"));
        assert!(message.contains("injected flush failure"));
    }

    #[test]
    fn pretty_json_reports_write_failures_before_flush() {
        let error = write_json_pretty_buffered(
            FailingWriter { fail_write: true },
            Path::new("private/report.json"),
            &"x".repeat(32_768),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("writing JSON to private/report.json"));
        assert!(message.contains("injected write failure"));
    }
}
