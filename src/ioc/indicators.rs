use super::*;
use regex::Regex;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::{
    fmt,
    io::{Cursor, Read},
    sync::OnceLock,
};

// A bounded record also bounds an OR expression's index expansion.
const MAX_INDICATOR_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Atom {
    Ip(IpAddr),
    Cidr(IpNet),
    Path(String),
    Prefix(String),
    Agent(String),
    Ja3(String),
    Ja4(String),
    Host(String),
    Url(String, String),
}

#[derive(Serialize)]
pub(super) struct Indicator {
    pub indicator_type: String,
    pub values: Vec<String>,
    pub label: Option<String>,
    pub input_file: String,
    pub record_number: u64,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub atoms: Vec<Atom>,
}

#[derive(Serialize)]
pub(super) struct IndicatorFile {
    #[serde(flatten)]
    provenance: PathProvenance,
    records: u64,
    loaded: usize,
    rejected: u64,
    duplicates: u64,
    comments_or_empty: u64,
    ignored_objects: u64,
    beyond_cap: u64,
    utf8_bom: bool,
}

type Identity = (Vec<Atom>, Option<DateTime<Utc>>, Option<DateTime<Utc>>);

struct Loader<'a> {
    options: &'a Options,
    summary: &'a mut Summary,
    rows: Vec<Indicator>,
    seen: BTreeSet<Identity>,
    input_file: String,
}

impl Loader<'_> {
    fn accept(&mut self, row: Indicator) {
        let key = (row.atoms.clone(), row.valid_from, row.valid_until);
        if !self.seen.insert(key) {
            self.summary.duplicate_records += 1;
            return;
        }
        *self
            .summary
            .loaded_by_type
            .entry(row.indicator_type.clone())
            .or_default() += 1;
        self.rows.push(row);
        self.summary.loaded_indicators += 1;
    }

    fn capped(&mut self) -> bool {
        if self.rows.len() >= self.options.max_indicators {
            self.summary.records_beyond_indicator_cap += 1;
            true
        } else {
            false
        }
    }

    fn tsv(&mut self, line: &[u8], record_number: u64) {
        self.summary.indicator_records += 1;
        let Ok(line) = std::str::from_utf8(line) else {
            self.summary.reject("invalid-utf8");
            return;
        };
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() || line.starts_with('#') {
            self.summary.comment_or_empty_records += 1;
            return;
        }
        if self.capped() {
            return;
        }
        if line.len() > MAX_INDICATOR_BYTES {
            self.summary.reject("indicator-too-large");
            return;
        }
        let columns: Vec<_> = line.split('\t').collect();
        if !(2..=3).contains(&columns.len()) {
            self.summary.reject("invalid-tsv-record");
            return;
        }
        if ![
            "ip",
            "cidr",
            "path",
            "path-prefix",
            "user-agent",
            "ja3",
            "ja4",
            "host",
        ]
        .contains(&columns[0])
        {
            self.summary.reject("unsupported-object-type");
            return;
        }
        match parse_atom(columns[0], columns[1]) {
            Ok(atom) => self.accept(Indicator {
                indicator_type: columns[0].into(),
                values: vec![columns[1].into()],
                label: columns
                    .get(2)
                    .filter(|v| !v.is_empty())
                    .map(|v| (*v).into()),
                input_file: self.input_file.clone(),
                record_number,
                valid_from: None,
                valid_until: None,
                atoms: vec![atom],
            }),
            Err(reason) => self.summary.reject(reason),
        }
    }

    fn stix(&mut self, object: Value, record_number: u64) {
        self.summary.indicator_records += 1;
        if object.get("type").and_then(Value::as_str) != Some("indicator") {
            self.summary.ignored_stix_objects += 1;
            return;
        }
        if self.capped() {
            return;
        }
        let parsed = (|| {
            match object.get("revoked") {
                Some(Value::Bool(true)) => return Err("revoked"),
                Some(Value::Bool(false)) | None => {}
                Some(_) => return Err("invalid-revoked"),
            }
            if object
                .get("spec_version")
                .and_then(Value::as_str)
                .is_some_and(|v| v != "2.1")
            {
                return Err("unsupported-stix-version");
            }
            if object.get("pattern_type").and_then(Value::as_str) != Some("stix") {
                return Err("unsupported-pattern-type");
            }
            if object
                .get("pattern_version")
                .and_then(Value::as_str)
                .is_some_and(|v| v != "2.1")
            {
                return Err("unsupported-stix-version");
            }
            let pattern = object
                .get("pattern")
                .and_then(Value::as_str)
                .ok_or("invalid-pattern")?;
            if pattern.len() > MAX_INDICATOR_BYTES {
                return Err("indicator-too-large");
            }
            let (kind, values, atoms) = parse_pattern(pattern)?;
            let date = |key| -> std::result::Result<Option<DateTime<Utc>>, &'static str> {
                object
                    .get(key)
                    .map(|value| {
                        value.as_str().ok_or("invalid-validity").and_then(|v| {
                            DateTime::parse_from_rfc3339(v)
                                .map(|v| v.with_timezone(&Utc))
                                .map_err(|_| "invalid-validity")
                        })
                    })
                    .transpose()
            };
            let valid_from = date("valid_from")?;
            let valid_until = date("valid_until")?;
            if matches!((valid_from, valid_until), (Some(a), Some(b)) if b <= a) {
                return Err("invalid-validity");
            }
            Ok(Indicator {
                indicator_type: kind,
                values,
                atoms,
                label: object
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                input_file: self.input_file.clone(),
                record_number,
                valid_from,
                valid_until,
            })
        })();
        match parsed {
            Ok(row) => self.accept(row),
            Err(reason) => self.summary.reject(reason),
        }
    }
}

fn parse_atom(kind: &str, value: &str) -> std::result::Result<Atom, &'static str> {
    if value.is_empty() {
        return Err("invalid-value");
    }
    Ok(match kind {
        "ip" => Atom::Ip(canonical_ip(value).ok_or("invalid-value")?),
        "cidr" => Atom::Cidr(value.parse::<IpNet>().map_err(|_| "invalid-value")?.trunc()),
        "path" | "path-prefix" if value.starts_with('/') && !value.contains(['?', '#']) => {
            if kind == "path" {
                Atom::Path(value.into())
            } else {
                Atom::Prefix(value.into())
            }
        }
        "path" | "path-prefix" => return Err("invalid-value"),
        "user-agent" => Atom::Agent(value.into()),
        "ja3" if value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Atom::Ja3(value.to_ascii_lowercase())
        }
        "ja4"
            if value.is_ascii()
                && !value
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) =>
        {
            Atom::Ja4(value.into())
        }
        "ja3" | "ja4" => return Err("invalid-value"),
        "host" if valid_host(value) => Atom::Host(normalize_host(value)),
        "host" => return Err("invalid-value"),
        "url" => {
            if value.contains('?') {
                return Err("url-query-unsupported");
            }
            if value.contains('#') {
                return Err("url-fragment-unsupported");
            }
            let rest = value
                .strip_prefix("https://")
                .or_else(|| value.strip_prefix("http://"))
                .ok_or("unsupported-url")?;
            let (host, path) = rest
                .split_once('/')
                .map_or((rest, "/".to_owned()), |(host, path)| {
                    (host, format!("/{path}"))
                });
            if !valid_host(host) || host.contains('@') {
                return Err("invalid-value");
            }
            let (name, port) = host_port(host);
            let name = normalize_host(name);
            let default_port = if value.starts_with("https://") {
                "443"
            } else {
                "80"
            };
            let authority = match port {
                Some(port) if port != default_port => format!("{name}:{port}"),
                _ => name,
            };
            Atom::Url(authority, path)
        }
        _ => return Err("unsupported-object-type"),
    })
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && !value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        && !value.contains(['/', '?', '#', '@', '\\'])
}

/// Accept one observation with a complete, homogeneous equality/OR expression.
fn parse_pattern(
    pattern: &str,
) -> std::result::Result<(String, Vec<String>, Vec<Atom>), &'static str> {
    static COMPARISON: OnceLock<Regex> = OnceLock::new();
    let pattern = pattern.trim();
    let mut quoted = false;
    let mut escaped = false;
    let mut brackets = Vec::new();
    for (i, c) in pattern.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && c == '\\' {
            escaped = true;
            continue;
        }
        if c == '\'' {
            quoted = !quoted;
        }
        if !quoted && matches!(c, '[' | ']') {
            brackets.push((i, c));
        }
    }
    if brackets.len() > 2 {
        return Err("compound-observation");
    }
    if brackets.len() != 2 || brackets[0] != (0, '[') || brackets[1].1 != ']' {
        return Err("invalid-pattern");
    }
    if brackets[1].0 != pattern.len() - 1 {
        return Err("unsupported-operator");
    }
    let mut rest = &pattern[1..pattern.len() - 1];
    let comparison = COMPARISON.get_or_init(|| {
        Regex::new(r#"^\s*([a-z0-9-]+):value\s*=\s*'((?:\\['\\]|[^'\\])*)'"#)
            .expect("valid STIX equality subset")
    });
    let mut kind = None;
    let mut values = Vec::new();
    let mut atoms = Vec::new();
    loop {
        let object_type = rest.trim_start().split_once(':').map(|(kind, _)| kind);
        if object_type
            .is_some_and(|kind| !["ipv4-addr", "ipv6-addr", "domain-name", "url"].contains(&kind))
        {
            return Err("unsupported-object-type");
        }
        let captures = comparison.captures(rest).ok_or("unsupported-operator")?;
        let current = captures[1].to_owned();
        if !["ipv4-addr", "ipv6-addr", "domain-name", "url"].contains(&current.as_str()) {
            return Err("unsupported-object-type");
        }
        if kind.as_ref().is_some_and(|kind| kind != &current) {
            return Err("mixed-observation-types");
        }
        kind = Some(current.clone());
        let mut value = String::new();
        let mut chars = captures[2].chars();
        while let Some(c) = chars.next() {
            value.push(if c == '\\' {
                chars.next().ok_or("invalid-pattern")?
            } else {
                c
            });
        }
        let atom_kind = match current.as_str() {
            "ipv4-addr" | "ipv6-addr" => {
                if value.contains('/') {
                    "cidr"
                } else {
                    "ip"
                }
            }
            "domain-name" => "host",
            _ => "url",
        };
        let atom = parse_atom(atom_kind, &value)?;
        if current == "ipv4-addr" || current == "ipv6-addr" {
            let is_v4 = if value.contains('/') {
                value
                    .parse::<IpNet>()
                    .map_err(|_| "invalid-value")?
                    .addr()
                    .is_ipv4()
            } else {
                value
                    .parse::<IpAddr>()
                    .map_err(|_| "invalid-value")?
                    .is_ipv4()
            };
            if is_v4 != (current == "ipv4-addr") {
                return Err("address-family-mismatch");
            }
        }
        atoms.push(atom);
        values.push(value);
        rest = rest[captures.get(0).unwrap().end()..].trim_start();
        if rest.is_empty() {
            break;
        }
        rest = rest
            .strip_prefix("OR")
            .filter(|tail| tail.starts_with(char::is_whitespace))
            .ok_or("unsupported-operator")?;
    }
    atoms.sort();
    atoms.dedup();
    values.sort();
    values.dedup();
    Ok((kind.ok_or("invalid-pattern")?, values, atoms))
}

struct Bundle<'a, 'b>(&'a mut Loader<'b>);
struct Objects<'a, 'b>(&'a mut Loader<'b>);

impl<'de> Visitor<'de> for Bundle<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a STIX bundle object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut bundle_type = None;
        let mut objects = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "type" if bundle_type.is_none() => bundle_type = Some(map.next_value::<String>()?),
                "objects" if !objects => {
                    map.next_value_seed(Objects(self.0))?;
                    objects = true;
                }
                "type" | "objects" => {
                    return Err(serde::de::Error::custom("duplicate STIX bundle field"))
                }
                _ => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        if bundle_type.as_deref() != Some("bundle") || !objects {
            return Err(serde::de::Error::custom(
                "expected STIX bundle with objects",
            ));
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for Bundle<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Objects<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a STIX objects array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        let mut number = 0;
        while let Some(object) = seq.next_element::<Value>()? {
            number += 1;
            self.0.stix(object, number);
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for Objects<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

pub(super) fn load_indicators(
    paths: &[PathBuf],
    options: &Options,
    summary: &mut Summary,
) -> Result<(Vec<Indicator>, Vec<IndicatorFile>)> {
    let mut paths = paths.to_vec();
    paths.sort();
    let mut loader = Loader {
        options,
        summary,
        rows: Vec::new(),
        seen: BTreeSet::new(),
        input_file: String::new(),
    };
    let mut files = Vec::new();
    for path in paths {
        loader.input_file = path.display().to_string();
        let records = loader.summary.indicator_records;
        let loaded = loader.rows.len();
        let rejected: u64 = loader.summary.rejected_by_reason.values().sum();
        let duplicates = loader.summary.duplicate_records;
        let comments = loader.summary.comment_or_empty_records;
        let ignored = loader.summary.ignored_stix_objects;
        let beyond = loader.summary.records_beyond_indicator_cap;
        let mut utf8_bom = false;
        let provenance = with_fingerprinted_input(&path, |reader| {
            let mut reader = BufReader::new(reader);
            let mut start = Vec::with_capacity(3);
            reader.by_ref().take(3).read_to_end(&mut start)?;
            utf8_bom = start == [0xef, 0xbb, 0xbf];
            if utf8_bom {
                start.clear();
            }
            let mut reader = BufReader::new(Cursor::new(start).chain(reader));
            let mut prefix = Vec::new();
            let first = loop {
                let bytes = reader.fill_buf()?;
                if bytes.is_empty() {
                    break None;
                }
                if let Some(&b) = bytes.iter().find(|b| !b.is_ascii_whitespace()) {
                    break Some(b);
                }
                prefix.extend_from_slice(bytes);
                let length = bytes.len();
                reader.consume(length);
            };
            // Replay sniffed whitespace so TSV blank lines and physical row numbers survive.
            let mut reader = BufReader::new(Cursor::new(prefix).chain(reader));
            if first == Some(b'{') {
                let mut deserializer = serde_json::Deserializer::from_reader(reader);
                Bundle(&mut loader).deserialize(&mut deserializer)?;
                deserializer.end()?;
            } else {
                let mut line = Vec::new();
                let mut number = 0;
                loop {
                    line.clear();
                    if reader.read_until(b'\n', &mut line)? == 0 {
                        break;
                    }
                    number += 1;
                    loader.tsv(&line, number);
                }
            }
            Ok(())
        })
        .with_context(|| format!("reading indicator file {}", path.display()))?;
        files.push(IndicatorFile {
            provenance,
            records: loader.summary.indicator_records - records,
            loaded: loader.rows.len() - loaded,
            rejected: loader.summary.rejected_by_reason.values().sum::<u64>() - rejected,
            duplicates: loader.summary.duplicate_records - duplicates,
            comments_or_empty: loader.summary.comment_or_empty_records - comments,
            ignored_objects: loader.summary.ignored_stix_objects - ignored,
            beyond_cap: loader.summary.records_beyond_indicator_cap - beyond,
            utf8_bom,
        });
    }
    loader.summary.indicator_files = files.len();
    Ok((loader.rows, files))
}
