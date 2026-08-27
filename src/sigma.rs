use std::{collections::BTreeMap, fs, path::Path};

use regex::Regex;
use serde::Deserialize;
use serde_yaml::Value;
use thiserror::Error;
use walkdir::WalkDir;

use crate::event::{LogSource, WebEvent};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Logsource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub title: String,
    pub level: Option<String>,
    pub cves: Vec<String>,
    logsource: Logsource,
    selections: BTreeMap<String, Selection>,
    condition: Condition,
}

impl CompiledRule {
    pub fn matches(&self, event: &WebEvent) -> bool {
        source_matches(&self.logsource, event.log_source)
            && evaluate_condition(&self.condition, &self.selections, event)
    }
}

#[derive(Debug, Clone)]
enum Selection {
    Fields(Vec<FieldMatch>),
    Keywords(Vec<String>),
}

#[derive(Debug, Clone)]
struct FieldMatch {
    field: String,
    contains: bool,
    all: bool,
    values: Vec<String>,
}

#[derive(Debug, Clone)]
enum Condition {
    Selection(String),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
}

#[derive(Debug, Clone)]
pub struct UnsupportedRule {
    pub path: String,
    pub title: Option<String>,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct RuleSet {
    pub supported: Vec<CompiledRule>,
    pub unsupported: Vec<UnsupportedRule>,
}

#[derive(Debug, Error)]
enum CompileError {
    #[error("rule must be a YAML mapping")]
    Root,
    #[error("missing required field `{0}`")]
    Missing(&'static str),
    #[error("unsupported Sigma feature: {0}")]
    Unsupported(String),
    #[error("invalid condition: {0}")]
    Condition(String),
}

#[derive(Debug, Deserialize)]
struct RawRule {
    title: Option<String>,
    id: Option<String>,
    level: Option<String>,
    tags: Option<Vec<String>>,
    #[serde(default)]
    logsource: Logsource,
    detection: Option<BTreeMap<String, Value>>,
    correlation: Option<Value>,
}

pub fn load_rules(path: &Path) -> RuleSet {
    let mut rules = RuleSet::default();
    for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file()
            || !matches!(
                entry.path().extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            )
        {
            continue;
        }
        let source_path = entry.path().display().to_string();
        let input = match fs::read_to_string(entry.path()) {
            Ok(input) => input,
            Err(error) => {
                rules.unsupported.push(UnsupportedRule {
                    path: source_path,
                    title: None,
                    reason: format!("cannot read rule: {error}"),
                });
                continue;
            }
        };
        match compile_rule(&input, entry.path()) {
            Ok(rule) => rules.supported.push(rule),
            Err((title, error)) => rules.unsupported.push(UnsupportedRule {
                path: source_path,
                title,
                reason: error.to_string(),
            }),
        }
    }
    rules
}

fn compile_rule(input: &str, path: &Path) -> Result<CompiledRule, (Option<String>, CompileError)> {
    let raw: RawRule = serde_yaml::from_str(input).map_err(|_| (None, CompileError::Root))?;
    let title_for_error = raw.title.clone();
    if raw.correlation.is_some() {
        return Err((
            title_for_error,
            CompileError::Unsupported("correlation rules".to_owned()),
        ));
    }
    let title = raw
        .title
        .ok_or_else(|| (title_for_error.clone(), CompileError::Missing("title")))?;
    let detection = raw
        .detection
        .ok_or_else(|| (Some(title.clone()), CompileError::Missing("detection")))?;
    let condition_value = detection.get("condition").ok_or_else(|| {
        (
            Some(title.clone()),
            CompileError::Missing("detection.condition"),
        )
    })?;
    let condition_text = condition_value.as_str().ok_or_else(|| {
        (
            Some(title.clone()),
            CompileError::Condition("condition must be a string".to_owned()),
        )
    })?;
    let mut selections = BTreeMap::new();
    for (name, value) in &detection {
        if name == "condition" {
            continue;
        }
        let selection =
            compile_selection(name, value).map_err(|error| (Some(title.clone()), error))?;
        selections.insert(name.clone(), selection);
    }
    let condition = ConditionParser::new(condition_text)
        .parse()
        .map_err(|error| (Some(title.clone()), error))?;
    validate_condition(&condition, &selections).map_err(|error| (Some(title.clone()), error))?;
    let cves = raw
        .tags
        .unwrap_or_default()
        .into_iter()
        .filter_map(|tag| {
            let lower = tag.to_ascii_lowercase();
            lower.strip_prefix("cve.").and_then(|value| {
                let normalized = value.replace('.', "-");
                Regex::new(r"^\d{4}-\d{4,}$")
                    .unwrap()
                    .is_match(&normalized)
                    .then(|| format!("CVE-{normalized}"))
            })
        })
        .collect();
    Ok(CompiledRule {
        id: raw.id.unwrap_or_else(|| {
            path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        }),
        title,
        level: raw.level,
        cves,
        logsource: raw.logsource,
        selections,
        condition,
    })
}

fn compile_selection(name: &str, value: &Value) -> Result<Selection, CompileError> {
    if name == "keywords" {
        return value
            .as_sequence()
            .ok_or_else(|| CompileError::Unsupported("keywords must be a list".to_owned()))
            .and_then(|values| {
                values
                    .iter()
                    .map(yaml_string)
                    .collect::<Result<Vec<_>, _>>()
                    .map(Selection::Keywords)
            });
    }
    let map = value.as_mapping().ok_or_else(|| {
        CompileError::Unsupported(format!("selection `{name}` must be a field map"))
    })?;
    let mut matches = Vec::new();
    for (field, expected) in map {
        let key = yaml_string(field)?;
        let (field, modifiers) = split_field_key(&key)?;
        let values = yaml_strings(expected)?;
        matches.push(FieldMatch {
            field,
            contains: modifiers.contains(&"contains"),
            all: modifiers.contains(&"all"),
            values,
        });
    }
    Ok(Selection::Fields(matches))
}

fn split_field_key(key: &str) -> Result<(String, Vec<&str>), CompileError> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default();
    if field.is_empty() {
        return Err(CompileError::Unsupported("empty field name".to_owned()));
    }
    if !known_field(field) {
        return Err(CompileError::Unsupported(format!(
            "unknown field `{field}`"
        )));
    }
    let modifiers: Vec<_> = parts.collect();
    if modifiers
        .iter()
        .any(|modifier| !matches!(*modifier, "contains" | "all"))
    {
        return Err(CompileError::Unsupported(format!(
            "modifier(s) `{}`",
            modifiers.join("|")
        )));
    }
    Ok((field.to_owned(), modifiers))
}

fn yaml_string(value: &Value) -> Result<String, CompileError> {
    value.as_str().map(str::to_owned).ok_or_else(|| {
        CompileError::Unsupported("only string field values are implemented".to_owned())
    })
}

fn yaml_strings(value: &Value) -> Result<Vec<String>, CompileError> {
    let values = if let Some(values) = value.as_sequence() {
        values.iter().map(yaml_string).collect()
    } else {
        Ok(vec![yaml_string(value)?])
    }?;
    if values
        .iter()
        .any(|value| value.contains('*') || value.contains('?'))
    {
        return Err(CompileError::Unsupported(
            "wildcard values are not implemented".to_owned(),
        ));
    }
    Ok(values)
}

fn known_field(field: &str) -> bool {
    matches!(
        field.to_ascii_lowercase().as_str(),
        "cs-method"
            | "method"
            | "cs-uri"
            | "uri"
            | "cs-uri-stem"
            | "uri_path"
            | "cs-uri-query"
            | "uri_query"
            | "cs-host"
            | "host"
            | "cs-user-agent"
            | "c-useragent"
            | "user_agent"
            | "cs-referer"
            | "referer"
            | "c-ip"
            | "source_ip"
            | "sc-status"
            | "status"
            | "ja3"
            | "ja4"
            | "waf_action"
            | "waf_rule_id"
            | "waf_labels"
    )
}

fn source_matches(logsource: &Logsource, source: LogSource) -> bool {
    if logsource
        .category
        .as_deref()
        .is_some_and(|category| !category.eq_ignore_ascii_case("webserver"))
    {
        return false;
    }
    match source {
        LogSource::AwsWaf => {
            logsource
                .product
                .as_deref()
                .is_none_or(|product| product.eq_ignore_ascii_case("aws"))
                && logsource
                    .service
                    .as_deref()
                    .is_none_or(|service| service.eq_ignore_ascii_case("waf"))
        }
        LogSource::NginxCombined => logsource
            .product
            .as_deref()
            .is_none_or(|product| product.eq_ignore_ascii_case("nginx")),
        LogSource::ApacheCombined | LogSource::ApacheVhostCombined => {
            logsource.product.as_deref().is_none_or(|product| {
                product.eq_ignore_ascii_case("apache")
                    || product.eq_ignore_ascii_case("apache_httpd")
            })
        }
    }
}

fn evaluate_condition(
    condition: &Condition,
    selections: &BTreeMap<String, Selection>,
    event: &WebEvent,
) -> bool {
    match condition {
        Condition::Selection(name) => selections
            .get(name)
            .is_some_and(|selection| selection_matches(selection, event)),
        Condition::And(left, right) => {
            evaluate_condition(left, selections, event)
                && evaluate_condition(right, selections, event)
        }
        Condition::Or(left, right) => {
            evaluate_condition(left, selections, event)
                || evaluate_condition(right, selections, event)
        }
        Condition::Not(inner) => !evaluate_condition(inner, selections, event),
    }
}

fn selection_matches(selection: &Selection, event: &WebEvent) -> bool {
    match selection {
        Selection::Keywords(keywords) => {
            let haystack = event.keyword_haystack().to_ascii_lowercase();
            keywords
                .iter()
                .any(|keyword| haystack.contains(&keyword.to_ascii_lowercase()))
        }
        Selection::Fields(matches) => matches.iter().all(|matcher| field_match(matcher, event)),
    }
}

fn field_match(matcher: &FieldMatch, event: &WebEvent) -> bool {
    let Some(actuals) = event.field_values(&matcher.field) else {
        return false;
    };
    let matches = |expected: &str| {
        actuals.iter().any(|actual| {
            if matcher.contains {
                actual
                    .to_ascii_lowercase()
                    .contains(&expected.to_ascii_lowercase())
            } else {
                actual.eq_ignore_ascii_case(expected)
            }
        })
    };
    if matcher.all {
        matcher.values.iter().all(|expected| matches(expected))
    } else {
        matcher.values.iter().any(|expected| matches(expected))
    }
}

fn validate_condition(
    condition: &Condition,
    selections: &BTreeMap<String, Selection>,
) -> Result<(), CompileError> {
    match condition {
        Condition::Selection(name) if !selections.contains_key(name) => Err(
            CompileError::Condition(format!("unknown selection `{name}`")),
        ),
        Condition::Selection(_) => Ok(()),
        Condition::And(left, right) | Condition::Or(left, right) => {
            validate_condition(left, selections)?;
            validate_condition(right, selections)
        }
        Condition::Not(inner) => validate_condition(inner, selections),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Name(String),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

struct ConditionParser {
    tokens: Vec<Token>,
    position: usize,
}

impl ConditionParser {
    fn new(input: &str) -> Self {
        Self {
            tokens: tokenize(input),
            position: 0,
        }
    }
    fn parse(mut self) -> Result<Condition, CompileError> {
        if self.tokens.is_empty() {
            return Err(CompileError::Condition("empty condition".to_owned()));
        }
        let expression = self.parse_or()?;
        if self.position != self.tokens.len() {
            return Err(CompileError::Condition("unexpected token".to_owned()));
        }
        Ok(expression)
    }
    fn parse_or(&mut self) -> Result<Condition, CompileError> {
        let mut expression = self.parse_and()?;
        while self.accept(&Token::Or) {
            expression = Condition::Or(Box::new(expression), Box::new(self.parse_and()?));
        }
        Ok(expression)
    }
    fn parse_and(&mut self) -> Result<Condition, CompileError> {
        let mut expression = self.parse_not()?;
        while self.accept(&Token::And) {
            expression = Condition::And(Box::new(expression), Box::new(self.parse_not()?));
        }
        Ok(expression)
    }
    fn parse_not(&mut self) -> Result<Condition, CompileError> {
        if self.accept(&Token::Not) {
            Ok(Condition::Not(Box::new(self.parse_not()?)))
        } else {
            self.parse_primary()
        }
    }
    fn parse_primary(&mut self) -> Result<Condition, CompileError> {
        if self.accept(&Token::LParen) {
            let expression = self.parse_or()?;
            if !self.accept(&Token::RParen) {
                return Err(CompileError::Condition(
                    "missing closing parenthesis".to_owned(),
                ));
            }
            return Ok(expression);
        }
        match self.next() {
            Some(Token::Name(name)) => Ok(Condition::Selection(name)),
            _ => Err(CompileError::Condition(
                "expected selection name".to_owned(),
            )),
        }
    }
    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).cloned();
        self.position += usize::from(token.is_some());
        token
    }
    fn accept(&mut self, expected: &Token) -> bool {
        if self.tokens.get(self.position) == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let push_word = |word: &mut String, tokens: &mut Vec<Token>| {
        if word.is_empty() {
            return;
        }
        tokens.push(match word.to_ascii_lowercase().as_str() {
            "and" => Token::And,
            "or" => Token::Or,
            "not" => Token::Not,
            _ => Token::Name(std::mem::take(word)),
        });
        word.clear();
    };
    for character in input.chars() {
        match character {
            '(' => {
                push_word(&mut word, &mut tokens);
                tokens.push(Token::LParen);
            }
            ')' => {
                push_word(&mut word, &mut tokens);
                tokens.push(Token::RParen);
            }
            c if c.is_whitespace() => push_word(&mut word, &mut tokens),
            c => word.push(c),
        }
    }
    push_word(&mut word, &mut tokens);
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::parse_line;

    fn event() -> WebEvent {
        parse_line(
            include_str!("../tests/fixtures/aws-waf/malicious.jsonl")
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn matches_contains_and_keywords() {
        let rules = load_rules(Path::new("tests/fixtures/rules"));
        assert_eq!(rules.supported.len(), 2);
        assert_eq!(rules.unsupported.len(), 1);
        assert!(rules.supported.iter().all(|rule| rule.matches(&event())));
    }

    #[test]
    fn evaluates_not_and_parentheses() {
        let parsed = ConditionParser::new("selection and not (filter or other)")
            .parse()
            .unwrap();
        let mut selections = BTreeMap::new();
        selections.insert(
            "selection".to_owned(),
            Selection::Keywords(vec!["jndi".to_owned()]),
        );
        selections.insert(
            "filter".to_owned(),
            Selection::Keywords(vec!["harmless".to_owned()]),
        );
        selections.insert(
            "other".to_owned(),
            Selection::Keywords(vec!["nope".to_owned()]),
        );
        assert!(evaluate_condition(&parsed, &selections, &event()));
    }

    #[test]
    fn all_modifier_requires_every_list_value() {
        let matcher = FieldMatch {
            field: "waf_labels".to_owned(),
            contains: true,
            all: true,
            values: vec!["core-rule-set".to_owned(), "threat-hunt".to_owned()],
        };
        assert!(field_match(&matcher, &event()));
    }
}
