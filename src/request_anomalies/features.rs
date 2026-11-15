use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::percent_encoding::{decode_once, hex_pair};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Feature {
    AbsoluteForm,
    AsteriskForm,
    AuthorityForm,
    BackslashPath,
    ControlChar,
    Crlf,
    DoubleEncoding,
    EmptyRequest,
    IisUnicode,
    InvalidPercentEscape,
    InvalidUtf8,
    LongTarget,
    NonHttpRequestLine,
    NulByte,
    OverlongUtf8,
    PathParameterTraversal,
    Traversal,
    TraversalEncoded,
}

impl Feature {
    pub const ALL: [Self; 18] = [
        Self::AbsoluteForm,
        Self::AsteriskForm,
        Self::AuthorityForm,
        Self::BackslashPath,
        Self::ControlChar,
        Self::Crlf,
        Self::DoubleEncoding,
        Self::EmptyRequest,
        Self::IisUnicode,
        Self::InvalidPercentEscape,
        Self::InvalidUtf8,
        Self::LongTarget,
        Self::NonHttpRequestLine,
        Self::NulByte,
        Self::OverlongUtf8,
        Self::PathParameterTraversal,
        Self::Traversal,
        Self::TraversalEncoded,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::AbsoluteForm => "absolute-form",
            Self::AsteriskForm => "asterisk-form",
            Self::AuthorityForm => "authority-form",
            Self::BackslashPath => "backslash-path",
            Self::ControlChar => "control-char",
            Self::Crlf => "crlf",
            Self::DoubleEncoding => "double-encoding",
            Self::EmptyRequest => "empty-request",
            Self::IisUnicode => "iis-unicode",
            Self::InvalidPercentEscape => "invalid-percent-escape",
            Self::InvalidUtf8 => "invalid-utf8",
            Self::LongTarget => "long-target",
            Self::NonHttpRequestLine => "non-http-request-line",
            Self::NulByte => "nul-byte",
            Self::OverlongUtf8 => "overlong-utf8",
            Self::PathParameterTraversal => "path-parameter-traversal",
            Self::Traversal => "traversal",
            Self::TraversalEncoded => "traversal-encoded",
        }
    }
}

pub(super) type Observations = BTreeMap<Feature, BTreeSet<&'static str>>;

pub(super) fn mark(found: &mut Observations, feature: Feature, part: &'static str) {
    found.entry(feature).or_default().insert(part);
}

fn overlong(bytes: &[u8]) -> bool {
    let continuation = |b: u8| (0x80..=0xbf).contains(&b);
    bytes
        .windows(2)
        .any(|s| matches!(s[0], 0xc0 | 0xc1) && continuation(s[1]))
        || bytes
            .windows(3)
            .any(|s| s[0] == 0xe0 && (0x80..=0x9f).contains(&s[1]) && continuation(s[2]))
        || bytes.windows(4).any(|s| {
            s[0] == 0xf0
                && (0x80..=0x8f).contains(&s[1])
                && continuation(s[2])
                && continuation(s[3])
        })
}

pub(super) fn inspect_bytes(bytes: &[u8], part: &'static str, found: &mut Observations) {
    if bytes.windows(5).any(|s| {
        s[0] == b'%' && s[1..3].eq_ignore_ascii_case(b"25") && hex_pair(s[3], s[4]).is_some()
    }) {
        mark(found, Feature::DoubleEncoding, part);
    }
    if bytes.windows(6).any(|s| {
        s[0] == b'%' && matches!(s[1], b'u' | b'U') && s[2..].iter().all(u8::is_ascii_hexdigit)
    }) {
        mark(found, Feature::IisUnicode, part);
    }
    if bytes.iter().enumerate().any(|(i, b)| {
        *b == b'%'
            && bytes
                .get(i + 1..i + 3)
                .is_none_or(|pair| hex_pair(pair[0], pair[1]).is_none())
    }) {
        mark(found, Feature::InvalidPercentEscape, part);
    }
    let first = decode_once(bytes);
    let second = decode_once(&first);
    for stage in [bytes, first.as_slice(), second.as_slice()] {
        if stage.contains(&0) {
            mark(found, Feature::NulByte, part);
        }
        if stage.iter().any(|b| matches!(*b, b'\r' | b'\n')) {
            mark(found, Feature::Crlf, part);
        }
        if stage
            .iter()
            .any(|b| matches!(*b, 1..=9 | 11..=12 | 14..=31 | 127))
        {
            mark(found, Feature::ControlChar, part);
        }
        if overlong(stage) {
            mark(found, Feature::OverlongUtf8, part);
        }
    }
    if std::str::from_utf8(&second).is_err() {
        mark(found, Feature::InvalidUtf8, part);
    }
}

fn decode_tagged(bytes: &[(u8, bool)]) -> Vec<(u8, bool)> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].0 == b'%' && i + 2 < bytes.len() {
            if let Some(value) = hex_pair(bytes[i + 1].0, bytes[i + 2].0) {
                decoded.push((value, true));
                i += 3;
                continue;
            }
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    decoded
}

pub(super) fn inspect_path(path: &[u8], found: &mut Observations) {
    let mut stage = path.iter().map(|b| (*b, false)).collect::<Vec<_>>();
    for pass in 0..=2 {
        if stage.iter().any(|(b, _)| *b == b'\\') {
            mark(found, Feature::BackslashPath, "path");
        }
        let mut start = 0;
        for end in 0..=stage.len() {
            if end == stage.len() || matches!(stage[end].0, b'/' | b'\\') {
                let segment = &stage[start..end];
                if segment.iter().position(|(b, _)| *b == b';') == Some(2)
                    && segment[..2].iter().all(|(b, _)| *b == b'.')
                {
                    mark(found, Feature::PathParameterTraversal, "path");
                }
                if segment.len() == 2 && segment.iter().all(|(b, _)| *b == b'.') {
                    let encoded = segment.iter().any(|(_, encoded)| *encoded)
                        || (start > 0 && stage[start - 1].1)
                        || (end < stage.len() && stage[end].1);
                    mark(
                        found,
                        if encoded {
                            Feature::TraversalEncoded
                        } else {
                            Feature::Traversal
                        },
                        "path",
                    );
                }
                start = end + 1;
            }
        }
        if pass < 2 {
            stage = decode_tagged(&stage);
        }
    }
}
