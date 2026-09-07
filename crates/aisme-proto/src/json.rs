// SPDX-License-Identifier: Apache-2.0
//! A small JSON codec, written here rather than taken as a dependency
//! (`F1.IPC.01`, closing `Q-12`).
//!
//! **The decision, and why.** `I-21` forbids `serde_json` in
//! `aisme-agentd`, and the control plane is served from the daemon's control
//! thread, so the protocol needs a codec that is not it. The alternatives
//! were a fast third-party codec (`sonic-rs`, `simd-json`: both large, both
//! `unsafe`-heavy, one x86-only) or writing the small one the protocol
//! actually needs. Annex I is twelve methods with fixed shapes; the parser
//! below is a few hundred lines with **no dependency, no `unsafe`, and no
//! recursion the input can drive without bound**. In a security product a
//! codec is an attack surface reached before authentication, so the
//! smallest auditable one wins over the fastest, and the control plane is
//! not the hot path (§3.3 step 14) where speed would argue back.
//!
//! What it does **not** do is as important: no floats (the protocol has
//! none, and float parsing is where JSON codecs get their CVEs), no
//! duplicate-key merging (a duplicate is an error, not a last-wins
//! surprise), and a bounded nesting depth.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The most nested a value may be. Deeper is an error rather than a stack
/// overflow: the input arrives before authentication.
pub const MAX_DEPTH: usize = 32;

/// A JSON value, as the protocol uses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A signed integer. The protocol has no floats.
    Int(i64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Value>),
    /// An object. `BTreeMap`, so writing is deterministic: the same value is
    /// the same bytes, which makes a protocol trace diffable.
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The integer, if this is one.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// A field of this object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

    /// Build an object from pairs.
    #[must_use]
    pub fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    /// A string value.
    #[must_use]
    pub fn string(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }
}

/// Why a document was refused, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset.
    pub at: usize,
    /// What went wrong.
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "byte {}: {}", self.at, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parse one JSON value; trailing content is an error.
///
/// # Errors
///
/// [`ParseError`] with the offset.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let bytes = text.as_bytes();
    let mut p = Parser { bytes, at: 0 };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.at != bytes.len() {
        return Err(p.error("trailing content after the value"));
    }
    Ok(value)
}

/// Write a value. Deterministic: object keys are sorted, so equal values are
/// equal bytes.
#[must_use]
pub fn write(value: &Value) -> String {
    let mut out = String::new();
    put(value, &mut out);
    out
}

fn put(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Str(s) => put_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                put(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                put_string(key, out);
                out.push(':');
                put(item, out);
            }
            out.push('}');
        }
    }
}

fn put_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn error(&self, message: &str) -> ParseError {
        ParseError {
            at: self.at,
            message: message.to_owned(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), ParseError> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected `{}`", byte as char)))
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, ParseError> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(self.error("unknown literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nested deeper than MAX_DEPTH"));
        }
        match self.peek() {
            None => Err(self.error("unexpected end of input")),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::Str),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.integer(),
            Some(other) => Err(self.error(&format!("unexpected `{}`", other as char))),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("expected `,` or `]`")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            let at = self.at;
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            // A duplicate key is an error, not a last-wins surprise: two
            // parsers disagreeing about which value won is how a signed
            // document means two things.
            if map.insert(key, value).is_some() {
                self.at = at;
                return Err(self.error("duplicate key"));
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(self.error("expected `,` or `}`")),
            }
        }
    }

    fn integer(&mut self) -> Result<Value, ParseError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(self.error("the protocol has no floats"));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|_| self.error("not UTF-8"))?;
        text.parse::<i64>()
            .map(Value::Int)
            .map_err(|_| self.error("not an i64"))
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.error("unterminated string"));
            };
            self.at += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(escape) = self.peek() else {
                        return Err(self.error("unterminated escape"));
                    };
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.error("unknown escape")),
                    }
                }
                // Control characters are not allowed raw in a JSON string.
                0x00..=0x1F => return Err(self.error("raw control character in a string")),
                _ => {
                    // Multi-byte UTF-8: take the whole character.
                    let start = self.at - 1;
                    let len = utf8_len(byte);
                    self.at = start + len;
                    let slice = self
                        .bytes
                        .get(start..self.at)
                        .ok_or_else(|| self.error("truncated UTF-8"))?;
                    out.push_str(std::str::from_utf8(slice).map_err(|_| self.error("not UTF-8"))?);
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let hex = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or_else(|| self.error("truncated \\u escape"))?;
        let text = std::str::from_utf8(hex).map_err(|_| self.error("not UTF-8"))?;
        let code = u32::from_str_radix(text, 16).map_err(|_| self.error("bad \\u escape"))?;
        self.at += 4;
        // A lone surrogate is not a character; the protocol does not need
        // surrogate pairs, and inventing a replacement would hide a
        // malformed input.
        char::from_u32(code).ok_or_else(|| self.error("\\u escape is not a character"))
    }
}

const fn utf8_len(byte: u8) -> usize {
    match byte {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shapes_the_protocol_uses_round_trip() {
        let value = Value::object([
            ("jsonrpc", Value::string("2.0")),
            ("id", Value::Int(7)),
            ("method", Value::string("getSession")),
            (
                "params",
                Value::object([
                    ("session_id", Value::Int(-3)),
                    ("active_only", Value::Bool(true)),
                    (
                        "kinds",
                        Value::Array(vec![Value::string("file"), Value::Null]),
                    ),
                ]),
            ),
        ]);
        let text = write(&value);
        assert_eq!(parse(&text).unwrap(), value);
        // Deterministic: keys sorted, so a protocol trace is diffable.
        assert!(
            text.starts_with(r#"{"id":7,"jsonrpc":"2.0","method":"getSession""#),
            "{text}"
        );
        assert_eq!(write(&parse(&text).unwrap()), text);
    }

    #[test]
    fn strings_escape_and_unescape_including_the_awkward_ones() {
        let value = Value::string("quote\" backslash\\ newline\n tab\t control\u{1} ñ 漢");
        let text = write(&value);
        assert!(text.contains("\\u0001"));
        assert_eq!(parse(&text).unwrap(), value);
        assert_eq!(parse(r#""ñ""#).unwrap(), Value::string("ñ"));
        assert_eq!(parse(r#""a\/b""#).unwrap(), Value::string("a/b"));
    }

    #[test]
    fn what_the_codec_refuses_is_the_point() {
        let refused = [
            ("1.5", "the protocol has no floats"),
            ("1e3", "the protocol has no floats"),
            (r#"{"a":1,"a":2}"#, "duplicate key"),
            (r#""unterminated"#, "unterminated string"),
            ("[1,2", "expected `,` or `]`"),
            ("{}{}", "trailing content"),
            ("", "unexpected end of input"),
            ("nul", "unknown literal"),
            ("\"\u{1}\"", "raw control character"),
            (r#""\q""#, "unknown escape"),
            (r#""\ud800""#, "not a character"),
        ];
        for (text, expected) in refused {
            let error = parse(text).unwrap_err();
            assert!(
                error.message.contains(expected),
                "{text:?}: expected {expected:?}, got {error}"
            );
        }
        // Depth is bounded: the input arrives before authentication, so a
        // deep document is an error rather than a stack overflow.
        let deep = format!(
            "{}1{}",
            "[".repeat(MAX_DEPTH + 2),
            "]".repeat(MAX_DEPTH + 2)
        );
        assert!(parse(&deep).unwrap_err().message.contains("MAX_DEPTH"));
        let fine = format!("{}1{}", "[".repeat(4), "]".repeat(4));
        assert!(parse(&fine).is_ok());
    }

    #[test]
    fn accessors_do_not_pretend() {
        let value = parse(r#"{"a":"x","b":3,"c":false}"#).unwrap();
        assert_eq!(value.get("a").and_then(Value::as_str), Some("x"));
        assert_eq!(value.get("b").and_then(Value::as_int), Some(3));
        assert_eq!(value.get("c").and_then(Value::as_bool), Some(false));
        assert_eq!(value.get("missing"), None);
        assert_eq!(
            value.get("a").and_then(Value::as_int),
            None,
            "a string is not an int"
        );
        assert_eq!(Value::Null.get("a"), None);
    }
}
