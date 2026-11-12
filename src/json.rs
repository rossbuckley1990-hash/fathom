//! Clean, dependency-free RFC 8259 JSON value, recursive-descent parser, and serializer.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn obj(entries: Vec<(&str, Json)>) -> Self {
        Json::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_f64().and_then(|n| {
            if n >= 0.0 && n.is_finite() {
                Some(n as u64)
            } else {
                None
            }
        })
    }

    pub fn as_usize(&self) -> Option<usize> {
        self.as_u64().map(|v| v as usize)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    pub fn to_string_compact(&self) -> String {
        let mut out = String::new();
        self.write_compact(&mut out);
        out
    }

    pub fn to_string_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    fn write_compact(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Number(n) => write_number(out, *n),
            Json::Str(s) => write_escaped_str(out, s),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_compact(out);
                }
                out.push(']');
            }
            Json::Object(pairs) => {
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped_str(out, k);
                    out.push(':');
                    v.write_compact(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, indent: usize) {
        let pad = "  ".repeat(indent);
        let inner = "  ".repeat(indent + 1);
        match self {
            Json::Array(items) if items.is_empty() => out.push_str("[]"),
            Json::Array(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&inner);
                    item.write_pretty(out, indent + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            Json::Object(pairs) if pairs.is_empty() => out.push_str("{}"),
            Json::Object(pairs) => {
                out.push_str("{\n");
                for (i, (k, v)) in pairs.iter().enumerate() {
                    out.push_str(&inner);
                    write_escaped_str(out, k);
                    out.push_str(": ");
                    v.write_pretty(out, indent + 1);
                    if i + 1 < pairs.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
            other => other.write_compact(out),
        }
    }
}

fn write_number(out: &mut String, n: f64) {
    if !n.is_finite() {
        out.push('0');
        return;
    }
    if n.fract() == 0.0 && n.abs() < 9_007_199_254_740_991.0 {
        out.push_str(&format!("{}", n as i64));
    } else {
        let s = format!("{n:.4}");
        let trimmed = s.trim_end_matches('0').trim_end_matches('.');
        out.push_str(trimmed);
    }
}

pub fn write_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonParseError {
    pub message: String,
    pub offset: usize,
}

impl fmt::Display for JsonParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON parse error at byte {}: {}",
            self.offset, self.message
        )
    }
}

impl std::error::Error for JsonParseError {}

pub fn parse_json(input: &str) -> Result<Json, JsonParseError> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(p.err("unexpected trailing characters"));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &str) -> JsonParseError {
        JsonParseError {
            message: msg.to_string(),
            offset: self.pos,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self) -> Result<Json, JsonParseError> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.parse_string().map(Json::Str),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b't') => {
                self.expect_bytes(b"true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.expect_bytes(b"false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.expect_bytes(b"null")?;
                Ok(Json::Null)
            }
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.err("unexpected token")),
            None => Err(self.err("unexpected end of JSON input")),
        }
    }

    fn expect_bytes(&mut self, lit: &[u8]) -> Result<(), JsonParseError> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn parse_number(&mut self) -> Result<Json, JsonParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos += 1;
            }
        }
        let slice = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("invalid UTF-8 in number"))?;
        let val = slice
            .parse::<f64>()
            .map_err(|_| self.err("invalid numeric literal"))?;
        Ok(Json::Number(val))
    }

    fn parse_string(&mut self) -> Result<String, JsonParseError> {
        if self.peek() != Some(b'"') {
            return Err(self.err("expected '\"'"));
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = *self
                    .bytes
                    .get(self.pos)
                    .ok_or_else(|| self.err("unterminated escape"))?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{08}'),
                    b'f' => out.push('\u{0c}'),
                    b'u' => {
                        let hex = self
                            .bytes
                            .get(self.pos..self.pos + 4)
                            .ok_or_else(|| self.err("short \\u escape"))?;
                        let hex_str =
                            std::str::from_utf8(hex).map_err(|_| self.err("invalid \\u hex"))?;
                        let code = u32::from_str_radix(hex_str, 16)
                            .map_err(|_| self.err("invalid \\u digits"))?;
                        self.pos += 4;
                        if let Some(ch) = char::from_u32(code) {
                            out.push(ch);
                        } else {
                            out.push('\u{FFFD}');
                        }
                    }
                    _ => return Err(self.err("unknown string escape")),
                }
            } else {
                let rest = std::str::from_utf8(&self.bytes[self.pos..])
                    .map_err(|_| self.err("invalid UTF-8 in string"))?;
                let ch = rest.chars().next().unwrap();
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }
        Err(self.err("unterminated string"))
    }

    fn parse_array(&mut self) -> Result<Json, JsonParseError> {
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']' in array")),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Json, JsonParseError> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut pairs = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':' after object key"));
            }
            self.pos += 1;
            let val = self.parse_value()?;
            pairs.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(pairs));
                }
                _ => return Err(self.err("expected ',' or '}' in object")),
            }
        }
    }
}
