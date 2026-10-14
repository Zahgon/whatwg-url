// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! JavaScript values as JSON carries them, with the JavaScript semantics the command relies on: `JSON.parse` (with
//! the `SyntaxError` messages of Node.js 22), `JSON.stringify`, property order, `String(value)`, `Number(value)`,
//! truthiness and number printing.

use crate::jsstring::{self, JsString};
use std::fmt;

/// A JavaScript value that JSON can carry.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(JsString),
    Array(Vec<Value>),
    Object(Object),
}

impl Drop for Value {
    /// Tears nested arrays and objects down with an explicit stack, so that dropping a deeply nested request cannot
    /// overflow the call stack.
    fn drop(&mut self) {
        let mut pending = Vec::new();
        take_children(self, &mut pending);
        while let Some(mut value) = pending.pop() {
            take_children(&mut value, &mut pending);
        }
    }
}

fn take_children(value: &mut Value, into: &mut Vec<Value>) {
    match value {
        Value::Array(items) => into.append(items),
        Value::Object(object) => into.extend(object.entries.drain(..).map(|(_, v)| v)),
        _ => {}
    }
}

/// A JavaScript object's own properties. Enumeration follows JavaScript: array-index keys in ascending numeric order
/// first, then the other keys in creation order; assigning an existing key keeps its place.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Object {
    entries: Vec<(JsString, Value)>,
}

impl Object {
    /// An empty object.
    pub fn new() -> Self {
        Object::default()
    }

    /// Sets a property, keeping the position of an existing one.
    pub fn insert(&mut self, key: JsString, value: Value) {
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key, value)),
        }
    }

    /// The value of an own property.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(k, _)| jsstring::eq_ascii(k, key))
            .map(|(_, v)| v)
    }

    /// `true` when the object has the own property.
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// The own properties in JavaScript's enumeration order.
    pub fn properties(&self) -> Vec<(&JsString, &Value)> {
        let mut indices: Vec<(u32, &JsString, &Value)> = Vec::new();
        let mut named = Vec::new();
        for (k, v) in &self.entries {
            match array_index(k) {
                Some(i) => indices.push((i, k, v)),
                None => named.push((k, v)),
            }
        }
        indices.sort_by_key(|&(i, _, _)| i);
        indices.into_iter().map(|(_, k, v)| (k, v)).chain(named).collect()
    }
}

/// The array index a property key stands for: the canonical decimal form of an integer up to 2^32 - 2.
fn array_index(key: &[u16]) -> Option<u32> {
    if key.is_empty() || key.len() > 10 || !key.iter().all(|&u| (0x30..=0x39).contains(&u)) {
        return None;
    }
    if key.len() > 1 && key[0] == 0x30 {
        return None;
    }
    let value = key.iter().fold(0u64, |acc, &u| acc * 10 + u64::from(u - 0x30));
    (value <= 4_294_967_294).then_some(value as u32)
}

/// A JavaScript error: its name and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsError {
    pub name: &'static str,
    pub message: JsString,
}

impl JsError {
    /// An error with an ASCII or well-formed message.
    pub fn new(name: &'static str, message: impl AsRef<str>) -> Self {
        JsError {
            name,
            message: jsstring::from_str(message.as_ref()),
        }
    }

    /// A `TypeError`.
    pub fn type_error(message: impl AsRef<str>) -> Self {
        JsError::new("TypeError", message)
    }
}

impl fmt::Display for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, jsstring::to_well_formed(&self.message))
    }
}

impl std::error::Error for JsError {}

// ------------------------------------------------------------------------------------------------ JSON.parse

const MAX_CONTEXT: usize = 10;
const MIN_LENGTH_FOR_CONTEXT: usize = 21;

/// The kind of token a character starts, as V8's JSON scanner classifies it.
enum Token {
    Eos,
    Number,
    String,
    Other,
}

/// An array or object whose members are still being parsed, with the name of the property being parsed.
enum Container {
    Array(Vec<Value>),
    Object(Object, JsString),
}

impl Container {
    fn into_value(self) -> Value {
        match self {
            Container::Array(items) => Value::Array(items),
            Container::Object(object, _) => Value::Object(object),
        }
    }
}

struct JsonParser<'a> {
    source: &'a [u16],
    pos: usize,
}

/// `JSON.parse(text)`, with V8's `SyntaxError` messages.
pub fn parse(text: &[u16]) -> Result<Value, JsError> {
    let mut parser = JsonParser { source: text, pos: 0 };
    parser.skip_whitespace();
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.pos < text.len() {
        return Err(parser.error_at("Unexpected non-whitespace character after JSON", parser.pos));
    }
    Ok(value)
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<u16> {
        self.source.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(0x20 | 0x09 | 0x0A | 0x0D)) {
            self.pos += 1;
        }
    }

    fn token_at(&self, pos: usize) -> Token {
        match self.source.get(pos) {
            None => Token::Eos,
            Some(&u) if u == u16::from(b'-') || (0x30..=0x39).contains(&u) => Token::Number,
            Some(&u) if u == u16::from(b'"') => Token::String,
            Some(_) => Token::Other,
        }
    }

    /// A message (`... in JSON`, or the one for trailing text) with the position and its line and column.
    fn error_at(&self, text: &str, pos: usize) -> JsError {
        let (line, column) = self.line_and_column(pos);
        JsError::new(
            "SyntaxError",
            format!("{text} at position {pos} (line {line} column {column})"),
        )
    }

    fn line_and_column(&self, pos: usize) -> (usize, usize) {
        let mut line = 1;
        let mut line_start = 0;
        let mut i = 0;
        while i < pos && i < self.source.len() {
            let u = self.source[i];
            if u == 0x0D && self.source.get(i + 1) == Some(&0x0A) && i + 1 < pos {
                i += 1;
            }
            if u == 0x0A || u == 0x0D {
                line += 1;
                line_start = i + 1;
            }
            i += 1;
        }
        (line, pos - line_start + 1)
    }

    /// The error for an unexpected token at `pos`, chosen as V8 chooses it.
    fn unexpected(&self, pos: usize) -> JsError {
        match self.token_at(pos) {
            Token::Eos => JsError::new("SyntaxError", "Unexpected end of JSON input"),
            Token::Number => self.error_at("Unexpected number in JSON", pos),
            Token::String => self.error_at("Unexpected string in JSON", pos),
            Token::Other => {
                let source = self.source;
                if ["NaN", "Infinity", "undefined", "[object Object]"]
                    .iter()
                    .any(|s| jsstring::eq_ascii(source, s))
                {
                    let mut message = jsstring::from_str("\"");
                    message.extend_from_slice(source);
                    message.extend(jsstring::from_str("\" is not valid JSON"));
                    return JsError {
                        name: "SyntaxError",
                        message,
                    };
                }
                let mut message = jsstring::from_str("Unexpected token '");
                message.push(source[pos]);
                message.extend(jsstring::from_str("', "));
                let len = source.len();
                let (prefix, start, end, suffix) = if len < MIN_LENGTH_FOR_CONTEXT {
                    ("\"", 0, len, "\"")
                } else if pos < MAX_CONTEXT {
                    ("\"", 0, pos + MAX_CONTEXT, "\"...")
                } else if pos < len - MAX_CONTEXT {
                    ("...\"", pos - MAX_CONTEXT, pos + MAX_CONTEXT, "\"...")
                } else {
                    ("...\"", pos - MAX_CONTEXT, len, "\"")
                };
                message.extend(jsstring::from_str(prefix));
                message.extend_from_slice(&source[start..end]);
                message.extend(jsstring::from_str(suffix));
                message.extend(jsstring::from_str(" is not valid JSON"));
                JsError {
                    name: "SyntaxError",
                    message,
                }
            }
        }
    }

    /// Parses one value. Arrays and objects being filled are kept on an explicit stack rather than the call stack, so,
    /// as in V8, nesting depth is limited only by memory.
    fn parse_value(&mut self) -> Result<Value, JsError> {
        let mut open: Vec<Container> = Vec::new();
        loop {
            let mut value = match self.peek() {
                Some(0x7B) => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(0x7D) {
                        self.pos += 1;
                        Value::Object(Object::new())
                    } else if self.peek() == Some(0x22) {
                        let key = self.parse_property_name()?;
                        open.push(Container::Object(Object::new(), key));
                        continue;
                    } else {
                        return Err(self.error_at("Expected property name or '}' in JSON", self.pos));
                    }
                }
                Some(0x5B) => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(0x5D) {
                        self.pos += 1;
                        Value::Array(Vec::new())
                    } else {
                        open.push(Container::Array(Vec::new()));
                        continue;
                    }
                }
                Some(0x22) => Value::String(self.parse_string()?),
                Some(u) if u == u16::from(b'-') || (0x30..=0x39).contains(&u) => self.parse_number()?,
                Some(0x74) => self.parse_literal("true", Value::Bool(true))?,
                Some(0x66) => self.parse_literal("false", Value::Bool(false))?,
                Some(0x6E) => self.parse_literal("null", Value::Null)?,
                _ => return Err(self.unexpected(self.pos)),
            };
            // Hand the value to the innermost open container; close every container that ends here.
            loop {
                self.skip_whitespace();
                let Some(container) = open.last_mut() else {
                    return Ok(value);
                };
                let closed = match container {
                    Container::Array(items) => {
                        items.push(value);
                        match self.peek() {
                            Some(0x2C) => {
                                self.pos += 1;
                                self.skip_whitespace();
                                false
                            }
                            Some(0x5D) => {
                                self.pos += 1;
                                true
                            }
                            _ => return Err(self.error_at("Expected ',' or ']' after array element in JSON", self.pos)),
                        }
                    }
                    Container::Object(object, key) => {
                        object.insert(std::mem::take(key), value);
                        match self.peek() {
                            Some(0x2C) => {
                                self.pos += 1;
                                self.skip_whitespace();
                                if self.peek() != Some(0x22) {
                                    return Err(self.error_at("Expected double-quoted property name in JSON", self.pos));
                                }
                                *key = self.parse_property_name()?;
                                false
                            }
                            Some(0x7D) => {
                                self.pos += 1;
                                true
                            }
                            _ => {
                                return Err(self.error_at("Expected ',' or '}' after property value in JSON", self.pos))
                            }
                        }
                    }
                };
                if !closed {
                    break;
                }
                match open.pop() {
                    Some(container) => value = container.into_value(),
                    None => break,
                }
            }
        }
    }

    /// A property name and its colon, leaving the position at the start of the property value.
    fn parse_property_name(&mut self) -> Result<JsString, JsError> {
        let key = self.parse_string()?;
        self.skip_whitespace();
        if self.peek() != Some(0x3A) {
            return Err(self.error_at("Expected ':' after property name in JSON", self.pos));
        }
        self.pos += 1;
        self.skip_whitespace();
        Ok(key)
    }

    fn parse_literal(&mut self, word: &str, value: Value) -> Result<Value, JsError> {
        for (offset, b) in word.bytes().enumerate() {
            let pos = self.pos + offset;
            if self.source.get(pos) != Some(&u16::from(b)) {
                return Err(self.unexpected(pos));
            }
        }
        self.pos += word.len();
        Ok(value)
    }

    fn parse_string(&mut self) -> Result<JsString, JsError> {
        self.pos += 1;
        let mut out = JsString::new();
        loop {
            let Some(u) = self.peek() else {
                return Err(self.error_at("Unterminated string in JSON", self.pos));
            };
            match u {
                0x22 => {
                    self.pos += 1;
                    return Ok(out);
                }
                0x5C => {
                    self.pos += 1;
                    let Some(escape) = self.peek() else {
                        return Err(self.unexpected(self.pos));
                    };
                    let unit = match escape {
                        0x22 => 0x22,
                        0x5C => 0x5C,
                        0x2F => 0x2F,
                        0x62 => 0x08,
                        0x66 => 0x0C,
                        0x6E => 0x0A,
                        0x72 => 0x0D,
                        0x74 => 0x09,
                        0x75 => {
                            let mut value = 0u16;
                            for offset in 1..=4 {
                                let digit = self
                                    .source
                                    .get(self.pos + offset)
                                    .and_then(|&d| char::from_u32(u32::from(d)))
                                    .and_then(|c| c.to_digit(16));
                                match digit {
                                    Some(d) => value = value * 16 + d as u16,
                                    None => return Err(self.error_at("Bad Unicode escape in JSON", self.pos + offset)),
                                }
                            }
                            self.pos += 4;
                            value
                        }
                        // V8 classifies only Latin-1 characters as escape candidates; any other code unit after a
                        // backslash is reported as an unexpected token.
                        _ if escape > 0xFF => return Err(self.unexpected(self.pos)),
                        _ => return Err(self.error_at("Bad escaped character in JSON", self.pos)),
                    };
                    out.push(unit);
                    self.pos += 1;
                }
                _ if u < 0x20 => return Err(self.error_at("Bad control character in string literal in JSON", self.pos)),
                _ => {
                    out.push(u);
                    self.pos += 1;
                }
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(0x30..=0x39)) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn parse_number(&mut self) -> Result<Value, JsError> {
        let start = self.pos;
        if self.peek() == Some(u16::from(b'-')) {
            self.pos += 1;
            if !matches!(self.peek(), Some(0x30..=0x39)) {
                return Err(self.error_at("No number after minus sign in JSON", self.pos));
            }
        }
        if self.peek() == Some(0x30) {
            self.pos += 1;
            if matches!(self.peek(), Some(0x30..=0x39)) {
                return Err(self.unexpected(self.pos));
            }
        } else {
            self.digits();
        }
        if self.peek() == Some(u16::from(b'.')) {
            self.pos += 1;
            if self.digits() == 0 {
                return Err(self.error_at("Unterminated fractional number in JSON", self.pos));
            }
        }
        if matches!(self.peek(), Some(0x65 | 0x45)) {
            self.pos += 1;
            if matches!(self.peek(), Some(0x2B | 0x2D)) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(self.error_at("Exponent part is missing a number in JSON", self.pos));
            }
        }
        let text: String = self.source[start..self.pos]
            .iter()
            .map(|&u| char::from(u as u8))
            .collect();
        // The scanner has checked the JSON number grammar, which Rust's float parser accepts in full.
        Ok(Value::Number(text.parse::<f64>().unwrap_or(f64::NAN)))
    }
}

// ------------------------------------------------------------------------------------------------ JSON.stringify

/// `JSON.stringify` of a string: the string quoted and escaped, which cannot fail.
pub fn quote_string(s: &[u16]) -> JsString {
    let mut out = JsString::with_capacity(s.len() + 2);
    quote(s, &mut out);
    out
}

fn quote(s: &[u16], out: &mut JsString) {
    out.push(u16::from(b'"'));
    let mut i = 0;
    while i < s.len() {
        let u = s[i];
        match u {
            0x22 => out.extend(jsstring::from_str("\\\"")),
            0x5C => out.extend(jsstring::from_str("\\\\")),
            0x08 => out.extend(jsstring::from_str("\\b")),
            0x0C => out.extend(jsstring::from_str("\\f")),
            0x0A => out.extend(jsstring::from_str("\\n")),
            0x0D => out.extend(jsstring::from_str("\\r")),
            0x09 => out.extend(jsstring::from_str("\\t")),
            _ if u < 0x20 => out.extend(jsstring::from_str(&format!("\\u{u:04x}"))),
            _ if jsstring::is_high_surrogate(u) && s.get(i + 1).is_some_and(|&n| jsstring::is_low_surrogate(n)) => {
                out.push(u);
                out.push(s[i + 1]);
                i += 1;
            }
            _ if jsstring::is_high_surrogate(u) || jsstring::is_low_surrogate(u) => {
                out.extend(jsstring::from_str(&format!("\\u{u:04x}")));
            }
            _ => out.push(u),
        }
        i += 1;
    }
    out.push(u16::from(b'"'));
}

/// How deep `JSON.stringify` and `String()` of nested arrays may go before Node.js 22 runs out of stack in the
/// reference command (`RangeError: Maximum call stack size exceeded`), counted in nested arrays and objects.
const MAX_STRINGIFY_DEPTH: usize = 3660;
const MAX_JOIN_DEPTH: usize = 2620;

fn stack_overflow() -> JsError {
    JsError::new("RangeError", "Maximum call stack size exceeded")
}

/// An array or object being serialized, with the index of its next member.
enum Open<'a> {
    Array(&'a [Value], usize),
    Object(Vec<(&'a JsString, &'a Value)>, usize),
}

/// `JSON.stringify(value)`, with nested arrays and objects kept on an explicit stack.
pub fn stringify(value: &Value) -> Result<JsString, JsError> {
    let mut out = JsString::new();
    let mut open: Vec<Open<'_>> = Vec::new();
    write_or_open(value, &mut out, &mut open)?;
    loop {
        let next = match open.last_mut() {
            None => return Ok(out),
            Some(Open::Array(items, i)) => {
                let items: &[Value] = items;
                if *i == items.len() {
                    None
                } else {
                    if *i > 0 {
                        out.push(u16::from(b','));
                    }
                    *i += 1;
                    Some(&items[*i - 1])
                }
            }
            Some(Open::Object(properties, i)) => match properties.get(*i).copied() {
                None => None,
                Some((key, item)) => {
                    if *i > 0 {
                        out.push(u16::from(b','));
                    }
                    *i += 1;
                    quote(key, &mut out);
                    out.push(u16::from(b':'));
                    Some(item)
                }
            },
        };
        match next {
            Some(item) => write_or_open(item, &mut out, &mut open)?,
            None => {
                let closing = if matches!(open.pop(), Some(Open::Array(..))) {
                    b']'
                } else {
                    b'}'
                };
                out.push(u16::from(closing));
            }
        }
    }
}

/// Writes a primitive, or opens an array or object, refusing to go deeper than V8 does.
fn write_or_open<'a>(value: &'a Value, out: &mut JsString, open: &mut Vec<Open<'a>>) -> Result<(), JsError> {
    match value {
        Value::Null => out.extend(jsstring::from_str("null")),
        Value::Bool(b) => out.extend(jsstring::from_str(if *b { "true" } else { "false" })),
        Value::Number(n) if n.is_finite() => out.extend(jsstring::from_str(&number_to_string(*n))),
        Value::Number(_) => out.extend(jsstring::from_str("null")),
        Value::String(s) => quote(s, out),
        Value::Array(_) | Value::Object(_) if open.len() + 1 >= MAX_STRINGIFY_DEPTH => return Err(stack_overflow()),
        Value::Array(items) => {
            out.push(u16::from(b'['));
            open.push(Open::Array(items, 0));
        }
        Value::Object(object) => {
            out.push(u16::from(b'{'));
            open.push(Open::Object(object.properties(), 0));
        }
    }
    Ok(())
}

/// `JSON.stringify` of a value that may be absent, as a template literal shows it: "undefined" for an absent one.
pub fn stringify_or_undefined(value: Option<&Value>) -> Result<String, JsError> {
    match value {
        None => Ok("undefined".to_owned()),
        Some(v) => Ok(jsstring::to_well_formed(&stringify(v)?)),
    }
}

// ------------------------------------------------------------------------------------------------ conversions

/// `Number.prototype.toString()`: the shortest digits that round-trip, a tie between two such digit strings going to
/// the even one, in plain or exponential notation by the ECMAScript rules.
pub fn number_to_string(x: f64) -> String {
    if x.is_nan() {
        return "NaN".to_owned();
    }
    if x == 0.0 {
        return "0".to_owned();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if x < 0.0 {
        return format!("-{}", number_to_string(-x));
    }
    let (digits, n) = shortest_digits(x);
    let k = digits.len() as i32;
    if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign = if e >= 0 { '+' } else { '-' };
        if k == 1 {
            format!("{digits}e{sign}{}", e.abs())
        } else {
            format!("{}.{}e{sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    }
}

/// The shortest round-trip digits of a positive finite number and its decimal exponent `n` (value = 0.d * 10^n).
fn shortest_digits(x: f64) -> (String, i32) {
    // `{:e}` always writes a mantissa, `e` and an integer exponent, so the splits and the parse below succeed.
    let formatted = format!("{x:e}");
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((&formatted, "0"));
    let mut digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);
    // A tie: the exact value lies halfway between two candidates of this length; ECMAScript takes the even one.
    let exact = format!("{x:.800e}");
    let (exact_mantissa, _) = exact.split_once('e').unwrap_or((&exact, "0"));
    let exact_digits: String = exact_mantissa.chars().filter(|c| *c != '.').collect();
    let exact_digits = exact_digits.trim_end_matches('0');
    if exact_digits.len() == digits.len() + 1 && exact_digits.ends_with('5') {
        let last = digits.as_bytes()[digits.len() - 1] - b'0';
        if last % 2 == 1 {
            let lower = &exact_digits[..digits.len()];
            let candidate = if lower == digits {
                increment(lower)
            } else {
                lower.to_owned()
            };
            if candidate.len() == digits.len() {
                let reparsed = format!("{}.{}e{exponent}", &candidate[..1], &candidate[1..]).parse::<f64>();
                if reparsed == Ok(x) {
                    digits = candidate;
                }
            }
        }
    }
    let trimmed = digits.trim_end_matches('0');
    let digits = if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    };
    (digits, exponent + 1)
}

fn increment(digits: &str) -> String {
    let mut bytes = digits.as_bytes().to_vec();
    for b in bytes.iter_mut().rev() {
        if *b == b'9' {
            *b = b'0';
        } else {
            *b += 1;
            return String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    format!("1{}", String::from_utf8_lossy(&bytes))
}

/// The error of converting an object to a primitive when its own `toString` is not a function (JSON cannot hold
/// one): neither `toString` nor `valueOf` then yields a primitive.
fn no_primitive() -> JsError {
    JsError::type_error("Cannot convert object to primitive value")
}

/// `String(value)` for a value that may be absent (`undefined`). An object converts as `[object Object]`, unless it
/// has an own `toString` property, which makes the conversion throw. Arrays join their elements with commas (`null`
/// elements as empty strings), with nested arrays kept on an explicit stack.
pub fn to_js_string(value: Option<&Value>) -> Result<JsString, JsError> {
    let Some(Value::Array(items)) = value else {
        return primitive_to_string(value);
    };
    let mut out = JsString::new();
    let mut open: Vec<(&[Value], usize)> = vec![(items, 0)];
    while let Some((items, i)) = open.last_mut() {
        let items: &[Value] = items;
        let Some(item) = items.get(*i) else {
            open.pop();
            continue;
        };
        if *i > 0 {
            out.push(u16::from(b','));
        }
        *i += 1;
        match item {
            Value::Null => {}
            Value::Array(_) if open.len() + 1 >= MAX_JOIN_DEPTH => return Err(stack_overflow()),
            Value::Array(inner) => open.push((inner, 0)),
            other => out.extend(primitive_to_string(Some(other))?),
        }
    }
    Ok(out)
}

/// `String(value)` for anything but an array.
fn primitive_to_string(value: Option<&Value>) -> Result<JsString, JsError> {
    Ok(match value {
        None => jsstring::from_str("undefined"),
        Some(Value::Null) => jsstring::from_str("null"),
        Some(Value::Bool(b)) => jsstring::from_str(if *b { "true" } else { "false" }),
        Some(Value::Number(n)) => jsstring::from_str(&number_to_string(*n)),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(_)) => to_js_string(value)?,
        Some(Value::Object(object)) if object.has("toString") => return Err(no_primitive()),
        Some(Value::Object(_)) => jsstring::from_str("[object Object]"),
    })
}

/// JavaScript truthiness of a value that may be absent.
pub fn is_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => *n != 0.0 && !n.is_nan(),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

fn is_js_whitespace(u: u16) -> bool {
    matches!(
        u,
        0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x20 | 0xA0 | 0x1680 | 0x2000
            ..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000 | 0xFEFF
    )
}

/// `Number(string)`: the StringNumericLiteral grammar, `NaN` for anything else.
pub fn string_to_number(s: &[u16]) -> f64 {
    let start = s.iter().position(|&u| !is_js_whitespace(u)).unwrap_or(s.len());
    let end = s.iter().rposition(|&u| !is_js_whitespace(u)).map_or(start, |i| i + 1);
    let trimmed = &s[start..end.max(start)];
    if trimmed.is_empty() {
        return 0.0;
    }
    if !trimmed.iter().all(|&u| u < 0x80) {
        return f64::NAN;
    }
    let text: String = trimmed.iter().map(|&u| char::from(u as u8)).collect();
    let lower = text.to_ascii_lowercase();
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            if rest.is_empty() || !rest.chars().all(|c| c.is_digit(radix)) {
                return f64::NAN;
            }
            return radix_to_number(rest, radix);
        }
    }
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(&text);
    let negative = text.starts_with('-');
    if unsigned == "Infinity" {
        return if negative { f64::NEG_INFINITY } else { f64::INFINITY };
    }
    if !is_decimal_literal(unsigned) {
        return f64::NAN;
    }
    // The literal grammar was checked above; Rust's float parser accepts every such literal.
    text.parse::<f64>().unwrap_or(f64::NAN)
}

fn radix_to_number(digits: &str, radix: u32) -> f64 {
    let digits = digits.trim_start_matches('0');
    let bits_per_digit = match radix {
        16 => 4,
        8 => 3,
        _ => 1,
    };
    if digits.len() * bits_per_digit <= 128 {
        // The digits were checked by the caller and fit in 128 bits, so the conversion succeeds.
        return u128::from_str_radix(digits, radix).map_or(f64::NAN, |v| v as f64);
    }
    // Beyond 128 bits: the leading 128 bits with a sticky bit for the rest, rounded once to a double.
    let mut value: u128 = 0;
    let mut bits = 0usize;
    let mut sticky = false;
    let mut extra_bits = 0i32;
    for c in digits.chars() {
        let d = c.to_digit(radix).unwrap_or(0) as u128; // a checked digit
        if bits + bits_per_digit <= 124 {
            value = (value << bits_per_digit) | d;
            bits += bits_per_digit;
        } else {
            sticky |= d != 0;
            extra_bits += bits_per_digit as i32;
        }
    }
    let value = (value << 1) | u128::from(sticky);
    (value as f64) * 2f64.powi(extra_bits - 1)
}

fn is_decimal_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    let int_digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    i += int_digits;
    let mut frac_digits = 0;
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        frac_digits = bytes[i..].iter().take_while(|b| b.is_ascii_digit()).count();
        i += frac_digits;
    }
    if int_digits == 0 && frac_digits == 0 {
        return false;
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let exp_digits = bytes[i..].iter().take_while(|b| b.is_ascii_digit()).count();
        if exp_digits == 0 {
            return false;
        }
        i += exp_digits;
    }
    i == bytes.len()
}

/// `Number(value)` for a JSON value; an object converts through its string form, or throws as [`to_js_string`] does.
pub fn to_number(value: &Value) -> Result<f64, JsError> {
    Ok(match value {
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Number(n) => *n,
        Value::String(s) => string_to_number(s),
        Value::Array(_) | Value::Object(_) => string_to_number(&to_js_string(Some(value))?),
    })
}

/// ToUint8: the number truncated and taken modulo 2^8.
pub fn to_uint8(n: f64) -> u8 {
    if !n.is_finite() {
        return 0;
    }
    n.trunc().rem_euclid(256.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsstring::from_str;

    fn parse_str(s: &str) -> Result<Value, String> {
        parse(&from_str(s)).map_err(|e| e.to_string())
    }

    #[test]
    fn parses_values() {
        let v = parse_str(r#"{"b":1,"2":[true,null],"1":"\ud800x","b":-0.5e1}"#).expect("valid JSON");
        assert_eq!(
            jsstring::to_well_formed(&stringify(&v).expect("serializes")),
            r#"{"1":"\ud800x","2":[true,null],"b":-5}"#
        );
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse_str("").unwrap_err(), "SyntaxError: Unexpected end of JSON input");
        assert_eq!(
            parse_str("nope").unwrap_err(),
            "SyntaxError: Unexpected token 'o', \"nope\" is not valid JSON"
        );
        assert_eq!(
            parse_str("[1 2]").unwrap_err(),
            "SyntaxError: Expected ',' or ']' after array element in JSON at position 3 (line 1 column 4)"
        );
        assert_eq!(parse_str("NaN").unwrap_err(), "SyntaxError: \"NaN\" is not valid JSON");
        assert_eq!(
            parse_str("abcdefghijklmnopqrstuvwxyz").unwrap_err(),
            "SyntaxError: Unexpected token 'a', \"abcdefghij\"... is not valid JSON"
        );
    }

    #[test]
    fn deep_nesting() {
        let depth = 100_000;
        let text = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let v = parse_str(&text).expect("any depth parses");
        assert_eq!(to_js_string(Some(&v)), Err(stack_overflow()));
        assert_eq!(stringify(&v), Err(stack_overflow()));
        let shallow = parse_str(&format!("{}{}", "[".repeat(100), "]".repeat(100))).expect("valid JSON");
        assert_eq!(to_js_string(Some(&shallow)).map(|s| s.len()), Ok(0));
    }

    #[test]
    fn prints_numbers() {
        assert_eq!(number_to_string(1e21), "1e+21");
        assert_eq!(number_to_string(123456789012345680000.0), "123456789012345680000");
        assert_eq!(number_to_string(0.000001), "0.000001");
        assert_eq!(number_to_string(1e-7), "1e-7");
        assert_eq!(number_to_string(-1.5), "-1.5");
        assert_eq!(number_to_string(2.9802322387695312e-8), "2.9802322387695312e-8");
    }

    #[test]
    fn converts_values() {
        let v = parse_str(r#"[1,[null,"a"],{"x":1}]"#).expect("valid JSON");
        let text = to_js_string(Some(&v)).expect("converts");
        assert_eq!(jsstring::to_well_formed(&text), "1,,a,[object Object]");
        let w = parse_str(r#"[{"toString":1}]"#).expect("valid JSON");
        assert_eq!(to_js_string(Some(&w)), Err(no_primitive()));
        assert_eq!(string_to_number(&from_str(" 0x1F ")), 31.0);
        assert!(string_to_number(&from_str("1_0")).is_nan());
        assert_eq!(to_uint8(-1.0), 255);
        assert_eq!(to_uint8(300.7), 44);
    }
}
