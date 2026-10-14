// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The URL Standard's basic URL parser (a state machine over the code points of the input), the host parsers and the
//! URL, host, path and origin serializers.

use crate::encoding::{utf8_decode_without_bom, utf8_encode};
use crate::infra;
use crate::jsstring::{self, JsString};
use crate::miscellaneous::{
    contains_forbidden_host_code_point, contains_percent_encoded_byte, default_port, domain_parser, ends_in_a_number,
    is_invalid_url_code_point, is_normalized_windows_drive_letter_string, is_special_scheme,
    is_windows_drive_letter_code_points, is_windows_drive_letter_string, parse_ipv4_number, push_error,
    ValidationErrors,
};
use crate::percent_encoding::{
    is_c0_control_percent_encode, is_fragment_percent_encode, is_path_percent_encode, is_query_percent_encode,
    is_special_query_percent_encode, is_userinfo_percent_encode, percent_decode_string, percent_encode_bytes,
    utf8_percent_encode_code_point, utf8_percent_encode_string,
};

/// A host: a domain, an opaque host or the empty host (all strings), an IPv4 address or an IPv6 address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// A domain, an opaque host, or the empty host.
    Name(String),
    /// An IPv4 address.
    Ipv4(u32),
    /// An IPv6 address as its eight pieces.
    Ipv6([u16; 8]),
}

/// A URL path: a list of segments, or an opaque path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlPath {
    /// Path segments.
    Segments(Vec<String>),
    /// An opaque path.
    Opaque(String),
}

/// A URL record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlRecord {
    pub scheme: String,
    pub username: String,
    pub password: String,
    pub host: Option<Host>,
    pub port: Option<u16>,
    pub path: UrlPath,
    pub query: Option<String>,
    pub fragment: Option<String>,
}

impl UrlRecord {
    /// A record with every component empty or null, which the parser starts from.
    pub fn new() -> Self {
        UrlRecord {
            scheme: String::new(),
            username: String::new(),
            password: String::new(),
            host: None,
            port: None,
            path: UrlPath::Segments(Vec::new()),
            query: None,
            fragment: None,
        }
    }

    fn is_special(&self) -> bool {
        is_special_scheme(&self.scheme)
    }

    fn includes_credentials(&self) -> bool {
        !self.username.is_empty() || !self.password.is_empty()
    }

    /// The path segments; the parser only reaches the states that use them for a URL without an opaque path.
    fn segments(&mut self) -> &mut Vec<String> {
        if let UrlPath::Opaque(_) = self.path {
            self.path = UrlPath::Segments(Vec::new());
        }
        match &mut self.path {
            UrlPath::Segments(segments) => segments,
            UrlPath::Opaque(_) => unreachable!("the path was just made a list"),
        }
    }
}

impl Default for UrlRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// `true` when the URL has an opaque path.
pub fn has_an_opaque_path(url: &UrlRecord) -> bool {
    matches!(url.path, UrlPath::Opaque(_))
}

/// `true` when the URL cannot have a username, password or port: a null or empty host, or the file scheme.
pub fn cannot_have_a_username_password_port(url: &UrlRecord) -> bool {
    url.host.is_none() || matches!(&url.host, Some(Host::Name(n)) if n.is_empty()) || url.scheme == "file"
}

/// The states of the basic URL parser; the ones a state override can name are listed in [`StateOverride`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    SchemeStart,
    Scheme,
    NoScheme,
    SpecialRelativeOrAuthority,
    PathOrAuthority,
    Relative,
    RelativeSlash,
    SpecialAuthoritySlashes,
    SpecialAuthorityIgnoreSlashes,
    Authority,
    Host,
    Hostname,
    Port,
    File,
    FileSlash,
    FileHost,
    PathStart,
    Path,
    OpaquePath,
    Query,
    Fragment,
}

/// The state overrides the URL API setters use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateOverride {
    SchemeStart,
    Host,
    Hostname,
    Port,
    PathStart,
    Query,
    Fragment,
}

impl StateOverride {
    /// The override named as in the URL Standard ("scheme start", "host", ...).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "scheme start" => StateOverride::SchemeStart,
            "host" => StateOverride::Host,
            "hostname" => StateOverride::Hostname,
            "port" => StateOverride::Port,
            "path start" => StateOverride::PathStart,
            "query" => StateOverride::Query,
            "fragment" => StateOverride::Fragment,
            _ => return None,
        })
    }

    fn state(self) -> State {
        match self {
            StateOverride::SchemeStart => State::SchemeStart,
            StateOverride::Host => State::Host,
            StateOverride::Hostname => State::Hostname,
            StateOverride::Port => State::Port,
            StateOverride::PathStart => State::PathStart,
            StateOverride::Query => State::Query,
            StateOverride::Fragment => State::Fragment,
        }
    }
}

/// What one state step tells the parser loop.
enum Step {
    Continue,
    Terminate,
    Failure,
}

const fn cp(c: u8) -> Option<u32> {
    Some(c as u32)
}

fn is_single_dot(buffer: &str) -> bool {
    buffer == "." || buffer.eq_ignore_ascii_case("%2e")
}

fn is_double_dot(buffer: &str) -> bool {
    let b = buffer.to_ascii_lowercase();
    b == ".." || b == "%2e." || b == ".%2e" || b == "%2e%2e"
}

fn is_invalid_percent_encoding(input: &[u32], pointer: usize) -> bool {
    let hex = |i: usize| infra::is_ascii_hex(input.get(i).copied());
    input.get(pointer) == cp(b'%').as_ref() && (!hex(pointer + 1) || !hex(pointer + 2))
}

fn validate_url_units(input: &[u16], errors: &mut ValidationErrors<'_>) {
    if errors.is_none() {
        return;
    }
    let code_points = jsstring::code_points(input);
    if code_points.iter().any(|&c| is_invalid_url_code_point(c)) {
        push_error(errors, "invalid-URL-unit");
    }
    if (0..code_points.len()).any(|i| is_invalid_percent_encoding(&code_points, i)) {
        push_error(errors, "invalid-URL-unit");
    }
}

/// Parses an IPv4 address; `None` is failure.
pub fn parse_ipv4(input: &str, errors: &mut ValidationErrors<'_>) -> Option<u32> {
    let mut parts: Vec<&str> = input.split('.').collect();
    if parts.last() == Some(&"") {
        push_error(errors, "IPv4-empty-part");
        if parts.len() > 1 {
            parts.pop();
        }
    }
    if parts.len() > 4 {
        push_error(errors, "IPv4-too-many-parts");
        return None;
    }
    if parts.len() < 4 {
        push_error(errors, "IPv4-too-few-parts");
    }
    let mut numbers = Vec::with_capacity(parts.len());
    for part in parts {
        match parse_ipv4_number(part, errors) {
            Some(n) => numbers.push(n),
            None => {
                push_error(errors, "IPv4-non-numeric-part");
                return None;
            }
        }
    }
    if numbers.iter().any(|&n| n > 255) {
        push_error(errors, "IPv4-out-of-range-part");
    }
    let (&last, rest) = numbers.split_last()?;
    if rest.iter().any(|&n| n > 255) {
        return None;
    }
    if last >= 256u64.pow(5 - numbers.len() as u32) {
        return None;
    }
    let mut ipv4 = last;
    for (counter, &n) in rest.iter().enumerate() {
        ipv4 += n * 256u64.pow(3 - counter as u32);
    }
    // The range checks above keep the address below 2^32.
    u32::try_from(ipv4).ok()
}

/// Serializes an IPv4 address in dotted-decimal form.
pub fn serialize_ipv4(address: u32) -> String {
    let b = address.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Parses an IPv6 address (without the brackets); `None` is failure.
pub fn parse_ipv6(input: &[u16], errors: &mut ValidationErrors<'_>) -> Option<[u16; 8]> {
    let mut address = [0u32; 8];
    let mut piece_index = 0usize;
    let mut compress: Option<usize> = None;
    let mut pointer = 0usize;
    let input = jsstring::code_points(input);
    let at = |i: usize| input.get(i).copied();

    if at(pointer) == cp(b':') {
        if at(pointer + 1) != cp(b':') {
            push_error(errors, "IPv6-invalid-compression");
            return None;
        }
        pointer += 2;
        piece_index += 1;
        compress = Some(piece_index);
    }

    while pointer < input.len() {
        if piece_index == 8 {
            push_error(errors, "IPv6-too-many-pieces");
            return None;
        }
        if at(pointer) == cp(b':') {
            if compress.is_some() {
                push_error(errors, "IPv6-multiple-compression");
                return None;
            }
            pointer += 1;
            piece_index += 1;
            compress = Some(piece_index);
            continue;
        }

        let mut value = 0u32;
        let mut length = 0u32;
        while length < 4 && infra::is_ascii_hex(at(pointer)) {
            // The loop condition has checked that this is an ASCII hex digit.
            value = value * 0x10 + char::from_u32(input[pointer]).and_then(|c| c.to_digit(16)).unwrap_or(0);
            pointer += 1;
            length += 1;
        }

        if at(pointer) == cp(b'.') {
            if length == 0 {
                push_error(errors, "IPv4-in-IPv6-invalid-code-point");
                return None;
            }
            pointer -= length as usize;
            if piece_index > 6 {
                push_error(errors, "IPv4-in-IPv6-too-many-pieces");
                return None;
            }
            let mut numbers_seen = 0;
            while at(pointer).is_some() {
                let mut ipv4_piece: Option<u32> = None;
                if numbers_seen > 0 {
                    if at(pointer) == cp(b'.') && numbers_seen < 4 {
                        pointer += 1;
                    } else {
                        push_error(errors, "IPv4-in-IPv6-invalid-code-point");
                        return None;
                    }
                }
                if !infra::is_ascii_digit(at(pointer)) {
                    push_error(errors, "IPv4-in-IPv6-invalid-code-point");
                    return None;
                }
                while infra::is_ascii_digit(at(pointer)) {
                    let number = input[pointer] - 0x30;
                    ipv4_piece = match ipv4_piece {
                        None => Some(number),
                        Some(0) => {
                            push_error(errors, "IPv4-in-IPv6-invalid-code-point");
                            return None;
                        }
                        Some(piece) => Some(piece * 10 + number),
                    };
                    if ipv4_piece > Some(255) {
                        push_error(errors, "IPv4-in-IPv6-out-of-range-part");
                        return None;
                    }
                    pointer += 1;
                }
                address[piece_index] = address[piece_index] * 0x100 + ipv4_piece.unwrap_or(0);
                numbers_seen += 1;
                if numbers_seen == 2 || numbers_seen == 4 {
                    piece_index += 1;
                }
            }
            if numbers_seen != 4 {
                push_error(errors, "IPv4-in-IPv6-too-few-parts");
                return None;
            }
            break;
        } else if at(pointer) == cp(b':') {
            pointer += 1;
            if at(pointer).is_none() {
                push_error(errors, "IPv6-invalid-code-point");
                return None;
            }
        } else if at(pointer).is_some() {
            push_error(errors, "IPv6-invalid-code-point");
            return None;
        }

        if length > 1 && value < 0x10u32.pow(length - 1) {
            push_error(errors, "IPv6-piece-leading-zero");
        }
        address[piece_index] = value;
        piece_index += 1;
    }

    if let Some(compress) = compress {
        let mut swaps = piece_index - compress;
        piece_index = 7;
        while piece_index != 0 && swaps > 0 {
            address.swap(compress + swaps - 1, piece_index);
            piece_index -= 1;
            swaps -= 1;
        }
    } else if piece_index != 8 {
        push_error(errors, "IPv6-too-few-pieces");
        return None;
    }

    let mut pieces = [0u16; 8];
    for (piece, value) in pieces.iter_mut().zip(address) {
        *piece = value as u16;
    }
    Some(pieces)
}

fn find_compressed_piece_index(address: &[u16; 8]) -> Option<usize> {
    let mut longest_index = None;
    let mut longest_size = 1;
    let mut found_index = None;
    let mut found_size = 0;
    for (piece_index, &piece) in address.iter().enumerate() {
        if piece != 0 {
            if found_size > longest_size {
                longest_index = found_index;
                longest_size = found_size;
            }
            found_index = None;
            found_size = 0;
        } else {
            if found_index.is_none() {
                found_index = Some(piece_index);
            }
            found_size += 1;
        }
    }
    if found_size > longest_size {
        return found_index;
    }
    longest_index
}

/// Serializes an IPv6 address (without brackets), compressing the longest run of two or more zero pieces.
pub fn serialize_ipv6(address: &[u16; 8]) -> String {
    let mut output = String::new();
    let compress = find_compressed_piece_index(address);
    let mut ignore0 = false;
    for (piece_index, &piece) in address.iter().enumerate() {
        if ignore0 && piece == 0 {
            continue;
        }
        ignore0 = false;
        if compress == Some(piece_index) {
            output.push_str(if piece_index == 0 { "::" } else { ":" });
            ignore0 = true;
            continue;
        }
        output.push_str(&format!("{piece:x}"));
        if piece_index != 7 {
            output.push(':');
        }
    }
    output
}

/// The host parser: `None` is failure.
pub fn parse_host(input: &[u16], errors: &mut ValidationErrors<'_>, is_opaque: bool) -> Option<Host> {
    if input.first() == Some(&u16::from(b'[')) {
        if input.last() != Some(&u16::from(b']')) {
            push_error(errors, "IPv6-unclosed");
            return None;
        }
        let inner = if input.len() >= 2 {
            &input[1..input.len() - 1]
        } else {
            &[][..]
        };
        return parse_ipv6(inner, errors).map(Host::Ipv6);
    }
    if is_opaque {
        return parse_opaque_host(input, errors);
    }
    if errors.is_some() && contains_percent_encoded_byte(input) {
        push_error(errors, "domain-percent-encoded");
    }
    let domain = jsstring::from_str(&utf8_decode_without_bom(&percent_decode_string(input)));
    let ascii_domain = domain_parser(&domain, errors, false)?;
    if ends_in_a_number(&ascii_domain) {
        if !infra::is_ascii_string(&domain) {
            push_error(errors, "IPv4-non-ASCII-input");
        }
        return parse_ipv4(&ascii_domain, errors).map(Host::Ipv4);
    }
    Some(Host::Name(ascii_domain))
}

fn parse_opaque_host(input: &[u16], errors: &mut ValidationErrors<'_>) -> Option<Host> {
    if contains_forbidden_host_code_point(input) {
        push_error(errors, "host-invalid-code-point");
        return None;
    }
    validate_url_units(input, errors);
    Some(Host::Name(utf8_percent_encode_string(
        input,
        is_c0_control_percent_encode,
        false,
    )))
}

/// The host serializer.
pub fn serialize_host(host: &Host) -> String {
    match host {
        Host::Ipv4(address) => serialize_ipv4(*address),
        Host::Ipv6(address) => format!("[{}]", serialize_ipv6(address)),
        Host::Name(name) => name.clone(),
    }
}

/// Removes leading and trailing C0 controls and spaces (code units up to U+0020).
fn trim_control_chars(s: &[u16]) -> &[u16] {
    let start = s.iter().position(|&u| u > 0x20).unwrap_or(s.len());
    let end = s.iter().rposition(|&u| u > 0x20).map_or(start, |i| i + 1);
    &s[start..end.max(start)]
}

fn shorten_path(url: &mut UrlRecord) {
    let is_file = url.scheme == "file";
    let segments = url.segments();
    if segments.is_empty() {
        return;
    }
    if is_file && segments.len() == 1 && is_normalized_windows_drive_letter_string(&segments[0]) {
        return;
    }
    segments.pop();
}

fn starts_with_windows_drive_letter(input: &[u32], pointer: usize) -> bool {
    let length = input.len().saturating_sub(pointer);
    length >= 2
        && is_windows_drive_letter_code_points(input.get(pointer).copied(), input.get(pointer + 1).copied())
        && (length == 2 || matches!(input.get(pointer + 2), Some(0x2F | 0x5C | 0x3F | 0x23)))
}

/// Appends to a component that may be null, as JavaScript's `+=` does: a null component reads as "null".
fn append_nullable(component: &mut Option<String>, text: &str) {
    let current = component.get_or_insert_with(|| "null".to_owned());
    current.push_str(text);
}

struct Parser<'a, 'e> {
    pointer: isize,
    input: Vec<u32>,
    base: Option<&'a UrlRecord>,
    state_override: Option<StateOverride>,
    url: &'a mut UrlRecord,
    errors: ValidationErrors<'e>,
    state: State,
    buffer: JsString,
    at_sign_seen: bool,
    inside_brackets: bool,
    password_token_seen: bool,
}

impl Parser<'_, '_> {
    fn error(&mut self, name: &'static str) {
        push_error(&mut self.errors, name);
    }

    fn at(&self, index: isize) -> Option<u32> {
        usize::try_from(index).ok().and_then(|i| self.input.get(i).copied())
    }

    fn next(&self, offset: isize) -> Option<u32> {
        self.at(self.pointer + offset)
    }

    fn validate_url_unit(&mut self, c: u32) {
        if self.errors.is_none() {
            return;
        }
        if is_invalid_url_code_point(c) {
            self.error("invalid-URL-unit");
        }
        if is_invalid_percent_encoding(&self.input, self.pointer as usize) {
            self.error("invalid-URL-unit");
        }
    }

    fn special(&self) -> bool {
        self.url.is_special()
    }

    fn run(&mut self) -> bool {
        let len = self.input.len() as isize;
        while self.pointer <= len {
            let c = self.at(self.pointer);
            let step = match self.state {
                State::SchemeStart => self.scheme_start(c),
                State::Scheme => self.scheme(c),
                State::NoScheme => self.no_scheme(c),
                State::SpecialRelativeOrAuthority => self.special_relative_or_authority(c),
                State::PathOrAuthority => self.path_or_authority(c),
                State::Relative => self.relative(c),
                State::RelativeSlash => self.relative_slash(c),
                State::SpecialAuthoritySlashes => self.special_authority_slashes(c),
                State::SpecialAuthorityIgnoreSlashes => self.special_authority_ignore_slashes(c),
                State::Authority => self.authority(c),
                State::Host | State::Hostname => self.host(c),
                State::Port => self.port(c),
                State::File => self.file(c),
                State::FileSlash => self.file_slash(c),
                State::FileHost => self.file_host(c),
                State::PathStart => self.path_start(c),
                State::Path => self.path(c),
                State::OpaquePath => self.opaque_path(c),
                State::Query => self.query(c),
                State::Fragment => self.fragment(c),
            };
            match step {
                Step::Continue => {}
                Step::Terminate => return true,
                Step::Failure => return false,
            }
            self.pointer += 1;
        }
        true
    }

    fn push_buffer(&mut self, c: u32) {
        jsstring::push_code_point(&mut self.buffer, c);
    }

    fn buffer_string(&self) -> String {
        jsstring::to_well_formed(&self.buffer)
    }

    fn scheme_start(&mut self, c: Option<u32>) -> Step {
        if infra::is_ascii_alpha(c) {
            self.push_buffer(c.map_or(0, |c| c | 0x20));
            self.state = State::Scheme;
        } else if self.state_override.is_none() {
            self.state = State::NoScheme;
            self.pointer -= 1;
        } else {
            return Step::Failure;
        }
        Step::Continue
    }

    fn scheme(&mut self, c: Option<u32>) -> Step {
        if infra::is_ascii_alphanumeric(c) || matches!(c, Some(0x2B | 0x2D | 0x2E)) {
            let c = c.unwrap_or(0);
            self.push_buffer(if (0x41..=0x5A).contains(&c) { c | 0x20 } else { c });
        } else if c == cp(b':') {
            let buffer = self.buffer_string();
            if self.state_override.is_some() {
                if self.special() && !is_special_scheme(&buffer) {
                    return Step::Terminate;
                }
                if !self.special() && is_special_scheme(&buffer) {
                    return Step::Terminate;
                }
                if (self.url.includes_credentials() || self.url.port.is_some()) && buffer == "file" {
                    return Step::Terminate;
                }
                if self.url.scheme == "file" && matches!(&self.url.host, Some(Host::Name(n)) if n.is_empty()) {
                    return Step::Terminate;
                }
            }
            self.url.scheme = buffer;
            if self.state_override.is_some() {
                if let Some(Some(port)) = default_port(&self.url.scheme) {
                    if self.url.port == Some(port) {
                        self.url.port = None;
                    }
                }
                return Step::Terminate;
            }
            self.buffer.clear();
            if self.url.scheme == "file" {
                if self.next(1) != cp(b'/') || self.next(2) != cp(b'/') {
                    self.error("special-scheme-missing-following-solidus");
                }
                self.state = State::File;
            } else if self.special() && self.base.is_some_and(|b| b.scheme == self.url.scheme) {
                self.state = State::SpecialRelativeOrAuthority;
            } else if self.special() {
                self.state = State::SpecialAuthoritySlashes;
            } else if self.next(1) == cp(b'/') {
                self.state = State::PathOrAuthority;
                self.pointer += 1;
            } else {
                self.url.path = UrlPath::Opaque(String::new());
                self.state = State::OpaquePath;
            }
        } else if self.state_override.is_none() {
            self.buffer.clear();
            self.state = State::NoScheme;
            self.pointer = -1;
        } else {
            return Step::Failure;
        }
        Step::Continue
    }

    fn no_scheme(&mut self, c: Option<u32>) -> Step {
        let Some(base) = self.base else {
            self.error("missing-scheme-non-relative-URL");
            return Step::Failure;
        };
        if has_an_opaque_path(base) && c != cp(b'#') {
            self.error("missing-scheme-non-relative-URL");
            return Step::Failure;
        } else if has_an_opaque_path(base) {
            self.url.scheme = base.scheme.clone();
            self.url.path = base.path.clone();
            self.url.query = base.query.clone();
            self.url.fragment = Some(String::new());
            self.state = State::Fragment;
        } else if base.scheme == "file" {
            self.state = State::File;
            self.pointer -= 1;
        } else {
            self.state = State::Relative;
            self.pointer -= 1;
        }
        Step::Continue
    }

    fn special_relative_or_authority(&mut self, c: Option<u32>) -> Step {
        if c == cp(b'/') && self.next(1) == cp(b'/') {
            self.state = State::SpecialAuthorityIgnoreSlashes;
            self.pointer += 1;
        } else {
            self.error("special-scheme-missing-following-solidus");
            self.state = State::Relative;
            self.pointer -= 1;
        }
        Step::Continue
    }

    fn path_or_authority(&mut self, c: Option<u32>) -> Step {
        if c == cp(b'/') {
            self.state = State::Authority;
        } else {
            self.state = State::Path;
            self.pointer -= 1;
        }
        Step::Continue
    }

    fn copy_authority_from_base(&mut self, base: &UrlRecord) {
        self.url.username = base.username.clone();
        self.url.password = base.password.clone();
        self.url.host = base.host.clone();
        self.url.port = base.port;
    }

    fn relative(&mut self, c: Option<u32>) -> Step {
        let Some(base) = self.base else {
            return Step::Failure;
        };
        self.url.scheme = base.scheme.clone();
        if c == cp(b'/') {
            self.state = State::RelativeSlash;
        } else if self.special() && c == cp(b'\\') {
            self.error("invalid-reverse-solidus");
            self.state = State::RelativeSlash;
        } else {
            self.copy_authority_from_base(base);
            self.url.path = base.path.clone();
            self.url.query = base.query.clone();
            if c == cp(b'?') {
                self.url.query = Some(String::new());
                self.state = State::Query;
            } else if c == cp(b'#') {
                self.url.fragment = Some(String::new());
                self.state = State::Fragment;
            } else if c.is_some() {
                self.url.query = None;
                self.url.segments().pop();
                self.state = State::Path;
                self.pointer -= 1;
            }
        }
        Step::Continue
    }

    fn relative_slash(&mut self, c: Option<u32>) -> Step {
        if self.special() && (c == cp(b'/') || c == cp(b'\\')) {
            if c == cp(b'\\') {
                self.error("invalid-reverse-solidus");
            }
            self.state = State::SpecialAuthorityIgnoreSlashes;
        } else if c == cp(b'/') {
            self.state = State::Authority;
        } else {
            if let Some(base) = self.base {
                self.copy_authority_from_base(base);
            }
            self.state = State::Path;
            self.pointer -= 1;
        }
        Step::Continue
    }

    fn special_authority_slashes(&mut self, c: Option<u32>) -> Step {
        if c == cp(b'/') && self.next(1) == cp(b'/') {
            self.state = State::SpecialAuthorityIgnoreSlashes;
            self.pointer += 1;
        } else {
            self.error("special-scheme-missing-following-solidus");
            self.state = State::SpecialAuthorityIgnoreSlashes;
            self.pointer -= 1;
        }
        Step::Continue
    }

    fn special_authority_ignore_slashes(&mut self, c: Option<u32>) -> Step {
        if c != cp(b'/') && c != cp(b'\\') {
            self.state = State::Authority;
            self.pointer -= 1;
        } else {
            self.error("special-scheme-missing-following-solidus");
        }
        Step::Continue
    }

    fn ends_authority(&self, c: Option<u32>) -> bool {
        c.is_none() || matches!(c, Some(0x2F | 0x3F | 0x23)) || (self.special() && c == cp(b'\\'))
    }

    fn authority(&mut self, c: Option<u32>) -> Step {
        if c == cp(b'@') {
            self.error("invalid-credentials");
            if self.at_sign_seen {
                let mut prefixed = jsstring::from_str("%40");
                prefixed.append(&mut self.buffer);
                self.buffer = prefixed;
            }
            self.at_sign_seen = true;
            for code_point in jsstring::code_points(&self.buffer) {
                if code_point == u32::from(b':') && !self.password_token_seen {
                    self.password_token_seen = true;
                    continue;
                }
                let encoded = utf8_percent_encode_code_point(code_point, is_userinfo_percent_encode);
                if self.password_token_seen {
                    self.url.password.push_str(&encoded);
                } else {
                    self.url.username.push_str(&encoded);
                }
            }
            self.buffer.clear();
        } else if self.ends_authority(c) {
            if self.at_sign_seen && self.buffer.is_empty() {
                self.error("host-missing");
                return Step::Failure;
            }
            self.pointer -= jsstring::code_points(&self.buffer).len() as isize + 1;
            self.buffer.clear();
            self.state = State::Host;
        } else if let Some(c) = c {
            self.push_buffer(c);
        }
        Step::Continue
    }

    fn host(&mut self, c: Option<u32>) -> Step {
        if self.state_override.is_some() && self.url.scheme == "file" {
            self.pointer -= 1;
            self.state = State::FileHost;
        } else if c == cp(b':') && !self.inside_brackets {
            if self.buffer.is_empty() {
                self.error("host-missing");
                return Step::Failure;
            }
            if self.state_override == Some(StateOverride::Hostname) {
                return Step::Failure;
            }
            let opaque = !self.special();
            let Some(host) = parse_host(&self.buffer, &mut self.errors, opaque) else {
                return Step::Failure;
            };
            self.url.host = Some(host);
            self.buffer.clear();
            self.state = State::Port;
        } else if self.ends_authority(c) {
            self.pointer -= 1;
            if self.special() && self.buffer.is_empty() {
                self.error("host-missing");
                return Step::Failure;
            } else if self.state_override.is_some()
                && self.buffer.is_empty()
                && (self.url.includes_credentials() || self.url.port.is_some())
            {
                return Step::Failure;
            }
            let opaque = !self.special();
            let Some(host) = parse_host(&self.buffer, &mut self.errors, opaque) else {
                return Step::Failure;
            };
            self.url.host = Some(host);
            self.buffer.clear();
            self.state = State::PathStart;
            if self.state_override.is_some() {
                return Step::Terminate;
            }
        } else if let Some(c) = c {
            if c == u32::from(b'[') {
                self.inside_brackets = true;
            } else if c == u32::from(b']') {
                self.inside_brackets = false;
            }
            self.push_buffer(c);
        }
        Step::Continue
    }

    fn port(&mut self, c: Option<u32>) -> Step {
        if infra::is_ascii_digit(c) {
            self.push_buffer(c.unwrap_or(0));
        } else if self.ends_authority(c) || self.state_override.is_some() {
            if !self.buffer.is_empty() {
                // parseInt of a run of ASCII digits; anything above 65535 fails, however long. Only zeros trim to
                // the empty string, which is port 0.
                let digits = self.buffer_string();
                let port = digits.trim_start_matches('0');
                let value = if port.len() > 5 {
                    u32::MAX
                } else {
                    port.parse::<u32>().unwrap_or(0)
                };
                if value > 65535 {
                    self.error("port-out-of-range");
                    return Step::Failure;
                }
                let value = value as u16;
                self.url.port = if default_port(&self.url.scheme) == Some(Some(value)) {
                    None
                } else {
                    Some(value)
                };
                self.buffer.clear();
                if self.state_override.is_some() {
                    return Step::Terminate;
                }
            }
            if self.state_override.is_some() {
                return Step::Failure;
            }
            self.state = State::PathStart;
            self.pointer -= 1;
        } else {
            self.error("port-invalid");
            return Step::Failure;
        }
        Step::Continue
    }

    fn file(&mut self, c: Option<u32>) -> Step {
        self.url.scheme = "file".to_owned();
        self.url.host = Some(Host::Name(String::new()));
        if c == cp(b'/') || c == cp(b'\\') {
            if c == cp(b'\\') {
                self.error("invalid-reverse-solidus");
            }
            self.state = State::FileSlash;
        } else if let Some(base) = self.base.filter(|b| b.scheme == "file") {
            self.url.host = base.host.clone();
            self.url.path = base.path.clone();
            self.url.query = base.query.clone();
            if c == cp(b'?') {
                self.url.query = Some(String::new());
                self.state = State::Query;
            } else if c == cp(b'#') {
                self.url.fragment = Some(String::new());
                self.state = State::Fragment;
            } else if c.is_some() {
                self.url.query = None;
                if !starts_with_windows_drive_letter(&self.input, self.pointer as usize) {
                    shorten_path(self.url);
                } else {
                    self.error("file-invalid-Windows-drive-letter");
                    self.url.path = UrlPath::Segments(Vec::new());
                }
                self.state = State::Path;
                self.pointer -= 1;
            }
        } else {
            self.state = State::Path;
            self.pointer -= 1;
        }
        Step::Continue
    }

    fn file_slash(&mut self, c: Option<u32>) -> Step {
        if c == cp(b'/') || c == cp(b'\\') {
            if c == cp(b'\\') {
                self.error("invalid-reverse-solidus");
            }
            self.state = State::FileHost;
        } else {
            if let Some(base) = self.base.filter(|b| b.scheme == "file") {
                let first = match &base.path {
                    UrlPath::Segments(segments) => segments.first().cloned(),
                    UrlPath::Opaque(_) => None,
                };
                if !starts_with_windows_drive_letter(&self.input, self.pointer as usize) {
                    if let Some(first) = first.filter(|f| is_normalized_windows_drive_letter_string(f)) {
                        self.url.segments().push(first);
                    }
                }
                self.url.host = base.host.clone();
            }
            self.state = State::Path;
            self.pointer -= 1;
        }
        Step::Continue
    }

    fn file_host(&mut self, c: Option<u32>) -> Step {
        if c.is_none() || matches!(c, Some(0x2F | 0x5C | 0x3F | 0x23)) {
            self.pointer -= 1;
            if self.state_override.is_none() && is_windows_drive_letter_string(&self.buffer) {
                self.error("file-invalid-Windows-drive-letter-host");
                self.state = State::Path;
            } else if self.buffer.is_empty() {
                self.url.host = Some(Host::Name(String::new()));
                if self.state_override.is_some() {
                    return Step::Terminate;
                }
                self.state = State::PathStart;
            } else {
                let opaque = !self.special();
                let Some(mut host) = parse_host(&self.buffer, &mut self.errors, opaque) else {
                    return Step::Failure;
                };
                if host == Host::Name("localhost".to_owned()) {
                    host = Host::Name(String::new());
                }
                self.url.host = Some(host);
                if self.state_override.is_some() {
                    return Step::Terminate;
                }
                self.buffer.clear();
                self.state = State::PathStart;
            }
        } else if let Some(c) = c {
            self.push_buffer(c);
        }
        Step::Continue
    }

    fn path_start(&mut self, c: Option<u32>) -> Step {
        if self.special() {
            if c == cp(b'\\') {
                self.error("invalid-reverse-solidus");
            }
            self.state = State::Path;
            if c != cp(b'/') && c != cp(b'\\') {
                self.pointer -= 1;
            }
        } else if self.state_override.is_none() && c == cp(b'?') {
            self.url.query = Some(String::new());
            self.state = State::Query;
        } else if self.state_override.is_none() && c == cp(b'#') {
            self.url.fragment = Some(String::new());
            self.state = State::Fragment;
        } else if c.is_some() {
            self.state = State::Path;
            if c != cp(b'/') {
                self.pointer -= 1;
            }
        } else if self.state_override.is_some() && self.url.host.is_none() {
            self.url.segments().push(String::new());
        }
        Step::Continue
    }

    fn path(&mut self, c: Option<u32>) -> Step {
        let special = self.special();
        let slash = c == cp(b'/') || (special && c == cp(b'\\'));
        if c.is_none() || slash || (self.state_override.is_none() && (c == cp(b'?') || c == cp(b'#'))) {
            if special && c == cp(b'\\') {
                self.error("invalid-reverse-solidus");
            }
            let buffer = self.buffer_string();
            if is_double_dot(&buffer) {
                shorten_path(self.url);
                if !slash {
                    self.url.segments().push(String::new());
                }
            } else if is_single_dot(&buffer) && !slash {
                self.url.segments().push(String::new());
            } else if !is_single_dot(&buffer) {
                let mut segment = buffer;
                if self.url.scheme == "file"
                    && self.url.segments().is_empty()
                    && is_windows_drive_letter_string(&self.buffer)
                {
                    segment = format!("{}:", &segment[..1]);
                }
                self.url.segments().push(segment);
            }
            self.buffer.clear();
            if c == cp(b'?') {
                self.url.query = Some(String::new());
                self.state = State::Query;
            }
            if c == cp(b'#') {
                self.url.fragment = Some(String::new());
                self.state = State::Fragment;
            }
        } else if let Some(c) = c {
            self.validate_url_unit(c);
            let encoded = utf8_percent_encode_code_point(c, is_path_percent_encode);
            self.buffer.extend(encoded.encode_utf16());
        }
        Step::Continue
    }

    fn opaque_path(&mut self, c: Option<u32>) -> Step {
        if c == cp(b'?') {
            self.url.query = Some(String::new());
            self.state = State::Query;
        } else if c == cp(b'#') {
            self.url.fragment = Some(String::new());
            self.state = State::Fragment;
        } else if c == cp(b' ') {
            self.error("invalid-URL-unit");
            let remaining = self.next(1);
            let text = if remaining == cp(b'?') || remaining == cp(b'#') {
                "%20"
            } else {
                " "
            };
            if let UrlPath::Opaque(path) = &mut self.url.path {
                path.push_str(text);
            }
        } else if let Some(c) = c {
            self.validate_url_unit(c);
            let encoded = utf8_percent_encode_code_point(c, is_c0_control_percent_encode);
            if let UrlPath::Opaque(path) = &mut self.url.path {
                path.push_str(&encoded);
            }
        }
        Step::Continue
    }

    fn query(&mut self, c: Option<u32>) -> Step {
        if (self.state_override.is_none() && c == cp(b'#')) || c.is_none() {
            let set = if self.special() {
                is_special_query_percent_encode
            } else {
                is_query_percent_encode
            };
            let encoded = percent_encode_bytes(&utf8_encode(&self.buffer), set, false);
            append_nullable(&mut self.url.query, &encoded);
            self.buffer.clear();
            if c == cp(b'#') {
                self.url.fragment = Some(String::new());
                self.state = State::Fragment;
            }
        } else if let Some(c) = c {
            self.validate_url_unit(c);
            self.push_buffer(c);
        }
        Step::Continue
    }

    fn fragment(&mut self, c: Option<u32>) -> Step {
        if let Some(c) = c {
            self.validate_url_unit(c);
            let encoded = utf8_percent_encode_code_point(c, is_fragment_percent_encode);
            append_nullable(&mut self.url.fragment, &encoded);
        }
        Step::Continue
    }
}

/// The options of the basic URL parser.
#[derive(Default)]
pub struct ParseOptions<'a> {
    /// The base URL, if any.
    pub base: Option<&'a UrlRecord>,
    /// The URL to modify, with the state to start in.
    pub url: Option<(&'a mut UrlRecord, StateOverride)>,
}

/// The basic URL parser. Without `options.url` it returns the new record, or `None` on failure; with it, it modifies
/// that record in place (also when it fails) and returns a copy of it, or `None` on failure. Validation errors are
/// collected into `errors` when given.
pub fn basic_url_parse_with_errors(
    input: &[u16],
    options: ParseOptions<'_>,
    errors: ValidationErrors<'_>,
) -> Option<UrlRecord> {
    let mut errors = errors;
    let mut fresh = UrlRecord::new();
    let (url, state_override) = match options.url {
        Some((url, state_override)) => (url, Some(state_override)),
        None => (&mut fresh, None),
    };
    let mut text: &[u16] = input;
    if state_override.is_none() {
        let trimmed = trim_control_chars(text);
        if trimmed.len() != text.len() {
            push_error(&mut errors, "invalid-URL-unit");
        }
        text = trimmed;
    }
    let without_tabs: JsString = text
        .iter()
        .copied()
        .filter(|&u| u != 0x09 && u != 0x0A && u != 0x0D)
        .collect();
    if without_tabs.len() != text.len() {
        push_error(&mut errors, "invalid-URL-unit");
    }
    let mut parser = Parser {
        pointer: 0,
        input: jsstring::code_points(&without_tabs),
        base: options.base,
        state_override,
        url,
        errors,
        state: state_override.map_or(State::SchemeStart, StateOverride::state),
        buffer: JsString::new(),
        at_sign_seen: false,
        inside_brackets: false,
        password_token_seen: false,
    };
    if parser.run() {
        Some(parser.url.clone())
    } else {
        None
    }
}

/// The basic URL parser without validation errors.
pub fn basic_url_parse(input: &[u16], options: ParseOptions<'_>) -> Option<UrlRecord> {
    basic_url_parse_with_errors(input, options, None)
}

/// Parses `input` against an optional base, as the URL parser does for the URL API.
pub fn parse_url(input: &[u16], base: Option<&UrlRecord>) -> Option<UrlRecord> {
    basic_url_parse(input, ParseOptions { base, url: None })
}

/// The URL serializer.
pub fn serialize_url(url: &UrlRecord, exclude_fragment: bool) -> String {
    let mut output = format!("{}:", url.scheme);
    if let Some(host) = &url.host {
        output.push_str("//");
        if url.includes_credentials() {
            output.push_str(&url.username);
            if !url.password.is_empty() {
                output.push(':');
                output.push_str(&url.password);
            }
            output.push('@');
        }
        output.push_str(&serialize_host(host));
        if let Some(port) = url.port {
            output.push_str(&format!(":{port}"));
        }
    }
    if url.host.is_none() {
        if let UrlPath::Segments(segments) = &url.path {
            if segments.len() > 1 && segments[0].is_empty() {
                output.push_str("/.");
            }
        }
    }
    output.push_str(&serialize_path(url));
    if let Some(query) = &url.query {
        output.push('?');
        output.push_str(query);
    }
    if !exclude_fragment {
        if let Some(fragment) = &url.fragment {
            output.push('#');
            output.push_str(fragment);
        }
    }
    output
}

/// The URL path serializer.
pub fn serialize_path(url: &UrlRecord) -> String {
    match &url.path {
        UrlPath::Opaque(path) => path.clone(),
        UrlPath::Segments(segments) => segments.iter().map(|s| format!("/{s}")).collect(),
    }
}

/// The serialization of the URL's origin: a tuple origin for the special schemes other than file, the origin of the
/// URL in the path for blob, and "null" (an opaque origin) otherwise.
pub fn serialize_url_origin(url: &UrlRecord) -> String {
    match url.scheme.as_str() {
        "blob" => match parse_url(&jsstring::from_str(&serialize_path(url)), None) {
            Some(path_url) if path_url.scheme == "http" || path_url.scheme == "https" => {
                serialize_url_origin(&path_url)
            }
            _ => "null".to_owned(),
        },
        "ftp" | "http" | "https" | "ws" | "wss" => {
            let mut result = format!("{}://", url.scheme);
            if let Some(host) = &url.host {
                result.push_str(&serialize_host(host));
            }
            if let Some(port) = url.port {
                result.push_str(&format!(":{port}"));
            }
            result
        }
        _ => "null".to_owned(),
    }
}

/// Sets the URL's username, percent-encoded with the userinfo set.
pub fn set_the_username(url: &mut UrlRecord, username: &[u16]) {
    url.username = utf8_percent_encode_string(username, is_userinfo_percent_encode, false);
}

/// Sets the URL's password, percent-encoded with the userinfo set.
pub fn set_the_password(url: &mut UrlRecord, password: &[u16]) {
    url.password = utf8_percent_encode_string(password, is_userinfo_percent_encode, false);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsstring::from_str;

    fn href(input: &str, base: Option<&str>) -> Option<String> {
        let base = base.map(|b| parse_url(&from_str(b), None).expect("base parses"));
        parse_url(&from_str(input), base.as_ref()).map(|u| serialize_url(&u, false))
    }

    #[test]
    fn parses_and_resolves() {
        assert_eq!(
            href("HTTP://EX.com:80/a/./b/../c?q#f", None).as_deref(),
            Some("http://ex.com/a/c?q#f")
        );
        assert_eq!(href("../x", Some("http://h/a/b/c")).as_deref(), Some("http://h/a/x"));
        assert_eq!(href("\\\\x\\y", Some("http://h/")).as_deref(), Some("http://x/y"));
        assert_eq!(href("file:c|/a/../..", None).as_deref(), Some("file:///c:/"));
        assert_eq!(href("mailto: a ?b", None).as_deref(), Some("mailto: a%20?b"));
        assert_eq!(href("x", None), None);
        assert_eq!(href("http://a:65536", None), None);
    }

    #[test]
    fn hosts() {
        assert_eq!(href("http://0x7f.1/", None).as_deref(), Some("http://127.0.0.1/"));
        assert_eq!(
            href("http://[0:0:0:0:0:ffff:1.2.3.4]/", None).as_deref(),
            Some("http://[::ffff:102:304]/")
        );
        assert_eq!(href("http://1.2.3.4.5/", None), None);
        assert_eq!(href("sc://%C3%A9/", None).as_deref(), Some("sc://%C3%A9/"));
    }

    #[test]
    fn collects_validation_errors() {
        let mut errors = Vec::new();
        let url = basic_url_parse_with_errors(&from_str(" http:\\\\a\t"), ParseOptions::default(), Some(&mut errors));
        assert!(url.is_some());
        assert_eq!(
            errors,
            vec![
                "invalid-URL-unit",
                "special-scheme-missing-following-solidus",
                "special-scheme-missing-following-solidus",
                "special-scheme-missing-following-solidus"
            ]
        );
    }

    #[test]
    fn state_override_appends_to_null_query() {
        let mut url = parse_url(&from_str("http://h/p"), None).expect("parses");
        let result = basic_url_parse(
            &from_str("a b"),
            ParseOptions {
                base: None,
                url: Some((&mut url, StateOverride::Query)),
            },
        );
        assert_eq!(result.and_then(|u| u.query).as_deref(), Some("nulla%20b"));
    }
}
