// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! Shared URL Standard definitions: special schemes, URL code points, forbidden host and domain code points, the
//! domain parser and IPv4 number parsing.

use crate::idna;
use crate::infra;
use crate::jsstring::{self, JsString};

/// The validation errors of one parse, by their URL Standard names; `None` when they are not collected.
pub type ValidationErrors<'a> = Option<&'a mut Vec<&'static str>>;

/// Records a validation error when errors are collected.
pub fn push_error(errors: &mut ValidationErrors<'_>, name: &'static str) {
    if let Some(list) = errors.as_deref_mut() {
        list.push(name);
    }
}

/// The default port of a special scheme: `Some(None)` for `file`, which has none; `None` for other schemes.
pub fn default_port(scheme: &str) -> Option<Option<u16>> {
    match scheme {
        "ftp" => Some(Some(21)),
        "file" => Some(None),
        "http" | "ws" => Some(Some(80)),
        "https" | "wss" => Some(Some(443)),
        _ => None,
    }
}

/// `true` for the special schemes ftp, file, http, https, ws and wss.
pub fn is_special_scheme(scheme: &str) -> bool {
    default_port(&scheme.to_ascii_lowercase()).is_some()
}

/// A special scheme other than file.
pub fn is_special_scheme_except_file(scheme: &str) -> bool {
    is_special_scheme(scheme) && !scheme.eq_ignore_ascii_case("file")
}

const URL_CODE_POINTS: &[u8] = b"!$&'()*+,-./:;=?@_~";

/// A URL code point.
pub fn is_url_code_point(c: u32) -> bool {
    infra::is_ascii_alphanumeric(Some(c))
        || (c < 0x80 && URL_CODE_POINTS.contains(&(c as u8)))
        || ((0xA0..=0x10FFFD).contains(&c) && !(0xD800..=0xDFFF).contains(&c) && !infra::is_noncharacter(c))
}

/// Neither a URL code point nor `%`.
pub fn is_invalid_url_code_point(c: u32) -> bool {
    !is_url_code_point(c) && c != u32::from(b'%')
}

/// A forbidden host code point.
pub fn is_forbidden_host_code_point(c: u32) -> bool {
    matches!(c, 0x00 | 0x09 | 0x0A | 0x0D | 0x20) || (c < 0x80 && b"#/:<>?@[\\]^|".contains(&(c as u8)))
}

/// A forbidden domain code point: a forbidden host code point, a C0 control, `%` or U+007F DELETE.
pub fn is_forbidden_domain_code_point(c: u32) -> bool {
    is_forbidden_host_code_point(c) || c <= 0x1F || c == u32::from(b'%') || c == 0x7F
}

/// `true` when a percent-encoded byte (`%` and two hex digits) starts at `index`.
pub fn is_percent_encoded_byte_at(input: &[u16], index: usize) -> bool {
    let hex = |i: usize| infra::is_ascii_hex(input.get(i).map(|&u| u32::from(u)));
    index + 2 < input.len() && input[index] == u16::from(b'%') && hex(index + 1) && hex(index + 2)
}

/// `true` when the string holds a percent-encoded byte anywhere.
pub fn contains_percent_encoded_byte(input: &[u16]) -> bool {
    (0..input.len()).any(|i| {
        let hex = |j: usize| infra::is_ascii_hex(input.get(j).map(|&u| u32::from(u)));
        input[i] == u16::from(b'%') && hex(i + 1) && hex(i + 2)
    })
}

/// `true` when a code point of the string is a forbidden host code point.
pub fn contains_forbidden_host_code_point(input: &[u16]) -> bool {
    jsstring::code_points(input)
        .into_iter()
        .any(is_forbidden_host_code_point)
}

fn contains_forbidden_domain_code_point(input: &str) -> bool {
    input.chars().any(|c| is_forbidden_domain_code_point(u32::from(c)))
}

fn domain_to_ascii(domain: &[u16], be_strict: bool) -> Option<String> {
    idna::to_ascii(
        domain,
        &idna::Options {
            check_hyphens: be_strict,
            check_bidi: true,
            check_joiners: true,
            use_std3_ascii_rules: be_strict,
            transitional_processing: false,
            verify_dns_length: be_strict,
            ignore_invalid_punycode: false,
        },
    )
}

/// Parses an IPv4 number: decimal, octal with a leading `0`, or hex with `0x`. The value saturates far above any
/// valid part. `None` is failure.
pub fn parse_ipv4_number(input: &str, errors: &mut ValidationErrors<'_>) -> Option<u64> {
    if input.is_empty() {
        return None;
    }
    let bytes = input.as_bytes();
    let (digits, radix, prefixed) = if bytes.len() >= 2 && bytes[0] == b'0' && bytes[1].eq_ignore_ascii_case(&b'x') {
        (&input[2..], 16, true)
    } else if bytes.len() >= 2 && bytes[0] == b'0' {
        (&input[1..], 8, true)
    } else {
        (input, 10, false)
    };
    if digits.is_empty() {
        push_error(errors, "IPv4-non-decimal-part");
        return Some(0);
    }
    if !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    if prefixed {
        push_error(errors, "IPv4-non-decimal-part");
    }
    // Every character was checked to be a digit of the radix above.
    Some(digits.chars().fold(0u64, |acc, c| {
        acc.saturating_mul(u64::from(radix))
            .saturating_add(u64::from(c.to_digit(radix).unwrap_or(0)))
    }))
}

/// `true` when the last label of a domain (ignoring one trailing dot) is a number, so the host is an IPv4 address.
pub fn ends_in_a_number(input: &str) -> bool {
    let mut parts: Vec<&str> = input.split('.').collect();
    if parts.last() == Some(&"") {
        if parts.len() == 1 {
            return false;
        }
        parts.pop();
    }
    let last = parts.last().copied().unwrap_or("");
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    parse_ipv4_number(last, &mut None).is_some()
}

/// The domain parser (domain to ASCII). A domain-to-ASCII validation error is reported whenever strict processing
/// fails, even when the lenient processing used for parsing succeeds; the strict pass runs only when it matters.
pub fn domain_parser(domain: &[u16], errors: &mut ValidationErrors<'_>, be_strict: bool) -> Option<String> {
    if be_strict || errors.is_some() {
        let strict = domain_to_ascii(domain, true);
        if strict.is_none() {
            push_error(errors, "domain-to-ASCII");
        }
        if be_strict {
            return strict;
        }
    }
    let result = if infra::is_ascii_string(domain) {
        // For web compatibility an ASCII domain is lower-cased whatever ToASCII says.
        jsstring::to_string(&jsstring::ascii_lowercase(domain))?
    } else {
        domain_to_ascii(domain, false)?
    };
    if result.is_empty() || contains_forbidden_domain_code_point(&result) {
        return None;
    }
    Some(result)
}

/// A Windows drive letter: an ASCII letter followed by `:` or `|`.
pub fn is_windows_drive_letter_code_points(cp1: Option<u32>, cp2: Option<u32>) -> bool {
    infra::is_ascii_alpha(cp1) && matches!(cp2, Some(0x3A | 0x7C))
}

/// A two-unit string that is a Windows drive letter.
pub fn is_windows_drive_letter_string(s: &[u16]) -> bool {
    s.len() == 2
        && infra::is_ascii_alpha(Some(jsstring::code_point_at(s, 0)))
        && (s[1] == u16::from(b':') || s[1] == u16::from(b'|'))
}

/// A normalized Windows drive letter: an ASCII letter followed by `:`.
pub fn is_normalized_windows_drive_letter_string(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// The string `s` as a JavaScript string (a convenience for ASCII constants).
pub fn js(s: &str) -> JsString {
    jsstring::from_str(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_numbers() {
        assert_eq!(parse_ipv4_number("0x", &mut None), Some(0));
        assert_eq!(parse_ipv4_number("010", &mut None), Some(8));
        assert_eq!(parse_ipv4_number("0x1F", &mut None), Some(31));
        assert_eq!(parse_ipv4_number("09", &mut None), None);
        assert!(ends_in_a_number("a.0x10."));
        assert!(!ends_in_a_number("a.b"));
    }

    #[test]
    fn domains() {
        assert_eq!(
            domain_parser(&js("EXAMPLE.com"), &mut None, false).as_deref(),
            Some("example.com")
        );
        let mut list = Vec::new();
        assert_eq!(
            domain_parser(&js("a_b"), &mut Some(&mut list), false).as_deref(),
            Some("a_b")
        );
        assert_eq!(list, vec!["domain-to-ASCII"]);
        assert_eq!(domain_parser(&js("a%b"), &mut None, false), None);
    }
}
