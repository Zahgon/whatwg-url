// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! JavaScript strings: sequences of UTF-16 code units that may hold lone surrogates.
//!
//! The library works on JavaScript strings, so lengths, indices, comparisons and iteration follow UTF-16 code units,
//! and code point iteration (`Array.from(string)`, `for (const c of string)`) yields a lone surrogate as a code point
//! of its own.

use std::cmp::Ordering;

/// A JavaScript string.
pub type JsString = Vec<u16>;

/// The JavaScript string holding the UTF-16 encoding of `s`.
pub fn from_str(s: &str) -> JsString {
    s.encode_utf16().collect()
}

/// `true` for a UTF-16 high (leading) surrogate code unit.
pub fn is_high_surrogate(unit: u16) -> bool {
    (0xD800..=0xDBFF).contains(&unit)
}

/// `true` for a UTF-16 low (trailing) surrogate code unit.
pub fn is_low_surrogate(unit: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&unit)
}

/// The code points of `s` as `Array.from(s, c => c.codePointAt(0))` yields them: a surrogate pair is one astral code
/// point and a lone surrogate is a code point of its own.
pub fn code_points(s: &[u16]) -> Vec<u32> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let unit = s[i];
        if is_high_surrogate(unit) && i + 1 < s.len() && is_low_surrogate(s[i + 1]) {
            out.push(0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(s[i + 1]) - 0xDC00));
            i += 2;
        } else {
            out.push(u32::from(unit));
            i += 1;
        }
    }
    out
}

/// `s.codePointAt(index)` for an index inside `s`.
pub fn code_point_at(s: &[u16], index: usize) -> u32 {
    let unit = s[index];
    if is_high_surrogate(unit) && index + 1 < s.len() && is_low_surrogate(s[index + 1]) {
        0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(s[index + 1]) - 0xDC00)
    } else {
        u32::from(unit)
    }
}

/// Appends `String.fromCodePoint(code_point)` to `out`.
pub fn push_code_point(out: &mut JsString, code_point: u32) {
    if code_point >= 0x10000 {
        let v = code_point - 0x10000;
        out.push(0xD800 + (v >> 10) as u16);
        out.push(0xDC00 + (v & 0x3FF) as u16);
    } else {
        out.push(code_point as u16);
    }
}

/// The JavaScript string of a list of code points, as `String.fromCodePoint(...code_points)` builds it.
pub fn from_code_points(code_points: &[u32]) -> JsString {
    let mut out = JsString::with_capacity(code_points.len());
    for &cp in code_points {
        push_code_point(&mut out, cp);
    }
    out
}

/// `s.toWellFormed()` as a Rust string: every lone surrogate becomes U+FFFD.
pub fn to_well_formed(s: &[u16]) -> String {
    char::decode_utf16(s.iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// `s` as a Rust string, or `None` when it holds a lone surrogate.
pub fn to_string(s: &[u16]) -> Option<String> {
    String::from_utf16(s).ok()
}

/// `true` when `s` holds a lone surrogate.
pub fn has_lone_surrogate(s: &[u16]) -> bool {
    char::decode_utf16(s.iter().copied()).any(|r| r.is_err())
}

/// `s.toLowerCase()` for the ASCII letters, the only ones the library lower-cases.
pub fn ascii_lowercase(s: &[u16]) -> JsString {
    s.iter()
        .map(|&u| if (0x41..=0x5A).contains(&u) { u + 0x20 } else { u })
        .collect()
}

/// `true` when `s` equals the ASCII string `ascii`.
pub fn eq_ascii(s: &[u16], ascii: &str) -> bool {
    s.len() == ascii.len() && s.iter().zip(ascii.bytes()).all(|(&u, b)| u == u16::from(b))
}

/// `true` when `s` starts with the ASCII string `ascii`.
pub fn starts_with_ascii(s: &[u16], ascii: &str) -> bool {
    s.len() >= ascii.len() && eq_ascii(&s[..ascii.len()], ascii)
}

/// `s.indexOf(unit)` for a single code unit.
pub fn index_of(s: &[u16], unit: u16) -> Option<usize> {
    s.iter().position(|&u| u == unit)
}

/// The comparison JavaScript's `<` and `>` make between two strings: code unit by code unit.
pub fn compare_utf16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `s.split(separator)` for a single code unit, which always yields at least one part.
pub fn split(s: &[u16], separator: u16) -> Vec<&[u16]> {
    s.split(|&u| u == separator).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_points_keep_lone_surrogates() {
        let s = vec![0x61, 0xD83D, 0xDE00, 0xD800, 0xDC00, 0xDC01];
        assert_eq!(code_points(&s), vec![0x61, 0x1F600, 0x10000, 0xDC01]);
        assert_eq!(from_code_points(&code_points(&s)), s);
    }

    #[test]
    fn well_formed_replaces_lone_surrogates() {
        assert_eq!(to_well_formed(&[0xD800, 0x41]), "\u{FFFD}A");
        assert_eq!(to_string(&[0xDC00]), None);
    }

    #[test]
    fn comparison_is_by_code_unit() {
        assert_eq!(compare_utf16("\u{FFFD}", "\u{1F600}"), Ordering::Greater);
        assert_eq!(compare_utf16("a", "b"), Ordering::Less);
    }
}
