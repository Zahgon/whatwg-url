// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! Percent-encoding and percent-decoding, and the URL Standard's percent-encode sets.
//!
//! Every percent-encode set is a predicate on one byte of the UTF-8 encoding of a code point, as in the original.

use crate::encoding::utf8_encode;
use crate::infra::is_ascii_hex;

/// A percent-encode set: `true` for a byte that is percent-encoded.
pub type PercentEncodeSet = fn(u8) -> bool;

/// `%XX` for a byte, with upper-case hex digits.
pub fn percent_encode(byte: u8) -> String {
    format!("%{byte:02X}")
}

/// Percent-decodes a byte sequence: `%` followed by two hex digits becomes that byte, anything else is kept.
pub fn percent_decode_bytes(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        let hex_at = |j: usize| is_ascii_hex(input.get(j).map(|&b| u32::from(b)));
        if byte == b'%' && hex_at(i + 1) && hex_at(i + 2) {
            output.push((hex_value(input[i + 1]) << 4) | hex_value(input[i + 2]));
            i += 3;
        } else {
            output.push(byte);
            i += 1;
        }
    }
    output
}

fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => digit - b'A' + 10,
    }
}

/// String percent-decode: UTF-8 encode the string, then percent-decode the bytes.
pub fn percent_decode_string(input: &[u16]) -> Vec<u8> {
    percent_decode_bytes(&utf8_encode(input))
}

/// The C0 control percent-encode set: C0 controls and every byte above `~`.
pub fn is_c0_control_percent_encode(c: u8) -> bool {
    c <= 0x1F || c > 0x7E
}

/// The fragment percent-encode set.
pub fn is_fragment_percent_encode(c: u8) -> bool {
    is_c0_control_percent_encode(c) || matches!(c, b' ' | b'"' | b'<' | b'>' | b'`')
}

/// The query percent-encode set.
pub fn is_query_percent_encode(c: u8) -> bool {
    is_c0_control_percent_encode(c) || matches!(c, b' ' | b'"' | b'#' | b'<' | b'>')
}

/// The special-query percent-encode set: the query set and `'`.
pub fn is_special_query_percent_encode(c: u8) -> bool {
    is_query_percent_encode(c) || c == b'\''
}

/// The path percent-encode set.
pub fn is_path_percent_encode(c: u8) -> bool {
    is_query_percent_encode(c) || matches!(c, b'?' | b'`' | b'{' | b'}' | b'^')
}

/// The userinfo percent-encode set.
pub fn is_userinfo_percent_encode(c: u8) -> bool {
    is_path_percent_encode(c) || matches!(c, b'/' | b':' | b';' | b'=' | b'@' | b'[' | b'\\' | b']' | b'|')
}

/// The component percent-encode set.
pub fn is_component_percent_encode(c: u8) -> bool {
    is_userinfo_percent_encode(c) || matches!(c, b'$' | b'%' | b'&' | b'+' | b',')
}

/// The `application/x-www-form-urlencoded` percent-encode set.
pub fn is_url_encoded_percent_encode(c: u8) -> bool {
    is_component_percent_encode(c) || matches!(c, b'!' | b'\'' | b'(' | b')' | b'~')
}

/// Percent-encodes bytes: every byte in the set becomes `%XX`, every other byte (which is ASCII) is kept; with
/// `space_as_plus` a space becomes `+`.
pub fn percent_encode_bytes(bytes: &[u8], set: PercentEncodeSet, space_as_plus: bool) -> String {
    let mut output = String::with_capacity(bytes.len());
    for &byte in bytes {
        if space_as_plus && byte == b' ' {
            output.push('+');
        } else if set(byte) {
            output.push_str(&percent_encode(byte));
        } else {
            output.push(char::from(byte));
        }
    }
    output
}

/// UTF-8 percent-encode a code point (a lone surrogate encodes as U+FFFD).
pub fn utf8_percent_encode_code_point(code_point: u32, set: PercentEncodeSet) -> String {
    let mut units = Vec::with_capacity(2);
    crate::jsstring::push_code_point(&mut units, code_point);
    percent_encode_bytes(&utf8_encode(&units), set, false)
}

/// UTF-8 percent-encode a string; with `space_as_plus` every space becomes `+`.
pub fn utf8_percent_encode_string(input: &[u16], set: PercentEncodeSet, space_as_plus: bool) -> String {
    percent_encode_bytes(&utf8_encode(input), set, space_as_plus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsstring::from_str;

    #[test]
    fn decodes_only_complete_escapes() {
        assert_eq!(percent_decode_bytes(b"%41%4%zz%"), b"A%4%zz%".to_vec());
    }

    #[test]
    fn encodes_by_set() {
        assert_eq!(
            utf8_percent_encode_string(&from_str("a b'é"), is_special_query_percent_encode, false),
            "a%20b%27%C3%A9"
        );
        assert_eq!(
            utf8_percent_encode_string(&from_str("a b~"), is_url_encoded_percent_encode, true),
            "a+b%7E"
        );
        assert_eq!(
            utf8_percent_encode_code_point(0xD800, is_path_percent_encode),
            "%EF%BF%BD"
        );
    }
}
