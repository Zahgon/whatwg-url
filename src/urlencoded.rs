// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The `application/x-www-form-urlencoded` parser and serializer.

use crate::encoding::{utf8_decode_without_bom, utf8_encode};
use crate::percent_encoding::{is_url_encoded_percent_encode, percent_decode_bytes, utf8_percent_encode_string};

/// One name-value pair of a list.
pub type Pair = (String, String);

/// Parses `application/x-www-form-urlencoded` bytes into name-value pairs.
pub fn parse_urlencoded(input: &[u8]) -> Vec<Pair> {
    let mut output = Vec::new();
    for bytes in strictly_split(input, b'&') {
        if bytes.is_empty() {
            continue;
        }
        let (name, value) = match bytes.iter().position(|&b| b == b'=') {
            Some(i) => (&bytes[..i], &bytes[i + 1..]),
            None => (bytes, &[][..]),
        };
        let plus_to_space = |b: &[u8]| -> Vec<u8> { b.iter().map(|&c| if c == b'+' { b' ' } else { c }).collect() };
        output.push((
            utf8_decode_without_bom(&percent_decode_bytes(&plus_to_space(name))),
            utf8_decode_without_bom(&percent_decode_bytes(&plus_to_space(value))),
        ));
    }
    output
}

/// Parses a string: UTF-8 encode it (lone surrogates become U+FFFD), then parse the bytes.
pub fn parse_urlencoded_string(input: &[u16]) -> Vec<Pair> {
    parse_urlencoded(&utf8_encode(input))
}

/// Serializes name-value pairs as `name=value` joined by `&`, spaces as `+`.
pub fn serialize_urlencoded(tuples: &[Pair]) -> String {
    let mut output = String::new();
    for (i, (name, value)) in tuples.iter().enumerate() {
        if i != 0 {
            output.push('&');
        }
        let encode =
            |s: &str| utf8_percent_encode_string(&crate::jsstring::from_str(s), is_url_encoded_percent_encode, true);
        output.push_str(&encode(name));
        output.push('=');
        output.push_str(&encode(value));
    }
    output
}

/// Splits at every occurrence of `separator`; unlike `split`, a trailing empty part is dropped.
fn strictly_split(input: &[u8], separator: u8) -> Vec<&[u8]> {
    let mut list = Vec::new();
    let mut last = 0;
    for (i, &b) in input.iter().enumerate() {
        if b == separator {
            list.push(&input[last..i]);
            last = i + 1;
        }
    }
    if last != input.len() {
        list.push(&input[last..]);
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pairs() {
        let pairs = parse_urlencoded(b"a=b+c&&d&e=%zz%C3%A9=&%FF");
        assert_eq!(
            pairs,
            vec![
                ("a".into(), "b c".into()),
                ("d".into(), String::new()),
                ("e".into(), "%zzé=".into()),
                ("\u{FFFD}".into(), String::new()),
            ]
        );
    }

    #[test]
    fn serializes_pairs() {
        let pairs = vec![
            ("a b".to_string(), "c&d~".to_string()),
            ("é".to_string(), String::new()),
        ];
        assert_eq!(serialize_urlencoded(&pairs), "a+b=c%26d%7E&%C3%A9=");
    }
}
