// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! UTF-8 encoding and decoding as the Encoding Standard defines them (`TextEncoder` and a `TextDecoder` that keeps a
//! byte order mark).

/// UTF-8 encode: the bytes of the string, with every lone surrogate encoded as U+FFFD.
pub fn utf8_encode(s: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in char::decode_utf16(s.iter().copied()) {
        let c = c.unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    out
}

/// UTF-8 decode without BOM: every maximal invalid subsequence becomes U+FFFD and a leading byte order mark is kept.
pub fn utf8_decode_without_bom(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lone_surrogates_as_replacement() {
        assert_eq!(utf8_encode(&[0xD800, 0x61]), vec![0xEF, 0xBF, 0xBD, 0x61]);
    }

    #[test]
    fn decodes_maximal_subparts() {
        assert_eq!(
            utf8_decode_without_bom(&[0xE2, 0x82, 0x41, 0xEF, 0xBB, 0xBF]),
            "\u{FFFD}A\u{FEFF}"
        );
    }
}
