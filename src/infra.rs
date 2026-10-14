// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The Infra Standard's code point classes. Code points are taken as numbers, as in the original, so that a missing
//! code point (`None`, JavaScript's `undefined`) belongs to no class.

/// An ASCII digit, 0-9.
pub fn is_ascii_digit(c: Option<u32>) -> bool {
    matches!(c, Some(0x30..=0x39))
}

/// An ASCII letter, A-Z or a-z.
pub fn is_ascii_alpha(c: Option<u32>) -> bool {
    matches!(c, Some(0x41..=0x5A | 0x61..=0x7A))
}

/// An ASCII letter or digit.
pub fn is_ascii_alphanumeric(c: Option<u32>) -> bool {
    is_ascii_alpha(c) || is_ascii_digit(c)
}

/// An ASCII hex digit, 0-9, A-F or a-f.
pub fn is_ascii_hex(c: Option<u32>) -> bool {
    is_ascii_digit(c) || matches!(c, Some(0x41..=0x46 | 0x61..=0x66))
}

/// `true` when every code unit of the string is ASCII.
pub fn is_ascii_string(s: &[u16]) -> bool {
    s.iter().all(|&u| u < 0x80)
}

/// A noncharacter: U+FDD0 to U+FDEF, or a code point ending in FFFE or FFFF.
pub fn is_noncharacter(c: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&c) || (c & 0xFFFE) == 0xFFFE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert!(is_ascii_hex(Some(u32::from(b'f'))));
        assert!(!is_ascii_hex(Some(u32::from(b'g'))));
        assert!(!is_ascii_digit(None));
        assert!(is_noncharacter(0x10FFFE));
        assert!(!is_noncharacter(0xFFFD));
    }
}
