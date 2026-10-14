// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The URL Standard's valid URL string grammar: whether a string is a valid URL string, absolute or relative to a
//! base URL.

use crate::infra;
use crate::jsstring::{self, starts_with_ascii};
use crate::miscellaneous::{
    domain_parser, ends_in_a_number, is_forbidden_host_code_point, is_percent_encoded_byte_at,
    is_special_scheme_except_file, is_url_code_point,
};
use crate::url_state_machine::{has_an_opaque_path, UrlRecord};

const SLASH: u16 = b'/' as u16;
const QUESTION: u16 = b'?' as u16;
const HASH: u16 = b'#' as u16;
const COLON: u16 = b':' as u16;
const PERCENT: u16 = b'%' as u16;

fn split_off(input: &[u16], at: u16) -> (&[u16], Option<&[u16]>) {
    match jsstring::index_of(input, at) {
        Some(i) => (&input[..i], Some(&input[i + 1..])),
        None => (input, None),
    }
}

/// `true` when `input` is a valid URL string: a valid absolute URL with fragment, or, with a base URL, a valid
/// relative URL with fragment.
pub fn is_valid_url_string(input: &[u16], base: Option<&UrlRecord>) -> bool {
    is_valid_absolute_url_with_fragment(input)
        || base.is_some_and(|base| is_valid_relative_url_with_fragment(input, base))
}

fn is_valid_absolute_url_with_fragment(input: &[u16]) -> bool {
    let (before, fragment) = split_off(input, HASH);
    fragment.is_none_or(is_valid_url_units_all) && is_valid_absolute_url(before)
}

/// The length of a leading `scheme:`, as `/^([A-Za-z][A-Za-z0-9+.-]*):/` matches it, without the colon.
fn scheme_prefix(input: &[u16]) -> Option<usize> {
    let is_alpha = |u: u16| (u as u8).is_ascii_alphabetic() && u < 0x80;
    let is_scheme_unit =
        |u: u16| u < 0x80 && ((u as u8).is_ascii_alphanumeric() || matches!(u as u8, b'+' | b'.' | b'-'));
    if !input.first().is_some_and(|&u| is_alpha(u)) {
        return None;
    }
    let end = input.iter().position(|&u| !is_scheme_unit(u))?;
    (input[end] == COLON).then_some(end)
}

fn is_valid_absolute_url(input: &[u16]) -> bool {
    let (before_query, query) = split_off(input, QUESTION);
    if query.is_some_and(|q| !is_valid_url_units_all(q)) {
        return false;
    }
    let Some(scheme_len) = scheme_prefix(before_query) else {
        return false;
    };
    let scheme = jsstring::to_well_formed(&before_query[..scheme_len]).to_ascii_lowercase();
    let after_scheme = &before_query[scheme_len + 1..];
    if is_special_scheme_except_file(&scheme) {
        return is_valid_scheme_relative_special_url(after_scheme);
    }
    if scheme == "file" {
        return is_valid_scheme_relative_file_url(after_scheme);
    }
    is_valid_scheme_relative_url(after_scheme)
        || is_valid_path_absolute_non_authority_url(after_scheme)
        || is_valid_opaque_path_url(after_scheme)
}

fn is_valid_relative_url_with_fragment(input: &[u16], base: &UrlRecord) -> bool {
    if has_an_opaque_path(base) {
        return input.first() == Some(&HASH) && is_valid_url_units_all(&input[1..]);
    }
    let (before, fragment) = split_off(input, HASH);
    is_valid_relative_url(before, base) && fragment.is_none_or(is_valid_url_units_all)
}

fn is_valid_relative_url(input: &[u16], base: &UrlRecord) -> bool {
    let (before_query, query) = split_off(input, QUESTION);
    let has_valid_query = query.is_none_or(is_valid_url_units_all);
    if is_valid_path_absolute_non_authority_url(before_query) {
        return has_valid_query;
    }
    if is_valid_path_relative_scheme_less_url(before_query) {
        return has_valid_query;
    }
    if is_special_scheme_except_file(&base.scheme) {
        return is_valid_scheme_relative_special_url(before_query) && has_valid_query;
    }
    if base.scheme == "file" {
        return is_valid_scheme_relative_file_url(before_query) && has_valid_query;
    }
    is_valid_scheme_relative_url(before_query) && has_valid_query
}

fn is_valid_scheme_relative_special_url(input: &[u16]) -> bool {
    if !starts_with_ascii(input, "//") {
        return false;
    }
    let (authority, path) = split_off_path(&input[2..]);
    is_valid_host_and_port(authority, is_valid_host) && path.is_none_or(is_valid_path_absolute_url)
}

fn is_valid_scheme_relative_url(input: &[u16]) -> bool {
    if !starts_with_ascii(input, "//") {
        return false;
    }
    let (authority, path) = split_off_path(&input[2..]);
    is_valid_opaque_host_and_port(authority) && path.is_none_or(is_valid_path_absolute_url)
}

fn is_valid_scheme_relative_file_url(input: &[u16]) -> bool {
    if !starts_with_ascii(input, "//") {
        return false;
    }
    let after_slashes = &input[2..];
    after_slashes.is_empty()
        || is_valid_host_and_path_absolute_url(after_slashes)
        || is_valid_path_absolute_url(after_slashes)
}

fn is_valid_host_and_path_absolute_url(input: &[u16]) -> bool {
    let (authority, path) = split_off_path(input);
    is_valid_host(authority) && path.is_none_or(is_valid_path_absolute_url)
}

/// Splits at the first `/`: the authority before it, and the path from it on.
fn split_off_path(input: &[u16]) -> (&[u16], Option<&[u16]>) {
    match jsstring::index_of(input, SLASH) {
        Some(i) => (&input[..i], Some(&input[i..])),
        None => (input, None),
    }
}

fn is_valid_host_and_port(input: &[u16], is_valid_host: fn(&[u16]) -> bool) -> bool {
    split_host_and_port(input)
        .is_some_and(|(host, port)| !host.is_empty() && is_valid_host(host) && port.is_none_or(is_valid_url_port))
}

fn is_valid_opaque_host_and_port(input: &[u16]) -> bool {
    if input.is_empty() {
        return true;
    }
    split_host_and_port(input).is_some_and(|(host, port)| {
        !host.is_empty() && is_valid_opaque_host(host) && port.is_none_or(is_valid_url_port)
    })
}

fn split_host_and_port(input: &[u16]) -> Option<(&[u16], Option<&[u16]>)> {
    if input.first() == Some(&u16::from(b'[')) {
        let host_end = jsstring::index_of(input, u16::from(b']'))?;
        let rest = &input[host_end + 1..];
        if !rest.is_empty() && rest[0] != COLON {
            return None;
        }
        return Some((
            &input[..host_end + 1],
            if rest.is_empty() { None } else { Some(&rest[1..]) },
        ));
    }
    Some(match jsstring::index_of(input, COLON) {
        Some(i) => (&input[..i], Some(&input[i + 1..])),
        None => (input, None),
    })
}

fn is_valid_host(input: &[u16]) -> bool {
    is_valid_domain(input) || is_valid_ipv4_address(input) || is_valid_bracketed_ipv6_address(input)
}

fn is_valid_domain(input: &[u16]) -> bool {
    domain_parser(input, &mut None, true).is_some_and(|domain| !ends_in_a_number(&domain))
}

fn is_valid_ipv4_address(input: &[u16]) -> bool {
    let pieces = jsstring::split(input, u16::from(b'.'));
    pieces.len() == 4 && pieces.iter().all(|p| is_valid_ipv4_piece(p))
}

fn is_valid_ipv4_piece(input: &[u16]) -> bool {
    if input.is_empty() || input.len() > 3 {
        return false;
    }
    if !input.iter().all(|&u| infra::is_ascii_digit(Some(u32::from(u)))) {
        return false;
    }
    if input.len() > 1 && input[0] == u16::from(b'0') {
        return false;
    }
    input.iter().fold(0u32, |acc, &u| acc * 10 + u32::from(u - 0x30)) <= 255
}

fn is_valid_bracketed_ipv6_address(input: &[u16]) -> bool {
    input.len() >= 2
        && input[0] == u16::from(b'[')
        && input[input.len() - 1] == u16::from(b']')
        && is_valid_ipv6_address(&input[1..input.len() - 1])
}

fn is_valid_ipv6_address(input: &[u16]) -> bool {
    ipv6_pieces_length(input) == Some(8)
        || ipv6_pieces_and_ipv4_length(input) == Some(8)
        || is_valid_compressed_ipv6_address(input)
}

fn find_double_colon(input: &[u16]) -> Vec<usize> {
    (0..input.len().saturating_sub(1))
        .filter(|&i| input[i] == COLON && input[i + 1] == COLON)
        .collect()
}

fn is_valid_compressed_ipv6_address(input: &[u16]) -> bool {
    let positions = find_double_colon(input);
    let (Some(&first), Some(&last)) = (positions.first(), positions.last()) else {
        return false;
    };
    if first != last {
        return false;
    }
    let preceding = &input[..first];
    let following = &input[first + 2..];
    let preceding_length = if preceding.is_empty() {
        Some(0)
    } else {
        ipv6_pieces_length(preceding)
    };
    let following_length = if following.is_empty() {
        Some(0)
    } else {
        ipv6_pieces_or_pieces_and_ipv4_length(following)
    };
    match (preceding_length, following_length) {
        (Some(p), Some(f)) => p + f <= 7,
        _ => false,
    }
}

fn ipv6_pieces_or_pieces_and_ipv4_length(input: &[u16]) -> Option<usize> {
    if is_valid_ipv6_pieces(input) {
        return ipv6_pieces_length(input);
    }
    if is_valid_ipv6_pieces_and_ipv4(input) {
        return ipv6_pieces_and_ipv4_length(input);
    }
    None
}

fn is_valid_ipv6_pieces_and_ipv4(input: &[u16]) -> bool {
    if is_valid_ipv4_address(input) {
        return true;
    }
    let Some(separator) = input.iter().rposition(|&u| u == COLON) else {
        return false;
    };
    is_valid_ipv6_pieces(&input[..separator]) && is_valid_ipv4_address(&input[separator + 1..])
}

fn ipv6_pieces_and_ipv4_length(input: &[u16]) -> Option<usize> {
    if !is_valid_ipv6_pieces_and_ipv4(input) {
        return None;
    }
    let Some(separator) = input.iter().rposition(|&u| u == COLON) else {
        return Some(2);
    };
    ipv6_pieces_length(&input[..separator]).map(|n| n + 2)
}

fn is_valid_ipv6_pieces(input: &[u16]) -> bool {
    !input.is_empty() && jsstring::split(input, COLON).iter().all(|p| is_valid_ipv6_piece(p))
}

fn ipv6_pieces_length(input: &[u16]) -> Option<usize> {
    is_valid_ipv6_pieces(input).then(|| jsstring::split(input, COLON).len())
}

fn is_valid_ipv6_piece(input: &[u16]) -> bool {
    if input.is_empty() || input.len() > 4 {
        return false;
    }
    if !input.iter().all(|&u| infra::is_ascii_hex(Some(u32::from(u)))) {
        return false;
    }
    input.len() == 1 || input[0] != u16::from(b'0')
}

fn is_valid_opaque_host(input: &[u16]) -> bool {
    is_valid_bracketed_ipv6_address(input) || (!input.is_empty() && is_valid_url_units(input, &[], true))
}

fn is_valid_url_port(input: &[u16]) -> bool {
    if input.is_empty() {
        return true;
    }
    if !input.iter().all(|&u| infra::is_ascii_digit(Some(u32::from(u)))) {
        return false;
    }
    let digits = jsstring::to_well_formed(input);
    let digits = digits.trim_start_matches('0');
    // All ASCII digits (checked above), and at most five of them, so the parse succeeds.
    digits.len() <= 5 && digits.parse::<u32>().unwrap_or(0) <= 65535
}

fn is_valid_path_absolute_url(input: &[u16]) -> bool {
    input.first() == Some(&SLASH)
        && jsstring::split(&input[1..], SLASH)
            .iter()
            .all(|s| is_valid_path_segment(s))
}

fn is_valid_path_absolute_non_authority_url(input: &[u16]) -> bool {
    is_valid_path_absolute_url(input) && !starts_with_ascii(input, "//")
}

fn is_valid_path_relative_url(input: &[u16]) -> bool {
    input.first() != Some(&SLASH) && jsstring::split(input, SLASH).iter().all(|s| is_valid_path_segment(s))
}

fn is_valid_path_segment(input: &[u16]) -> bool {
    is_valid_url_units(input, &[SLASH, QUESTION], false)
}

fn is_valid_path_relative_scheme_less_url(input: &[u16]) -> bool {
    is_valid_path_relative_url(input) && scheme_prefix(input).is_none()
}

fn is_valid_opaque_path_url(input: &[u16]) -> bool {
    (input.is_empty() || input[0] != SLASH) && is_valid_url_units(input, &[QUESTION], false)
}

fn is_valid_url_units_all(input: &[u16]) -> bool {
    is_valid_url_units(input, &[], false)
}

/// `true` when the string is URL units: URL code points and percent-encoded bytes, none of them in `excluded` (or a
/// forbidden host code point, with `exclude_forbidden_host`).
fn is_valid_url_units(input: &[u16], excluded: &[u16], exclude_forbidden_host: bool) -> bool {
    let mut i = 0;
    while i < input.len() {
        if input[i] == PERCENT {
            if !is_percent_encoded_byte_at(input, i) {
                return false;
            }
            i += 3;
            continue;
        }
        let code_point = jsstring::code_point_at(input, i);
        let is_excluded = (code_point < 0x10000 && excluded.contains(&(code_point as u16)))
            || (exclude_forbidden_host && is_forbidden_host_code_point(code_point));
        if !is_url_code_point(code_point) || is_excluded {
            return false;
        }
        i += if code_point > 0xFFFF { 2 } else { 1 };
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsstring::from_str;
    use crate::url_state_machine::parse_url;

    fn valid(input: &str, base: Option<&str>) -> bool {
        let base = base.and_then(|b| parse_url(&from_str(b), None));
        is_valid_url_string(&from_str(input), base.as_ref())
    }

    #[test]
    fn absolute_urls() {
        assert!(valid("https://example.com/a?b#c", None));
        assert!(valid("http://[::1]:8080/", None));
        assert!(valid("mailto:someone@example.com", None));
        assert!(!valid("http://exa mple.com/", None));
        assert!(!valid("http://1.2.3/", None));
        assert!(!valid("http://a/%zz", None));
    }

    #[test]
    fn relative_urls() {
        assert!(valid("../a/b?c", Some("http://h/x/y")));
        assert!(valid("#frag", Some("mailto:x")));
        assert!(!valid("a", Some("mailto:x")));
        assert!(valid("a:b", None));
        assert!(!valid("//a b", Some("http://h/")));
    }
}
