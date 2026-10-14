// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! UTS #46 processing (`ToASCII`) as the tr46 package the original depends on implements it: mapping with the IDNA
//! mapping table, NFC normalization, Punycode conversion and the label validity criteria (hyphens, joiners, Bidi).

mod tables;

use crate::jsstring;
use crate::punycode;
use unicode_normalization::UnicodeNormalization;

/// The IDNA mapping table status of a code point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Replaced by its mapping.
    Mapped,
    /// Kept.
    Valid,
    /// Kept, and makes the label invalid.
    Disallowed,
    /// Kept by nontransitional processing.
    Deviation,
    /// Removed.
    Ignored,
}

/// The options of `ToASCII`, named as in UTS #46.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub check_hyphens: bool,
    pub check_bidi: bool,
    pub check_joiners: bool,
    pub use_std3_ascii_rules: bool,
    pub verify_dns_length: bool,
    pub transitional_processing: bool,
    pub ignore_invalid_punycode: bool,
}

const ZWNJ: u32 = 0x200C;
const ZWJ: u32 = 0x200D;

fn in_class(class: &[(u32, u32)], cp: u32) -> bool {
    class
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                std::cmp::Ordering::Less
            } else if lo > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn find_status(cp: u32) -> (Status, &'static str) {
    match tables::MAPPING_TABLE.binary_search_by(|&(lo, hi, _, _)| {
        if hi < cp {
            std::cmp::Ordering::Less
        } else if lo > cp {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    }) {
        Ok(i) => (tables::MAPPING_TABLE[i].2, tables::MAPPING_TABLE[i].3),
        // The table covers every code point; a value outside it (none exists) would be disallowed.
        Err(_) => (Status::Disallowed, ""),
    }
}

fn contains_non_ascii(s: &str) -> bool {
    !s.is_ascii()
}

fn map_chars(domain: &str, options: &Options) -> String {
    let mut processed = String::with_capacity(domain.len());
    for ch in domain.chars() {
        let (status, mapping) = find_status(u32::from(ch));
        match status {
            Status::Disallowed | Status::Valid => processed.push(ch),
            Status::Ignored => {}
            Status::Mapped => {
                if options.transitional_processing && ch == '\u{1E9E}' {
                    processed.push_str("ss");
                } else {
                    processed.push_str(mapping);
                }
            }
            Status::Deviation => {
                if options.transitional_processing {
                    processed.push_str(mapping);
                } else {
                    processed.push(ch);
                }
            }
        }
    }
    processed
}

/// `class1 class2* $` anywhere: some code point of `class1` is followed only by code points of `class2` up to the end.
fn ends_with_class_then_run(cps: &[u32], last: &[(u32, u32)], run: &[(u32, u32)]) -> bool {
    for &cp in cps.iter().rev() {
        if in_class(last, cp) {
            return true;
        }
        if !in_class(run, cp) {
            return false;
        }
    }
    false
}

/// The ContextJ rule for one ZERO WIDTH NON-JOINER inside `cps`: `L/D T* ZWNJ T* R/D`.
fn zwnj_in_context(cps: &[u32], at: usize) -> bool {
    let before = ends_with_class_then_run(&cps[..at], tables::VALID_ZWNJ0, tables::VALID_ZWNJ1);
    let after = cps[at + 1..]
        .iter()
        .find(|&&cp| !in_class(tables::VALID_ZWNJ2, cp))
        .is_some_and(|&cp| in_class(tables::VALID_ZWNJ3, cp));
    before && after
}

struct LabelCheck<'a> {
    options: &'a Options,
    transitional_processing: bool,
    is_bidi: bool,
}

impl LabelCheck<'_> {
    fn validate(&self, label: &str) -> bool {
        // "must be satisfied for a non-empty label"
        if label.is_empty() {
            return true;
        }
        // 1. The label must be in Unicode Normalization Form NFC.
        if label.nfc().ne(label.chars()) {
            return false;
        }
        let cps: Vec<u32> = label.chars().map(u32::from).collect();
        let hyphen = u32::from(b'-');
        // 2-3. Hyphens in the third and fourth positions, and at the start and end.
        if self.options.check_hyphens
            && ((cps.get(2) == Some(&hyphen) && cps.get(3) == Some(&hyphen))
                || label.starts_with('-')
                || label.ends_with('-'))
        {
            return false;
        }
        // 4. If not CheckHyphens, the label must not begin with "xn--".
        if !self.options.check_hyphens && label.starts_with("xn--") {
            return false;
        }
        // 5. No FULL STOP.
        if label.contains('.') {
            return false;
        }
        // 6. The label must not begin with a combining mark.
        if in_class(tables::COMBINING_MARKS, cps[0]) {
            return false;
        }
        // 7. Every code point must have an allowed status.
        for &cp in &cps {
            let (status, _) = find_status(cp);
            let allowed = if self.transitional_processing {
                status == Status::Valid
            } else {
                status == Status::Valid || status == Status::Deviation
            };
            if !allowed {
                return false;
            }
            if self.options.use_std3_ascii_rules && cp <= 0x7F {
                let c = cp as u8;
                if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
                    return false;
                }
            }
        }
        // 8. ContextJ rules (RFC 5892, appendix A).
        if self.options.check_joiners && !self.joiners_valid(&cps) {
            return false;
        }
        // 9. Bidi rules (RFC 5893, section 2) for a Bidi domain name.
        if self.options.check_bidi && self.is_bidi {
            return bidi_valid(label, &cps);
        }
        true
    }

    fn joiners_valid(&self, cps: &[u32]) -> bool {
        let mut last = 0;
        for (i, &cp) in cps.iter().enumerate() {
            if cp != ZWNJ && cp != ZWJ {
                continue;
            }
            if i > 0 {
                if in_class(tables::COMBINING_CLASS_VIRAMA, cps[i - 1]) {
                    continue;
                }
                if cp == ZWNJ {
                    // As in tr46, the ZWNJ rule is tested on the code points from just after the last ZWNJ that
                    // passed it up to the next ZWNJ, and any ZWNJ of that run in context passes it.
                    let next = cps[i + 1..].iter().position(|&c| c == ZWNJ).map(|p| p + i + 1);
                    let run = &cps[last..next.unwrap_or(cps.len())];
                    if (0..run.len()).any(|j| run[j] == ZWNJ && zwnj_in_context(run, j)) {
                        last = i + 1;
                        continue;
                    }
                }
            }
            return false;
        }
        true
    }
}

fn bidi_valid(label: &str, cps: &[u32]) -> bool {
    let first = cps[0];
    let rtl = if in_class(tables::BIDI_S1_LTR, first) {
        false
    } else if in_class(tables::BIDI_S1_RTL, first) {
        true
    } else {
        return false;
    };
    let all_in = |class: &[(u32, u32)]| label.chars().all(|c| in_class(class, u32::from(c)));
    let any_in = |class: &[(u32, u32)]| label.chars().any(|c| in_class(class, u32::from(c)));
    if rtl {
        all_in(tables::BIDI_S2)
            && ends_with_class_then_run(cps, tables::BIDI_S30, tables::BIDI_S31)
            && !(any_in(tables::BIDI_S4_EN) && any_in(tables::BIDI_S4_AN))
    } else {
        all_in(tables::BIDI_S5) && ends_with_class_then_run(cps, tables::BIDI_S60, tables::BIDI_S61)
    }
}

/// The Punycode decoding of an `xn--` label as a string, `None` when it fails or yields a lone surrogate.
fn decode_label(label: &str) -> Result<Option<String>, punycode::PunycodeError> {
    let cps = punycode::decode(&jsstring::from_str(&label[4..]))?;
    Ok(cps.into_iter().map(char::from_u32).collect())
}

fn is_bidi_domain(labels: &[String]) -> bool {
    labels.iter().any(|label| {
        let decoded;
        let text: &str = if label.starts_with("xn--") {
            // As in tr46, a label whose Punycode does not decode counts as empty here: the Bidi test only asks
            // whether the domain has right-to-left characters, and the label's own error is reported by processing.
            decoded = decode_label(label).ok().flatten().unwrap_or_default();
            &decoded
        } else {
            label
        };
        text.chars().any(|c| in_class(tables::BIDI_DOMAIN, u32::from(c)))
    })
}

/// UTS #46 processing: the processed labels, or `None` when any label is in error.
fn processing(domain: &str, options: &Options) -> Option<Vec<String>> {
    // 1. Map. 2. Normalize.
    let string: String = map_chars(domain, options).nfc().collect();
    // 3. Break.
    let mut labels: Vec<String> = string.split('.').map(str::to_owned).collect();
    let is_bidi = is_bidi_domain(&labels);
    // 4. Convert/Validate.
    for label in &mut labels {
        let mut transitional_processing = options.transitional_processing;
        if label.starts_with("xn--") {
            if contains_non_ascii(label) {
                return None;
            }
            match decode_label(label) {
                Ok(Some(decoded)) => *label = decoded,
                // A lone surrogate is disallowed, so the label cannot pass validation below.
                Ok(None) => return None,
                Err(_) if options.ignore_invalid_punycode => {}
                Err(_) => return None,
            }
            if label.is_empty() || !contains_non_ascii(label) {
                return None;
            }
            transitional_processing = false;
        }
        let check = LabelCheck {
            options,
            transitional_processing,
            is_bidi,
        };
        if !check.validate(label) {
            return None;
        }
    }
    Some(labels)
}

/// `ToASCII`: the ASCII form of a domain, or `None` on any error. A domain with a lone surrogate is an error, since
/// surrogates are disallowed.
pub fn to_ascii(domain: &[u16], options: &Options) -> Option<String> {
    let domain = jsstring::to_string(domain)?;
    let labels = processing(&domain, options)?;
    let joined = labels.join(".");
    let mut out = Vec::new();
    for label in joined.split('.') {
        if contains_non_ascii(label) {
            let cps: Vec<u32> = label.chars().map(u32::from).collect();
            // A label Punycode cannot encode makes ToASCII fail, as tr46 reports it.
            out.push(format!("xn--{}", punycode::encode(&cps).ok()?));
        } else {
            out.push(label.to_owned());
        }
    }
    let result = out.join(".");
    if options.verify_dns_length {
        if result.is_empty() || result.len() > 253 {
            return None;
        }
        if out.iter().any(|l| l.is_empty() || l.len() > 63) {
            return None;
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsstring::from_str;

    fn lenient() -> Options {
        Options {
            check_bidi: true,
            check_joiners: true,
            ..Options::default()
        }
    }

    #[test]
    fn maps_and_encodes() {
        assert_eq!(
            to_ascii(&from_str("Bücher.EXAMPLE"), &lenient()).as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(to_ascii(&from_str("a\u{3002}b"), &lenient()).as_deref(), Some("a.b"));
        assert_eq!(
            to_ascii(&from_str("faß.de"), &lenient()).as_deref(),
            Some("xn--fa-hia.de")
        );
    }

    #[test]
    fn rejects_invalid_labels() {
        assert_eq!(to_ascii(&from_str("xn--a"), &lenient()), None);
        assert_eq!(to_ascii(&from_str("\u{0301}a"), &lenient()), None);
        assert_eq!(to_ascii(&[0xD800], &lenient()), None);
        assert_eq!(to_ascii(&from_str("a\u{200D}b"), &lenient()), None);
    }

    #[test]
    fn strict_rules() {
        let strict = Options {
            check_hyphens: true,
            use_std3_ascii_rules: true,
            verify_dns_length: true,
            ..lenient()
        };
        assert_eq!(to_ascii(&from_str("-a.b"), &strict), None);
        assert_eq!(to_ascii(&from_str("a_b"), &strict), None);
        assert_eq!(to_ascii(&from_str("a."), &strict), None);
        assert_eq!(to_ascii(&from_str("a_b"), &lenient()).as_deref(), Some("a_b"));
    }
}
