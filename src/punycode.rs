// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr
// SPDX-FileCopyrightText: Mathias Bynens <https://mathiasbynens.be/>

//! Punycode (RFC 3492) as the punycode.js package the original depends on implements it, with its 31-bit integer
//! limits.

const MAX_INT: i64 = 2_147_483_647;
const BASE: i64 = 36;
const T_MIN: i64 = 1;
const T_MAX: i64 = 26;
const SKEW: i64 = 38;
const DAMP: i64 = 700;
const INITIAL_BIAS: i64 = 72;
const INITIAL_N: i64 = 128;
const DELIMITER: u16 = b'-' as u16;

/// Why a Punycode conversion failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunycodeError {
    /// The input needs wider integers to process.
    Overflow,
    /// A code point at or above 0x80 sits among the basic code points.
    NotBasic,
    /// The input is not valid Punycode.
    InvalidInput,
    /// A decoded value is not a Unicode code point.
    InvalidCodePoint,
}

fn basic_to_digit(code_unit: u16) -> i64 {
    match code_unit {
        0x30..=0x39 => 26 + i64::from(code_unit - 0x30),
        0x41..=0x5A => i64::from(code_unit - 0x41),
        0x61..=0x7A => i64::from(code_unit - 0x61),
        _ => BASE,
    }
}

fn digit_to_basic(digit: i64) -> char {
    // 0..25 map to a..z, 26..35 to 0..9.
    let byte = if digit < 26 { digit + 97 } else { digit + 22 };
    char::from(byte as u8)
}

fn threshold(k: i64, bias: i64) -> i64 {
    if k <= bias {
        T_MIN
    } else if k >= bias + T_MAX {
        T_MAX
    } else {
        k - bias
    }
}

fn adapt(delta: i64, num_points: i64, first_time: bool) -> i64 {
    let mut k = 0;
    let mut delta = if first_time { delta / DAMP } else { delta >> 1 };
    delta += delta / num_points;
    while delta > ((BASE - T_MIN) * T_MAX) >> 1 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
}

/// Decodes a Punycode string (the part after `xn--`) into code points; lone surrogates may come out.
pub fn decode(input: &[u16]) -> Result<Vec<u32>, PunycodeError> {
    let mut output: Vec<i64> = Vec::new();
    let input_length = input.len();
    let mut i: i64 = 0;
    let mut n = INITIAL_N;
    let mut bias = INITIAL_BIAS;

    let basic = input.iter().rposition(|&u| u == DELIMITER).unwrap_or(0);
    for &unit in &input[..basic] {
        if unit >= 0x80 {
            return Err(PunycodeError::NotBasic);
        }
        output.push(i64::from(unit));
    }

    let mut index = if basic > 0 { basic + 1 } else { 0 };
    while index < input_length {
        let old_i = i;
        let mut w: i64 = 1;
        let mut k = BASE;
        loop {
            if index >= input_length {
                return Err(PunycodeError::InvalidInput);
            }
            let digit = basic_to_digit(input[index]);
            index += 1;
            if digit >= BASE {
                return Err(PunycodeError::InvalidInput);
            }
            if digit > (MAX_INT - i) / w {
                return Err(PunycodeError::Overflow);
            }
            i += digit * w;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            let base_minus_t = BASE - t;
            if w > MAX_INT / base_minus_t {
                return Err(PunycodeError::Overflow);
            }
            w *= base_minus_t;
            k += BASE;
        }
        let out = output.len() as i64 + 1;
        bias = adapt(i - old_i, out, old_i == 0);
        if i / out > MAX_INT - n {
            return Err(PunycodeError::Overflow);
        }
        n += i / out;
        i %= out;
        output.insert(i as usize, n);
        i += 1;
    }

    output
        .into_iter()
        .map(|cp| {
            if cp <= 0x10FFFF {
                Ok(cp as u32)
            } else {
                Err(PunycodeError::InvalidCodePoint)
            }
        })
        .collect()
}

/// Encodes code points as a Punycode string (without the `xn--` prefix).
pub fn encode(input: &[u32]) -> Result<String, PunycodeError> {
    let mut output = String::new();
    let input_length = input.len() as i64;
    let mut n = INITIAL_N;
    let mut delta: i64 = 0;
    let mut bias = INITIAL_BIAS;

    for &cp in input {
        if cp < 0x80 {
            output.push(char::from(cp as u8));
        }
    }
    let basic_length = output.len() as i64;
    let mut handled = basic_length;
    if basic_length > 0 {
        output.push('-');
    }

    while handled < input_length {
        let m = input
            .iter()
            .map(|&cp| i64::from(cp))
            .filter(|&cp| cp >= n)
            .fold(MAX_INT, i64::min);
        let handled_plus_one = handled + 1;
        if m - n > (MAX_INT - delta) / handled_plus_one {
            return Err(PunycodeError::Overflow);
        }
        delta += (m - n) * handled_plus_one;
        n = m;
        for &cp in input {
            let cp = i64::from(cp);
            if cp < n {
                delta += 1;
                if delta > MAX_INT {
                    return Err(PunycodeError::Overflow);
                }
            }
            if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = threshold(k, bias);
                    if q < t {
                        break;
                    }
                    output.push(digit_to_basic(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit_to_basic(q));
                bias = adapt(delta, handled_plus_one, handled == basic_length);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsstring::from_str;

    #[test]
    fn round_trips() {
        let munchen: Vec<u32> = "münchen".chars().map(u32::from).collect();
        assert_eq!(encode(&munchen).as_deref(), Ok("mnchen-3ya"));
        assert_eq!(decode(&from_str("mnchen-3ya")), Ok(munchen));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode(&from_str("a-é")), Err(PunycodeError::InvalidInput));
        assert_eq!(decode(&from_str("é-a")), Err(PunycodeError::NotBasic));
        assert_eq!(decode(&from_str("99999999999")), Err(PunycodeError::Overflow));
    }
}
