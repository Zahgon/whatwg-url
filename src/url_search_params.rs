// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The `URLSearchParams` interface: an ordered list of name-value pairs, parsed from and serialized to the
//! `application/x-www-form-urlencoded` format.

use crate::jsstring;
use crate::urlencoded::{parse_urlencoded_string, serialize_urlencoded, Pair};

/// How a `URLSearchParams` object is initialized, after the WebIDL conversion of the constructor argument.
#[derive(Debug, Clone, PartialEq)]
pub enum Init {
    /// A sequence of sequences of strings; each inner sequence must hold exactly a name and a value.
    Sequence(Vec<Vec<String>>),
    /// A record of names to values, in the record's key order.
    Record(Vec<Pair>),
    /// A query string, parsed as `application/x-www-form-urlencoded` (a leading `?` is removed).
    String(String),
}

/// The error the constructor throws for an inner sequence that is not a pair.
pub const NOT_A_PAIR: &str =
    "Failed to construct 'URLSearchParams': parameter 1 sequence's element does not contain exactly two elements.";

/// A list of name-value pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UrlSearchParams {
    list: Vec<Pair>,
}

impl UrlSearchParams {
    /// An empty list.
    pub fn new() -> Self {
        UrlSearchParams::default()
    }

    /// `new URLSearchParams(init)`; `Err` holds the message of the `TypeError` for an inner sequence that is not a
    /// pair.
    pub fn from_init(init: Init) -> Result<Self, &'static str> {
        let list = match init {
            Init::Sequence(pairs) => {
                let mut list = Vec::with_capacity(pairs.len());
                for pair in pairs {
                    let [name, value]: [String; 2] = pair.try_into().map_err(|_| NOT_A_PAIR)?;
                    list.push((name, value));
                }
                list
            }
            Init::Record(pairs) => pairs,
            Init::String(s) => {
                let query = s.strip_prefix('?').unwrap_or(&s);
                parse_urlencoded_string(&jsstring::from_str(query))
            }
        };
        Ok(UrlSearchParams { list })
    }

    /// The list parsed from a URL's query, as the URL object keeps it (no `?` is removed).
    pub fn from_query(query: &str) -> Self {
        UrlSearchParams {
            list: parse_urlencoded_string(&jsstring::from_str(query)),
        }
    }

    /// Replaces the list.
    pub fn set_list(&mut self, list: Vec<Pair>) {
        self.list = list;
    }

    /// The pairs, in order.
    pub fn entries(&self) -> &[Pair] {
        &self.list
    }

    /// The number of pairs.
    pub fn size(&self) -> usize {
        self.list.len()
    }

    /// Appends a pair.
    pub fn append(&mut self, name: String, value: String) {
        self.list.push((name, value));
    }

    /// Removes every pair with the name (and the value, when given).
    pub fn delete(&mut self, name: &str, value: Option<&str>) {
        self.list
            .retain(|(n, v)| !(n == name && value.is_none_or(|value| v == value)));
    }

    /// The value of the first pair with the name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.list.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The values of every pair with the name.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.list
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// `true` when a pair has the name (and the value, when given).
    pub fn has(&self, name: &str, value: Option<&str>) -> bool {
        self.list
            .iter()
            .any(|(n, v)| n == name && value.is_none_or(|value| v == value))
    }

    /// Sets the value of the first pair with the name and removes the others, or appends a pair.
    pub fn set(&mut self, name: String, value: String) {
        let mut found = false;
        self.list.retain_mut(|(n, v)| {
            if *n != name {
                return true;
            }
            if found {
                return false;
            }
            found = true;
            *v = value.clone();
            true
        });
        if !found {
            self.list.push((name, value));
        }
    }

    /// Sorts the pairs by name, comparing UTF-16 code units; the sort is stable.
    pub fn sort(&mut self) {
        self.list.sort_by(|a, b| jsstring::compare_utf16(&a.0, &b.0));
    }

    /// The `application/x-www-form-urlencoded` serialization.
    pub fn serialize(&self) -> String {
        serialize_urlencoded(&self.list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_operations() {
        let mut p = UrlSearchParams::from_init(Init::String("?a=1&b=2&a=3".into())).expect("string init");
        assert_eq!(p.get_all("a"), vec!["1", "3"]);
        p.set("a".into(), "x".into());
        assert_eq!(p.serialize(), "a=x&b=2");
        p.append("\u{1F600}".into(), "y".into());
        p.append("\u{FFFD}".into(), "z".into());
        p.sort();
        assert_eq!(p.entries()[2].0, "\u{1F600}");
        p.delete("b", Some("3"));
        assert!(p.has("b", None));
        p.delete("b", None);
        assert_eq!(p.size(), 3);
    }

    #[test]
    fn sequence_needs_pairs() {
        assert_eq!(
            UrlSearchParams::from_init(Init::Sequence(vec![vec!["a".into()]])),
            Err(NOT_A_PAIR)
        );
    }
}
