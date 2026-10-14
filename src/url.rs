// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The `URL` interface: a URL record with its attribute getters and setters, and the `URLSearchParams` list linked to
//! its query.

use crate::jsstring;
use crate::url_search_params::UrlSearchParams;
use crate::url_state_machine::{
    basic_url_parse, cannot_have_a_username_password_port, has_an_opaque_path, serialize_host, serialize_path,
    serialize_url, serialize_url_origin, set_the_password, set_the_username, ParseOptions, StateOverride, UrlRecord,
};
use crate::urlencoded::parse_urlencoded_string;

/// Why the `URL` constructor failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    /// The base URL does not parse.
    InvalidBase(String),
    /// The URL does not parse.
    InvalidUrl(String),
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlError::InvalidBase(base) => write!(f, "Invalid base URL: {base}"),
            UrlError::InvalidUrl(url) => write!(f, "Invalid URL: {url}"),
        }
    }
}

impl std::error::Error for UrlError {}

fn parse_str(input: &str, options: ParseOptions<'_>) -> Option<UrlRecord> {
    basic_url_parse(&jsstring::from_str(input), options)
}

/// A URL object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    url: UrlRecord,
    query: UrlSearchParams,
}

impl Url {
    /// `new URL(url, base)`.
    pub fn new(url: &str, base: Option<&str>) -> Result<Self, UrlError> {
        let parsed_base = match base {
            Some(base) => {
                Some(parse_str(base, ParseOptions::default()).ok_or_else(|| UrlError::InvalidBase(base.to_owned()))?)
            }
            None => None,
        };
        let parsed = parse_str(
            url,
            ParseOptions {
                base: parsed_base.as_ref(),
                url: None,
            },
        )
        .ok_or_else(|| UrlError::InvalidUrl(url.to_owned()))?;
        let query = UrlSearchParams::from_query(parsed.query.as_deref().unwrap_or(""));
        Ok(Url { url: parsed, query })
    }

    /// `URL.parse(url, base)`: the URL, or `None` where the constructor throws.
    pub fn parse(url: &str, base: Option<&str>) -> Option<Self> {
        Url::new(url, base).ok()
    }

    /// `URL.canParse(url, base)`.
    pub fn can_parse(url: &str, base: Option<&str>) -> bool {
        let parsed_base = match base {
            Some(base) => match parse_str(base, ParseOptions::default()) {
                Some(b) => Some(b),
                None => return false,
            },
            None => None,
        };
        parse_str(
            url,
            ParseOptions {
                base: parsed_base.as_ref(),
                url: None,
            },
        )
        .is_some()
    }

    /// The URL record.
    pub fn record(&self) -> &UrlRecord {
        &self.url
    }

    fn reparse(&mut self, input: &str, state_override: StateOverride) {
        // A setter ignores a failed parse; the record keeps whatever the parser changed before it failed.
        let _ = parse_str(
            input,
            ParseOptions {
                base: None,
                url: Some((&mut self.url, state_override)),
            },
        );
    }

    /// The `href` attribute.
    pub fn href(&self) -> String {
        serialize_url(&self.url, false)
    }

    /// Sets `href`: the whole URL is replaced, or the setter throws for a string that does not parse.
    pub fn set_href(&mut self, value: &str) -> Result<(), UrlError> {
        let parsed = parse_str(value, ParseOptions::default()).ok_or_else(|| UrlError::InvalidUrl(value.to_owned()))?;
        self.query.set_list(match &parsed.query {
            Some(query) => parse_urlencoded_string(&jsstring::from_str(query)),
            None => Vec::new(),
        });
        self.url = parsed;
        Ok(())
    }

    /// The `origin` attribute.
    pub fn origin(&self) -> String {
        serialize_url_origin(&self.url)
    }

    /// The `protocol` attribute: the scheme and `:`.
    pub fn protocol(&self) -> String {
        format!("{}:", self.url.scheme)
    }

    /// Sets `protocol`.
    pub fn set_protocol(&mut self, value: &str) {
        self.reparse(&format!("{value}:"), StateOverride::SchemeStart);
    }

    /// The `username` attribute.
    pub fn username(&self) -> String {
        self.url.username.clone()
    }

    /// Sets `username`, unless the URL cannot have one.
    pub fn set_username(&mut self, value: &str) {
        if !cannot_have_a_username_password_port(&self.url) {
            set_the_username(&mut self.url, &jsstring::from_str(value));
        }
    }

    /// The `password` attribute.
    pub fn password(&self) -> String {
        self.url.password.clone()
    }

    /// Sets `password`, unless the URL cannot have one.
    pub fn set_password(&mut self, value: &str) {
        if !cannot_have_a_username_password_port(&self.url) {
            set_the_password(&mut self.url, &jsstring::from_str(value));
        }
    }

    /// The `host` attribute: the host and, when there is one, `:` and the port.
    pub fn host(&self) -> String {
        match (&self.url.host, self.url.port) {
            (None, _) => String::new(),
            (Some(host), None) => serialize_host(host),
            (Some(host), Some(port)) => format!("{}:{port}", serialize_host(host)),
        }
    }

    /// Sets `host`, unless the URL has an opaque path.
    pub fn set_host(&mut self, value: &str) {
        if !has_an_opaque_path(&self.url) {
            self.reparse(value, StateOverride::Host);
        }
    }

    /// The `hostname` attribute.
    pub fn hostname(&self) -> String {
        self.url.host.as_ref().map(serialize_host).unwrap_or_default()
    }

    /// Sets `hostname`, unless the URL has an opaque path.
    pub fn set_hostname(&mut self, value: &str) {
        if !has_an_opaque_path(&self.url) {
            self.reparse(value, StateOverride::Hostname);
        }
    }

    /// The `port` attribute.
    pub fn port(&self) -> String {
        self.url.port.map(|p| p.to_string()).unwrap_or_default()
    }

    /// Sets `port`, unless the URL cannot have one; the empty string removes it.
    pub fn set_port(&mut self, value: &str) {
        if cannot_have_a_username_password_port(&self.url) {
            return;
        }
        if value.is_empty() {
            self.url.port = None;
        } else {
            self.reparse(value, StateOverride::Port);
        }
    }

    /// The `pathname` attribute.
    pub fn pathname(&self) -> String {
        serialize_path(&self.url)
    }

    /// Sets `pathname`, unless the URL has an opaque path.
    pub fn set_pathname(&mut self, value: &str) {
        if has_an_opaque_path(&self.url) {
            return;
        }
        self.url.path = crate::url_state_machine::UrlPath::Segments(Vec::new());
        self.reparse(value, StateOverride::PathStart);
    }

    /// The `search` attribute: `?` and the query, or the empty string for a null or empty query.
    pub fn search(&self) -> String {
        match self.url.query.as_deref() {
            None | Some("") => String::new(),
            Some(query) => format!("?{query}"),
        }
    }

    /// Sets `search` (a leading `?` is removed) and the search parameters with it.
    pub fn set_search(&mut self, value: &str) {
        if value.is_empty() {
            self.url.query = None;
            self.query.set_list(Vec::new());
            return;
        }
        let input = value.strip_prefix('?').unwrap_or(value);
        self.url.query = Some(String::new());
        self.reparse(input, StateOverride::Query);
        // The query was set to the empty string above and the query state only appends to it.
        let query = jsstring::from_str(self.url.query.as_deref().unwrap_or(""));
        self.query.set_list(parse_urlencoded_string(&query));
    }

    /// The `hash` attribute: `#` and the fragment, or the empty string for a null or empty fragment.
    pub fn hash(&self) -> String {
        match self.url.fragment.as_deref() {
            None | Some("") => String::new(),
            Some(fragment) => format!("#{fragment}"),
        }
    }

    /// Sets `hash` (a leading `#` is removed).
    pub fn set_hash(&mut self, value: &str) {
        if value.is_empty() {
            self.url.fragment = None;
            return;
        }
        let input = value.strip_prefix('#').unwrap_or(value);
        self.url.fragment = Some(String::new());
        self.reparse(input, StateOverride::Fragment);
    }

    /// The `searchParams` attribute.
    pub fn search_params(&self) -> &UrlSearchParams {
        &self.query
    }

    /// Runs `f` on the search parameters, then writes their serialization back to the query (null when empty), as
    /// every list change of a URL's `URLSearchParams` does.
    pub fn update_search_params<T>(&mut self, f: impl FnOnce(&mut UrlSearchParams) -> T) -> T {
        let result = f(&mut self.query);
        let serialized = self.query.serialize();
        self.url.query = if serialized.is_empty() { None } else { Some(serialized) };
        result
    }

    /// `toJSON()`: the `href`.
    pub fn to_json(&self) -> String {
        self.href()
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.href())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_and_getters() {
        let url = Url::new("../c?x=1#y", Some("https://user:pw@EXAMPLE.org:8443/a/b")).expect("parses");
        assert_eq!(url.href(), "https://user:pw@example.org:8443/c?x=1#y");
        assert_eq!(url.origin(), "https://example.org:8443");
        assert_eq!(url.search_params().get("x"), Some("1"));
        assert_eq!(Url::new("x", None), Err(UrlError::InvalidUrl("x".into())));
        assert_eq!(
            Url::new("x", Some("y")).map_err(|e| e.to_string()),
            Err("Invalid base URL: y".into())
        );
    }

    #[test]
    fn setters() {
        let mut url = Url::new("http://h/p?a=b c", None).expect("parses");
        url.set_port("8080x");
        url.set_protocol("ws");
        url.set_hash("#");
        url.update_search_params(|p| p.append("d".into(), "e f".into()));
        assert_eq!(url.href(), "ws://h:8080/p?a=b+c&d=e+f#");
        url.set_search("");
        url.set_pathname("/x/../y");
        assert_eq!(url.to_string(), "ws://h:8080/y#");
        assert!(url.set_href("nope").is_err());
    }
}
