// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! An implementation of the WHATWG URL Standard's URL API and parsing machinery, ported from the whatwg-url
//! JavaScript package.
//!
//! - [`url::Url`] and [`url_search_params::UrlSearchParams`] are the `URL` and `URLSearchParams` interfaces.
//! - [`url_state_machine`] holds the basic URL parser, the host parsers and the serializers, working on URL records.
//! - [`url_string_validator::is_valid_url_string`] checks the valid URL string grammar.
//! - [`cli`] is the `whatwg-url` command, a JSON-lines front end with JavaScript's value semantics ([`json`],
//!   [`webidl`]).
//!
//! Strings that come from outside the URL API are JavaScript strings ([`jsstring::JsString`], UTF-16 code units that
//! may hold lone surrogates), as in the original.

pub mod cli;
pub mod encoding;
pub mod idna;
pub mod infra;
pub mod json;
pub mod jsstring;
pub mod miscellaneous;
pub mod percent_encoding;
pub mod punycode;
pub mod url;
pub mod url_search_params;
pub mod url_state_machine;
pub mod url_string_validator;
pub mod urlencoded;
pub mod webidl;
