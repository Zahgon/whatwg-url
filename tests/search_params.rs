// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! `URLSearchParams` and the `application/x-www-form-urlencoded` format, ported from the original's test suite.

use whatwg_url::url::Url;
use whatwg_url::url_search_params::{Init, UrlSearchParams};

fn from(s: &str) -> UrlSearchParams {
    UrlSearchParams::from_init(Init::String(s.to_owned())).expect("string init")
}

#[test]
fn parses_and_serializes() {
    let params = from("?a=b+c&d=%26&e&=f&%zz=%E2%82");
    let pairs: Vec<(&str, &str)> = params.entries().iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    assert_eq!(
        pairs,
        vec![("a", "b c"), ("d", "&"), ("e", ""), ("", "f"), ("%zz", "\u{FFFD}")]
    );
    assert_eq!(params.serialize(), "a=b+c&d=%26&e=&=f&%25zz=%EF%BF%BD");
    assert_eq!(from("a=~!'()*").serialize(), "a=%7E%21%27%28%29*");
}

#[test]
fn sorts_by_code_units_and_keeps_order_of_equal_names() {
    let mut params = from("z=1&\u{FFFD}=2&\u{1F600}=3&a=4&z=5");
    params.sort();
    assert_eq!(params.serialize(), "a=4&z=1&z=5&%F0%9F%98%80=3&%EF%BF%BD=2");
}

#[test]
fn list_methods() {
    let mut params = from("a=1&b=2&a=3");
    params.set("a".into(), "x".into());
    params.delete("b", Some("9"));
    assert!(params.has("b", Some("2")));
    params.delete("b", None);
    assert_eq!(params.get("a"), Some("x"));
    assert_eq!(params.get_all("missing"), Vec::<&str>::new());
    assert_eq!(params.size(), 1);
}

#[test]
fn updates_the_url_query() {
    let mut url = Url::new("http://h/?q=a b", None).expect("parses");
    assert_eq!(url.search(), "?q=a%20b");
    url.update_search_params(|p| p.append("x".into(), "y z".into()));
    assert_eq!(url.search(), "?q=a+b&x=y+z");
    url.update_search_params(|p| {
        p.delete("q", None);
        p.delete("x", None);
    });
    assert_eq!(url.href(), "http://h/");
    url.set_search("?n=1");
    assert_eq!(url.search_params().get("n"), Some("1"));
}

#[test]
fn sequences_need_pairs() {
    let init = Init::Sequence(vec![vec!["a".into(), "b".into()], vec!["c".into()]]);
    assert!(UrlSearchParams::from_init(init).is_err());
}
