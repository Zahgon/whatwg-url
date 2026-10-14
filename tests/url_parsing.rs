// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! URL parsing, the setters, hosts, validation errors and the valid URL string checker, ported from the original's
//! test suite (which runs the web-platform-tests URL data).

use whatwg_url::jsstring::from_str;
use whatwg_url::url::Url;
use whatwg_url::url_state_machine::{basic_url_parse_with_errors, parse_url, ParseOptions};
use whatwg_url::url_string_validator::is_valid_url_string;

fn href(input: &str, base: Option<&str>) -> Option<String> {
    Url::new(input, base).ok().map(|u| u.href())
}

#[test]
fn parses_absolute_urls() {
    let cases = [
        ("http://example\t.\norg", "http://example.org/"),
        (
            "http://user:pass@foo:21/bar;par?b#c",
            "http://user:pass@foo:21/bar;par?b#c",
        ),
        ("https://test:@test", "https://test@test/"),
        ("http://f:00000000000000/c", "http://f:0/c"),
        ("http://f:00000000000000000000080/c", "http://f/c"),
        ("http:/example.com/", "http://example.com/"),
        ("ftp:/example.com/", "ftp://example.com/"),
        ("madeupscheme:/example.com/", "madeupscheme:/example.com/"),
        ("http://example.com/foo/%2e%2", "http://example.com/foo/%2e%2"),
        (
            "http://example.com/foo/%2e./%2e%2e/.%2e/%2e.bar",
            "http://example.com/%2e.bar",
        ),
        ("http://www/foo%2Ehtml", "http://www/foo%2Ehtml"),
        (
            "http://example.com/\u{1F600}?\u{1F600}#\u{1F600}",
            "http://example.com/%F0%9F%98%80?%F0%9F%98%80#%F0%9F%98%80",
        ),
        ("sc://\u{F1}/", "sc://%C3%B1/"),
        ("sc: x ?y", "sc: x%20?y"),
        ("non-spec:/.//p", "non-spec:/.//p"),
        ("file:C:/x/../../..", "file:///C:/"),
        ("file://localhost/x", "file:///x"),
        ("http://[1:0::]", "http://[1::]/"),
        ("http://[::127.0.0.1]", "http://[::7f00:1]/"),
        ("http://0x7f.1", "http://127.0.0.1/"),
        ("http://4294967295", "http://255.255.255.255/"),
        ("http://GOO\u{200B}\u{2060}\u{FEFF}goo.com", "http://googoo.com/"),
        ("https://fa\u{DF}.ExAmPlE/", "https://xn--fa-hia.example/"),
        ("http://\u{FF27}\u{FF4F}.com", "http://go.com/"),
    ];
    for (input, expected) in cases {
        assert_eq!(href(input, None).as_deref(), Some(expected), "{input}");
    }
}

#[test]
fn rejects_invalid_urls() {
    for input in [
        "http://4294967296",
        "http://[::1",
        "http://a:b@",
        "https://x x/",
        "http://1.2.3.4.5",
        "sc://\u{0}/",
        "http://[1:2:3:4:5:6:7:8:9]",
        "http://ex%00mple.com",
        "http://xn--\u{E9}/",
        "non-special://[:80/",
        "x",
        "",
    ] {
        assert_eq!(href(input, None), None, "{input:?}");
    }
}

#[test]
fn resolves_relative_references() {
    let base = "http://a/b/c/d;p?q";
    let cases = [
        ("g", "http://a/b/c/g"),
        ("./g", "http://a/b/c/g"),
        ("g/", "http://a/b/c/g/"),
        ("/g", "http://a/g"),
        ("//g", "http://g/"),
        ("?y", "http://a/b/c/d;p?y"),
        ("#s", "http://a/b/c/d;p?q#s"),
        ("", "http://a/b/c/d;p?q"),
        ("..", "http://a/b/"),
        ("../../../g", "http://a/g"),
        ("g;x=1/../y", "http://a/b/c/y"),
        ("\\\\h\\p", "http://h/p"),
    ];
    for (input, expected) in cases {
        assert_eq!(href(input, Some(base)).as_deref(), Some(expected), "{input}");
    }
    assert_eq!(href("#x", Some("mailto:a")).as_deref(), Some("mailto:a#x"));
    assert_eq!(href("x", Some("mailto:a")), None);
    assert_eq!(href("C|", Some("file:///D:/x")).as_deref(), Some("file:///C:"));
}

#[test]
fn setters_follow_the_standard() {
    let mut url = Url::new("https://user:pw@example.com:8443/a/b?x#y", None).expect("parses");
    url.set_protocol("http");
    assert_eq!(url.href(), "http://user:pw@example.com:8443/a/b?x#y");
    url.set_protocol("file");
    assert_eq!(url.protocol(), "http:");
    url.set_port("80");
    assert_eq!(url.port(), "");
    url.set_host("[::1]:81");
    assert_eq!(url.host(), "[::1]:81");
    url.set_hostname("h:1");
    assert_eq!(url.hostname(), "[::1]");
    url.set_username("a b");
    url.set_password(":@");
    assert_eq!(url.href(), "http://a%20b:%3A%40@[::1]:81/a/b?x#y");
    url.set_pathname("../c/./d");
    url.set_search("?q=1 2");
    url.set_hash("f g");
    assert_eq!(url.href(), "http://a%20b:%3A%40@[::1]:81/c/d?q=1%202#f%20g");
    let mut opaque = Url::new("sc:a b ?q#f", None).expect("parses");
    opaque.set_search("");
    opaque.set_hash("");
    assert_eq!(opaque.href(), "sc:a b%20");
    assert!(url.set_href("not a url").is_err());
}

#[test]
fn origins() {
    let origin = |s: &str| Url::new(s, None).expect("parses").origin();
    assert_eq!(origin("blob:https://a.example:8080/x"), "https://a.example:8080");
    assert_eq!(origin("blob:ftp://x/"), "null");
    assert_eq!(origin("file:///x"), "null");
    assert_eq!(origin("WS://H:80/"), "ws://h");
}

#[test]
fn reports_validation_errors() {
    let mut errors = Vec::new();
    let url = basic_url_parse_with_errors(
        &from_str("http://ex%41mple.com\\a"),
        ParseOptions::default(),
        Some(&mut errors),
    );
    assert!(url.is_some());
    assert_eq!(errors, vec!["domain-percent-encoded", "invalid-reverse-solidus"]);
    let mut errors = Vec::new();
    basic_url_parse_with_errors(
        &from_str("http://1.2.3.0x4/"),
        ParseOptions::default(),
        Some(&mut errors),
    );
    assert_eq!(errors, vec!["IPv4-non-decimal-part"]);
}

#[test]
fn checks_valid_url_strings() {
    let base = parse_url(&from_str("https://example.com/a/b"), None).expect("parses");
    assert!(is_valid_url_string(&from_str("https://example.com/%20?x#y"), None));
    assert!(is_valid_url_string(&from_str("../c?d"), Some(&base)));
    assert!(!is_valid_url_string(&from_str("https://exa mple.com/"), None));
    assert!(!is_valid_url_string(&from_str("http://[::1/"), None));
    assert!(!is_valid_url_string(&from_str("a\u{0}b"), Some(&base)));
}
