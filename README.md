# whatwg-url

whatwg-url is a full implementation of the WHATWG [URL Standard](https://url.spec.whatwg.org/) in Rust, ported from the JavaScript package of the same name. It can be used standalone, but it also exposes a lot of the internal algorithms that are useful for integrating a URL parser into a project like [jsdom](https://github.com/jsdom/jsdom).

## Specification conformance

whatwg-url is currently up to date with the URL spec up to commit [fde3f74](https://github.com/whatwg/url/commit/fde3f74f063341a28d437216f75735b8b40128f5).

For `file:` URLs, whose [origin is left unspecified](https://url.spec.whatwg.org/#concept-url-origin), whatwg-url chooses to use a new opaque origin (which serializes to `"null"`).

Domains go through [UTS #46](https://www.unicode.org/reports/tr46/) processing with the Unicode 18.0 IDNA mapping table and character classes of the tr46 package, and NFC normalization with Unicode 16.0 data, as the JavaScript package does on Node.js 22. Queries are always encoded as UTF-8.

## Building

The crate needs Rust 1.85 or later and builds offline from its sources:

```sh
cargo build --release
cargo test --release
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Its only dependency is `unicode-normalization` (pinned to 0.1.24, Unicode 16.0).

## API

### The `URL` and `URLSearchParams` interfaces

The main API is `whatwg_url::url::Url` and `whatwg_url::url_search_params::UrlSearchParams`, which follow the [`URL`](https://url.spec.whatwg.org/#url-class) and [`URLSearchParams`](https://url.spec.whatwg.org/#interface-urlsearchparams) interfaces in all ways:

```rust
use whatwg_url::url::Url;

let mut url = Url::new("../c?x=1", Some("https://example.org/a/b")).unwrap();
assert_eq!(url.href(), "https://example.org/c?x=1");
url.set_port("8080");
url.update_search_params(|params| params.append("y".into(), "z w".into()));
assert_eq!(url.href(), "https://example.org:8080/c?x=1&y=z+w");
```

`Url::new` fails with `UrlError::InvalidBase` or `UrlError::InvalidUrl` where the JavaScript constructor throws; `Url::parse` and `Url::can_parse` are the static methods. Every attribute has a getter and a setter; changes to the search parameters go through `Url::update_search_params`, which writes the serialized list back to the URL's query.

### Low-level URL Standard API

The `url_state_machine` module holds the algorithms on URL records (`UrlRecord`, with its `Host` and `UrlPath`):

- [Basic URL parser](https://url.spec.whatwg.org/#concept-basic-url-parser): `basic_url_parse(input, ParseOptions { base, url })`, where `url` is a record to modify together with a `StateOverride` (`SchemeStart`, `Host`, `Hostname`, `Port`, `PathStart`, `Query` or `Fragment`)
- URL parser with [validation errors](https://url.spec.whatwg.org/#validation-error): `basic_url_parse_with_errors(input, options, Some(&mut errors))`
- [URL parser](https://url.spec.whatwg.org/#concept-url-parser): `parse_url(input, base)`
- [URL serializer](https://url.spec.whatwg.org/#concept-url-serializer): `serialize_url(record, exclude_fragment)`
- [Host serializer](https://url.spec.whatwg.org/#concept-host-serializer): `serialize_host(host)`
- [URL path serializer](https://url.spec.whatwg.org/#url-path-serializer): `serialize_path(record)`
- [Origin](https://url.spec.whatwg.org/#concept-url-origin) serializer: `serialize_url_origin(record)`
- [Set the username](https://url.spec.whatwg.org/#set-the-username) and [password](https://url.spec.whatwg.org/#set-the-password): `set_the_username(record, username)`, `set_the_password(record, password)`
- [Has an opaque path](https://url.spec.whatwg.org/#url-opaque-path): `has_an_opaque_path(record)`
- [Cannot have a username/password/port](https://url.spec.whatwg.org/#cannot-have-a-username-password-port): `cannot_have_a_username_password_port(record)`

Elsewhere:

- [Valid URL string](https://url.spec.whatwg.org/#valid-url-string) checker: `url_string_validator::is_valid_url_string(input, base)`
- [Percent decode bytes](https://url.spec.whatwg.org/#percent-decode) and [a string](https://url.spec.whatwg.org/#string-percent-decode): `percent_encoding::percent_decode_bytes(bytes)`, `percent_encoding::percent_decode_string(input)`
- The `application/x-www-form-urlencoded` [parser](https://url.spec.whatwg.org/#concept-urlencoded-parser) and [serializer](https://url.spec.whatwg.org/#concept-urlencoded-serializer): `urlencoded::parse_urlencoded`, `urlencoded::serialize_urlencoded`
- UTS #46 `ToASCII`: `idna::to_ascii(domain, options)`, and Punycode: `punycode::encode`, `punycode::decode`

Strings that come from outside the URL API are JavaScript strings (`jsstring::JsString`, UTF-16 code units that may hold lone surrogates), so these functions treat lone surrogates as the JavaScript package does.

## The `whatwg-url` command

The binary answers JSON-lines requests on standard input, one JSON response line each on standard output, with JavaScript's semantics for the values it reads and writes (`JSON.parse` and `JSON.stringify`, the WebIDL conversion of arguments). Requests drive the `URL` and `URLSearchParams` interfaces and the low-level functions:

```sh
echo '{"op":"url","input":"HTTPS://Example.com/a/../b?x=1","steps":[["set","port","8080"],["params","append","y","z"]]}' | whatwg-url
```

The ops are `url`, `parse`, `canParse`, `params`, `record`, `validate`, `serialize`, `percentDecode` and `percentDecodeBytes`; run `whatwg-url --help` for the request forms. The exit status is 0 when no response was an error and 1 otherwise; any argument prints the usage text and exits with status 2.
