// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The `whatwg-url` command: JSON-lines requests on standard input, one JSON response line each on standard output.
//!
//! Every non-empty line of standard input (decoded as UTF-8, split at `\n`) is one request, parsed as `JSON.parse`
//! parses it; every response is serialized as `JSON.stringify` writes it. The exit status is 0 when no response and
//! no step result was an error and 1 otherwise; any command-line argument is a usage error (exit status 2).

use crate::json::{self, is_truthy, stringify, stringify_or_undefined, to_number, to_uint8, JsError, Object, Value};
use crate::jsstring::{self, JsString};
use crate::percent_encoding::{percent_decode_bytes, percent_decode_string};
use crate::url::{Url, UrlError};
use crate::url_search_params::UrlSearchParams;
use crate::url_state_machine::{
    basic_url_parse, basic_url_parse_with_errors, cannot_have_a_username_password_port, has_an_opaque_path,
    serialize_host, serialize_path, serialize_url, serialize_url_origin, set_the_password, set_the_username, Host,
    ParseOptions, StateOverride, UrlPath, UrlRecord,
};
use crate::url_string_validator::is_valid_url_string;
use crate::webidl::{require_arguments, search_params_init, usv_string};

/// The usage text, written to standard error for any command-line argument.
pub const USAGE: &str = concat!(
    "usage: whatwg-url < requests.jsonl\n",
    "\n",
    "Reads one JSON request per line on standard input and writes one JSON response per line.\n",
    "Requests: {\"op\":\"url\",\"input\":V,\"base\":V,\"steps\":[...]}, {\"op\":\"parse\",\"input\":V,\"base\":V},\n",
    "          {\"op\":\"canParse\",\"input\":V,\"base\":V}, {\"op\":\"params\",\"init\":V,\"steps\":[...]},\n",
    "          {\"op\":\"record\",\"input\":S,\"base\":S,\"url\":S,\"stateOverride\":S}, {\"op\":\"validate\",\"input\":S,\"base\":S},\n",
    "          {\"op\":\"serialize\",\"input\":S,\"base\":S,\"excludeFragment\":V,\"username\":S,\"password\":S},\n",
    "          {\"op\":\"percentDecode\",\"input\":S}, {\"op\":\"percentDecodeBytes\",\"bytes\":[...]}\n",
);

const SETTABLE: [&str; 10] = [
    "href", "protocol", "username", "password", "host", "hostname", "port", "pathname", "search", "hash",
];

/// The outcome of one run of the command.
pub struct Output {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
    /// The exit status.
    pub status: i32,
}

/// Runs the command on its arguments (without the program name) and standard input.
pub fn run(args: &[String], stdin: &[u8]) -> Output {
    if !args.is_empty() {
        return Output {
            stdout: Vec::new(),
            stderr: USAGE.as_bytes().to_vec(),
            status: 2,
        };
    }
    let text = String::from_utf8_lossy(stdin);
    let mut session = Session { failed: false };
    let mut stdout = String::new();
    for line in text.split('\n').filter(|line| !line.is_empty()) {
        let response = match json::parse(&jsstring::from_str(line)) {
            Ok(request) => session.handle(&request).unwrap_or_else(|e| session.error_response(&e)),
            Err(e) => session.error_response(&e),
        };
        // Responses are built by the command and nest only a few levels, so serializing one does not reach
        // JSON.stringify's depth limit; if it ever did, the line reports that error as the reference would.
        let text = match stringify(&response) {
            Ok(text) => text,
            Err(error) => session.error_line(&error),
        };
        stdout.push_str(&jsstring::to_well_formed(&text));
        stdout.push('\n');
    }
    Output {
        stdout: stdout.into_bytes(),
        stderr: Vec::new(),
        status: i32::from(session.failed),
    }
}

fn string(s: &str) -> Value {
    Value::String(jsstring::from_str(s))
}

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut out = Object::new();
    for (key, value) in members {
        out.insert(jsstring::from_str(key), value);
    }
    Value::Object(out)
}

fn request_error(message: impl AsRef<str>) -> JsError {
    JsError::new("RequestError", message)
}

fn url_error(error: UrlError) -> JsError {
    JsError::type_error(error.to_string())
}

fn pairs_value(pairs: &[(String, String)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(n, v)| Value::Array(vec![string(n), string(v)]))
            .collect(),
    )
}

fn snapshot(url: &Url) -> Value {
    object(vec![
        ("href", string(&url.href())),
        ("origin", string(&url.origin())),
        ("protocol", string(&url.protocol())),
        ("username", string(&url.username())),
        ("password", string(&url.password())),
        ("host", string(&url.host())),
        ("hostname", string(&url.hostname())),
        ("port", string(&url.port())),
        ("pathname", string(&url.pathname())),
        ("search", string(&url.search())),
        ("hash", string(&url.hash())),
        ("params", pairs_value(url.search_params().entries())),
    ])
}

fn params_state(params: &UrlSearchParams) -> Value {
    object(vec![
        ("entries", pairs_value(params.entries())),
        ("string", string(&params.serialize())),
    ])
}

fn nullable(value: Option<&str>) -> Value {
    value.map_or(Value::Null, string)
}

fn record_value(url: &UrlRecord) -> Value {
    let host = match &url.host {
        None => Value::Null,
        Some(Host::Name(name)) => string(name),
        Some(Host::Ipv4(address)) => Value::Number(f64::from(*address)),
        Some(Host::Ipv6(pieces)) => Value::Array(pieces.iter().map(|&p| Value::Number(f64::from(p))).collect()),
    };
    let path = match &url.path {
        UrlPath::Opaque(path) => string(path),
        UrlPath::Segments(segments) => Value::Array(segments.iter().map(|s| string(s)).collect()),
    };
    object(vec![
        ("scheme", string(&url.scheme)),
        ("username", string(&url.username)),
        ("password", string(&url.password)),
        ("host", host),
        ("port", url.port.map_or(Value::Null, |p| Value::Number(f64::from(p)))),
        ("path", path),
        ("query", nullable(url.query.as_deref())),
        ("fragment", nullable(url.fragment.as_deref())),
    ])
}

fn optional_record(value: Option<&UrlRecord>) -> Value {
    value.map_or(Value::Null, record_value)
}

/// One request's view of its members.
struct Request<'a>(&'a Object);

impl<'a> Request<'a> {
    fn get(&self, name: &str) -> Option<&'a Value> {
        self.0.get(name)
    }

    fn has(&self, name: &str) -> bool {
        self.0.has(name)
    }

    fn string_member(&self, name: &str) -> Result<&'a JsString, JsError> {
        match self.get(name) {
            Some(Value::String(s)) => Ok(s),
            _ => Err(request_error(format!("{name} must be a string"))),
        }
    }

    fn array_member(&self, name: &str) -> Result<&'a [Value], JsError> {
        match self.get(name) {
            None => Ok(&[]),
            Some(Value::Array(items)) => Ok(items),
            Some(_) => Err(request_error(format!("{name} must be an array"))),
        }
    }

    /// The URL constructor arguments: the input, then the base only when the request has one.
    fn url_arguments(&self) -> Vec<&'a Value> {
        let mut args = Vec::new();
        if let Some(input) = self.get("input") {
            args.push(input);
            if let Some(base) = self.get("base") {
                args.push(base);
            }
        }
        args
    }

    /// `basicURLParse` of a string member, when the request has it.
    fn optional_record(&self, name: &str) -> Result<Option<Option<UrlRecord>>, JsError> {
        if !self.has(name) {
            return Ok(None);
        }
        let text = self.string_member(name)?;
        Ok(Some(basic_url_parse(text, ParseOptions::default())))
    }
}

/// The WebIDL-converted `(url, base)` arguments of the URL constructor and its static methods.
fn converted_url_arguments(prefix: &str, args: &[&Value]) -> Result<(String, Option<String>), JsError> {
    require_arguments(prefix, args.len(), 1)?;
    let input = usv_string(args.first().copied())?;
    let base = args.get(1).map(|b| usv_string(Some(b))).transpose()?;
    Ok((input, base))
}

/// Where a `URLSearchParams` call goes: a standalone object, or the one a URL owns (whose changes update the URL).
enum ParamsTarget<'a> {
    Standalone(&'a mut UrlSearchParams),
    OfUrl(&'a mut Url),
}

impl ParamsTarget<'_> {
    fn read(&self) -> &UrlSearchParams {
        match self {
            ParamsTarget::Standalone(params) => params,
            ParamsTarget::OfUrl(url) => url.search_params(),
        }
    }

    fn modify(&mut self, f: impl FnOnce(&mut UrlSearchParams)) {
        match self {
            ParamsTarget::Standalone(params) => f(params),
            ParamsTarget::OfUrl(url) => url.update_search_params(f),
        }
    }
}

fn method_prefix(name: &str) -> String {
    format!("Failed to execute '{name}' on 'URLSearchParams'")
}

/// One call on a `URLSearchParams` object, `[name, args...]`; `None` is an `undefined` result.
fn call_params(target: &mut ParamsTarget<'_>, call: &[Value]) -> Result<Option<Value>, JsError> {
    let Some(Value::String(name)) = call.first() else {
        return Err(request_error("a call must be an array starting with a name"));
    };
    let args = &call[1..];
    let name = jsstring::to_well_formed(name);
    // The converted argument `i`, `None` when it is absent (only optional arguments can be: the argument count is
    // checked first).
    let arg = |i: usize| args.get(i).map(|v| usv_string(Some(v))).transpose();
    let pairs = |p: &UrlSearchParams| pairs_value(p.entries());
    match name.as_str() {
        "size" => Ok(Some(Value::Number(target.read().size() as f64))),
        "append" | "set" => {
            require_arguments(&method_prefix(&name), args.len(), 2)?;
            let (key, value) = (arg(0)?.unwrap_or_default(), arg(1)?.unwrap_or_default());
            if name == "append" {
                target.modify(|p| p.append(key, value));
            } else {
                target.modify(|p| p.set(key, value));
            }
            Ok(None)
        }
        "delete" => {
            require_arguments(&method_prefix(&name), args.len(), 1)?;
            let (key, value) = (arg(0)?.unwrap_or_default(), arg(1)?);
            target.modify(|p| p.delete(&key, value.as_deref()));
            Ok(None)
        }
        "get" => {
            require_arguments(&method_prefix(&name), args.len(), 1)?;
            Ok(Some(nullable(target.read().get(&arg(0)?.unwrap_or_default()))))
        }
        "getAll" => {
            require_arguments(&method_prefix(&name), args.len(), 1)?;
            let key = arg(0)?.unwrap_or_default();
            let values = target.read().get_all(&key).into_iter().map(string).collect();
            Ok(Some(Value::Array(values)))
        }
        "has" => {
            require_arguments(&method_prefix(&name), args.len(), 1)?;
            let (key, value) = (arg(0)?.unwrap_or_default(), arg(1)?);
            Ok(Some(Value::Bool(target.read().has(&key, value.as_deref()))))
        }
        "sort" => {
            target.modify(UrlSearchParams::sort);
            Ok(None)
        }
        "toString" => Ok(Some(string(&target.read().serialize()))),
        "entries" => Ok(Some(pairs(target.read()))),
        "keys" => Ok(Some(Value::Array(
            target.read().entries().iter().map(|(n, _)| string(n)).collect(),
        ))),
        "values" => Ok(Some(Value::Array(
            target.read().entries().iter().map(|(_, v)| string(v)).collect(),
        ))),
        "forEach" => Ok(Some(Value::Array(
            target
                .read()
                .entries()
                .iter()
                .map(|(n, v)| Value::Array(vec![string(v), string(n)]))
                .collect(),
        ))),
        _ => Err(request_error(format!("unknown call: {}", json_text(&name)))),
    }
}

/// A call of the `params` op: an array starting with a name.
fn call_array(call: &Value) -> Result<&[Value], JsError> {
    match call {
        Value::Array(items) => Ok(items),
        _ => Err(request_error("a call must be an array starting with a name")),
    }
}

fn json_text(s: &str) -> String {
    jsstring::to_well_formed(&json::quote_string(&jsstring::from_str(s)))
}

fn with_value(value: Option<Value>, rest: (&str, Value)) -> Value {
    let mut members = Vec::new();
    if let Some(value) = value {
        members.push(("value", value));
    }
    members.push(rest);
    object(members)
}

fn run_step(url: &mut Url, step: &Value) -> Result<Value, JsError> {
    let Value::Array(step) = step else {
        return Err(request_error("a step must be an array starting with a name"));
    };
    let Some(Value::String(name)) = step.first() else {
        return Err(request_error("a step must be an array starting with a name"));
    };
    match jsstring::to_well_formed(name).as_str() {
        "set" => {
            let attribute = match step.get(1) {
                Some(Value::String(a)) => SETTABLE.iter().find(|s| jsstring::eq_ascii(a, s)).copied(),
                _ => None,
            };
            let Some(attribute) = attribute else {
                return Err(request_error(format!(
                    "unknown attribute: {}",
                    stringify_or_undefined(step.get(1))?
                )));
            };
            let value = usv_string(step.get(2))?;
            match attribute {
                "href" => url.set_href(&value).map_err(url_error)?,
                "protocol" => url.set_protocol(&value),
                "username" => url.set_username(&value),
                "password" => url.set_password(&value),
                "host" => url.set_host(&value),
                "hostname" => url.set_hostname(&value),
                "port" => url.set_port(&value),
                "pathname" => url.set_pathname(&value),
                "search" => url.set_search(&value),
                _ => url.set_hash(&value),
            }
            Ok(snapshot(url))
        }
        "params" => {
            let value = call_params(&mut ParamsTarget::OfUrl(url), &step[1..])?;
            Ok(with_value(value, ("url", snapshot(url))))
        }
        "toJSON" => Ok(object(vec![("value", string(&url.to_json()))])),
        "toString" => Ok(object(vec![("value", string(&url.to_string()))])),
        other => Err(request_error(format!("unknown step: {}", json_text(other)))),
    }
}

struct Session {
    failed: bool,
}

impl Session {
    fn error_response(&mut self, error: &JsError) -> Value {
        self.failed = true;
        object(vec![(
            "error",
            object(vec![
                ("name", string(error.name)),
                ("message", Value::String(error.message.clone())),
            ]),
        )])
    }

    /// The serialized error response, written directly so that it cannot fail.
    fn error_line(&mut self, error: &JsError) -> JsString {
        self.failed = true;
        let mut line = jsstring::from_str("{\"error\":{\"name\":");
        line.extend(json::quote_string(&jsstring::from_str(error.name)));
        line.extend(jsstring::from_str(",\"message\":"));
        line.extend(json::quote_string(&error.message));
        line.extend(jsstring::from_str("}}"));
        line
    }

    fn guarded(&mut self, result: Result<Value, JsError>) -> Value {
        result.unwrap_or_else(|e| self.error_response(&e))
    }

    fn handle(&mut self, request: &Value) -> Result<Value, JsError> {
        let Value::Object(members) = request else {
            return Err(request_error("a request must be a JSON object"));
        };
        let request = Request(members);
        let op = match request.get("op") {
            Some(Value::String(op)) => jsstring::to_string(op),
            _ => None,
        };
        match op.as_deref() {
            Some("url") => self.url_op(&request),
            Some("parse") => {
                let args = request.url_arguments();
                let (input, base) = converted_url_arguments("Failed to execute 'parse' on 'URL'", &args)?;
                let url = Url::parse(&input, base.as_deref());
                Ok(object(vec![("url", url.as_ref().map_or(Value::Null, snapshot))]))
            }
            Some("canParse") => {
                let args = request.url_arguments();
                let (input, base) = converted_url_arguments("Failed to execute 'canParse' on 'URL'", &args)?;
                Ok(object(vec![(
                    "result",
                    Value::Bool(Url::can_parse(&input, base.as_deref())),
                )]))
            }
            Some("params") => self.params_op(&request),
            Some("record") => record_op(&request),
            Some("validate") => validate_op(&request),
            Some("serialize") => serialize_op(&request),
            Some("percentDecode") => {
                let input = request.string_member("input")?;
                Ok(object(vec![("bytes", bytes_value(&percent_decode_string(input)))]))
            }
            Some("percentDecodeBytes") => {
                let Some(Value::Array(items)) = request.get("bytes") else {
                    return Err(request_error("bytes must be an array"));
                };
                let bytes = items
                    .iter()
                    .map(|v| to_number(v).map(to_uint8))
                    .collect::<Result<Vec<u8>, _>>()?;
                Ok(object(vec![("bytes", bytes_value(&percent_decode_bytes(&bytes)))]))
            }
            _ => Err(request_error(format!(
                "unknown op: {}",
                stringify_or_undefined(request.get("op"))?
            ))),
        }
    }

    fn url_op(&mut self, request: &Request<'_>) -> Result<Value, JsError> {
        let steps = request.array_member("steps")?;
        let args = request.url_arguments();
        let (input, base) = converted_url_arguments("Failed to construct 'URL'", &args)?;
        let mut url = Url::new(&input, base.as_deref()).map_err(url_error)?;
        let first = snapshot(&url);
        let results = steps.iter().map(|step| run_step(&mut url, step)).collect::<Vec<_>>();
        let results = results.into_iter().map(|r| self.guarded(r)).collect();
        Ok(object(vec![("url", first), ("steps", Value::Array(results))]))
    }

    fn params_op(&mut self, request: &Request<'_>) -> Result<Value, JsError> {
        let steps = request.array_member("steps")?;
        let mut params = match request.get("init") {
            Some(init) => UrlSearchParams::from_init(search_params_init(init)?).map_err(JsError::type_error)?,
            None => UrlSearchParams::new(),
        };
        let first = params_state(&params);
        let mut results = Vec::with_capacity(steps.len());
        for call in steps {
            let result = call_array(call)
                .and_then(|call| call_params(&mut ParamsTarget::Standalone(&mut params), call))
                .map(|value| with_value(value, ("params", params_state(&params))));
            results.push(self.guarded(result));
        }
        Ok(object(vec![("params", first), ("steps", Value::Array(results))]))
    }
}

fn bytes_value(bytes: &[u8]) -> Value {
    Value::Array(bytes.iter().map(|&b| Value::Number(f64::from(b))).collect())
}

fn record_op(request: &Request<'_>) -> Result<Value, JsError> {
    let input = request.string_member("input")?;
    let base = request.optional_record("base")?.flatten();
    if request.has("url") != request.has("stateOverride") {
        return Err(request_error("url and stateOverride go together"));
    }
    if !request.has("url") {
        let result = basic_url_parse(
            input,
            ParseOptions {
                base: base.as_ref(),
                url: None,
            },
        );
        return Ok(object(vec![("result", optional_record(result.as_ref()))]));
    }
    let Some(mut url) = request.optional_record("url")?.flatten() else {
        return Err(request_error("url must be a URL string that parses"));
    };
    let state_override = match request.get("stateOverride") {
        Some(Value::String(name)) => jsstring::to_string(name).as_deref().and_then(StateOverride::from_name),
        _ => None,
    };
    let Some(state_override) = state_override else {
        return Err(request_error(format!(
            "unknown stateOverride: {}",
            stringify_or_undefined(request.get("stateOverride"))?
        )));
    };
    if state_override == StateOverride::PathStart && has_an_opaque_path(&url) {
        return Err(request_error("path start needs a url without an opaque path"));
    }
    let result = basic_url_parse(
        input,
        ParseOptions {
            base: base.as_ref(),
            url: Some((&mut url, state_override)),
        },
    );
    Ok(object(vec![
        ("result", optional_record(result.as_ref())),
        ("url", record_value(&url)),
    ]))
}

fn validate_op(request: &Request<'_>) -> Result<Value, JsError> {
    let input = request.string_member("input")?;
    let base = request.optional_record("base")?.flatten();
    let mut errors = Vec::new();
    let url = basic_url_parse_with_errors(
        input,
        ParseOptions {
            base: base.as_ref(),
            url: None,
        },
        Some(&mut errors),
    );
    Ok(object(vec![
        ("url", optional_record(url.as_ref())),
        ("errors", Value::Array(errors.into_iter().map(string).collect())),
        ("valid", Value::Bool(is_valid_url_string(input, base.as_ref()))),
    ]))
}

fn serialize_op(request: &Request<'_>) -> Result<Value, JsError> {
    let input = request.string_member("input")?;
    let base = request.optional_record("base")?.flatten();
    let username = if request.has("username") {
        Some(request.string_member("username")?)
    } else {
        None
    };
    let password = if request.has("password") {
        Some(request.string_member("password")?)
    } else {
        None
    };
    let Some(mut record) = basic_url_parse(
        input,
        ParseOptions {
            base: base.as_ref(),
            url: None,
        },
    ) else {
        return Ok(object(vec![("record", Value::Null)]));
    };
    if let Some(username) = username {
        set_the_username(&mut record, username);
    }
    if let Some(password) = password {
        set_the_password(&mut record, password);
    }
    let exclude_fragment = is_truthy(request.get("excludeFragment"));
    Ok(object(vec![
        ("record", record_value(&record)),
        ("href", string(&serialize_url(&record, exclude_fragment))),
        (
            "host",
            record.host.as_ref().map_or(Value::Null, |h| string(&serialize_host(h))),
        ),
        ("path", string(&serialize_path(&record))),
        ("origin", string(&serialize_url_origin(&record))),
        ("opaquePath", Value::Bool(has_an_opaque_path(&record))),
        (
            "cannotHaveUsernamePasswordPort",
            Value::Bool(cannot_have_a_username_password_port(&record)),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(input: &str) -> (String, i32) {
        let out = run(&[], input.as_bytes());
        (String::from_utf8(out.stdout).expect("UTF-8 output"), out.status)
    }

    #[test]
    fn answers_requests() {
        let (out, status) = lines("{\"op\":\"canParse\",\"input\":\"x\",\"base\":\"http://a/\"}\n\n");
        assert_eq!(out, "{\"result\":true}\n");
        assert_eq!(status, 0);
    }

    #[test]
    fn reports_errors() {
        let (out, status) = lines("{\"op\":\"url\",\"input\":\"x\"}\n[]\n");
        assert_eq!(
            out,
            "{\"error\":{\"name\":\"TypeError\",\"message\":\"Invalid URL: x\"}}\n\
             {\"error\":{\"name\":\"RequestError\",\"message\":\"a request must be a JSON object\"}}\n"
        );
        assert_eq!(status, 1);
    }

    #[test]
    fn usage() {
        let out = run(&["-h".to_owned()], b"");
        assert_eq!(out.status, 2);
        assert!(out.stdout.is_empty());
        assert_eq!(out.stderr, USAGE.as_bytes());
    }
}
