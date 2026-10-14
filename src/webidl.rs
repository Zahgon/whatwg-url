// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The WebIDL layer of the `URL` and `URLSearchParams` interfaces: argument counts and the conversion of JavaScript
//! values to `USVString`, and of the `URLSearchParams` constructor argument to a sequence, a record or a string, with
//! the `TypeError` messages of the original's generated bindings.

use crate::json::{to_js_string, JsError, Object, Value};
use crate::jsstring;
use crate::url_search_params::Init;

/// The `USVString` conversion: `String(value)`, then every lone surrogate replaced by U+FFFD.
pub fn usv_string(value: Option<&Value>) -> Result<String, JsError> {
    Ok(jsstring::to_well_formed(&to_js_string(value)?))
}

/// The `TypeError` for too few arguments.
pub fn arity_error(prefix: &str, required: usize, present: usize) -> JsError {
    let noun = if required == 1 { "argument" } else { "arguments" };
    JsError::type_error(format!(
        "{prefix}: {required} {noun} required, but only {present} present."
    ))
}

/// Checks that at least `required` of the `present` arguments are there.
pub fn require_arguments(prefix: &str, present: usize, required: usize) -> Result<(), JsError> {
    if present < required {
        return Err(arity_error(prefix, required, present));
    }
    Ok(())
}

const PARAMS_PREFIX: &str = "Failed to construct 'URLSearchParams': parameter 1";

/// Converts the `URLSearchParams` constructor argument: an array is a sequence of sequences, any other object a
/// record, anything else a string.
pub fn search_params_init(value: &Value) -> Result<Init, JsError> {
    match value {
        Value::Array(items) => {
            let mut pairs = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Array(inner) => {
                        pairs.push(inner.iter().map(|v| usv_string(Some(v))).collect::<Result<_, _>>()?)
                    }
                    // A plain object is an object but has no iterator, so iterating it throws.
                    Value::Object(_) => return Err(JsError::type_error("tmp is not iterable")),
                    _ => {
                        return Err(JsError::type_error(format!(
                            "{PARAMS_PREFIX} sequence's element is not an iterable object."
                        )))
                    }
                }
            }
            Ok(Init::Sequence(pairs))
        }
        Value::Object(object) => Ok(Init::Record(record_pairs(object)?)),
        other => Ok(Init::String(usv_string(Some(other))?)),
    }
}

/// The record conversion: every own key and value converted to `USVString`; keys that convert to the same string
/// keep the place of the first and the value of the last; the result enumerates as a JavaScript object does.
fn record_pairs(object: &Object) -> Result<Vec<(String, String)>, JsError> {
    let mut result = Object::new();
    for (key, value) in object.properties() {
        let key = jsstring::from_str(&jsstring::to_well_formed(key));
        result.insert(key, Value::String(jsstring::from_str(&usv_string(Some(value))?)));
    }
    result
        .properties()
        .into_iter()
        .map(|(k, v)| Ok((jsstring::to_well_formed(k), usv_string(Some(v))?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;
    use crate::jsstring::from_str;

    #[test]
    fn converts_values() {
        let v = parse(&from_str(r#"[1.5,null,"\ud800",[1,[2]],{}]"#)).expect("valid JSON");
        let Value::Array(items) = &v else { panic!("an array") };
        let converted: Vec<String> = items.iter().map(|i| usv_string(Some(i)).expect("converts")).collect();
        assert_eq!(converted, vec!["1.5", "null", "\u{FFFD}", "1,2", "[object Object]"]);
        assert_eq!(usv_string(None).as_deref(), Ok("undefined"));
    }

    #[test]
    fn record_order() {
        let v = parse(&from_str(r#"{"b":1,"10":2,"2":3,"\ud800":4,"�":5}"#)).expect("valid JSON");
        let init = search_params_init(&v).expect("a record");
        let expected = vec![("2", "3"), ("10", "2"), ("b", "1"), ("\u{FFFD}", "5")];
        let expected: Vec<(String, String)> = expected.into_iter().map(|(a, b)| (a.into(), b.into())).collect();
        assert_eq!(init, Init::Record(expected));
    }

    #[test]
    fn arity() {
        assert_eq!(
            arity_error("Failed to execute 'append' on 'URLSearchParams'", 2, 1).to_string(),
            "TypeError: Failed to execute 'append' on 'URLSearchParams': 2 arguments required, but only 1 present."
        );
    }
}
