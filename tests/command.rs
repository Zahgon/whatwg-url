// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The `whatwg-url` command, run as a process.

use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], stdin: &str) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_whatwg-url"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the command starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())
        .expect("stdin is written");
    let out = child.wait_with_output().expect("the command finishes");
    (
        String::from_utf8(out.stdout).expect("UTF-8 stdout"),
        String::from_utf8(out.stderr).expect("UTF-8 stderr"),
        out.status.code().expect("an exit status"),
    )
}

#[test]
fn url_requests_and_steps() {
    let (out, err, status) = run(
        &[],
        concat!(
            r#"{"op":"url","input":"HTTPS://Ex.com:443/a?b=1","steps":[["set","port",8080.5],["params","append","c","d e"],["toJSON"]]}"#,
            "\n"
        ),
    );
    let expected = concat!(
        r#"{"url":{"href":"https://ex.com/a?b=1","origin":"https://ex.com","protocol":"https:","username":"","#,
        r#""password":"","host":"ex.com","hostname":"ex.com","port":"","pathname":"/a","search":"?b=1","hash":"","#,
        r#""params":[["b","1"]]},"steps":[{"href":"https://ex.com:8080/a?b=1","origin":"https://ex.com:8080","#,
        r#""protocol":"https:","username":"","password":"","host":"ex.com:8080","hostname":"ex.com","port":"8080","#,
        r#""pathname":"/a","search":"?b=1","hash":"","params":[["b","1"]]},{"value":null,"url":{"#
    );
    assert!(
        out.starts_with(&expected[..expected.len() - r#"{"value":null,"url":{"#.len()]),
        "{out}"
    );
    assert!(out.contains(r#"{"value":"https://ex.com:8080/a?b=1&c=d+e"}"#), "{out}");
    assert_eq!((err.as_str(), status), ("", 0));
}

#[test]
fn records_and_validation() {
    let (out, _, status) = run(
        &[],
        concat!(
            r#"{"op":"record","input":"http://[::1.2.3.4]:80/x"}"#,
            "\n",
            r#"{"op":"validate","input":"http://a\\b"}"#,
            "\n",
            r#"{"op":"record","input":"q","url":"http://h/","stateOverride":"query"}"#,
            "\n"
        ),
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        r#"{"result":{"scheme":"http","username":"","password":"","host":[0,0,0,0,0,0,258,772],"port":null,"path":["x"],"query":null,"fragment":null}}"#
    );
    assert_eq!(
        lines[1],
        r#"{"url":{"scheme":"http","username":"","password":"","host":"a","port":null,"path":["b"],"query":null,"fragment":null},"errors":["invalid-reverse-solidus"],"valid":false}"#
    );
    assert!(lines[2].contains(r#""query":"nullq""#), "{}", lines[2]);
    assert_eq!(status, 0);
}

#[test]
fn errors_set_the_exit_status() {
    let (out, _, status) = run(&[], "nope\n{\"op\":\"params\",\"init\":[[1]]}\n");
    assert_eq!(
        out,
        concat!(
            r#"{"error":{"name":"SyntaxError","message":"Unexpected token 'o', \"nope\" is not valid JSON"}}"#,
            "\n",
            r#"{"error":{"name":"TypeError","message":"Failed to construct 'URLSearchParams': parameter 1 sequence's element does not contain exactly two elements."}}"#,
            "\n"
        )
    );
    assert_eq!(status, 1);
}

#[test]
fn arguments_are_a_usage_error() {
    let (out, err, status) = run(&["--help"], "");
    assert_eq!(out, "");
    assert!(err.starts_with("usage: whatwg-url < requests.jsonl\n"));
    assert_eq!(status, 2);
}
