// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Sebastian Mayr

//! The `whatwg-url` command; see [`whatwg_url::cli`].

use std::io::{self, Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdin = Vec::new();
    if let Err(error) = io::stdin().read_to_end(&mut stdin) {
        eprintln!("whatwg-url: cannot read standard input: {error}");
        return ExitCode::from(1);
    }
    let output = whatwg_url::cli::run(&args, &stdin);
    let written = io::stdout()
        .write_all(&output.stdout)
        .and_then(|()| io::stdout().flush())
        .and_then(|()| io::stderr().write_all(&output.stderr));
    if let Err(error) = written {
        eprintln!("whatwg-url: cannot write the output: {error}");
        return ExitCode::from(1);
    }
    ExitCode::from(output.status as u8)
}
