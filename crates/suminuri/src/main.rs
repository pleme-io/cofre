//! The binary. Argv in, exit code out, and nothing else.
//!
//! Every decision lives in [`suminuri::app`] behind the `Environment` seam; this
//! file exists to translate a process into that call and back. Keeping it this
//! thin is what makes the whole operator-visible surface testable without a real
//! filesystem or a real key.

use std::io::Write as _;
use suminuri::app;
use suminuri::cli;
use suminuri::env::RealEnvironment;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let invocation = match cli::parse(&args) {
        Ok(i) => i,
        Err(e) => {
            // Usage errors go to stderr with the generic code, matching sops.
            let _ = writeln!(std::io::stderr(), "suminuri: {e}");
            let _ = write!(std::io::stderr(), "\n{}", cli::help_text());
            std::process::exit(cli::exit::GENERIC);
        }
    };

    let env = RealEnvironment;
    let mut stdout = std::io::stdout().lock();
    match app::run(&invocation, &env, &mut stdout) {
        Ok(outcome) => {
            let _ = stdout.flush();
            if let Some(msg) = outcome.message {
                // Progress goes to stderr so `suminuri -d f | consumer` stays a
                // clean pipe — the reason a decrypt's summary is not on stdout.
                let _ = writeln!(std::io::stderr(), "suminuri: {msg}");
            }
            std::process::exit(outcome.code);
        }
        Err(e) => {
            let _ = stdout.flush();
            let _ = writeln!(std::io::stderr(), "suminuri: {e}");
            std::process::exit(cli::exit::GENERIC);
        }
    }
}
