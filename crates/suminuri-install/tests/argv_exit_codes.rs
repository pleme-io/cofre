//! The drop-in's argv contract, pinned by SPAWNING it.
//!
//! ★ These cannot be unit tests. An exit code is a property of the process,
//! and the defect being pinned was precisely that `--help` returned FAILURE
//! while printing the right text — so any test checking output rather than
//! status would have passed against the bug.
//!
//! Why the code matters more than the prose here: sops-nix activation runs
//! this program from a script. A wrapper reads the status, not the text, and
//! an activation running under `set -e` aborts the whole switch on a non-zero
//! return. A help invocation that exits 1 is therefore not cosmetic.

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_suminuri-install-secrets"))
        .args(args)
        .output()
        .expect("the binary must be built for its own integration test");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn help_succeeds_and_goes_to_stdout() {
    let (code, stdout, _) = run(&["--help"]);
    assert_eq!(code, 0, "asking for help is a success");
    // stdout, not stderr: help answers a question, it does not complain.
    assert!(
        stdout.contains("usage:"),
        "help must reach stdout: {stdout:?}"
    );
}

#[test]
fn short_help_too() {
    assert_eq!(run(&["-h"]).0, 0);
}

#[test]
fn no_manifest_fails_and_goes_to_stderr() {
    let (code, stdout, stderr) = run(&[]);
    assert_eq!(code, 1, "a missing manifest is a real failure");
    assert!(stderr.contains("usage:"), "must complain on stderr");
    assert!(stdout.is_empty(), "a failure must not write to stdout");
}

#[test]
fn dry_run_without_a_manifest_still_fails() {
    // --dry-run does not make the manifest optional. Exiting 0 here would tell
    // a caller "the plan is fine" having planned nothing at all.
    assert_eq!(run(&["--dry-run"]).0, 1);
}

#[test]
fn a_missing_manifest_file_fails_rather_than_installing_nothing() {
    let (code, _, stderr) = run(&["/nonexistent/manifest.json"]);
    assert_eq!(code, 1);
    assert!(
        !stderr.contains("0 entries"),
        "an unreadable manifest must not be reported as an empty one: {stderr:?}"
    );
}

#[test]
fn the_usage_text_names_both_the_flag_and_the_operand() {
    // Anti-vacuity: if USAGE were emptied, every assertion above that checks
    // only a code would still pass. This pins that the text is real.
    let (_, stdout, _) = run(&["--help"]);
    assert!(stdout.contains("--dry-run"), "{stdout:?}");
    assert!(stdout.contains("<manifest.json>"), "{stdout:?}");
}
