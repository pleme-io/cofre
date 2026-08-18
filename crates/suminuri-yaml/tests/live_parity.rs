//! Byte-parity against files this repo does not own.
//!
//! The committed corpus in `byte_parity.rs` is synthetic — small, inert, and
//! generated for the purpose. That makes it a good oracle and a weak *sample*:
//! seven files of a few dozen lines each, all written by one sops version on one
//! afternoon.
//!
//! This test points the same claim at whatever real files an operator names, so
//! the parity evidence can include a 217 KB production file with 272 encrypted
//! leaves and three armored recipients — the shape that actually has to keep
//! working. It reads paths, never writes, and never decrypts.
//!
//! ```text
//! SUMINURI_PARITY_FILES=/path/secrets.yaml:/path/users/x/secrets.yaml \
//!   cargo test -p suminuri-yaml --test live_parity -- --nocapture
//! ```
//!
//! # Why it skips instead of failing when unset
//!
//! The files are private fleet config; they cannot be committed and will not
//! exist in CI. A test that failed on their absence would be red for everyone
//! except one machine, and would get deleted. It therefore **prints its own
//! denominator** — how many files it actually checked — so a skip is legible as a
//! skip and never reads as a pass. `SUMINURI_PARITY_REQUIRE=1` turns the skip into
//! a failure, which is how the operator's own gate runs it.

use suminuri_yaml::{EmitOptions, emit, parse};

fn redact(line: &str) -> String {
    // These are encrypted values, but the discipline is the same either way: a
    // failure report says where the shape diverged, never what a value contains.
    match line.find("ENC[") {
        Some(k) => format!("{}ENC[… {} chars …]", &line[..k], line.len() - k),
        None => {
            if line.len() > 120 {
                format!("{}… {} chars …", &line[..40], line.len())
            } else {
                line.to_string()
            }
        }
    }
}

fn diverging_lines(want: &str, got: &str) -> Vec<String> {
    want.lines()
        .zip(got.lines())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, (a, b))| {
            format!(
                "  line {}:\n    sops : {}\n    ours : {}",
                i + 1,
                redact(a),
                redact(b)
            )
        })
        .collect()
}

#[test]
fn named_real_files_round_trip_byte_exactly() {
    let Ok(list) = std::env::var("SUMINURI_PARITY_FILES") else {
        let required = std::env::var("SUMINURI_PARITY_REQUIRE").is_ok_and(|v| v == "1");
        assert!(
            !required,
            "SUMINURI_PARITY_REQUIRE=1 but SUMINURI_PARITY_FILES is unset — the gate was asked to run and had nothing to check"
        );
        println!("checked 0 files: SUMINURI_PARITY_FILES unset (this is a SKIP, not a pass)");
        return;
    };

    let paths: Vec<&str> = list.split(':').filter(|s| !s.is_empty()).collect();
    assert!(
        !paths.is_empty(),
        "SUMINURI_PARITY_FILES was set but named no paths"
    );

    let mut checked = 0usize;
    let mut total_lines = 0usize;
    let mut total_leaves = 0usize;

    for path in &paths {
        let want = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => panic!("{path}: unreadable: {e}"),
        };
        // The indent a file was written with is discoverable from the file: the
        // column of the first nested key. Guessing 4 would make a `--indent 2`
        // file look like an emitter bug.
        let indent = detect_indent(&want).unwrap_or(4);
        let doc = parse(&want).unwrap_or_else(|e| panic!("{path}: parse failed: {e}"));
        let got = emit(&doc, EmitOptions { indent })
            .unwrap_or_else(|e| panic!("{path}: emit failed: {e}"));

        let leaves = want.matches("ENC[AES256_GCM,").count();
        let lines = want.lines().count();
        if got != want {
            let diffs = diverging_lines(&want, &got);
            panic!(
                "{path}: {} of {lines} lines differ (indent {indent}, {leaves} encrypted leaves)\n{}",
                diffs.len(),
                diffs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
            );
        }
        println!(
            "  ✓ {path}: {lines} lines, {leaves} encrypted leaves, indent {indent} — byte-identical"
        );
        checked += 1;
        total_lines += lines;
        total_leaves += leaves;
    }

    println!(
        "checked {checked} file(s), {total_lines} lines, {total_leaves} encrypted leaves — all byte-identical"
    );
    assert_eq!(checked, paths.len(), "every named file must be checked");
}

/// The indent width a file was emitted with: the column of the first line that is
/// more indented than the line before it.
fn detect_indent(src: &str) -> Option<usize> {
    let mut previous = 0usize;
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let col = line.len() - trimmed.len();
        if col > previous {
            return Some(col - previous);
        }
        previous = col;
    }
    None
}

#[test]
fn indent_detection_reads_the_first_nesting_step() {
    assert_eq!(detect_indent("a:\n    b: 1\n"), Some(4));
    assert_eq!(detect_indent("a:\n  b: 1\n"), Some(2));
    assert_eq!(
        detect_indent("a: 1\nb: 2\n"),
        None,
        "a flat file has no nesting step"
    );
    // A sequence's dash counts as a nesting step, which is the shape a sops
    // metadata block always has.
    assert_eq!(detect_indent("age:\n    - x\n"), Some(4));
}
