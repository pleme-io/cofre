//! The CORPUS gate: every real encrypted file under a directory, both binaries,
//! byte-compared.
//!
//! # Why this exists as a test and not as a shell loop somebody remembers to run
//!
//! Comment support was written against seven synthetic fixtures and looked right.
//! Pointing it at the fleet's actual 171 encrypted k8s files found SIX distinct
//! bugs that no fixture had provoked:
//!
//!   1. a foot comment with no following item was hoisted out of its block, which
//!      changed its AAD path so an encrypted comment failed its GCM tag and came
//!      out as raw ciphertext,
//!   2. `visit_comment` gated DECRYPT on the selector, refusing to decrypt a
//!      comment the file itself marked `type:comment`,
//!   3. a block scalar opened as a bare sequence entry (`- |`) was invisible to the
//!      comment scanner, so `#` lines in a shell script were duplicated,
//!   4. a block scalar inside a `- ` item took the wrong indent branch (rounded up
//!      instead of dash + 2),
//!   5. non-BMP characters need `\UXXXXXXXX` escaping in double quotes while BMP
//!      ones do not,
//!   6. a YAML `null` in an encrypted region is not a leaf at all — it reached the
//!      cipher and errored, and it was also wrongly fed to the MAC.
//!
//! Every one of those is a byte difference in a file an operator depends on, and
//! not one was reachable from a hand-written fixture. So the corpus IS the test.
//!
//! # Running it
//!
//! Opt-in, because it needs both binaries, real files and a real age key:
//!
//! ```sh
//! SUMINURI_CORPUS_DIR=~/code/github/pleme-io/k8s \
//! SUMINURI_SOPS_ORACLE=$(command -v sops-upstream) \
//! SUMINURI_CORPUS_REQUIRE=167 \
//!     cargo test -p suminuri --test corpus_differential
//! ```
//!
//! `SUMINURI_CORPUS_REQUIRE` is the anti-vacuity half and is the reason this gate
//! cannot rot into a no-op: without it, a discovery bug that found zero files would
//! report success. With it, the run fails unless at least that many files were
//! actually compared. Measured 2026-08-19: 167 of 171 compare (the other 4 are
//! encrypted to a key this host does not hold, and are skipped as such rather than
//! counted as passes).

use std::path::{Path, PathBuf};
use std::process::Command;

fn oracle() -> Option<PathBuf> {
    let p = std::env::var_os("SUMINURI_SOPS_ORACLE").map(PathBuf::from)?;
    // The same identity check the unit differential uses: an oracle that is
    // actually us proves nothing, and the alias makes that easy to do by accident.
    let out = Command::new(&p).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        !text.contains("suminuri"),
        "SUMINURI_SOPS_ORACLE points at suminuri itself ({}) — that is not an oracle",
        p.display()
    );
    Some(p)
}

fn ours() -> PathBuf {
    // The binary cargo just built, beside this test's executable.
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("suminuri")
}

fn encrypted_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name != ".git" && name != "target" {
                    stack.push(path);
                }
            } else if matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("yaml" | "yml" | "json" | "env" | "ini")
            ) && std::fs::read_to_string(&path)
                .is_ok_and(|s| s.contains("ENC[AES256_GCM"))
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

fn decrypt(bin: &Path, file: &Path) -> Option<Vec<u8>> {
    let out = Command::new(bin).arg("-d").arg(file).output().ok()?;
    out.status.success().then_some(out.stdout)
}

#[test]
fn every_real_encrypted_file_decrypts_byte_identically_to_upstream() {
    let Some(dir) = std::env::var_os("SUMINURI_CORPUS_DIR").map(PathBuf::from) else {
        eprintln!("SUMINURI_CORPUS_DIR unset — corpus gate skipped");
        return;
    };
    let Some(oracle) = oracle() else {
        eprintln!("SUMINURI_SOPS_ORACLE unset — corpus gate skipped");
        return;
    };
    let ours = ours();
    assert!(ours.exists(), "our binary not found at {}", ours.display());

    let files = encrypted_files(&dir);
    assert!(
        !files.is_empty(),
        "no encrypted files found under {} — discovery is broken, which is exactly \
         what SUMINURI_CORPUS_REQUIRE exists to catch",
        dir.display()
    );

    let mut compared = 0usize;
    let mut skipped_no_key = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for f in &files {
        // A file this host holds no key for is SKIPPED, never counted as a pass —
        // rounding an unreadable file up to agreement is how a corpus gate lies.
        let Some(theirs) = decrypt(&oracle, f) else {
            skipped_no_key += 1;
            continue;
        };
        match decrypt(&ours, f) {
            None => failures.push(format!("{}: we refused a file upstream read", f.display())),
            Some(mine) if mine != theirs => {
                // Never print the plaintext: this is real secret material. Report
                // the shape of the disagreement instead.
                failures.push(format!(
                    "{}: {} bytes vs upstream's {} (first difference at byte {})",
                    f.display(),
                    mine.len(),
                    theirs.len(),
                    mine.iter()
                        .zip(theirs.iter())
                        .position(|(a, b)| a != b)
                        .map_or(mine.len().min(theirs.len()), |i| i)
                ));
            }
            Some(_) => compared += 1,
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} files disagree with upstream:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );

    if let Some(min) = std::env::var("SUMINURI_CORPUS_REQUIRE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        assert!(
            compared >= min,
            "only {compared} files were actually compared, below the required {min} \
             (skipped for no key: {skipped_no_key}). A gate that compares nothing \
             passes for the wrong reason."
        );
    }
    println!("corpus: {compared} byte-identical, {skipped_no_key} skipped (no key)");
}
