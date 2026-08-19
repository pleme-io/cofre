//! The cross-implementation differential — the gate the parity claim rests on.
//!
//! Everything else in this workspace is a self-consistency test: our encrypt is
//! checked against our decrypt, our emitter against fixtures we generated. That
//! proves we agree with ourselves, which is exactly the vacuous shape this repo's
//! Nix invariants warn about. **This file is the only test that asks the other
//! implementation.**
//!
//! It runs both binaries over the same corpus and compares bytes, in both
//! directions:
//!
//! | # | claim |
//! |---|---|
//! | 1 | we encrypt → **real sops** decrypts to what sops itself would produce |
//! | 2 | **real sops** encrypts → we decrypt to the same thing |
//! | 3 | we rotate a sops-written file → sops still reads it |
//! | 4 | sops rotates a file we wrote → we still read it |
//! | 5 | `--extract` returns the same bytes from both |
//! | 6 | the same leaves get encrypted under `unencrypted_suffix` |
//! | 7 | a decrypted file's *rendering* is byte-identical — the style ladder, the
//!       literal blocks, the float spellings |
//! | 8 | a file neither can decrypt is refused by both |
//!
//! # Why this shells out, in a no-shell repo
//!
//! The doctrine forbids shell as an *implementation* language. Here the other
//! binary **is the oracle**, and invoking an oracle is what a differential test
//! does — there is no way to ask upstream sops what it would emit without running
//! it. Nothing about the tool's own behaviour is implemented in a subprocess:
//! every call below is `Command::new` with an argv, no shell, no interpolation.
//!
//! # Skips are legible, never silent
//!
//! Upstream sops will not exist in every environment. Absent it, the test prints
//! the number of comparisons it made — **zero** — and returns. A skip that reads
//! like a pass is worse than no test. `SUMINURI_DIFFERENTIAL_REQUIRE=1` turns the
//! skip into a failure, which is how it runs when the claim is being made.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The plaintext corpus. Deliberately covers every leaf type sops can write, both
/// collection kinds, and the three shapes that each cost a real bug: a multi-line
/// string, a value needing single quotes, and a float large enough to render in
/// exponent form.
const CORPUS: &[(&str, &str)] = &[
    (
        "flat",
        "alpha: one\nbeta: two\ncount: 3\nratio: 1.5\nenabled: true\n",
    ),
    (
        "nested",
        "outer:\n    inner:\n        leaf: deep\n    sibling: shallow\n",
    ),
    (
        "sequences",
        "scalars:\n    - first\n    - second\nmappings:\n    - name: a\n      value: x\n    - name: b\n      value: y\n",
    ),
    // The three shapes that each cost a bug, kept together so a regression in any
    // one of them is attributable.
    (
        "styles",
        "hash: \"has # hash\"\ncolon: \"a: b\"\nlead_space: \" leading\"\ntabbed: \"a\\tb\"\nbool_str: \"true\"\nnum_str: \"42\"\nplainish: normal-value\n",
    ),
    (
        "bigfloat",
        "client_id: 608863452348.1149\nsmall: 0.00001\nedge: 999999.0\n",
    ),
    (
        "multiline",
        "pem: |\n    -----BEGIN THING-----\n    b3BlbnNzaA\n    -----END THING-----\n",
    ),
    ("suffix", "covered: hide-me\nport_unencrypted: 8080\n"),
    ("empties", "blank: \"\"\nfilled: v\n"),
];

struct Oracle {
    sops: PathBuf,
    suminuri: PathBuf,
    dir: PathBuf,
    key_file: PathBuf,
    recipient: String,
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join(name))
            .find(|p| p.is_file())
    })
}

/// Our own binary, as cargo built it. Derived from the test executable's own path
/// rather than assumed, so it works under `cargo test`, `--release`, and a custom
/// target dir alike.
fn our_binary() -> Option<PathBuf> {
    let mut dir = std::env::current_exe().ok()?;
    dir.pop(); // .../deps
    if dir.ends_with("deps") {
        dir.pop();
    }
    let candidate = dir.join("suminuri");
    candidate.is_file().then_some(candidate)
}

/// What a candidate oracle binary says it is.
///
/// ★ THE POSITIVE CONTROL THIS GATE WAS MISSING, AND THE ALIAS IS WHY IT NEEDS ONE.
///
/// The oracle used to be `find_on_path("sops")`. That was correct right up to the
/// moment the fleet overlay made `sops` resolve to **suminuri** — after which this
/// entire file compared suminuri against suminuri and reported green. Measured on
/// cid 2026-08-19: a full 289-test run passed with `sops --version` printing
/// `suminuri 0.1.8`.
///
/// A differential whose oracle is the implementation under test proves nothing, and
/// it fails *silently* — every assertion holds trivially. So the identity of the
/// oracle is now checked rather than assumed, and a candidate that identifies as
/// suminuri is refused outright instead of used.
fn identifies_as_suminuri(bin: &Path) -> bool {
    Command::new(bin)
        .arg("--version")
        .env("SOPS_DISABLE_VERSION_CHECK", "1")
        .output()
        .map(|o| {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            text.to_lowercase().contains("suminuri")
        })
        // A candidate we cannot even run is not a usable oracle either; treat it as
        // unusable rather than silently accepting it.
        .unwrap_or(true)
}

/// Find a real upstream sops, in the order that survives the alias being live.
///
/// `sops-upstream` first: the fleet overlay binds that name to the Go binary
/// precisely so an upstream is still reachable once `sops` has been rebound. Plain
/// `sops` is still tried, because on a machine that has not adopted the overlay it
/// *is* upstream — but it is identity-checked either way.
fn find_oracle() -> Option<PathBuf> {
    // An EXPLICIT oracle is honoured strictly: if the operator names a binary and
    // it turns out to be us, that is a hard error, not something to route around.
    // Quietly substituting a different binary than the one asked for is its own
    // form of dishonesty — the run would report green about a comparison nobody
    // requested. (The first version of this function *did* fall through, which is
    // why its own red run came out green.)
    if let Some(explicit) = std::env::var_os("SUMINURI_SOPS_ORACLE").map(PathBuf::from) {
        assert!(
            !identifies_as_suminuri(&explicit),
            "SUMINURI_SOPS_ORACLE points at {}, which identifies as suminuri.\n\nThat is the implementation under test, not an oracle — every assertion in this\nfile would hold trivially and the run would report green while comparing nothing.\nPoint it at a real upstream sops (on a fleet node: `sops-upstream`).",
            explicit.display()
        );
        return Some(explicit);
    }
    // Discovered candidates: prefer the name the fleet overlay reserves for
    // upstream, then plain `sops` for a machine that never adopted the overlay.
    // Skip — rather than refuse — anything that identifies as suminuri, because a
    // rebound `sops` on PATH is the expected state, not an operator error.
    [find_on_path("sops-upstream"), find_on_path("sops")]
        .into_iter()
        .flatten()
        .find(|c| !identifies_as_suminuri(c))
}

impl Oracle {
    fn discover() -> Option<Self> {
        let sops = find_oracle()?;
        let suminuri = our_binary()?;
        let age_keygen = find_on_path("age-keygen")?;

        // Unique per Oracle, NOT per process. Every test in this file builds its
        // own Oracle and `Drop` removes the directory — so keying on
        // `process::id()` alone gave all eight tests ONE shared directory that
        // the first one to finish deleted out from under the others. It passed
        // under `--test-threads=1` and failed 7 of 8 in parallel, which is the
        // worst failure mode available: green in the run you reach for when
        // something looks wrong.
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("suminuri-diff-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let key_file = dir.join("key.txt");
        let out = Command::new(age_keygen)
            .arg("-o")
            .arg(&key_file)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        // age-keygen prints `Public key: age1…` on stderr.
        let printed = String::from_utf8_lossy(&out.stderr).into_owned();
        let recipient = printed
            .split_whitespace()
            .find(|w| w.starts_with("age1"))
            .map(str::to_string)?;

        std::fs::write(
            dir.join(".sops.yaml"),
            format!("creation_rules:\n  - age: {recipient}\n"),
        )
        .ok()?;
        Some(Self {
            sops,
            suminuri,
            dir,
            key_file,
            recipient,
        })
    }

    fn run(&self, bin: &Path, args: &[&str]) -> (i32, Vec<u8>, String) {
        let out = Command::new(bin)
            .args(args)
            .current_dir(&self.dir)
            // `SOPS_DISABLE_VERSION_CHECK` is not cosmetic: without it sops
            // reaches out for a release check and hangs for minutes on a
            // network-restricted host, which turns this test into a timeout.
            .env("SOPS_DISABLE_VERSION_CHECK", "1")
            .env("SOPS_AGE_KEY_FILE", &self.key_file)
            .env("SOPS_AGE_RECIPIENTS", &self.recipient)
            .output()
            .unwrap_or_else(|e| panic!("spawning {} failed: {e}", bin.display()));
        (
            out.status.code().unwrap_or(-1),
            out.stdout,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn sops(&self, args: &[&str]) -> (i32, Vec<u8>, String) {
        let sops = self.sops.clone();
        self.run(&sops, args)
    }

    fn ours(&self, args: &[&str]) -> (i32, Vec<u8>, String) {
        let ours = self.suminuri.clone();
        self.run(&ours, args)
    }

    fn write(&self, name: &str, body: &[u8]) {
        std::fs::write(self.dir.join(name), body).expect("write fixture");
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        // The corpus is synthetic and the key is throwaway, but leaving either
        // behind is still litter with a private key in it.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The skip. Prints its own denominator so an absent oracle never reads as a pass.
fn oracle_or_skip() -> Option<Oracle> {
    match Oracle::discover() {
        Some(o) => Some(o),
        None => {
            let required = std::env::var("SUMINURI_DIFFERENTIAL_REQUIRE").is_ok_and(|v| v == "1");
            assert!(
                !required,
                "SUMINURI_DIFFERENTIAL_REQUIRE=1 but no USABLE oracle was found.\n\nNeed a real upstream sops plus age-keygen. Candidates are tried in order:\n  $SUMINURI_SOPS_ORACLE, then `sops-upstream`, then `sops`\nand any candidate whose --version says `suminuri` is REFUSED — comparing the\nimplementation against itself is not a differential. On a fleet node where the\noverlay has rebound `sops`, use `sops-upstream`."
            );
            println!(
                "0 comparisons made: no usable upstream oracle (a candidate identifying as suminuri is refused). This is a SKIP, not a pass."
            );
            None
        }
    }
}

fn redact(line: &str) -> String {
    match line.find("ENC[") {
        Some(k) => format!("{}ENC[… {} chars …]", &line[..k], line.len() - k),
        None => line.to_string(),
    }
}

fn diff_report(want: &str, got: &str) -> String {
    want.lines()
        .zip(got.lines())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .take(4)
        .map(|(i, (a, b))| {
            format!(
                "  line {}:\n    want: {}\n    got : {}",
                i + 1,
                redact(a),
                redact(b)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn our_ciphertext_is_readable_by_real_sops() {
    let Some(o) = oracle_or_skip() else { return };
    let mut checked = 0;
    for (name, plain) in CORPUS {
        let src = format!("{name}-plain.yaml");
        o.write(&src, plain.as_bytes());

        let (code, encrypted, err) = o.ours(&["-e", &src]);
        assert_eq!(code, 0, "{name}: our encrypt failed: {err}");
        let enc_name = format!("{name}-ours.yaml");
        o.write(&enc_name, &encrypted);

        let (code, decrypted, err) = o.sops(&["-d", &enc_name]);
        assert_eq!(
            code, 0,
            "{name}: real sops could not decrypt our file: {err}"
        );
        let ours_via_sops = String::from_utf8_lossy(&decrypted).into_owned();

        // The reference is sops's decrypt of *its own* encryption of the same
        // source — not the original plaintext. sops does not round-trip every
        // YAML text unchanged, and the one that proves it is in this corpus:
        // `value: y` comes back as `value: "y"`, because yaml.v3 resolves `y` as a
        // string and then quotes it defensively (`isOldBool`) so a YAML 1.1 parser
        // cannot read it as a bool. Asserting against the original would fail on
        // upstream's behaviour and call it our bug.
        let round_trip_src = format!("{name}-ref.yaml");
        o.write(&round_trip_src, plain.as_bytes());
        let (_, theirs_enc, _) = o.sops(&["-e", &round_trip_src]);
        let theirs_enc_name = format!("{name}-ref-enc.yaml");
        o.write(&theirs_enc_name, &theirs_enc);
        let (_, theirs_dec, _) = o.sops(&["-d", &theirs_enc_name]);
        let reference = String::from_utf8_lossy(&theirs_dec).into_owned();
        assert!(
            !reference.is_empty(),
            "{name}: the oracle produced no reference"
        );

        assert_eq!(
            ours_via_sops,
            reference,
            "{name}: sops read our file differently than it reads its own\n{}",
            diff_report(&reference, &ours_via_sops)
        );
        checked += 1;
    }
    println!("{checked} comparisons: real sops read every file we wrote");
    assert_eq!(checked, CORPUS.len());
}

#[test]
fn real_sops_ciphertext_is_readable_by_us() {
    let Some(o) = oracle_or_skip() else { return };
    let mut checked = 0;
    for (name, plain) in CORPUS {
        let src = format!("{name}-plain.yaml");
        o.write(&src, plain.as_bytes());

        let (code, encrypted, err) = o.sops(&["-e", &src]);
        assert_eq!(code, 0, "{name}: sops encrypt failed: {err}");
        let enc_name = format!("{name}-sops.yaml");
        o.write(&enc_name, &encrypted);

        let (code, decrypted, err) = o.ours(&["-d", &enc_name]);
        assert_eq!(
            code, 0,
            "{name}: we could not decrypt a real sops file: {err}"
        );
        let mine = String::from_utf8_lossy(&decrypted).into_owned();

        // Same reasoning as the other direction: the reference is sops's own
        // decrypt, because sops does not round-trip `value: y` unchanged.
        let (_, theirs, terr) = o.sops(&["-d", &enc_name]);
        let reference = String::from_utf8_lossy(&theirs).into_owned();
        assert!(
            !reference.is_empty(),
            "{name}: the oracle produced no reference: {terr}"
        );
        assert_eq!(
            mine,
            reference,
            "{name}: we read a sops file differently than sops does\n{}",
            diff_report(&reference, &mine)
        );
        checked += 1;
    }
    println!("{checked} comparisons: we read every file real sops wrote");
    assert_eq!(checked, CORPUS.len());
}

/// The rendering claim, and the strictest one here: given the *same* ciphertext,
/// both binaries must emit byte-identical plaintext. This is what the style ladder,
/// the literal-block rule and the two float spellings are all for.
#[test]
fn both_binaries_render_a_decrypt_identically() {
    let Some(o) = oracle_or_skip() else { return };
    let mut checked = 0;
    for (name, plain) in CORPUS {
        let src = format!("{name}-plain.yaml");
        o.write(&src, plain.as_bytes());
        let (code, encrypted, err) = o.sops(&["-e", &src]);
        assert_eq!(code, 0, "{name}: sops encrypt failed: {err}");
        let enc_name = format!("{name}-shared.yaml");
        o.write(&enc_name, &encrypted);

        let (_, theirs, _) = o.sops(&["-d", &enc_name]);
        let (_, mine, err) = o.ours(&["-d", &enc_name]);
        let theirs = String::from_utf8_lossy(&theirs).into_owned();
        let mine = String::from_utf8_lossy(&mine).into_owned();
        assert!(
            !theirs.is_empty(),
            "{name}: the oracle produced nothing to compare against"
        );
        assert_eq!(
            mine,
            theirs,
            "{name}: renderings differ ({err})\n{}",
            diff_report(&theirs, &mine)
        );
        checked += 1;
    }
    println!("{checked} comparisons: identical rendering of every decrypt");
    assert_eq!(checked, CORPUS.len());
}

#[test]
fn a_rotation_by_either_binary_is_readable_by_the_other() {
    let Some(o) = oracle_or_skip() else { return };
    let plain = "alpha: one\nnested:\n    deep: v\n";
    o.write("rot-plain.yaml", plain.as_bytes());

    // sops writes it, we rotate it, sops reads it.
    let (_, encrypted, _) = o.sops(&["-e", "rot-plain.yaml"]);
    o.write("rot-a.yaml", &encrypted);
    let (code, _, err) = o.ours(&["rotate", "-i", "rot-a.yaml"]);
    assert_eq!(code, 0, "our rotate failed: {err}");
    let (code, out, err) = o.sops(&["-d", "rot-a.yaml"]);
    assert_eq!(code, 0, "sops could not read our rotation: {err}");
    assert_eq!(String::from_utf8_lossy(&out), plain);

    // We write it, sops rotates it, we read it.
    let (_, encrypted, _) = o.ours(&["-e", "rot-plain.yaml"]);
    o.write("rot-b.yaml", &encrypted);
    let (code, _, err) = o.sops(&["-r", "-i", "rot-b.yaml"]);
    assert_eq!(code, 0, "sops rotate failed: {err}");
    let (code, out, err) = o.ours(&["-d", "rot-b.yaml"]);
    assert_eq!(code, 0, "we could not read sops's rotation: {err}");
    assert_eq!(String::from_utf8_lossy(&out), plain);
}

#[test]
fn extract_agrees() {
    let Some(o) = oracle_or_skip() else { return };
    o.write(
        "ex-plain.yaml",
        b"nested:\n    deep: the-value\nlist:\n    - zero\n    - one\n",
    );
    let (_, encrypted, _) = o.sops(&["-e", "ex-plain.yaml"]);
    o.write("ex.yaml", &encrypted);

    for path in ["[\"nested\"][\"deep\"]", "[\"list\"][1]"] {
        let (tc, theirs, terr) = o.sops(&["-d", "--extract", path, "ex.yaml"]);
        let (mc, mine, merr) = o.ours(&["-d", "--extract", path, "ex.yaml"]);
        assert_eq!(tc, 0, "sops --extract {path} failed: {terr}");
        assert_eq!(mc, 0, "our --extract {path} failed: {merr}");
        assert_eq!(
            String::from_utf8_lossy(&mine),
            String::from_utf8_lossy(&theirs),
            "--extract {path} disagreed"
        );
    }
}

#[test]
fn the_same_leaves_are_encrypted_under_a_suffix_rule() {
    let Some(o) = oracle_or_skip() else { return };
    let plain = "covered: hide-me\nport_unencrypted: 8080\nnested:\n    also_unencrypted: visible\n    hidden: covered\n";
    o.write("suf-plain.yaml", plain.as_bytes());

    let (_, theirs, _) = o.sops(&["-e", "suf-plain.yaml"]);
    let (_, mine, err) = o.ours(&["-e", "suf-plain.yaml"]);
    let theirs = String::from_utf8_lossy(&theirs).into_owned();
    let mine = String::from_utf8_lossy(&mine).into_owned();

    let count = |s: &str| s.matches("ENC[AES256_GCM,").count();
    assert_eq!(
        count(&mine),
        count(&theirs),
        "different leaf counts encrypted ({err})"
    );
    assert!(
        count(&theirs) > 0,
        "the oracle encrypted nothing; the fixture is wrong"
    );

    // And the cleared lines are identical text, not merely the same number.
    for key in ["port_unencrypted:", "also_unencrypted:"] {
        let t = theirs
            .lines()
            .find(|l| l.contains(key))
            .expect("oracle line");
        let m = mine.lines().find(|l| l.contains(key)).expect("our line");
        assert_eq!(m, t, "{key} rendered differently in the clear");
    }
}

/// The EDITOR-hijack contract, both binaries — because `cofre`'s own `SopsBackend`
/// depends on it and the overlay put suminuri underneath it.
///
/// The shape: set `EDITOR` to a program that rewrites the decrypted tempfile, run
/// `sops <file>`, and the tool re-encrypts whatever the "editor" left. Three repos
/// independently ported this trick because `sops set` takes its value as argv with
/// no stdin form. What they all branch on is the **exit code**:
///
/// | editor did | exit |
/// |---|---|
/// | rewrote the file | 0 |
/// | nothing | **200** — sops's documented "file has not changed" |
///
/// `cofre/crates/cofre/src/backends.rs` treats 200 as an idempotent no-op. Get it
/// wrong and every unchanged `cofre apply` reports a failure.
#[test]
fn the_editor_hijack_contract_agrees_including_exit_200() {
    let Some(o) = oracle_or_skip() else { return };

    // Two "editors": one that injects a key, one that does nothing.
    let injector = o.dir.join("inject.sh");
    std::fs::write(
        &injector,
        "#!/bin/sh\nprintf 'existing: value\\ninjected: by-hook\\n' > \"$1\"\n",
    )
    .expect("write injector");
    let noop = o.dir.join("noop.sh");
    std::fs::write(&noop, "#!/bin/sh\nexit 0\n").expect("write noop");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for p in [&injector, &noop] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
    }

    let plain = "existing: value\n";
    o.write("hijack-plain.yaml", plain.as_bytes());

    // One encrypted file per binary, so neither run disturbs the other's.
    let mut verdicts = Vec::new();
    for (label, is_ours) in [("sops", false), ("ours", true)] {
        let src = format!("hijack-{label}.yaml");
        let (_, enc, err) = o.sops(&["-e", "hijack-plain.yaml"]);
        assert!(!enc.is_empty(), "{label}: encrypt produced nothing: {err}");
        o.write(&src, &enc);

        let run = |editor: &std::path::Path, args: &[&str]| -> i32 {
            let bin = if is_ours { &o.suminuri } else { &o.sops };
            std::process::Command::new(bin)
                .args(args)
                .current_dir(&o.dir)
                .env("SOPS_DISABLE_VERSION_CHECK", "1")
                .env("SOPS_AGE_KEY_FILE", &o.key_file)
                .env("EDITOR", editor)
                .status()
                .unwrap_or_else(|e| panic!("{label}: spawn failed: {e}"))
                .code()
                .unwrap_or(-1)
        };

        let unchanged = run(&noop, &[&src]);
        let changed = run(&injector, &[&src]);
        verdicts.push((label, unchanged, changed));

        // And the edited file must still decrypt — through the OTHER binary, so
        // this is a parity claim and not a self-check.
        let (code, out, derr) = if is_ours {
            o.sops(&["-d", &src])
        } else {
            o.ours(&["-d", &src])
        };
        assert_eq!(
            code, 0,
            "{label}: the other binary could not read the edited file: {derr}"
        );
        assert_eq!(
            String::from_utf8_lossy(&out),
            "existing: value\ninjected: by-hook\n",
            "{label}: the editor's write did not survive the round trip"
        );
    }

    for (label, unchanged, changed) in &verdicts {
        assert_eq!(
            *unchanged, 200,
            "{label}: an unchanged edit must be exit 200"
        );
        assert_eq!(*changed, 0, "{label}: a changed edit must be exit 0");
    }
    println!("2 binaries x 2 editor outcomes: exit codes and round-trips agree");
}

/// sops does **not** round-trip every YAML text unchanged, and this is the case
/// that proves it. Recorded as its own test because it is a real behaviour an
/// operator will eventually hit, and because it is the reason the two round-trip
/// tests above compare against the oracle rather than against the input.
///
/// `value: y` becomes `value: "y"`. yaml.v3 dropped YAML 1.1's boolean set, so `y`
/// resolves as the *string* `"y"` — and then `isOldBool` quotes it on the way out
/// "so that the marshalled output [is] valid for YAML 1.1 parsing". Both binaries
/// do this, identically. The values that survive unquoted are the six real bool
/// spellings and nothing else.
#[test]
fn neither_binary_round_trips_the_yaml_one_one_booleans() {
    let Some(o) = oracle_or_skip() else { return };
    let plain = "a: y\nb: yes\nc: on\nd: no\ne: off\nf: true\ng: false\n";
    o.write("oldbool-plain.yaml", plain.as_bytes());

    let (_, enc, _) = o.sops(&["-e", "oldbool-plain.yaml"]);
    o.write("oldbool.yaml", &enc);
    let (_, theirs, _) = o.sops(&["-d", "oldbool.yaml"]);
    let (_, mine, err) = o.ours(&["-d", "oldbool.yaml"]);
    let theirs = String::from_utf8_lossy(&theirs).into_owned();
    let mine = String::from_utf8_lossy(&mine).into_owned();

    assert_ne!(
        theirs, plain,
        "the premise: sops itself does not round-trip these"
    );
    assert_eq!(mine, theirs, "but we must match it exactly ({err})");
    // The 1.1 spellings come back quoted; the real bools do not.
    for quoted in [
        "a: \"y\"",
        "b: \"yes\"",
        "c: \"on\"",
        "d: \"no\"",
        "e: \"off\"",
    ] {
        assert!(
            theirs.contains(quoted),
            "oracle should quote: {quoted}\n{theirs}"
        );
        assert!(mine.contains(quoted), "we should quote: {quoted}\n{mine}");
    }
    assert!(theirs.contains("f: true") && theirs.contains("g: false"));
    assert!(mine.contains("f: true") && mine.contains("g: false"));
}

/// The negative control. Without it, every assertion above could be satisfied by a
/// binary that decrypts anything it is handed.
#[test]
fn a_file_neither_holds_a_key_for_is_refused_by_both() {
    let Some(o) = oracle_or_skip() else { return };
    o.write("stranger-plain.yaml", b"k: v\n");

    // Encrypt to a recipient nobody has the identity for.
    let stranger = "age1jpfgn0cm8su4dt3a2c0928cyvhquvx0ayyssnctk5nwjdnpv85vsqssjrh";
    let (code, encrypted, err) = o.sops(&["-e", "--age", stranger, "stranger-plain.yaml"]);
    assert_eq!(code, 0, "encrypting to a stranger should still work: {err}");
    o.write("stranger.yaml", &encrypted);

    let (theirs, _, _) = o.sops(&["-d", "stranger.yaml"]);
    let (mine, out, _) = o.ours(&["-d", "stranger.yaml"]);
    assert_ne!(theirs, 0, "sops must refuse a file it has no key for");
    assert_ne!(mine, 0, "we must refuse a file we have no key for");
    assert!(out.is_empty(), "a refusal must print no plaintext");
}

/// ★ `set` AGAINST THE ORACLE — the case that decides whether the alias is honest.
///
/// `set` was the one refused verb the fleet actually used (one live caller in the
/// nix repo plus two operator docs), so it is also the one whose *semantics* had to
/// match rather than merely exist. Both binaries write the same key on the same
/// encrypted file; the check is that the DECRYPTED result agrees, and that each
/// binary's output is readable by the other.
///
/// The comparison is deliberately on the decrypted plaintext, not the ciphertext:
/// two correct implementations produce different bytes for the leaf they rewrite
/// (fresh nonce), so a byte comparison of the file would fail for a good reason and
/// teach nothing.
#[test]
fn both_binaries_set_a_key_to_the_same_result() {
    let Some(o) = oracle_or_skip() else { return };
    let mut checked = 0;
    for (name, plain) in CORPUS {
        let src = format!("{name}-set-plain.yaml");
        o.write(&src, plain.as_bytes());
        let (code, encrypted, err) = o.sops(&["-e", &src]);
        assert_eq!(code, 0, "{name}: sops encrypt failed: {err}");

        // Pick a key that exists in this fixture's top level, so the case exercises
        // an overwrite rather than a create on every corpus entry.
        let Some(key) = plain
            .lines()
            .find(|l| !l.starts_with(' ') && l.contains(':') && !l.trim_end().ends_with(':'))
            .and_then(|l| l.split(':').next())
            .map(str::to_string)
        else {
            continue;
        };
        let path = format!("[\"{key}\"]");

        let theirs_file = format!("{name}-set-theirs.yaml");
        let ours_file = format!("{name}-set-ours.yaml");
        o.write(&theirs_file, &encrypted);
        o.write(&ours_file, &encrypted);

        let (tc, _, terr) = o.sops(&["set", &theirs_file, &path, "\"differential\""]);
        assert_eq!(tc, 0, "{name}: oracle set failed: {terr}");
        let (oc, _, oerr) = o.ours(&["set", &ours_file, &path, "\"differential\""]);
        assert_eq!(oc, 0, "{name}: our set failed: {oerr}");

        // Each binary reads the other's output — the property that makes the alias
        // safe to roll back mid-flight.
        let (_, theirs_plain, _) = o.sops(&["-d", &ours_file]);
        let (_, ours_plain, err) = o.ours(&["-d", &theirs_file]);
        let theirs_plain = String::from_utf8_lossy(&theirs_plain).into_owned();
        let ours_plain = String::from_utf8_lossy(&ours_plain).into_owned();

        assert!(
            !theirs_plain.is_empty(),
            "{name}: the oracle could not read our set output"
        );
        assert!(
            theirs_plain.contains("differential"),
            "{name}: our set did not take effect as the oracle reads it"
        );
        assert_eq!(
            ours_plain,
            theirs_plain,
            "{name}: set results differ ({err})\n{}",
            diff_report(&theirs_plain, &ours_plain)
        );
        checked += 1;
    }
    println!("{checked} comparisons: `set` agrees with the oracle, both directions");
    assert!(checked > 0, "the corpus yielded no comparable case");
}

/// `unset` likewise: the key must be gone, and the oracle must agree it is gone.
#[test]
fn both_binaries_unset_a_key_to_the_same_result() {
    let Some(o) = oracle_or_skip() else { return };
    let plain = "alpha: one\nbeta: two\ngamma: three\n";
    o.write("unset-plain.yaml", plain.as_bytes());
    let (code, encrypted, err) = o.sops(&["-e", "unset-plain.yaml"]);
    assert_eq!(code, 0, "sops encrypt failed: {err}");
    o.write("unset-theirs.yaml", &encrypted);
    o.write("unset-ours.yaml", &encrypted);

    let (tc, _, terr) = o.sops(&["unset", "unset-theirs.yaml", "[\"beta\"]"]);
    assert_eq!(tc, 0, "oracle unset failed: {terr}");
    let (oc, _, oerr) = o.ours(&["unset", "unset-ours.yaml", "[\"beta\"]"]);
    assert_eq!(oc, 0, "our unset failed: {oerr}");

    let (_, theirs_plain, _) = o.sops(&["-d", "unset-ours.yaml"]);
    let (_, ours_plain, err) = o.ours(&["-d", "unset-theirs.yaml"]);
    let theirs_plain = String::from_utf8_lossy(&theirs_plain).into_owned();
    let ours_plain = String::from_utf8_lossy(&ours_plain).into_owned();

    assert!(
        !theirs_plain.contains("beta"),
        "the oracle still sees beta after our unset:\n{theirs_plain}"
    );
    assert_eq!(
        ours_plain,
        theirs_plain,
        "unset results differ ({err})\n{}",
        diff_report(&theirs_plain, &ours_plain)
    );
}
