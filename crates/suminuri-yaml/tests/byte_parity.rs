//! The emitter byte-parity gate.
//!
//! Every fixture in `tests/fixtures/` was produced by **upstream sops v3.12.1**,
//! so it is a go-yaml v3 artifact and therefore the oracle. The gate is a single
//! claim: `emit(parse(f)) == f`, byte for byte, for every one of them.
//!
//! # Why this shape of test
//!
//! A round-trip against our own output would prove only that we are
//! self-consistent, which is exactly the vacuous gate this repo's Nix invariants
//! warn about. The bytes have to come from the *other* implementation, and they
//! do — regenerate with the recipe below and the oracle is refreshed from real
//! sops, not from us.
//!
//! ```text
//! age-keygen -o key.txt
//! export SOPS_DISABLE_VERSION_CHECK=1 SOPS_AGE_KEY_FILE=$PWD/key.txt
//! R=<the printed public key>
//! sops --age $R -e plain-flat.yaml            > enc-plain-flat.yaml
//! sops --age $R -e plain-nested.yaml          > enc-plain-nested.yaml
//! sops --age $R -e plain-seq.yaml             > enc-plain-seq.yaml
//! sops --age $R --unencrypted-suffix _unencrypted -e plain-suffix.yaml > enc-plain-suffix.yaml
//! sops --age "$R,$R2" -e plain-flat.yaml      > enc-two-recipients.yaml
//! sops --age $R --mac-only-encrypted -e plain-suffix.yaml > enc-mac-only.yaml
//! sops --age $R --indent 2 -e plain-nested.yaml > enc-indent2.yaml
//! ```
//!
//! `SOPS_DISABLE_VERSION_CHECK=1` is not cosmetic: without it sops reaches out for
//! a release check and hangs for minutes on a network-restricted host. That is
//! also a behaviour the CLI front has to reproduce.
//!
//! # No secrets here
//!
//! The fixtures are ciphertext under a **throwaway** age key that was generated
//! for this corpus and protects nothing; the key itself is deliberately *not*
//! committed. These tests never decrypt — parse and emit are all that byte-parity
//! needs, so the corpus is inert by construction rather than by policy.

use suminuri_yaml::{EmitOptions, emit, parse};

/// Every fixture, with the indent real sops used to write it.
///
/// The indent is part of the oracle: `enc-indent2.yaml` was written with
/// `--indent 2`, and re-emitting it at 4 would differ on every line. A fixture
/// list that forgot this would look like an emitter bug.
const CORPUS: &[(&str, usize)] = &[
    ("enc-plain-flat.yaml", 4),
    ("enc-plain-nested.yaml", 4),
    ("enc-plain-seq.yaml", 4),
    ("enc-plain-suffix.yaml", 4),
    ("enc-two-recipients.yaml", 4),
    ("enc-mac-only.yaml", 4),
    ("enc-indent2.yaml", 2),
];

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {} unreadable: {e}", path.display()))
}

/// Report the first divergence structurally. Never prints a ciphertext body —
/// these are inert fixtures, but the same helper shape is what a failure against
/// a *real* file would use.
fn first_divergence(want: &str, got: &str) -> String {
    let w: Vec<&str> = want.lines().collect();
    let g: Vec<&str> = got.lines().collect();
    for (i, (a, b)) in w.iter().zip(g.iter()).enumerate() {
        if a != b {
            return format!(
                "line {}:\n  sops : {}\n  ours : {}",
                i + 1,
                redact(a),
                redact(b)
            );
        }
    }
    format!(
        "no differing line in the common prefix; sops has {} lines, ours {}",
        w.len(),
        g.len()
    )
}

fn redact(line: &str) -> String {
    match line.find("ENC[") {
        Some(k) => format!("{}ENC[… {} chars …]", &line[..k], line.len() - k),
        None => line.to_string(),
    }
}

#[test]
fn every_fixture_round_trips_byte_exactly() {
    let mut checked = 0usize;
    for (name, indent) in CORPUS {
        let want = fixture(name);
        let doc = parse(&want).unwrap_or_else(|e| panic!("{name}: parse failed: {e}"));
        let got = emit(&doc, EmitOptions { indent: *indent })
            .unwrap_or_else(|e| panic!("{name}: emit failed: {e}"));
        assert_eq!(
            got.len(),
            want.len(),
            "{name}: byte length differs ({} vs {})\n{}",
            got.len(),
            want.len(),
            first_divergence(&want, &got)
        );
        assert!(
            got == want,
            "{name}: bytes differ\n{}",
            first_divergence(&want, &got)
        );
        checked += 1;
    }
    // The denominator. An empty corpus — a moved directory, a bad glob — would
    // otherwise pass this test while checking nothing.
    assert_eq!(checked, CORPUS.len(), "every fixture must be checked");
    assert!(
        checked >= 7,
        "the corpus shrank; a parity gate with fewer cases is a weaker claim"
    );
}

/// The specific line shape that distinguishes go-yaml from libyaml. Pinned
/// separately from the whole-file compare so a failure names the *cause* rather
/// than just "bytes differ".
#[test]
fn the_sequence_indent_matches_go_yaml_in_a_real_sops_file() {
    let src = fixture("enc-plain-seq.yaml");
    assert!(
        src.contains("        - recipient: "),
        "the oracle itself should carry the go-yaml shape"
    );
    assert!(
        !src.contains("    -   recipient"),
        "the oracle should not carry the libyaml shape"
    );
    let got = emit(&parse(&src).expect("parse"), EmitOptions::default()).expect("emit");
    assert!(
        got.contains("        - recipient: "),
        "we must emit the go-yaml shape"
    );
    assert!(
        !got.contains("    -   recipient"),
        "we must not emit the libyaml shape"
    );
}

/// A fixture written at `--indent 2` re-emitted at 4 *must* differ. Without this,
/// an emitter that ignored the indent option entirely could still pass the corpus
/// — the parity test would be measuring nothing about indentation.
#[test]
fn the_indent_option_is_actually_load_bearing() {
    let src = fixture("enc-indent2.yaml");
    let doc = parse(&src).expect("parse");
    let at_two = emit(&doc, EmitOptions { indent: 2 }).expect("emit");
    let at_four = emit(&doc, EmitOptions { indent: 4 }).expect("emit");
    assert_eq!(at_two, src, "indent 2 reproduces the oracle");
    assert_ne!(
        at_four, src,
        "indent 4 must NOT, or the option is being ignored"
    );
}

/// Re-emitting our own output must be a fixed point. A parity pass plus a
/// non-idempotent emitter would mean the second `sops edit` reflows the file.
#[test]
fn emission_is_idempotent() {
    for (name, indent) in CORPUS {
        let src = fixture(name);
        let opts = EmitOptions { indent: *indent };
        let once = emit(&parse(&src).expect("parse"), opts).expect("emit");
        let twice = emit(&parse(&once).expect("reparse"), opts).expect("re-emit");
        assert_eq!(once, twice, "{name}: emission is not a fixed point");
    }
}

/// Key order survives the round-trip. `plain-flat.yaml` was authored in a
/// deliberately non-alphabetical order, because order is what the file MAC is
/// computed over — a sorted re-emit would produce a file that fails its own MAC.
#[test]
fn key_order_is_preserved_because_the_mac_depends_on_it() {
    let src = fixture("enc-plain-flat.yaml");
    let doc = parse(&src).expect("parse");
    let root = doc.root().expect("single document");
    let suminuri_yaml::Value::Mapping(items) = root else {
        panic!("mapping root")
    };
    let keys: Vec<&str> = items
        .iter()
        .filter_map(|i| match i {
            suminuri_yaml::Item::Pair { key, .. } => Some(key.as_str()),
            suminuri_yaml::Item::Comment(_) => None,
        })
        .collect();
    assert_eq!(
        keys,
        vec!["alpha", "beta", "count", "ratio", "enabled", "sops"],
        "source order, with `sops` last where sops appends it"
    );
}

/// The corpus covers every leaf datatype sops can write, so a regression in one
/// type's rendering cannot hide behind the others.
#[test]
fn the_corpus_exercises_every_writable_datatype() {
    let src = fixture("enc-plain-flat.yaml");
    for ty in ["type:str", "type:int", "type:float", "type:bool"] {
        assert!(src.contains(ty), "the corpus must exercise {ty}");
    }
}

/// A file real sops wrote with `--mac-only-encrypted` carries the flag, and it
/// has to survive the round-trip or the file's MAC becomes uncheckable.
#[test]
fn the_mac_only_encrypted_flag_survives() {
    let src = fixture("enc-mac-only.yaml");
    assert!(
        src.contains("mac_only_encrypted: true"),
        "the oracle carries the flag"
    );
    let got = emit(&parse(&src).expect("parse"), EmitOptions::default()).expect("emit");
    assert!(got.contains("mac_only_encrypted: true"), "and so must ours");
}

/// Two recipients means two entries in the `sops.age` sequence — the exact shape
/// whose indentation diverges between the two YAML engines, and the shape the
/// operator's own `secrets.yaml` carries three of.
#[test]
fn a_multi_recipient_file_keeps_both_entries_in_order() {
    let src = fixture("enc-two-recipients.yaml");
    let got = emit(&parse(&src).expect("parse"), EmitOptions::default()).expect("emit");
    assert_eq!(got, src);
    assert_eq!(
        src.matches("- recipient: ").count(),
        2,
        "the oracle has two recipients"
    );
    assert_eq!(got.matches("- recipient: ").count(), 2);
}
