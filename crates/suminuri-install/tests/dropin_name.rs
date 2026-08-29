//! The drop-in must answer to the name its CALLER uses.
//!
//! ── ★ THE FAILURE THIS PINS (zek, 2026-08-29) ───────────────────────────
//!
//! sops-nix hardcodes `${cfg.package}/bin/sops-install-secrets` in its manifest
//! builder, its systemd unit and its darwin activation script. The package
//! shipped only `suminuri-install-secrets`, so the first real cutover died at
//! BUILD time:
//!
//! ```text
//! error: Cannot build 'manifest.json.drv'.
//!        Reason: builder failed with exit code 127.
//!        > …/bin/sops-install-secrets
//! ```
//!
//! ★ Why no amount of differential testing would have caught it: the
//! differential invoked the binary by its own absolute path. It proved the
//! placement byte-identical against upstream on two real manifests while never
//! once exercising the NAME the caller resolves. A behavioural differential
//! cannot see an interface mismatch it does not use — the interface has to be
//! asserted separately, which is what this file is.

use std::process::Command;

#[test]
fn the_dropin_name_exists_and_runs() {
    // The whole point: this binary must EXIST under this name.
    let out = Command::new(env!("CARGO_BIN_EXE_sops-install-secrets"))
        .arg("--help")
        .output()
        .expect("sops-install-secrets must be a built binary of this crate");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn both_names_are_the_same_program() {
    // Not a copy: both call one library entry point, so they cannot drift.
    // Compared on --help output, which names the usage contract.
    let a = Command::new(env!("CARGO_BIN_EXE_sops-install-secrets"))
        .arg("--help")
        .output()
        .expect("runs");
    let b = Command::new(env!("CARGO_BIN_EXE_suminuri-install-secrets"))
        .arg("--help")
        .output()
        .expect("runs");
    assert_eq!(a.stdout, b.stdout, "the two names must behave identically");
    assert_eq!(a.status.code(), b.status.code());
}

#[test]
fn the_dropin_name_refuses_a_missing_manifest_the_same_way() {
    // The contract sops-nix actually depends on: a bad invocation is a
    // non-zero exit, not a silent success that leaves secrets unplaced.
    let out = Command::new(env!("CARGO_BIN_EXE_sops-install-secrets"))
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(1));
}
