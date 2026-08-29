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

// ── ★ THE CALLER'S ARGUMENT GRAMMAR ─────────────────────────────────────────
//
// sops-nix invokes this at BUILD time as
//     sops-install-secrets -check-mode=sopsfile <manifest.json>
// (read off zek's manifest.json.drv). Go's flag package uses ONE dash, and the
// original parser took any argument not starting with `--` as the manifest
// path -- so the flag became the path and the build died naming a file nobody
// asked for.
//
// Like the binary name, this was invisible to every behavioural differential:
// those invoked the program with the arguments WE chose, never the ones the
// caller sends. An interface needs its own evidence.

#[test]
fn a_go_style_check_mode_flag_is_not_mistaken_for_the_manifest() {
    let dir = std::env::temp_dir().join(format!("suminuri-cm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch");
    let mf = dir.join("manifest.json");
    std::fs::write(
        &mf,
        r#"{"secretsMountPoint":"/run/secrets.d","symlinkPath":"/run/secrets",
            "keepGenerations":1,
            "secrets":[{"name":"a","key":"k","path":"/run/secrets/a",
                        "sopsFile":"/etc/s.yaml","format":"yaml","mode":"0400",
                        "uid":0,"gid":0}],
            "templates":[]}"#,
    )
    .expect("write");

    let out = Command::new(env!("CARGO_BIN_EXE_sops-install-secrets"))
        .args(["-check-mode=sopsfile", mf.to_str().unwrap()])
        .output()
        .expect("runs");
    let err = String::from_utf8_lossy(&out.stderr);

    assert_eq!(out.status.code(), Some(0), "check mode must succeed: {err}");
    assert!(err.contains("check-mode=sopsfile"), "{err}");
    assert!(
        err.contains("nothing installed"),
        "check mode must install NOTHING -- it runs inside a nix builder with no \
         /run/secrets and no identities: {err}"
    );
    // The failure this pins: the flag being read as the path.
    assert!(
        !err.contains("cannot read the manifest"),
        "the flag was taken as the manifest path: {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn check_mode_still_refuses_a_manifest_that_does_not_exist() {
    // Anti-vacuity: check mode must not be a blanket success.
    let out = Command::new(env!("CARGO_BIN_EXE_sops-install-secrets"))
        .args(["-check-mode=sopsfile", "/nonexistent/manifest.json"])
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(1));
}
