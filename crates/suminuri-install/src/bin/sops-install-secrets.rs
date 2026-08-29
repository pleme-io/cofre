//! `sops-install-secrets` — the drop-in name sops-nix actually invokes.
//!
//! ── ★ WHY THIS FILE EXISTS (zek, 2026-08-29) ────────────────────────────
//!
//! A drop-in has to answer to the name its CALLER uses. sops-nix hardcodes
//! `${cfg.package}/bin/sops-install-secrets` — in the manifest builder, in the
//! systemd unit, and in the darwin activation script. The crate's own binary is
//! `suminuri-install-secrets`, so pointing `sops.package` at it produced:
//!
//! ```text
//! error: Cannot build 'manifest.json.drv'.
//!        Reason: builder failed with exit code 127.
//!        > …/bin/sops-install-secrets
//! ```
//!
//! 127 is "command not found". The failure surfaced only on a real cutover:
//! the differential invoked the binary by its own absolute path, so it proved
//! the PLACEMENT was byte-identical while never once exercising the name the
//! caller resolves. A behavioural differential cannot catch an interface
//! mismatch it does not use.
//!
//! Both names ship. `suminuri-install-secrets` is the pleme-io-native name and
//! stays the one a person types; this is the compatibility surface, and the two
//! are the SAME program rather than a copy — the shared `main` lives in the
//! library, so they cannot drift.
fn main() -> std::process::ExitCode {
    suminuri_install::entry::run()
}
