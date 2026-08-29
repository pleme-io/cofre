//! suminuri-install — the `sops-install-secrets` drop-in.
//!
//! ── ★ WHAT THIS IS FOR ─────────────────────────────────────────────────
//!
//! `overlays/suminuri.nix` rebinds `pkgs.sops` fleet-wide and captured two of
//! suminuri's four fronts. It **provably cannot** capture the third: upstream
//! `sops-install-secrets/main.go:343` calls `decrypt.File` as a Go *library*,
//! and the only `exec.Command`s in that file are
//! `systemctl`/`getconf`/`hdiutil`/`newfs_hfs`/`mount`. There is no `sops` process to
//! substitute, so a PATH swap reaches nothing.
//!
//! sops-nix exposes a `sops.package` seam instead. The fleet surfaces it as
//! `pleme.suminuri.installSecretsPackage` — declared in
//! `modules/pleme/shared/suminuri.nix:79`, forwarded by blackmatter-secrets,
//! and held closed by an assertion because no drop-in existed. This crate is
//! the drop-in.
//!
//! **Front 3 carries the fleet's real load: 337 secret declarations across 18
//! nodes, re-materialised on every rebuild.**
//!
//! ── ★ THE IDENTITY IT USES IS THE NODE'S SSH HOST KEY ──────────────────
//!
//! The manifest's `ageSshKeyPaths` names `/etc/ssh/ssh_host_ed25519_key`, and
//! `sshKeyPaths` names the RSA one. A node's **ssh host identity IS its
//! secret-decryption identity** — which is why `theory/NATURALIZE-NIXOS.md`
//! records the sshd row and this one as two ends of a single path, sharing
//! exactly one constraint: *never regenerate the host keys*.
//!
//! ── STATUS ─────────────────────────────────────────────────────────────
//!
//! **Manifest layer only.** The typed contract with sops-nix's JSON, its two
//! placement passes, and the octal-mode trap. Decryption reuses
//! `suminuri`. The ssh-ed25519 → age gap named in the first commit is
//! **closed**: `age 0.11` already implements the conversion behind its `ssh`
//! feature, so it took a feature flag rather than a hand-written birational
//! map — the right outcome for the one place in this fleet where rolling our
//! own crypto would be least defensible.

pub mod apply;
pub mod identity;
pub mod manifest;
pub mod place;
pub mod real;
pub mod template;

pub use apply::{Applied, ApplyError, Decryptor, Fs, apply};
pub use identity::{IdentityError, Source};
pub use manifest::{Manifest, ManifestError, Secret};
pub use place::{PlanError, Step, plan, prune};

// ── ★ THE ENTRY POINT LIVES HERE, NOT IN A BIN ──────────────────────────────
//
// Two binaries ship: `suminuri-install-secrets` (the pleme-io-native name) and
// `sops-install-secrets` (the name sops-nix hardcodes in its manifest builder,
// its systemd unit and its darwin activation script). They must be the SAME
// program, so the entry point is a library function both call rather than a
// file one of them copies.
//
// Learned on zek: pointing `sops.package` at a package lacking the second name
// fails at BUILD time with exit 127, and the differential could not see it —
// it invoked the binary by absolute path, proving placement byte-identical
// while never exercising the name the caller resolves.
pub mod entry;
