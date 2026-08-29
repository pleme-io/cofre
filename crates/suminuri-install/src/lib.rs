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

pub mod identity;
pub mod manifest;
pub mod place;

pub use identity::{IdentityError, Source};
pub use manifest::{Manifest, ManifestError, Secret};
pub use place::{PlanError, Step, plan, prune};
