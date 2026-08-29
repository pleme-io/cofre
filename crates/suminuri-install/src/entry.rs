//! `suminuri-install-secrets` — the sops-install-secrets drop-in.
//!
//! Argument-compatible with upstream: one positional manifest path, which is
//! all sops-nix's activation passes. `--dry-run` prints the plan and touches
//! nothing, which is how a node is checked before
//! `pleme.suminuri.installSecretsPackage` is ever flipped.

use std::process::ExitCode;

use crate::apply::apply;
use crate::manifest::Manifest;
use crate::place::plan;
use crate::real::{RealFs, SuminuriDecryptor};
use suminuri::AgeIdentities;
use suminuri::env::RealEnvironment;

/// One string, two consumers: `--help` prints it to stdout and exits 0, a
/// missing manifest prints it to stderr and exits 1. Written once so the two
/// cannot drift into describing different flags.
const USAGE: &str = "usage: suminuri-install-secrets [--dry-run] <manifest.json>\n\
     \n\
     The sops-install-secrets drop-in. --dry-run prints the plan and\n\
     touches nothing.";

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::FAILURE
}

/// The generation number to install as.
///
/// ★ Derived from the wall clock, not from "highest existing + 1". Scanning
/// the mount point and incrementing races a concurrent installer into
/// producing the SAME number, and two processes writing one generation
/// directory is the corruption this whole design avoids elsewhere.
fn generation() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| d.as_secs())
}

pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // ★ ASKING FOR HELP IS A SUCCESS. Without this, `--help` starts with `--`,
    // so it is not taken as the manifest path, falls through to usage(), and
    // exits 1 -- a question answered with a failure code.
    //
    // Sibling of the defect that produced `shikumi::daemon`: there, three
    // daemons ignored `--help` entirely and started. Here it is answered but
    // graded wrong. Both come from argv handling written as an afterthought
    // around the real work, and both matter because a wrapper reads the code,
    // not the text: an activation script running this under `set -e` would
    // abort on a help invocation.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    // ── ★ UPSTREAM'S FLAGS ARE GO-STYLE, SINGLE-DASH ────────────────────────
    //
    // sops-nix invokes this at BUILD time as
    //
    //     sops-install-secrets -check-mode=sopsfile <manifest.json>
    //
    // read off zek's manifest.json.drv. Go's `flag` package uses one dash, and
    // the original parser took "any argument not starting with `--`" as the
    // manifest path -- so `-check-mode=sopsfile` WAS the path, and the build
    // died with "cannot read the manifest: No such file or directory (os error
    // 2)" naming a file nobody asked for.
    //
    // ★ A drop-in's argument grammar is part of its interface, exactly like its
    // binary name. Both were invisible to every behavioural differential: those
    // called this program with the arguments WE chose, never the ones the
    // caller sends.
    let dry = args.iter().any(|a| a == "--dry-run");
    let check_mode = args.iter().find_map(|a| {
        a.strip_prefix("-check-mode=")
            .or_else(|| a.strip_prefix("--check-mode="))
    });
    // The manifest is the first argument that is not a flag in EITHER grammar.
    let Some(path) = args.iter().find(|a| !a.starts_with('-')) else {
        return usage();
    };

    let manifest = match Manifest::load(std::path::Path::new(path)) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("suminuri-install-secrets: {e}");
            return ExitCode::FAILURE;
        }
    };

    // ── ★ CHECK MODE: VALIDATE, INSTALL NOTHING ─────────────────────────────
    //
    // Upstream runs this inside a nix builder to fail a BUILD on a bad manifest
    // rather than an activation on a live host. The mode names what to check;
    // `sopsfile` is the one sops-nix actually passes.
    //
    // Installing here would be a serious bug -- a sandboxed builder has no
    // /run/secrets, no identities and no business writing anything -- so this
    // returns BEFORE any step is executed.
    if let Some(mode) = check_mode {
        // The manifest already parsed above; that is most of the check. The
        // rest is that it PLANS, which is where a bad mode string, a missing
        // ownership or an unresolvable runtime specifier surfaces.
        return match plan(&manifest, 0) {
            Ok(steps) => {
                eprintln!(
                    "suminuri-install-secrets: check-mode={mode} OK — {} entries, {} steps, nothing installed",
                    manifest.secrets.len(),
                    steps.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("suminuri-install-secrets: check-mode={mode} FAILED: {e:?}");
                ExitCode::FAILURE
            }
        };
    }

    let gen_id = generation();
    eprintln!(
        "suminuri-install-secrets: {} entries ({} needed for users) over {} file(s), generation {gen_id}",
        manifest.secrets.len(),
        manifest.user_pass().len(),
        manifest.distinct_files().len(),
    );

    if dry {
        // ★ The dry run plans but does NOT resolve identities or decrypt. It
        // answers "is this manifest installable and in what order", which is
        // checkable anywhere — including a workstation that holds none of the
        // node's keys. Conflating it with a decryption check would make the
        // safe question require the dangerous inputs.
        match plan(&manifest, gen_id) {
            Ok(steps) => {
                for s in &steps {
                    println!("{s:?}");
                }
                eprintln!(
                    "suminuri-install-secrets: {} steps, nothing executed",
                    steps.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("suminuri-install-secrets: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        let env = RealEnvironment;
        let age_files: Vec<String> = manifest.age_key_file.iter().cloned().collect();
        let identities =
            match AgeIdentities::from_paths(&env, &age_files, &manifest.age_ssh_key_paths) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("suminuri-install-secrets: identities: {e}");
                    return ExitCode::FAILURE;
                }
            };
        if identities.is_empty() {
            // ★ Named, not a bare decrypt failure later. "No identity" and
            // "wrong identity" send an operator to different files.
            eprintln!(
                "suminuri-install-secrets: no usable identity from {} age file(s) and {} ssh key(s)",
                age_files.len(),
                manifest.age_ssh_key_paths.len()
            );
            return ExitCode::FAILURE;
        }
        eprintln!(
            "suminuri-install-secrets: {} identity/identities",
            identities.len()
        );

        match apply(
            &manifest,
            gen_id,
            &RealFs,
            &SuminuriDecryptor::new(identities),
        ) {
            Ok(a) => {
                eprintln!(
                    "suminuri-install-secrets: generation {} published, {} written",
                    a.generation, a.written
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("suminuri-install-secrets: {e}");
                ExitCode::FAILURE
            }
        }
    }
}
