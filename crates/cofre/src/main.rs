//! `cofre` — typed secret materialization CLI.
//!
//! Subcommands:
//!   plan      — show what apply would do (no plaintext touched)
//!   apply     — materialize missing secrets; --rotate forces re-gen
//!   verify    — confirm every declared secret exists in its backend
//!   inventory — emit BLAKE3-attested inventory (no values, ever)
//!
//! Hard rules (security-critical, audited per release):
//!   - Plaintext NEVER hits stdout, stderr, argv, env, or any log line.
//!   - Plaintext lives only in `Zeroizing<String>` (zeroed on drop).
//!   - Generation uses `getrandom` (OS CSPRNG).
//!   - SOPS writes go via EDITOR-mode hijack — value lives in our own
//!     editor child's memory and the temp file SOPS creates with 0600.
//!   - Akeyless writes go via `akeyless-api` SDK (HTTPS) — never via the
//!     `akeyless` CLI's `--value` argv flag.

#![warn(clippy::pedantic)]

mod backends;
mod generation;
mod inventory;

use crate::backends::SecretBackend;
use clap::{Parser, Subcommand};
use cofre_types::{BackendKind, RotationPolicy, SecretMaterializationPlan, SecretRef};

#[derive(Parser, Debug)]
#[command(version, about = "Typed secret materialization — never see your secrets again.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Plan {
        #[arg(long)]
        manifest: String,
    },
    Apply {
        #[arg(long)]
        manifest: String,
        /// Force-rotate this specific secret (by name) even if present.
        /// Refuses on RotationPolicy::Never secrets.
        #[arg(long)]
        rotate: Option<String>,
        /// Mock backends only — for tests.
        #[arg(long)]
        mock: bool,
    },
    Verify {
        #[arg(long)]
        manifest: String,
        #[arg(long)]
        mock: bool,
    },
    Inventory {
        #[arg(long)]
        manifest: String,
    },
    /// Internal — invoked by cofre apply as $EDITOR.
    #[command(name = "__sops-editor-hook", hide = true)]
    SopsEditorHook { path: String },
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let exit_code = rt.block_on(async {
        match cli.command {
            Command::Plan { manifest } => cmd_plan(&manifest).await,
            Command::Apply { manifest, rotate, mock } => {
                cmd_apply(&manifest, rotate.as_deref(), mock).await
            }
            Command::Verify { manifest, mock } => cmd_verify(&manifest, mock).await,
            Command::Inventory { manifest } => cmd_inventory(&manifest).await,
            Command::SopsEditorHook { path } => cmd_sops_editor_hook(&path),
        }
    });
    std::process::exit(exit_code);
}

fn load_plan(path: &str) -> Option<SecretMaterializationPlan> {
    match std::fs::read_to_string(path) {
        Ok(body) => match SecretMaterializationPlan::from_yaml(&body) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("error: parse plan: {e}");
                None
            }
        },
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            None
        }
    }
}

async fn cmd_plan(manifest: &str) -> i32 {
    let Some(plan) = load_plan(manifest) else {
        return 2;
    };
    println!("plan: {} ({} secret(s))", plan.metadata.name, plan.secrets.len());
    if let Some(src) = &plan.metadata.source {
        println!("source: {src}");
    }
    for s in &plan.secrets {
        let policy = match &s.generation {
            None => "external".to_string(),
            Some(g) => format!("{g:?}"),
        };
        println!(
            "  - {} [backend: {}] [gen: {}] [rotation: {:?}]",
            s.name,
            s.backend.stable_id(),
            policy,
            s.rotation
        );
    }
    eprintln!("note: plan-time inspection — no backends contacted, no secrets generated.");
    0
}

async fn cmd_apply(manifest: &str, rotate: Option<&str>, mock: bool) -> i32 {
    let Some(plan) = load_plan(manifest) else {
        return 2;
    };

    // Validate rotate target (if any) up front.
    if let Some(name) = rotate {
        match plan.secrets.iter().find(|s| s.name == name) {
            Some(s) if s.rotation == RotationPolicy::Never => {
                eprintln!(
                    "error: secret {name:?} has RotationPolicy::Never — cofre refuses to rotate it"
                );
                return 4;
            }
            Some(_) => {}
            None => {
                eprintln!("error: --rotate target {name:?} not found in plan");
                return 4;
            }
        }
    }

    // Akeyless backend (lazy-init only when needed).
    let mut akeyless: Option<backends::AkeylessBackend> = None;
    let mock_backend = if mock { Some(backends::MockBackend::new()) } else { None };

    // SOPS apply works in batches per file.
    let mut sops_batches: std::collections::HashMap<
        String,
        Vec<backends::SopsHookEntry>,
    > = std::collections::HashMap::new();

    let argv0 = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("cofre"));

    let mut wrote = 0;
    let mut skipped = 0;
    let mut errored = 0;

    for s in &plan.secrets {
        let force = rotate == Some(s.name.as_str());
        let Some(policy) = s.generation.clone() else {
            // External secret — cofre never owns its lifecycle.
            skipped += 1;
            continue;
        };

        match &s.backend {
            BackendKind::Akeyless { .. } => {
                if mock {
                    let mb = mock_backend.as_ref().unwrap();
                    if let Err(e) = apply_one_via_backend(mb, s, &policy, force).await {
                        eprintln!("error: {} via mock: {e}", s.name);
                        errored += 1;
                        continue;
                    }
                } else {
                    if akeyless.is_none() {
                        match backends::AkeylessBackend::from_env().await {
                            Ok(b) => akeyless = Some(b),
                            Err(e) => {
                                eprintln!("error: akeyless auth: {e}");
                                return 5;
                            }
                        }
                    }
                    let ab = akeyless.as_ref().unwrap();
                    if let Err(e) = apply_one_via_backend(ab, s, &policy, force).await {
                        eprintln!("error: {} via akeyless: {e}", s.name);
                        errored += 1;
                        continue;
                    }
                }
                wrote += 1;
            }
            BackendKind::Sops { file, yaml_path } => {
                sops_batches
                    .entry(file.clone())
                    .or_default()
                    .push(backends::SopsHookEntry {
                        yaml_path: yaml_path.clone(),
                        policy,
                        force,
                    });
            }
            BackendKind::Mock { .. } => {
                if !mock {
                    eprintln!(
                        "error: secret {} targets a Mock backend but --mock not given",
                        s.name
                    );
                    return 4;
                }
                let mb = mock_backend.as_ref().unwrap();
                if let Err(e) = apply_one_via_backend(mb, s, &policy, force).await {
                    eprintln!("error: {} via mock: {e}", s.name);
                    errored += 1;
                    continue;
                }
                wrote += 1;
            }
        }
    }

    // Run SOPS batches (one editor invocation per file).
    for (file, entries) in &sops_batches {
        let backend = match backends::SopsBackend::new(file.clone(), argv0.clone()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: sops backend init for {file}: {e}");
                errored += entries.len();
                continue;
            }
        };
        if let Err(e) = backend.apply_batch(entries).await {
            eprintln!("error: sops apply for {file}: {e}");
            errored += entries.len();
            continue;
        }
        wrote += entries.len();
    }

    println!(
        "wrote: {} | skipped: {} | errored: {} | (rotate: {:?})",
        wrote, skipped, errored, rotate
    );
    if errored > 0 {
        1
    } else {
        0
    }
}

async fn apply_one_via_backend(
    backend: &dyn backends::SecretBackend,
    secret: &SecretRef,
    policy: &cofre_types::SecretGenPolicy,
    force: bool,
) -> Result<bool, String> {
    let exists = backend
        .exists(secret)
        .await
        .map_err(|e| format!("exists: {e}"))?;
    if exists && !force {
        return Ok(false);
    }
    let value = generation::generate(policy).map_err(|e| format!("generate: {e}"))?;
    backend
        .write(secret, value)
        .await
        .map_err(|e| format!("write: {e}"))?;
    Ok(true)
}

async fn cmd_verify(manifest: &str, mock: bool) -> i32 {
    let Some(plan) = load_plan(manifest) else {
        return 2;
    };

    let akeyless = if mock {
        None
    } else {
        match backends::AkeylessBackend::from_env().await {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("error: akeyless auth: {e}");
                return 5;
            }
        }
    };
    let mock_backend = if mock { Some(backends::MockBackend::new()) } else { None };

    let mut missing = 0;
    let mut present = 0;
    for s in &plan.secrets {
        let exists_result = match &s.backend {
            BackendKind::Akeyless { .. } => {
                if mock {
                    Ok(false)
                } else {
                    akeyless.as_ref().unwrap().exists(s).await
                }
            }
            BackendKind::Mock { .. } => mock_backend.as_ref().unwrap().exists(s).await,
            BackendKind::Sops { .. } => {
                // SOPS existence requires decryption; for verify we
                // surface that distinction rather than running sops.
                eprintln!("  ? {} (sops backend — `verify` doesn't decrypt; run `apply` for idempotent reconciliation)", s.name);
                continue;
            }
        };
        match exists_result {
            Ok(true) => {
                println!("  ✓ {} (present)", s.name);
                present += 1;
            }
            Ok(false) => {
                println!("  × {} (missing)", s.name);
                missing += 1;
            }
            Err(e) => {
                println!("  ! {} (error: {})", s.name, e);
                missing += 1;
            }
        }
    }
    println!("present: {} | missing: {}", present, missing);
    if missing > 0 {
        1
    } else {
        0
    }
}

async fn cmd_inventory(manifest: &str) -> i32 {
    let Some(plan) = load_plan(manifest) else {
        return 2;
    };
    // Inventory production requires reading values to BLAKE3-hash them.
    // For now we emit only the structural inventory (no value hashes —
    // that needs a per-backend `read_for_inventory` impl which is a
    // separate trait method we'll add when we ship rotation tracking).
    eprintln!("note: inventory emits structural-only entries; value hashing lands when rotation tracking ships.");
    let entries: Vec<inventory::InventoryEntry> = plan
        .secrets
        .iter()
        .map(|s| inventory::InventoryEntry {
            name: s.name.clone(),
            backend: s.backend.stable_id(),
            salt_hex: String::new(),
            value_hash_hex: String::new(),
            last_applied_utc: String::new(),
            rotation: s.rotation,
        })
        .collect();
    let inv = inventory::Inventory {
        plan: plan.metadata.name.clone(),
        entries,
    };
    match serde_yaml::to_string(&inv) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!("error: inventory serialize: {e}");
            6
        }
    }
}

fn cmd_sops_editor_hook(path: &str) -> i32 {
    let p = std::path::Path::new(path);
    match backends::run_editor_hook(p) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("__sops-editor-hook: {e}");
            7
        }
    }
}
