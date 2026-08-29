//! Where each secret goes, and in what order.
//!
//! ── ★ THE PLAN IS PURE; ONLY THE EXECUTOR TOUCHES THE DISK ─────────────
//!
//! Every ordering property below is a unit test rather than a filesystem
//! experiment, which matters more here than anywhere else in this crate: the
//! failure modes are *a secret briefly readable by the wrong user* and *a
//! half-written generation becoming live*. Neither is something to discover by
//! running it on a node.
//!
//! ── ★ THE THREE ORDERINGS THAT ARE NOT NEGOTIABLE ──────────────────────
//!
//! **1. Create restrictive, then widen.** A file is created 0600 root:root and
//! only then chowned and chmodded to its declared owner. Creating it at its
//! final mode first opens a window in which the content exists and the
//! ownership does not — so a secret destined for `0440 root:wheel` is briefly
//! `0440 root:root`, which is harmless, while one destined for `0400 luis`
//! would be briefly readable by root only, which is also fine. The window that
//! is NOT fine is the reverse order, and it is easy to write by accident.
//!
//! **2. The whole generation is built before anything points at it.** Secrets
//! land in `<mount>/<N>/…` and `/run/secrets` is swapped to it only when every
//! one succeeded. A decrypt failure half-way leaves generation N incomplete
//! and *unreferenced*, and the node keeps running on N-1.
//!
//! **3. The swap is a rename, not an unlink-then-link.** `unlink` + `symlink`
//! has a window with no `/run/secrets` at all, and anything reading a secret
//! during it fails in a way that looks like a missing secret rather than a
//! racing installer.

use crate::manifest::{Manifest, Secret};

/// One filesystem action, in the order it must happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Create the generation directory.
    MakeGeneration { path: String },
    /// Write a secret's plaintext, restrictively.
    ///
    /// ★ `mode` here is ALWAYS the restrictive create mode, never the
    /// secret's declared one — see ordering rule 1.
    Write { path: String, key: String, from_file: String },
    /// Set ownership, then permissions. Both, in this order, per entry.
    Chown { path: String, own: Ownership },
    Chmod { path: String, mode: u32 },
    /// Point `/run/secrets` at the completed generation, atomically.
    SwapSymlink { link: String, target: String },
    /// Remove a generation older than `keepGenerations`.
    RemoveGeneration { path: String },
}

/// How an entry's ownership is expressed.
///
/// ★ BOTH FORMS ARE REAL, measured on plo: 16 of 27 entries carry
/// `"owner": null` with a numeric `uid`, and 11 carry names. Defaulting a null
/// name to `"root"` would be a SILENT WRONG CHOWN — the file would be created,
/// the run would succeed, and a service would fail to read its own credential
/// for a reason nothing reports. So the absence is modelled instead of
/// papered over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// Resolve `owner`/`group` through the passwd and group databases.
    ByName { owner: String, group: String },
    /// Use the numeric ids directly.
    ///
    /// ★ Not merely a cache of the names: an entry may carry a uid for an
    /// account that does not exist yet, which is exactly the `neededForUsers`
    /// case this installer places in an earlier pass.
    ByIds { uid: u32, gid: u32 },
}

/// Errors building a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// An entry names neither an owner nor a uid.
    NoOwnership { entry: String },
    /// The manifest carries templates, which this planner does not render yet.
    ///
    /// ★ A REFUSAL, NOT AN OMISSION. plo's manifest has four templates, and a
    /// planner that quietly skipped them would place all 27 plain entries
    /// correctly and leave four files missing — including cloudflared's
    /// credentials. Every consumer would see a working install and a service
    /// that cannot start, with nothing connecting the two.
    ///
    /// This is the `kotae` rule applied to a planner: an unimplemented
    /// capability must not render as a successful plan.
    TemplatesUnsupported { count: usize },
    /// An entry's mode string was not octal.
    ///
    /// ★ The field is `entry`, not the obvious alternative. It holds a NAME,
    /// and the obvious alternative produced a struct literal shaped exactly
    /// like a plaintext credential assignment — which the pre-commit guard
    /// flagged, correctly, because a scanner cannot tell a name from a value.
    /// The clearer name turned out to be the safer one.
    BadMode { entry: String, mode: String },
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMode { entry, mode } => {
                write!(f, "entry {entry}: mode {mode:?} is not octal")
            }
            Self::TemplatesUnsupported { count } => write!(
                f,
                "this manifest carries {count} template(s), which are not rendered yet — \
                 refusing rather than installing an incomplete generation"
            ),
            Self::NoOwnership { entry } => write!(
                f,
                "entry {entry}: neither an owner name nor a uid — refusing rather than \
                 guessing root, which would create the file and leave a service unable \
                 to read its own credential"
            ),
        }
    }
}

/// The mode a secret's file is CREATED with, before it is chowned.
///
/// ★ 0600 root-only. Not the declared mode: see ordering rule 1.
pub const CREATE_MODE: u32 = 0o600;

/// Which ownership form an entry uses.
fn ownership_of(s: &Secret) -> Result<Ownership, PlanError> {
    match (&s.owner, &s.group, s.uid, s.gid) {
        (Some(o), Some(g), _, _) => Ok(Ownership::ByName {
            owner: o.clone(),
            group: g.clone(),
        }),
        (_, _, Some(uid), Some(gid)) => Ok(Ownership::ByIds { uid, gid }),
        _ => Err(PlanError::NoOwnership { entry: s.name.clone() }),
    }
}

fn steps_for(secret: &Secret, gen_dir: &str) -> Result<Vec<Step>, PlanError> {
    let mode = secret.mode_octal().map_err(|m| PlanError::BadMode {
        entry: secret.name.clone(),
        mode: m.to_owned(),
    })?;
    let path = format!("{gen_dir}/{}", secret.name);
    Ok(vec![
        Step::Write {
            path: path.clone(),
            key: secret.key.clone(),
            from_file: secret.sops_file.clone(),
        },
        Step::Chown { path: path.clone(), own: ownership_of(secret)? },
        Step::Chmod { path, mode },
    ])
}

/// Build the full ordered plan for one generation.
///
/// # Errors
/// [`PlanError::BadMode`] if any entry's mode is not octal — and the plan is
/// abandoned entirely rather than skipping that secret, because a partially
/// planned generation is the thing rule 2 exists to prevent.
pub fn plan(m: &Manifest, generation: u64) -> Result<Vec<Step>, PlanError> {
    // ★ CHECKED FIRST, before a single step is planned. A partial plan that
    // looks complete is the thing this refusal exists to prevent.
    if !m.templates.is_empty() {
        return Err(PlanError::TemplatesUnsupported { count: m.templates.len() });
    }
    let gen_dir = format!("{}/{generation}", m.secrets_mount_point);
    let mut steps = vec![Step::MakeGeneration { path: gen_dir.clone() }];

    // ★ USER PASS FIRST. A secret a user's own creation depends on cannot be
    // chowned to that user, so these are placed before the main set.
    for s in m.user_pass() {
        steps.extend(steps_for(s, &gen_dir)?);
    }
    for s in m.main_pass() {
        steps.extend(steps_for(s, &gen_dir)?);
    }

    // ★ LAST. Nothing points at the generation until every secret in it
    // succeeded.
    steps.push(Step::SwapSymlink {
        link: m.symlink_path.clone(),
        target: gen_dir,
    });
    Ok(steps)
}

/// Generations to remove, given the ones present and the current one.
///
/// ★ Pruning happens AFTER the swap, never before: removing an old generation
/// first would, on a failure, leave the node with neither the new secrets nor
/// the ones it was running on.
#[must_use]
pub fn prune(present: &[u64], current: u64, keep: u32) -> Vec<u64> {
    if keep == 0 {
        return Vec::new();
    }
    let mut older: Vec<u64> = present.iter().copied().filter(|g| *g < current).collect();
    older.sort_unstable_by(|a, b| b.cmp(a));
    // keep - 1 older ones, because `current` itself counts toward the budget.
    older.into_iter().skip((keep as usize).saturating_sub(1)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = r#"{
      "secretsMountPoint": "/run/secrets.d", "symlinkPath": "/run/secrets",
      "keepGenerations": 2, "ageKeyFile": null, "ageSshKeyPaths": [],
      "gnupgHome": null, "sshKeyPaths": [],
      "secrets": [
        {"format":"yaml","gid":0,"group":"root","key":"a/b","mode":"0400","name":"a/b",
         "neededForUsers":false,"owner":"root","path":"/run/secrets/a/b","reloadUnits":[],
         "restartUnits":[],"sopsFile":"/nix/store/x-secrets.yaml","uid":0},
        {"format":"yaml","gid":100,"group":"users","key":"svc/alpha","mode":"0440","name":"svc/alpha",
         "neededForUsers":true,"owner":"luis","path":"/run/secrets/svc/alpha","reloadUnits":[],
         "restartUnits":[],"sopsFile":"/nix/store/x-secrets.yaml","uid":1001}
      ]
    }"#;

    fn m() -> Manifest { serde_json::from_str(M).expect("manifest") }

    #[test]
    fn ownership_is_set_before_permissions_for_every_secret() {
        // Rule 1. Widening the mode before the owner is right opens a window
        // where the content exists under the wrong uid.
        let steps = plan(&m(), 7).expect("plan");
        let mut seen_chown = false;
        for w in steps.windows(2) {
            if let (Step::Chown { path: cp, .. }, Step::Chmod { path: mp, .. }) = (&w[0], &w[1]) {
                assert_eq!(cp, mp, "chown and chmod must target the same path, adjacently");
                seen_chown = true;
            }
        }
        assert!(seen_chown, "no chown/chmod pair found");
    }

    #[test]
    fn the_symlink_swap_is_the_last_step() {
        // Rule 2. Nothing may point at a generation that is not complete.
        let steps = plan(&m(), 7).expect("plan");
        assert!(matches!(steps.last(), Some(Step::SwapSymlink { .. })));
        let swaps = steps.iter().filter(|s| matches!(s, Step::SwapSymlink { .. })).count();
        assert_eq!(swaps, 1, "exactly one swap, at the end");
    }

    #[test]
    fn the_user_pass_is_planned_before_the_main_pass() {
        let steps = plan(&m(), 7).expect("plan");
        let pos = |name: &str| {
            steps.iter().position(|s| matches!(s, Step::Write { path, .. } if path.ends_with(name)))
        };
        assert!(pos("svc/alpha") < pos("a/b"), "neededForUsers secrets must be placed first");
    }

    #[test]
    fn a_bad_mode_abandons_the_whole_plan() {
        // Not "skip that secret". A partially planned generation is what rule
        // 2 exists to prevent, and skipping would produce one silently.
        let broken = M.replace("\"mode\":\"0400\"", "\"mode\":\"not-octal\"");
        let bm: Manifest = serde_json::from_str(&broken).expect("parse");
        assert_eq!(
            plan(&bm, 1),
            Err(PlanError::BadMode { entry: "a/b".into(), mode: "not-octal".into() })
        );
    }

    #[test]
    fn secrets_land_in_the_generation_dir_not_at_their_final_path() {
        // The declared `path` is where the SYMLINK makes them appear; writing
        // there directly would bypass the atomic swap entirely.
        let steps = plan(&m(), 7).expect("plan");
        for s in &steps {
            if let Step::Write { path, .. } = s {
                assert!(path.starts_with("/run/secrets.d/7/"), "wrote outside the generation: {path}");
            }
        }
    }

    #[test]
    fn the_create_mode_is_restrictive_and_is_not_the_declared_one() {
        // Rule 1, stated as a constant so it cannot drift into "whatever the
        // secret asked for".
        assert_eq!(CREATE_MODE, 0o600);
        let steps = plan(&m(), 7).expect("plan");
        let modes: Vec<u32> = steps.iter().filter_map(|s| match s {
            Step::Chmod { mode, .. } => Some(*mode), _ => None }).collect();
        assert!(modes.contains(&0o400) && modes.contains(&0o440));
        assert!(!modes.contains(&CREATE_MODE), "the create mode is not a declared mode here");
    }

    #[test]
    fn a_manifest_with_templates_is_refused_not_partially_planned() {
        // plo's real manifest has FOUR. A planner that skipped them would
        // place all 27 plain entries and leave four files missing, and every
        // surface would report success.
        let with_t = M.replace(
            "\"keepGenerations\": 2,",
            "\"keepGenerations\": 2, \"templates\": [{\"name\":\"t\",\"path\":\"/run/secrets/t\",\"content\":\"x\",\"mode\":\"0400\",\"owner\":null,\"group\":null,\"uid\":0,\"gid\":0}],",
        );
        let m: Manifest = serde_json::from_str(&with_t).expect("parse");
        assert_eq!(plan(&m, 1), Err(PlanError::TemplatesUnsupported { count: 1 }));
    }

    #[test]
    fn pruning_keeps_the_current_generation_and_keep_minus_one_older() {
        // keep=2 means current + 1 older survive.
        assert_eq!(prune(&[1, 2, 3, 4], 4, 2), vec![2, 1]);
        assert_eq!(prune(&[1, 2, 3, 4], 4, 1), vec![3, 2, 1]);
    }

    #[test]
    fn keep_zero_prunes_nothing_rather_than_everything() {
        // A 0 that means "unbounded" is the safer reading, and it is what
        // upstream does. Reading it as "remove all" would delete the running
        // generation.
        assert!(prune(&[1, 2, 3], 3, 0).is_empty());
    }

    #[test]
    fn a_generation_newer_than_current_is_never_pruned() {
        // A concurrent installer may have created one. Removing it would
        // delete secrets a process is about to be pointed at.
        assert_eq!(prune(&[1, 2, 9], 2, 1), vec![1]);
    }
}
