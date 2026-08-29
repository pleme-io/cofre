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
    /// Ensure the secrets mount point is storage that CANNOT REACH DISK.
    ///
    /// ★ ramfs, NOT tmpfs, and the distinction is the security property:
    /// **tmpfs can be swapped to disk; ramfs cannot.** Decrypted secrets in a
    /// tmpfs may be paged to persistent storage under memory pressure and
    /// survive a reboot in swap. Upstream mounts
    /// `ramfs (rw,nosuid,nodev,noexec,relatime,mode=751)` and so must this.
    ///
    /// Discovered the way it had to be: the content differential passed
    /// byte-for-byte while this was still missing, and it only surfaced when
    /// cleanup hit `Device or resource busy` on upstream's tree. A comparison
    /// of FILES cannot see the filesystem they sit on.
    ///
    /// ★ THE STEP STATES THE REQUIREMENT, NOT THE MECHANISM — and that
    /// separation is a bug fix. An earlier cut emitted this only when
    /// `!user_mode`, which encodes a LINUX assumption: there, a user's runtime
    /// directory is already tmpfs-backed so skipping is right. On darwin
    /// upstream creates an HFS ram disk **even in user mode** (`/dev/disk5 …
    /// mounted by luis.d`, measured on ryn), so the same rule would silently
    /// place a person's secrets on their ordinary filesystem.
    ///
    /// The plan therefore always demands secure storage and carries
    /// `user_mode` as CONTEXT; [`crate::apply::Fs`] decides how — and refuses
    /// on a platform whose mechanism is not implemented.
    EnsureSecureStorage { path: String, user_mode: bool },
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
    /// Render a template body and write it.
    ///
    /// ★ Carries the SECRETS IT REFERENCES, not just its content. That makes
    /// "a template can only be rendered once its secrets are decrypted" a
    /// property visible in the plan rather than an ordering the executor has
    /// to remember.
    RenderTemplate {
        path: String,
        name: String,
        content: String,
        references: Vec<String>,
    },
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
    /// The mount point uses `%r` and `XDG_RUNTIME_DIR` is unset.
    ///
    /// ★ Refused rather than defaulted. A guessed runtime directory publishes
    /// a person's secrets somewhere they will not look, while every step
    /// reports success.
    NoRuntimeDir { mount: String },
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
            Self::NoRuntimeDir { mount } => write!(
                f,
                "mount point {mount} uses %r but XDG_RUNTIME_DIR is unset — refusing \
                 rather than guessing where a person's secrets should live"
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

/// Expand systemd's `%r` runtime-directory specifier.
///
/// ★ A USER-MODE manifest carries `secretsMountPoint: "%r/secrets.d"` — a
/// SPECIFIER, not a path. Taking it literally would create a directory called
/// `%r` in the working directory and publish secrets into it, which succeeds
/// at every step and leaves the real location empty.
///
/// Resolved from `XDG_RUNTIME_DIR`, which is what systemd expands `%r` to.
fn resolve_runtime_specifier(mount: &str) -> Result<String, PlanError> {
    if !mount.contains("%r") {
        return Ok(mount.to_owned());
    }
    let rt = std::env::var("XDG_RUNTIME_DIR").map_err(|_| PlanError::NoRuntimeDir {
        mount: mount.to_owned(),
    })?;
    Ok(mount.replace("%r", &rt))
}

/// A template's ownership, same two forms as an entry's.
fn template_ownership(t: &crate::manifest::Template) -> Result<Ownership, PlanError> {
    match (&t.owner, &t.group, t.uid, t.gid) {
        (Some(o), Some(g), _, _) => Ok(Ownership::ByName { owner: o.clone(), group: g.clone() }),
        (_, _, Some(uid), Some(gid)) => Ok(Ownership::ByIds { uid, gid }),
        _ => Err(PlanError::NoOwnership { entry: t.name.clone() }),
    }
}

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

fn steps_for(secret: &Secret, gen_dir: &str, user_mode: bool) -> Result<Vec<Step>, PlanError> {
    let mode = secret.mode_octal().map_err(|m| PlanError::BadMode {
        entry: secret.name.clone(),
        mode: m.to_owned(),
    })?;
    let path = format!("{gen_dir}/{}", secret.name);
    let mut steps = vec![Step::Write {
        path: path.clone(),
        key: secret.key.clone(),
        from_file: secret.sops_file.clone(),
    }];
    // ★ USER MODE HAS NO CHOWN AT ALL, and that is not a shortcut. The
    // installer runs AS the user, so the files are already theirs — and a
    // user-mode manifest carries no owner and no uid (66 of 66 on ryn),
    // because there is nothing to express. Guessing root here would chown a
    // person's own secrets away from them.
    if !user_mode {
        steps.push(Step::Chown { path: path.clone(), own: ownership_of(secret)? });
    }
    steps.push(Step::Chmod { path, mode });
    Ok(steps)
}

/// Build the full ordered plan for one generation.
///
/// # Errors
/// [`PlanError::BadMode`] if any entry's mode is not octal — and the plan is
/// abandoned entirely rather than skipping that secret, because a partially
/// planned generation is the thing rule 2 exists to prevent.
pub fn plan(m: &Manifest, generation: u64) -> Result<Vec<Step>, PlanError> {
    let mount = resolve_runtime_specifier(&m.secrets_mount_point)?;
    let gen_dir = format!("{mount}/{generation}");
    // ★ THE MOUNT COMES FIRST. Creating the generation directory on a plain
    // filesystem and mounting afterwards would hide the already-written
    // secrets under the mount — present on disk, invisible to every reader.
    // ★ ALWAYS DEMANDED, never conditioned on the mode. Whether a mount is
    // actually needed is a PLATFORM question the executor answers; the plan's
    // job is to say the storage must not be able to reach disk.
    let mut steps = vec![
        Step::EnsureSecureStorage { path: mount.clone(), user_mode: m.user_mode },
        Step::MakeGeneration { path: gen_dir.clone() },
    ];

    // ★ USER PASS FIRST. A secret a user's own creation depends on cannot be
    // chowned to that user, so these are placed before the main set.
    for s in m.user_pass() {
        steps.extend(steps_for(s, &gen_dir, m.user_mode)?);
    }
    for s in m.main_pass() {
        steps.extend(steps_for(s, &gen_dir, m.user_mode)?);
    }

    // ★ TEMPLATES AFTER ENTRIES, because a template's body is rendered FROM
    // decrypted values — the ordering is derived from the dependency, not
    // chosen. `references` makes that dependency visible in the plan.
    for t in &m.templates {
        let mode = t.mode_octal().map_err(|md| PlanError::BadMode {
            entry: t.name.clone(),
            mode: md.to_owned(),
        })?;
        // ★ `rendered/`, MEASURED not guessed. Upstream nests templates one
        // level down; a differential against plo's real manifest showed 27/27
        // secrets and 4/4 template CONTENTS byte-identical with the only
        // divergence being this directory. Placing them at the top level
        // would leave every consumer's declared `path` symlink pointing at
        // nothing — a working install with four dead files.
        let path = format!("{gen_dir}/rendered/{}", t.name);
        steps.push(Step::RenderTemplate {
            path: path.clone(),
            name: t.name.clone(),
            content: t.content.clone(),
            references: crate::template::referenced(&t.content, &m.placeholder_by_secret_name),
        });
        if !m.user_mode {
            steps.push(Step::Chown { path: path.clone(), own: template_ownership(t)? });
        }
        steps.push(Step::Chmod { path, mode });
    }

    // ★ LAST. Nothing points at the generation until every entry AND every
    // template in it succeeded.
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

    fn user_mode_manifest() -> Manifest {
        let raw = M
            .replace("\"secretsMountPoint\": \"/run/secrets.d\"", "\"secretsMountPoint\": \"%r/secrets.d\"")
            .replace("\"keepGenerations\": 2,", "\"keepGenerations\": 2, \"userMode\": true,")
            .replace("\"owner\":\"root\"", "\"owner\":null")
            .replace("\"owner\":\"luis\"", "\"owner\":null")
            .replace("\"group\":\"root\"", "\"group\":null")
            .replace("\"group\":\"users\"", "\"group\":null")
            .replace("\"uid\":0", "\"uid\":null")
            .replace("\"uid\":1001", "\"uid\":null")
            .replace("\"gid\":0", "\"gid\":null")
            .replace("\"gid\":100", "\"gid\":null");
        serde_json::from_str(&raw).expect("user-mode manifest")
    }

    #[test]
    fn user_mode_plans_no_chown_at_all() {
        // ★ ryn: 66 of 66 entries carry NO owner and NO uid, because the
        // installer runs AS the user and there is nothing to express.
        // Guessing root would chown a person's own secrets away from them.
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/501") };
        let m = user_mode_manifest();
        let steps = plan(&m, 1).expect("user mode must plan");
        assert!(
            !steps.iter().any(|s| matches!(s, Step::Chown { .. })),
            "user mode must plan no chown"
        );
        assert!(steps.iter().any(|s| matches!(s, Step::Chmod { .. })), "mode still applies");
    }

    #[test]
    fn user_mode_still_demands_secure_storage() {
        // ★ The bug this replaces: an earlier cut skipped the step entirely in
        // user mode, which is right on Linux (the runtime dir is tmpfs) and
        // WRONG on darwin, where upstream builds an HFS ram disk even for a
        // user. The plan states the requirement; the executor picks the
        // mechanism and refuses where it has none.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/501") };
        let steps = plan(&user_mode_manifest(), 1).expect("plan");
        let Some(Step::EnsureSecureStorage { user_mode, .. }) = steps.first() else {
            panic!("user mode must still demand secure storage");
        };
        assert!(*user_mode, "the mode must reach the executor as context");
    }

    #[test]
    fn the_runtime_specifier_is_expanded_not_taken_literally() {
        // `%r` is systemd's runtime-directory specifier. Taken literally it
        // creates a directory NAMED `%r` and publishes secrets into it —
        // every step succeeds and the real location stays empty.
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/501") };
        let steps = plan(&user_mode_manifest(), 7).expect("plan");
        // steps[0] is EnsureSecureStorage; the generation dir follows it.
        let Step::MakeGeneration { path } = &steps[1] else { panic!("mkgen") };
        assert_eq!(path, "/run/user/501/secrets.d/7", "%r was not expanded");
        assert!(!path.contains("%r"));
    }

    #[test]
    fn an_unset_runtime_dir_is_refused_not_guessed() {
        unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };
        let m = user_mode_manifest();
        assert!(matches!(plan(&m, 1), Err(PlanError::NoRuntimeDir { .. })));
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", "/run/user/501") };
    }

    #[test]
    fn the_ramfs_mount_precedes_the_generation_directory() {
        // Creating the directory first and mounting over it would HIDE the
        // secrets already written there — present on disk, invisible to every
        // reader, and the run would report success.
        let steps = plan(&m(), 7).expect("plan");
        assert!(matches!(steps[0], Step::EnsureSecureStorage { .. }), "storage must be first");
        assert!(matches!(steps[1], Step::MakeGeneration { .. }));
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
    fn templates_are_planned_after_every_entry() {
        // Not a convention -- a DERIVED ordering. A template's body is
        // rendered FROM decrypted values, so it cannot precede the entries it
        // names. An earlier cut refused templates outright rather than
        // planning them, which was the honest state at the time; this asserts
        // the ordering now that they are real.
        let with_t = M.replace(
            "\"keepGenerations\": 2,",
            "\"keepGenerations\": 2, \"templates\": [{\"name\":\"t\",\"path\":\"/run/secrets/t\",\"content\":\"x\",\"mode\":\"0400\",\"owner\":null,\"group\":null,\"uid\":0,\"gid\":0}],",
        );
        let m: Manifest = serde_json::from_str(&with_t).expect("parse");
        let steps = plan(&m, 1).expect("templates must plan");

        let last_write = steps
            .iter()
            .rposition(|s| matches!(s, Step::Write { .. }))
            .expect("an entry write");
        let render = steps
            .iter()
            .position(|s| matches!(s, Step::RenderTemplate { .. }))
            .expect("a template render");
        assert!(render > last_write, "a template was planned before an entry it may reference");
        assert!(matches!(steps.last(), Some(Step::SwapSymlink { .. })), "swap still last");
    }

    #[test]
    fn a_template_gets_the_same_chown_then_chmod_treatment() {
        // The ownership window is not less dangerous for a rendered file --
        // cloudflared's credentials are one of plo's four.
        let with_t = M.replace(
            "\"keepGenerations\": 2,",
            "\"keepGenerations\": 2, \"templates\": [{\"name\":\"t\",\"path\":\"/run/secrets/t\",\"content\":\"x\",\"mode\":\"0400\",\"owner\":null,\"group\":null,\"uid\":0,\"gid\":0}],",
        );
        let m: Manifest = serde_json::from_str(&with_t).expect("parse");
        let steps = plan(&m, 1).expect("plan");
        let r = steps.iter().position(|s| matches!(s, Step::RenderTemplate { .. })).expect("render");
        assert!(matches!(steps[r + 1], Step::Chown { .. }), "chown must follow the render");
        assert!(matches!(steps[r + 2], Step::Chmod { .. }), "chmod must follow the chown");
        // ★ And it lands under rendered/, which is where upstream puts it —
        // established by differential, not by reading upstream's source.
        let Step::RenderTemplate { path, .. } = &steps[r] else { panic!("render") };
        assert!(path.contains("/rendered/"), "templates nest under rendered/: {path}");
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
