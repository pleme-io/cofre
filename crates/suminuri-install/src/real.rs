//! The real filesystem and the real decryptor.
//!
//! ── ★ THE DECRYPTOR IS suminuri's, NOT A SECOND IMPLEMENTATION ─────────
//!
//! `suminuri` owns the sops wire format and has a green byte-differential
//! against upstream over the fleet's real `secrets.yaml`. Re-deriving any part
//! of it here would create a second answer to a question that already has one
//! — and the second answer is the one nobody would differential-test.
//!
//! ── ★ `verify()` IS NOT OPTIONAL, AND THE TYPE SAYS SO ─────────────────
//!
//! `SopsFile::decrypt` returns `Unverified<WalkStats>`. The plaintext is in
//! the tree either way — the walk mutates it — but the *permission to trust
//! it* only comes from `verify`. An installer that skipped it would place
//! unauthenticated plaintext into `/run/secrets` and every consumer would
//! treat it as genuine. The marker exists precisely so that cannot be an
//! oversight, and this module honours it.

use std::collections::HashMap;
use std::sync::Mutex;

use suminuri::{AgeIdentities, SopsFile};
use suminuri_yaml::Value;

use crate::apply::{Decryptor, Fs};

/// std filesystem + libc ownership.
pub struct RealFs;

fn uid_of(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string; getpwnam returns a pointer
    // into static storage or null, and we only read it before any other libc
    // call could overwrite it.
    let p = unsafe { libc::getpwnam(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { (*p).pw_uid })
    }
}

fn gid_of(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: as above, for getgrnam.
    let p = unsafe { libc::getgrnam(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { (*p).gr_gid })
    }
}

/// Create `path` and every missing ancestor at `DIR_MODE`, owned by `DIR_GROUP`.
///
/// ★ WHY NOT `create_dir_all` (rio, 2026-08-29). `create_dir_all` applies the
/// process UMASK, and root's umask inside a systemd unit is 022 — so directories
/// landed 0755, granting world **list** on the secret tree and letting any local
/// user enumerate secret NAMES. Upstream's are 0751: traverse without list.
///
/// The mode is set with `DirBuilder::mode`, i.e. at CREATION, not by a later
/// chmod. A chmod-after leaves a window in which the directory is world-listable
/// while secrets are already being written into it — the same reasoning as
/// `write_restrictive` setting its mode on the open.
///
/// ★ `mode()` is also subject to umask, so the umask is cleared for the
/// duration and restored afterwards. Without that the DirBuilder mode is a
/// ceiling rather than the value, and 0751 & !022 silently becomes 0751 & 0755
/// = 0751 today but would drift with any other umask.
fn create_dir_secure(path: &str) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt as _;

    // SAFETY: umask is process-global; this runs single-threaded during
    // activation, and the previous value is restored before returning.
    let prev = unsafe { libc::umask(0) };
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true).mode(crate::place::DIR_MODE);
    let created = b.create(path);
    unsafe { libc::umask(prev) };
    created.map_err(|e| e.to_string())?;

    // Group is best-effort by design: a node without `keys` keeps root:root,
    // which together with DIR_MODE is STRICTLY MORE restrictive than upstream
    // (no group members can list). Failing the install over a missing group
    // would trade a safe divergence for an outage.
    if let Some(gid) = gid_of(crate::place::DIR_GROUP) {
        let c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
        // SAFETY: `c` is a valid NUL-terminated path; -1 leaves the uid alone.
        let rc = unsafe { libc::chown(c.as_ptr(), u32::MAX, gid) };
        if rc != 0 {
            return Err(format!(
                "chgrp {} on {path}: {}",
                crate::place::DIR_GROUP,
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

impl Fs for RealFs {
    fn ensure_secure_storage(&self, path: &str, user_mode: bool) -> Result<(), String> {
        // The MOUNT POINT gets the same treatment: measured 751 root:keys on
        // rio, and it is the directory an attacker would list first.
        create_dir_secure(path)?;

        // ★ IDEMPOTENT. sops-install-secrets runs on EVERY rebuild, and
        // mounting a second backing store over the first would stack them —
        // old generations still underneath, invisible, never pruned. Storage
        // that is already secure is success, not something to redo.
        if already_secure(path) {
            return Ok(());
        }

        // ★ USER MODE ON LINUX NEEDS NO MOUNT, and that is a PLATFORM fact,
        // not a mode fact. XDG_RUNTIME_DIR is tmpfs-backed and owned by the
        // user, so the requirement is already met. Mounting would need
        // privilege a person does not have and would fail with EPERM.
        //
        // It is checked here rather than in the plan because on darwin the
        // same mode DOES need a ram disk — upstream builds one per user.
        if user_mode && cfg!(target_os = "linux") {
            return Ok(());
        }

        mount_secure(path)
    }

    fn make_dir(&self, path: &str) -> Result<(), String> {
        create_dir_secure(path)
    }

    fn write_restrictive(&self, path: &str, contents: &[u8]) -> Result<(), String> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        if let Some(parent) = std::path::Path::new(path).parent() {
            // ★ Through the SAME helper as make_dir. A second call site using
            // bare create_dir_all is how the 0755 leak reached the tree in the
            // first place: the generation directory was one code path and every
            // secret's parent directory was another.
            create_dir_secure(&parent.to_string_lossy())?;
        }
        // ★ The mode is on the OPEN, not a later chmod. Creating 0644 and
        // narrowing afterwards leaves a window in which the plaintext exists
        // and is world-readable — the exact window `place.rs` rule 1 forbids,
        // enforced here at the syscall rather than by convention.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(crate::place::CREATE_MODE)
            .open(path)
            .map_err(|e| e.to_string())?;
        f.write_all(contents).map_err(|e| e.to_string())
    }

    fn chown(&self, path: &str, own: &crate::place::Ownership) -> Result<(), String> {
        // ★ A name that does not resolve is an ERROR, never a fallback to 0.
        // Silently chowning a credential to root is the failure that looks
        // exactly like success.
        let (uid, gid) = match own {
            crate::place::Ownership::ByName { owner, group } => (
                uid_of(owner).ok_or_else(|| format!("no such user: {owner}"))?,
                gid_of(group).ok_or_else(|| format!("no such group: {group}"))?,
            ),
            crate::place::Ownership::ByIds { uid, gid } => (*uid, *gid),
        };
        let c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
        // SAFETY: valid path string; uid/gid came from the passwd/group db.
        if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())
    }

    fn swap_symlink(&self, link: &str, target: &str) -> Result<(), String> {
        // ★ ATOMIC. Create the new link at a temporary name beside the real
        // one, then RENAME over it. `unlink` + `symlink` has a window with no
        // link at all, and a reader during it fails looking like a missing
        // secret rather than a racing installer.
        let tmp = format!("{link}.new");
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(target, &tmp).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, link).map_err(|e| e.to_string())
    }

    fn reap_generations(&self, mount: &str, keep: u32, current: &str) -> Result<(), String> {
        let mut gens: Vec<(u64, std::path::PathBuf)> = std::fs::read_dir(mount)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            // ★ Only NUMERIC names. The mount also holds `age-keys.txt` and a
            // `gpg<random>` scratch directory that upstream leaves behind;
            // treating either as a generation would delete live key material.
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.parse::<u64>().ok().map(|k| (k, e.path()))
            })
            .filter(|(_, p)| p.to_string_lossy() != current)
            .collect();
        // Newest first, so `keep` counts from the most recent.
        gens.sort_by(|a, b| b.0.cmp(&a.0));

        // ★ `current` is excluded above and NOT counted against `keep`: it is
        // the live generation, not a kept spare. keep=1 therefore means "the
        // live one plus one previous", which is what upstream leaves behind and
        // is what makes a rollback possible at all.
        for (_, path) in gens.into_iter().skip(keep as usize) {
            std::fs::remove_dir_all(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(())
    }

    fn remove_dir_all(&self, path: &str) -> Result<(), String> {
        std::fs::remove_dir_all(path).map_err(|e| e.to_string())
    }
}

/// Create storage at `path` that cannot reach disk.
///
/// ★ Linux-only, and ABSENT rather than stubbed elsewhere. A darwin build
/// returning `Ok(())` would report a mounted ramfs where none exists, and the
/// caller would then write decrypted secrets to a plain filesystem believing
/// they were in unswappable memory. jikoku's clock arm is gated the same way
/// and for the same reason: a stub that succeeds is worse than a build that
/// cannot.
#[cfg(target_os = "linux")]
fn mount_secure(path: &str) -> Result<(), String> {
    let src = std::ffi::CString::new("none").map_err(|e| e.to_string())?;
    let target = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
    let fstype = std::ffi::CString::new("ramfs").map_err(|e| e.to_string())?;
    let opts = std::ffi::CString::new("mode=751").map_err(|e| e.to_string())?;
    // SAFETY: all four are valid NUL-terminated C strings outliving the call.
    let r = unsafe {
        libc::mount(
            src.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RELATIME,
            opts.as_ptr().cast(),
        )
    };
    if r != 0 {
        return Err(format!(
            "mounting a ramfs at {path}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// The darwin ram disk's size, in 512-byte units.
///
/// ★ 131072 = 64 MiB, MEASURED from the live volume on ryn
/// (`diskutil info /dev/disk4`: "exactly 131072 512-Byte-Units"), not chosen.
/// Matching upstream matters because the size is a hard ceiling on every
/// secret a node holds — picking a smaller number would fail a node that
/// upstream serves fine, and a larger one silently reserves more wired memory.
#[cfg(target_os = "macos")]
pub const RAMDISK_SECTORS: u64 = 131_072;

/// Run one command, returning stdout, and treat a non-zero exit as an error.
///
/// ★ A typed wrapper over `Command`, not a shell string. The NO-SHELL rule
/// permits exactly this shape: arguments are separate values, so a path with
/// a space cannot become two arguments and nothing is word-split.
#[cfg(target_os = "macos")]
fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Pull the device node out of `hdiutil attach -nomount`'s output.
///
/// ★ THE PADDING TRAP, measured on ryn 2026-08-29 rather than assumed.
/// `hdiutil` pads its output to a fixed column width: the real bytes are
/// `"/dev/disk6"` followed by 42 spaces and a TAB — **53 bytes for a 10-byte
/// path**. It is not a tidy one-line answer.
///
/// This matters because the failure is DISGUISED. Passing the padded string
/// on gets you:
///
/// ```text
/// newfs_hfs: cannot create filesystem on /dev/rdisk6		: No such file or directory
/// ```
///
/// — which names a device that looks correct, so the natural reading is "the
/// device vanished" and the natural fix is a retry or a sleep. The actual
/// cause is invisible whitespace. Measured exactly this way: a probe that
/// stripped spaces but not the tab failed here and left a 64 MiB ram disk
/// attached, because the teardown path could not name the device either.
///
/// `str::trim` covers it (it is `char::is_whitespace`, which includes `\t`),
/// but that is a load-bearing detail rather than an incidental tidy-up, so it
/// is a named function with a test rather than a `.trim()` someone later
/// removes as redundant.
#[cfg(target_os = "macos")]
fn parse_device_node(raw: &str) -> Result<String, String> {
    let device = raw.trim();
    if device.is_empty() {
        return Err("hdiutil returned no device node".to_owned());
    }
    // A second guard: after trimming there must be no INTERIOR whitespace
    // either. `hdiutil` can list several entries when a volume has partitions;
    // taking the whole block as one path would produce the same disguised
    // error as the padding does.
    if device.split_whitespace().count() != 1 {
        return Err(format!(
            "hdiutil returned {} whitespace-separated fields, expected one device node: {device:?}",
            device.split_whitespace().count()
        ));
    }
    if !device.starts_with("/dev/") {
        return Err(format!("hdiutil returned a non-device path: {device:?}"));
    }
    Ok(device.to_owned())
}

#[cfg(target_os = "macos")]
fn mount_secure(path: &str) -> Result<(), String> {
    // ★ THE DARWIN MECHANISM, measured on ryn rather than inferred:
    //     /dev/disk4 on /private/var/run/secrets.d (hfs, local, nodev, nosuid, nobrowse)
    // macOS has no ramfs. Upstream builds an HFS volume on a RAM-backed device,
    // which achieves the same property by a different route: the backing store
    // is wired memory, never a file, so it cannot be paged to disk.

    // 1. Allocate the RAM device WITHOUT mounting it. `-nomount` matters:
    //    letting the system automount would attach it read-write in /Volumes
    //    under a name we do not control, visible in Finder.
    let raw = run(
        "hdiutil",
        &["attach", "-nomount", &format!("ram://{RAMDISK_SECTORS}")],
    )?;
    let device = parse_device_node(&raw)?;
    let device = device.as_str();

    // 2. Format it. `-v` names the volume; without it the volume is "Untitled"
    //    and two of them collide in /Volumes.
    if let Err(e) = run("newfs_hfs", &["-v", "suminuri-secrets", device]) {
        // ★ DETACH ON FAILURE. A formatted-or-not RAM device left attached is
        // 64 MiB of wired memory that no later run will reclaim, and rebuilds
        // are frequent.
        let _ = run("hdiutil", &["detach", "-force", device]);
        return Err(e);
    }

    // 3. Mount it. nobrowse keeps it out of Finder; nodev/nosuid match what
    //    upstream sets and what the Linux ramfs carries.
    if let Err(e) = run(
        "mount",
        &["-t", "hfs", "-o", "nodev,nosuid,nobrowse", device, path],
    ) {
        let _ = run("hdiutil", &["detach", "-force", device]);
        return Err(e);
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn mount_secure(path: &str) -> Result<(), String> {
    // ★ REFUSES rather than pretending. Returning Ok(()) would place decrypted
    // secrets on ordinary, persistent storage while every caller believed they
    // were in unswappable memory.
    Err(format!(
        "no secure-storage mechanism for {path} on this platform: Linux uses ramfs and \
         darwin an hdiutil ram disk. Refusing rather than writing decrypted secrets to \
         ordinary storage"
    ))
}

/// Is `path` already backed by storage that cannot reach disk?
///
/// ★ Read from `/proc/mounts` rather than `statfs`: the fs TYPE is what
/// matters and `statfs`'s `f_type` for ramfs is the same magic as tmpfs on
/// some kernels, so the cheap check is the wrong one.
///
/// Only `ramfs` counts. tmpfs is deliberately NOT accepted for the system
/// path: it can be swapped, which is the whole distinction.
#[cfg(target_os = "linux")]
fn already_secure(path: &str) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };
    mounts.lines().any(|l| {
        let mut f = l.split_whitespace();
        let (_src, target, fstype) = (f.next(), f.next(), f.next());
        target == Some(path) && fstype == Some("ramfs")
    })
}

/// On darwin, "already secure" means an HFS volume on a RAM-backed device is
/// mounted here.
///
/// ★ `/proc/mounts` does not exist; the mount table comes from `mount(8)`.
/// The check is by MOUNT POINT and filesystem type — an hfs mount at the
/// secrets path is one we (or upstream) made, because nothing else mounts hfs
/// inside `/run` or a runtime directory.
#[cfg(target_os = "macos")]
fn already_secure(path: &str) -> bool {
    let Ok(table) = run("mount", &[]) else {
        return false;
    };
    table
        .lines()
        .any(|l| l.contains(&format!(" on {path} ")) && l.contains("hfs"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn already_secure(_path: &str) -> bool {
    false
}

/// Decrypts through suminuri, caching one decrypted tree per file.
pub struct SuminuriDecryptor {
    identities: AgeIdentities,
    /// ★ Decrypt once per FILE. plo's manifest names 27 entries over far fewer
    /// files, and each decrypt verifies a MAC over the whole document.
    cache: Mutex<HashMap<String, Value>>,
}

impl SuminuriDecryptor {
    #[must_use]
    pub fn new(identities: AgeIdentities) -> Self {
        Self {
            identities,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// How many identities this decryptor holds — reported when nothing
    /// decrypts, so "no identity" is distinguishable from "wrong identity".
    #[must_use]
    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }
}

/// Walk a slash-separated key path.
///
/// ★ sops-nix uses `attic/jwt/token`, NOT sops's own `["a"]["b"]` bracket
/// syntax. Reusing the bracket parser would be wrong for this input, and
/// wrong in a way that only shows on nested keys.
fn at_path<'a>(tree: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('/').try_fold(tree, |node, seg| node.get(seg))
}

impl Decryptor for SuminuriDecryptor {
    fn extract(&self, sops_file: &str, key: &str) -> Result<Vec<u8>, String> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| "cache poisoned".to_string())?;
        if !cache.contains_key(sops_file) {
            // ★ `load_encrypted` takes the file's CONTENT, not its path.
            // Passing the path parses the FILENAME as YAML, which has no
            // `sops:` block — so it reports "not encrypted", which is a true
            // statement about the wrong input. Caught by the first
            // differential run against plo, not by any unit test here,
            // because every unit test built its tree in memory.
            let raw =
                std::fs::read_to_string(sops_file).map_err(|e| format!("read {sops_file}: {e}"))?;
            let mut file = SopsFile::load_encrypted(&raw).map_err(|e| format!("load: {e}"))?;
            let data_key = file
                .data_key(&self.identities)
                .map_err(|e| format!("no usable identity ({} held): {e}", self.identities.len()))?;
            let mut stash = suminuri_wire::IvStash::default();
            let unverified = file
                .decrypt(&data_key, &mut stash)
                .map_err(|e| format!("decrypt: {e}"))?;
            // ★ THE MAC CHECK. Not optional: the plaintext is already in the
            // tree, and this is the only thing that makes trusting it
            // legitimate. Skipping it would place unauthenticated bytes.
            unverified
                .verify(&data_key)
                .map_err(|e| format!("MAC verification failed: {e}"))?;
            cache.insert(sops_file.to_owned(), file.tree);
        }
        let tree = cache.get(sops_file).ok_or("cache miss after insert")?;
        match at_path(tree, key) {
            Some(Value::Scalar(s)) => Ok(s.value.as_bytes().to_vec()),
            Some(_) => Err(format!("{key} is not a scalar")),
            // ★ A missing key is NOT an empty secret. Returning `Ok(vec![])`
            // here would place a zero-length file that every consumer reads as
            // a valid, empty credential.
            None => Err(format!("{key} not found in {sops_file}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use suminuri_yaml::{Item, Scalar};

    fn leaf(v: &str) -> Value {
        Value::Scalar(Scalar::new(v))
    }

    fn nested() -> Value {
        Value::Mapping(vec![Item::Pair {
            key: "attic".into(),
            value: Value::Mapping(vec![Item::Pair {
                key: "jwt".into(),
                value: Value::Mapping(vec![Item::Pair {
                    key: "token".into(),
                    value: leaf("v"),
                }]),
            }]),
        }])
    }

    #[test]
    fn a_slash_path_walks_nested_mappings() {
        // sops-nix's key form, not sops's bracket syntax. Getting this wrong
        // only shows on NESTED keys, which is most of plo's manifest.
        assert!(matches!(
            at_path(&nested(), "attic/jwt/token"),
            Some(Value::Scalar(_))
        ));
    }

    #[test]
    fn a_missing_path_is_none_not_an_empty_value() {
        // Returning an empty value here would become a zero-length file that
        // every consumer reads as a valid, empty credential.
        assert!(at_path(&nested(), "attic/jwt/absent").is_none());
        assert!(at_path(&nested(), "nope").is_none());
    }

    #[test]
    fn a_partial_path_that_lands_on_a_mapping_is_not_a_leaf() {
        let tree = nested();
        let v = at_path(&tree, "attic/jwt");
        assert!(
            matches!(v, Some(Value::Mapping(_))),
            "must not be mistaken for a scalar"
        );
    }

    #[test]
    fn already_secure_reads_proc_mounts_and_is_false_for_a_plain_path() {
        // /tmp is a real path and is not a ramfs on any fleet node; a `true`
        // here would mean the mount is skipped and secrets land on whatever
        // filesystem happens to be there.
        assert!(!already_secure("/definitely/not/mounted/9f3c"));
    }

    #[test]
    fn the_create_mode_used_by_the_real_fs_is_the_restrictive_one() {
        // Asserted against the constant the plan uses, so the two cannot drift.
        assert_eq!(crate::place::CREATE_MODE, 0o600);
    }

    #[test]
    fn root_and_a_real_group_resolve_but_a_fabricated_one_does_not() {
        // The name->id lookup is the part that silently "works" if written
        // badly: a failed lookup that defaults to 0 would chown secrets to
        // root instead of erroring.
        assert_eq!(uid_of("root"), Some(0));
        assert!(uid_of("definitely-not-a-user-9f3c").is_none());
        assert!(gid_of("definitely-not-a-group-9f3c").is_none());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod darwin_tests {
    use super::*;

    /// The EXACT bytes `hdiutil attach -nomount ram://131072` wrote on ryn,
    /// captured with `od -c`. Not a plausible-looking fixture -- a recording.
    const REAL_HDIUTIL_OUTPUT: &str = "/dev/disk6                                          \t";

    #[test]
    fn parses_the_real_padded_hdiutil_output() {
        // 53 bytes in, 10 out. If this ever reads as already-clean, the
        // fixture has been "tidied" and the test no longer proves anything.
        assert_eq!(REAL_HDIUTIL_OUTPUT.len(), 53, "fixture lost its padding");
        assert_eq!(
            parse_device_node(REAL_HDIUTIL_OUTPUT).unwrap(),
            "/dev/disk6"
        );
    }

    #[test]
    fn refuses_empty_output() {
        // Better to refuse than to hand "" to newfs_hfs, which would report
        // an error about a path the operator never chose.
        assert!(parse_device_node("   \t \n ").is_err());
    }

    #[test]
    fn refuses_multiple_fields_rather_than_guessing_which_is_the_device() {
        let multi = "/dev/disk6        \tApple_HFS      \t/Volumes/x";
        let e = parse_device_node(multi).unwrap_err();
        assert!(e.contains("expected one device node"), "{e}");
    }

    #[test]
    fn refuses_a_non_device_path() {
        assert!(parse_device_node("/tmp/not-a-device").is_err());
    }

    /// ★ The size is MEASURED, not chosen. `diskutil info` on the live
    /// upstream volume reported "exactly 131072 512-Byte-Units"; a smaller
    /// number would fail a node upstream serves, a larger one silently wires
    /// more memory.
    #[test]
    fn ramdisk_size_matches_the_measured_upstream_volume() {
        assert_eq!(RAMDISK_SECTORS, 131_072);
        assert_eq!(RAMDISK_SECTORS * 512 / 1024 / 1024, 64, "should be 64 MiB");
    }
}

#[cfg(test)]
mod dir_and_reap_tests {
    use super::*;

    /// ★ 0751, NOT 0755 — and the difference is a name leak.
    ///
    /// Measured on rio after the first cutover: the drop-in had created
    /// `/run/secrets.d/<gen>/github` as `755 root:root` where upstream's was
    /// `751 root:keys`. `create_dir_all` applies the process umask (022 for
    /// root under systemd), so the permissive mode was INHERITED, never chosen.
    ///
    /// It survived a byte-identical verdict, because the differential compared
    /// FILES by name/mode/uid/gid/content and never looked at DIRECTORY modes.
    #[test]
    fn the_directory_mode_denies_listing() {
        assert_eq!(crate::place::DIR_MODE, 0o751);
        // The bit that matters, stated as the property rather than the number:
        // world may traverse, world may NOT read (list).
        assert_eq!(crate::place::DIR_MODE & 0o001, 0o001, "world traverse");
        assert_eq!(crate::place::DIR_MODE & 0o004, 0, "world must NOT list");
        assert_ne!(crate::place::DIR_MODE, 0o755, "0755 is the regression");
    }

    #[test]
    fn create_dir_secure_applies_the_mode_despite_umask() {
        // ★ The umask is the whole point: DirBuilder::mode is masked by it, so
        // without clearing it 0751 silently becomes 0751 & !umask. Set a hostile
        // umask and require the mode to survive.
        let base = std::env::temp_dir().join(format!("cds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let deep = base.join("a/b/c");
        let prev = unsafe { libc::umask(0o077) };
        let r = create_dir_secure(&deep.to_string_lossy());
        unsafe { libc::umask(prev) };
        r.expect("creates");

        use std::os::unix::fs::PermissionsExt as _;
        for p in [base.join("a"), base.join("a/b"), deep.clone()] {
            let m = std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777;
            assert_eq!(m, 0o751, "{} got {m:o}, umask leaked in", p.display());
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// Reaping: the numeric filter is the safety property.
    #[test]
    fn reaping_keeps_current_and_the_newest_and_ignores_non_generations() {
        let base = std::env::temp_dir().join(format!("reap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base");
        for n in ["1", "2", "3", "10"] {
            std::fs::create_dir_all(base.join(n)).expect("gen");
        }
        // ★ The two things upstream leaves in the mount that are NOT
        // generations. Treating either as one would delete live key material.
        std::fs::write(base.join("age-keys.txt"), b"AGE-SECRET").expect("keyfile");
        std::fs::create_dir_all(base.join("gpg4114821736")).expect("gpg scratch");

        let current = base.join("10");
        RealFs
            .reap_generations(&base.to_string_lossy(), 1, &current.to_string_lossy())
            .expect("reaps");

        let left: std::collections::BTreeSet<String> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        assert!(left.contains("10"), "current must survive: {left:?}");
        assert!(
            left.contains("3"),
            "keep=1 keeps the newest previous: {left:?}"
        );
        assert!(!left.contains("2"), "older must be reaped: {left:?}");
        assert!(!left.contains("1"), "older must be reaped: {left:?}");
        assert!(
            left.contains("age-keys.txt"),
            "KEY MATERIAL must survive: {left:?}"
        );
        assert!(
            left.contains("gpg4114821736"),
            "a non-numeric scratch dir is not a generation: {left:?}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn reaping_with_nothing_to_reap_is_not_an_error() {
        // Anti-vacuity's sibling: the common case must not throw, or the
        // not-fatal handling in apply would hide a real failure behind noise.
        let base = std::env::temp_dir().join(format!("reap0-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("7")).expect("gen");
        let cur = base.join("7");
        RealFs
            .reap_generations(&base.to_string_lossy(), 1, &cur.to_string_lossy())
            .expect("no-op is success");
        assert!(cur.exists());
        std::fs::remove_dir_all(&base).ok();
    }
}
