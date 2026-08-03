//! `cofre-fs` — atomic secret-file creation.
//!
//! Writes a file whose permission bits are established at `open(2)` rather
//! than applied afterwards, so the file is never briefly readable by anyone
//! other than its owner.
//!
//! Three properties:
//!
//! 1. **Mode at creation.** `OpenOptions::mode` sets the bits in the same
//!    syscall that creates the file. A later `chmod` cannot retroactively
//!    close the interval before it ran.
//! 2. **`create_new(true)`.** Refuses to open an existing path, so a symlink
//!    or an inode placed there beforehand is not written through.
//! 3. **`mode` is a required argument.** No default, so the intended
//!    permissions are always visible at the call site.
//!
//! Use it for anything a process should be the only reader of: keys, tokens,
//! kubeconfigs, rendered credential files.

#![cfg(unix)]

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

/// Write `bytes` to `path`, creating it with exactly `mode` at `open(2)`.
///
/// Replaces an existing file at `path`. The unlink-then-`create_new` pair is
/// deliberate: plain `create(true).truncate(true)` on an existing path
/// **keeps the old file's mode**, so a file that was once 0644 stays 0644 no
/// matter what `mode` says here.
///
/// # Errors
/// Propagates the underlying `io::Error`. A failure to remove a pre-existing
/// path is ignored (it usually means "absent"), but a failure to *create* is
/// fatal and returned — this function never falls back to a laxer mode.
pub fn write_secret(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    // Ignore the result: the common case is "absent". If something genuinely
    // undeletable sits here, create_new below fails loudly rather than
    // silently writing through it.
    let _ = std::fs::remove_file(path);

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;

    f.write_all(bytes)?;
    // Explicit sync: a caller that writes a key and immediately spawns a
    // process reading it should not race the page cache.
    f.sync_all()
}

/// Create `path` as a directory with exactly `mode`, including parents.
///
/// Parents get the SAME mode: a restrictive leaf inside a permissive parent
/// is still listable.
///
/// Idempotent: an existing directory is left alone but its mode is corrected.
///
/// # Errors
/// Propagates the underlying `io::Error`.
pub fn create_secret_dir(path: &Path, mode: u32) -> io::Result<()> {
    if path.is_dir() {
        return std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode));
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Runs the body under a permissive umask, so a test asserting the mode
    /// is asserting what `open(2)` set rather than what the umask happened to
    /// mask off.
    fn with_permissive_umask<T>(f: impl FnOnce() -> T) -> T {
        // SAFETY: umask is process-global; tests in this module are the only
        // ones touching it and each restores the prior value.
        let prev = unsafe { libc_umask(0o000) };
        let out = f();
        unsafe { libc_umask(prev) };
        out
    }

    unsafe extern "C" {
        #[link_name = "umask"]
        fn libc_umask(mask: u32) -> u32;
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cofre-fs-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn mode_is_exact_under_a_permissive_umask() {
        let d = tmpdir("mode");
        let p = d.join("secret");
        with_permissive_umask(|| write_secret(&p, b"hunter2", 0o600).unwrap());

        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            m, 0o600,
            "mode must come from open(2), not from a later chmod — got {m:o}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn replacing_an_existing_0644_file_does_not_inherit_its_mode() {
        let d = tmpdir("replace");
        let p = d.join("secret");
        std::fs::write(&p, b"old").unwrap();
        std::fs::set_permissions(&p, PermissionsExt::from_mode(0o644)).unwrap();

        with_permissive_umask(|| write_secret(&p, b"new", 0o600).unwrap());

        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "a pre-existing 0644 file must not keep its mode");
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        std::fs::remove_dir_all(&d).ok();
    }

    /// A symlink already present at the target path must not be written
    /// through.
    #[test]
    fn refuses_to_follow_a_pre_planted_symlink() {
        let d = tmpdir("symlink");
        let target = d.join("attacker-owned");
        let link = d.join("wg0.conf");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // remove_file unlinks the LINK, so the write succeeds — and crucially
        // it writes to a fresh inode at `link`, never through to `target`.
        write_secret(&link, b"PrivateKey = xxx", 0o600).unwrap();

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"",
            "the secret must not have been written through the symlink"
        );
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn dir_mode_is_exact_and_parents_are_not_left_open() {
        let d = tmpdir("dir");
        let nested = d.join("a").join("b");
        with_permissive_umask(|| create_secret_dir(&nested, 0o700).unwrap());

        for p in [&nested, &d.join("a")] {
            let m = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o700, "{} should be 0700, got {m:o}", p.display());
        }
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn create_secret_dir_is_idempotent_and_corrects_a_loose_mode() {
        let d = tmpdir("idem");
        let p = d.join("vault");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, PermissionsExt::from_mode(0o755)).unwrap();

        create_secret_dir(&p, 0o700).unwrap();

        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o700, "an existing loose dir must be tightened");
        std::fs::remove_dir_all(&d).ok();
    }
}
