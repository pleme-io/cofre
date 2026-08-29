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
    if p.is_null() { None } else { Some(unsafe { (*p).pw_uid }) }
}

fn gid_of(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: as above, for getgrnam.
    let p = unsafe { libc::getgrnam(c.as_ptr()) };
    if p.is_null() { None } else { Some(unsafe { (*p).gr_gid }) }
}

impl Fs for RealFs {
    fn make_dir(&self, path: &str) -> Result<(), String> {
        std::fs::create_dir_all(path).map_err(|e| e.to_string())
    }

    fn write_restrictive(&self, path: &str, contents: &[u8]) -> Result<(), String> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
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

    fn remove_dir_all(&self, path: &str) -> Result<(), String> {
        std::fs::remove_dir_all(path).map_err(|e| e.to_string())
    }
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
        Self { identities, cache: Mutex::new(HashMap::new()) }
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
        let mut cache = self.cache.lock().map_err(|_| "cache poisoned".to_string())?;
        if !cache.contains_key(sops_file) {
            let mut file =
                SopsFile::load_encrypted(sops_file).map_err(|e| format!("load: {e}"))?;
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
        assert!(matches!(at_path(&nested(), "attic/jwt/token"), Some(Value::Scalar(_))));
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
        assert!(matches!(v, Some(Value::Mapping(_))), "must not be mistaken for a scalar");
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
