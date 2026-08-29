//! Turning a plan into syscalls.
//!
//! ── ★ TWO SEAMS, NOT ONE ───────────────────────────────────────────────
//!
//! [`Fs`] is the filesystem and [`Decryptor`] is the plaintext source. They
//! are separate traits because they fail for unrelated reasons and the
//! response differs: a decrypt failure means *this generation is wrong* and
//! must not be published, while a chmod failure means *the node is not what we
//! think it is* and is worth surfacing differently. Folding them into one
//! error type would lose that.
//!
//! ── ★ THE ALL-OR-NOTHING BOUNDARY IS THE SWAP ──────────────────────────
//!
//! Everything before [`Step::SwapSymlink`] writes into a generation directory
//! nothing references. If any of it fails, [`apply`] returns without swapping
//! and the node continues on its previous generation — untouched, still
//! decryptable, still serving whatever was reading `/run/secrets`.
//!
//! That is why the executor does NOT clean up a failed generation by default.
//! A half-written directory is inert, and it is *evidence*: an operator
//! debugging why secrets did not update can read exactly how far it got.
//! Pruning removes it on the next successful run.

use crate::place::{PlanError, Step, plan};
use crate::manifest::Manifest;

/// Filesystem effects.
pub trait Fs {
    /// Ensure `path` is a ramfs mount, mounting one if it is not already.
    ///
    /// # Errors
    /// Implementation-defined mount failure.
    fn ensure_ramfs(&self, path: &str) -> Result<(), String>;

    /// Create a directory and any missing parents.
    ///
    /// # Errors
    /// Implementation-defined I/O failure.
    fn make_dir(&self, path: &str) -> Result<(), String>;

    /// Write `contents` to `path`, creating it with the restrictive mode.
    ///
    /// # Errors
    /// Implementation-defined I/O failure.
    fn write_restrictive(&self, path: &str, contents: &[u8]) -> Result<(), String>;

    /// # Errors
    /// Implementation-defined I/O failure.
    fn chown(&self, path: &str, own: &crate::place::Ownership) -> Result<(), String>;

    /// # Errors
    /// Implementation-defined I/O failure.
    fn chmod(&self, path: &str, mode: u32) -> Result<(), String>;

    /// Point `link` at `target` ATOMICALLY.
    ///
    /// # Errors
    /// Implementation-defined I/O failure.
    fn swap_symlink(&self, link: &str, target: &str) -> Result<(), String>;

    /// # Errors
    /// Implementation-defined I/O failure.
    fn remove_dir_all(&self, path: &str) -> Result<(), String>;
}

/// The plaintext source.
pub trait Decryptor {
    /// Extract one key from one encrypted file.
    ///
    /// # Errors
    /// Implementation-defined decryption failure.
    fn extract(&self, sops_file: &str, key: &str) -> Result<Vec<u8>, String>;
}

/// What went wrong, and — crucially — whether the swap happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    Plan(PlanError),
    /// A decrypt failed. The generation is abandoned unpublished.
    Decrypt { file: String, key: String, detail: String },
    /// A filesystem step failed. Also unpublished.
    Fs { step: String, detail: String },
    /// A template could not be rendered. Also unpublished.
    ///
    /// ★ Separate from `Fs` because the remedy is different: a template
    /// failure means the manifest and the secrets disagree, not that the disk
    /// misbehaved.
    Template { detail: String },
    /// ★ The swap ITSELF failed — the one failure where the generation is
    /// complete and correct but unreachable. Named separately because the
    /// remedy differs: everything is on disk, and re-running succeeds.
    Swap { detail: String },
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plan(e) => write!(f, "{e}"),
            Self::Decrypt { file, key, detail } => {
                write!(f, "decrypting {key} from {file}: {detail} — generation not published")
            }
            Self::Fs { step, detail } => {
                write!(f, "{step}: {detail} — generation not published")
            }
            Self::Template { detail } => {
                write!(f, "{detail} — generation not published")
            }
            Self::Swap { detail } => write!(
                f,
                "the generation is complete but could not be published: {detail}"
            ),
        }
    }
}

/// A successful run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub generation: u64,
    pub written: usize,
    pub pruned: Vec<u64>,
}

/// Execute a plan.
///
/// # Errors
/// [`ApplyError`]. On every variant except [`ApplyError::Swap`], the previous
/// generation is still live and untouched.
pub fn apply<F: Fs, D: Decryptor>(
    m: &Manifest,
    generation: u64,
    fs: &F,
    dec: &D,
) -> Result<Applied, ApplyError> {
    let steps = plan(m, generation).map_err(ApplyError::Plan)?;
    let mut written = 0usize;
    // ★ Plaintexts are kept because TEMPLATES ARE RENDERED FROM THEM. Holding
    // them for the length of one run is what upstream does too; the
    // alternative is decrypting each referenced secret a second time, which
    // doubles the MAC verifications for no gain.
    let mut values: std::collections::BTreeMap<String, Vec<u8>> =
        std::collections::BTreeMap::new();

    for step in &steps {
        match step {
            Step::EnsureRamfs { path } => fs.ensure_ramfs(path).map_err(|d| ApplyError::Fs {
                step: format!("ensure ramfs at {path}"),
                detail: d,
            })?,
            Step::MakeGeneration { path } => fs.make_dir(path).map_err(|d| ApplyError::Fs {
                step: format!("mkdir {path}"),
                detail: d,
            })?,
            Step::Write { path, key, from_file } => {
                // ★ Decrypt, then write. A decrypt failure must not leave a
                // zero-length file behind that a later reader could mistake
                // for an empty secret.
                let plaintext =
                    dec.extract(from_file, key).map_err(|d| ApplyError::Decrypt {
                        file: from_file.clone(),
                        key: key.clone(),
                        detail: d,
                    })?;
                fs.write_restrictive(path, &plaintext)
                    .map_err(|d| ApplyError::Fs { step: format!("write {path}"), detail: d })?;
                values.insert(key.clone(), plaintext);
                written += 1;
            }
            Step::Chown { path, own } => {
                fs.chown(path, own).map_err(|d| ApplyError::Fs {
                    step: format!("chown {path}"),
                    detail: d,
                })?;
            }
            Step::Chmod { path, mode } => {
                fs.chmod(path, *mode).map_err(|d| ApplyError::Fs {
                    step: format!("chmod {path}"),
                    detail: d,
                })?;
            }
            Step::RenderTemplate { path, name, content, references } => {
                // ★ `references` is checked against what we actually hold, so
                // a template naming a secret the manifest never placed fails
                // HERE with both names rather than as a stray marker later.
                for r in references {
                    if !values.contains_key(r) {
                        return Err(ApplyError::Template {
                            detail: format!("template {name}: {r} was never placed"),
                        });
                    }
                }
                let body = crate::template::render(
                    name,
                    content,
                    &m.placeholder_by_secret_name,
                    &values,
                )
                .map_err(|e| ApplyError::Template { detail: e.to_string() })?;
                fs.write_restrictive(path, body.as_bytes())
                    .map_err(|d| ApplyError::Fs { step: format!("write {path}"), detail: d })?;
                written += 1;
            }
            Step::SwapSymlink { link, target } => {
                fs.swap_symlink(link, target)
                    .map_err(|d| ApplyError::Swap { detail: d })?;
            }
            Step::RemoveGeneration { path } => {
                // ★ A prune failure is NOT fatal. The generation is published
                // and the node is correct; failing here would report an
                // overall failure for a disk-tidiness problem, and an operator
                // would go looking for a secrets bug that does not exist.
                let _ = fs.remove_dir_all(path);
            }
        }
    }
    Ok(Applied { generation, written, pruned: Vec::new() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const M: &str = r#"{
      "secretsMountPoint": "/run/secrets.d", "symlinkPath": "/run/secrets",
      "keepGenerations": 2, "ageKeyFile": null, "ageSshKeyPaths": [],
      "gnupgHome": null, "sshKeyPaths": [],
      "secrets": [
        {"format":"yaml","gid":0,"group":"root","key":"a/b","mode":"0400","name":"a/b",
         "neededForUsers":false,"owner":"root","path":"/run/secrets/a/b","reloadUnits":[],
         "restartUnits":[],"sopsFile":"/nix/store/x.yaml","uid":0}
      ]
    }"#;
    fn m() -> Manifest { serde_json::from_str(M).expect("manifest") }

    #[derive(Default)]
    struct SpyFs {
        log: RefCell<Vec<String>>,
        fail_on: Option<&'static str>,
    }
    impl SpyFs {
        fn failing(what: &'static str) -> Self {
            Self { log: RefCell::new(Vec::new()), fail_on: Some(what) }
        }
        fn note(&self, what: &str) -> Result<(), String> {
            self.log.borrow_mut().push(what.to_owned());
            if self.fail_on.is_some_and(|f| what.starts_with(f)) {
                return Err("injected".into());
            }
            Ok(())
        }
        fn did(&self, prefix: &str) -> bool {
            self.log.borrow().iter().any(|l| l.starts_with(prefix))
        }
    }
    impl Fs for SpyFs {
        fn ensure_ramfs(&self, p: &str) -> Result<(), String> { self.note(&format!("ramfs {p}")) }
        fn make_dir(&self, p: &str) -> Result<(), String> { self.note(&format!("mkdir {p}")) }
        fn write_restrictive(&self, p: &str, _c: &[u8]) -> Result<(), String> { self.note(&format!("write {p}")) }
        fn chown(&self, p: &str, _o: &crate::place::Ownership) -> Result<(), String> { self.note(&format!("chown {p}")) }
        fn chmod(&self, p: &str, _m: u32) -> Result<(), String> { self.note(&format!("chmod {p}")) }
        fn swap_symlink(&self, l: &str, t: &str) -> Result<(), String> { self.note(&format!("swap {l}->{t}")) }
        fn remove_dir_all(&self, p: &str) -> Result<(), String> { self.note(&format!("rm {p}")) }
    }

    struct OkDec;
    impl Decryptor for OkDec {
        fn extract(&self, _f: &str, _k: &str) -> Result<Vec<u8>, String> { Ok(b"plaintext".to_vec()) }
    }
    struct FailDec;
    impl Decryptor for FailDec {
        fn extract(&self, _f: &str, _k: &str) -> Result<Vec<u8>, String> { Err("no identity".into()) }
    }

    #[test]
    fn a_decrypt_failure_never_reaches_the_swap() {
        // THE property. The previous generation stays live because nothing
        // ever pointed at the new one.
        let fs = SpyFs::default();
        let e = apply(&m(), 3, &fs, &FailDec).expect_err("must fail");
        assert!(matches!(e, ApplyError::Decrypt { .. }));
        assert!(!fs.did("swap"), "swapped despite a decrypt failure");
    }

    #[test]
    fn a_decrypt_failure_leaves_no_file_at_all() {
        // Not even an empty one -- a zero-length file is indistinguishable
        // from an empty secret to whatever reads it next.
        let fs = SpyFs::default();
        let _ = apply(&m(), 3, &fs, &FailDec);
        assert!(!fs.did("write"), "wrote a file for a secret that failed to decrypt");
    }

    #[test]
    fn a_chmod_failure_also_stops_before_the_swap() {
        let fs = SpyFs::failing("chmod");
        let e = apply(&m(), 3, &fs, &OkDec).expect_err("must fail");
        assert!(matches!(e, ApplyError::Fs { .. }));
        assert!(!fs.did("swap"));
    }

    #[test]
    fn a_swap_failure_is_its_own_variant() {
        // The one failure where the generation is COMPLETE but unreachable.
        // Named separately because the remedy differs: re-running succeeds.
        let fs = SpyFs::failing("swap");
        let e = apply(&m(), 3, &fs, &OkDec).expect_err("must fail");
        assert!(matches!(e, ApplyError::Swap { .. }), "got {e:?}");
        assert!(fs.did("write") && fs.did("chmod"), "the generation should be complete");
    }

    #[test]
    fn the_happy_path_swaps_exactly_once_and_last() {
        let fs = SpyFs::default();
        let r = apply(&m(), 3, &fs, &OkDec).expect("ok");
        assert_eq!(r.written, 1);
        let log = fs.log.borrow();
        assert!(log.last().is_some_and(|l| l.starts_with("swap")), "swap must be last");
        assert_eq!(log.iter().filter(|l| l.starts_with("swap")).count(), 1);
    }

    #[test]
    fn ownership_precedes_permissions_in_the_actual_call_order() {
        // The plan asserts this; here it is asserted on what the executor
        // really DID, which is the thing that matters.
        let fs = SpyFs::default();
        apply(&m(), 3, &fs, &OkDec).expect("ok");
        let log = fs.log.borrow();
        let chown = log.iter().position(|l| l.starts_with("chown")).expect("chown");
        let chmod = log.iter().position(|l| l.starts_with("chmod")).expect("chmod");
        assert!(chown < chmod, "chmod ran before chown — ownership window");
    }

    #[test]
    fn nothing_is_written_outside_the_generation_directory() {
        let fs = SpyFs::default();
        apply(&m(), 3, &fs, &OkDec).expect("ok");
        for line in fs.log.borrow().iter().filter(|l| l.starts_with("write")) {
            assert!(line.contains("/run/secrets.d/3/"), "escaped the generation: {line}");
        }
    }
}
