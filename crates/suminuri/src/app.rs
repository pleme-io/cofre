//! The interpreter: an [`Invocation`] applied to an [`Environment`].
//!
//! Every verb lands here, and nothing here touches the real world directly — the
//! `Environment` seam does that. So the whole operator-visible surface is
//! exercisable against a mock: no real files, no real keys, no plaintext in
//! `/tmp` during a test run.
//!
//! # The one place output is not a return value
//!
//! Decrypted output goes to a caller-supplied writer rather than being returned as
//! a `String`, because `sops -d` streams to stdout and the plaintext should not
//! sit in a second buffer on its way there. The writer is the caller's, so a test
//! captures it into a `Vec<u8>` and the binary hands it `stdout`.

use crate::cli::{Invocation, Verb, exit};
use crate::config::{ConfigError, SopsConfig};
use crate::env::Environment;
use crate::file::{FileError, SopsFile};
use crate::keys::{AgeIdentities, KeyError, wrap_for_age_recipients};
use std::path::Path;
use suminuri_wire::{DataKey, IvStash, Metadata};
use suminuri_yaml::Value;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{path}: {reason}")]
    Io { path: String, reason: String },
    #[error("no file given; suminuri needs a path to operate on")]
    NoFile,
    #[error(
        "this build cannot honour {flags}. Refusing rather than ignoring them, because a silently-dropped flag writes a file with the wrong protection and reports success."
    )]
    UnsupportedFlags { flags: String },
    #[error(
        "`{verb}` is not implemented in this build; use upstream sops for it (both read and write the same format)"
    )]
    UnimplementedVerb { verb: String },
    #[error(
        "--extract path `{path}` is malformed; expected the sops form, e.g. '[\"db\"][\"password\"]'"
    )]
    BadExtractPath { path: String },
    #[error("--extract found nothing at `{path}`")]
    ExtractNotFound { path: String },
    #[error("no age identity available. {detail}")]
    NoIdentity { detail: String },
    #[error(
        "refusing to encrypt with no recipients: nothing would ever be able to decrypt the result"
    )]
    NoRecipients,
}

/// What a run produced.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub code: i32,
    /// A short line for the operator, on stderr. Never a secret.
    pub message: Option<String>,
}

impl Outcome {
    fn ok() -> Self {
        Self {
            code: exit::OK,
            message: None,
        }
    }
    fn ok_with(msg: impl Into<String>) -> Self {
        Self {
            code: exit::OK,
            message: Some(msg.into()),
        }
    }
    fn unchanged() -> Self {
        Self {
            code: exit::FILE_HAS_NOT_CHANGED,
            message: Some("file has not changed".to_string()),
        }
    }
}

/// Run one invocation.
pub fn run(
    inv: &Invocation,
    env: &dyn Environment,
    out: &mut dyn std::io::Write,
) -> Result<Outcome, AppError> {
    // Refuse *before* doing anything. A flag we cannot honour has to stop the run
    // while the file is still untouched.
    if !inv.unsupported.is_empty() {
        return Err(AppError::UnsupportedFlags {
            flags: inv.unsupported.join(", "),
        });
    }

    match &inv.verb {
        Verb::Help => {
            write_all(out, &crate::cli::help_text())?;
            Ok(Outcome::ok())
        }
        Verb::Version => {
            write_all(out, &crate::cli::version_text())?;
            Ok(Outcome::ok())
        }
        Verb::Unimplemented(v) => Err(AppError::UnimplementedVerb { verb: v.clone() }),
        Verb::Decrypt => decrypt(inv, env, out),
        Verb::Encrypt => encrypt(inv, env, out),
        Verb::Edit => edit(inv, env),
        Verb::Rotate => rotate(inv, env, out),
        Verb::UpdateKeys => update_keys(inv, env),
        Verb::FileStatus => file_status(inv, env, out),
    }
}

fn file_of(inv: &Invocation) -> Result<&Path, AppError> {
    inv.file.as_deref().ok_or(AppError::NoFile)
}

fn read(env: &dyn Environment, path: &Path) -> Result<String, AppError> {
    env.read_to_string(path).map_err(|e| AppError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    })
}

fn write_all(out: &mut dyn std::io::Write, s: &str) -> Result<(), AppError> {
    out.write_all(s.as_bytes()).map_err(|e| AppError::Io {
        path: "<stdout>".to_string(),
        reason: e.to_string(),
    })
}

/// The mode a file holding secrets is written with.
///
/// 0600 unconditionally, including for an encrypted file. The ciphertext does not
/// need protecting, but the *habit* of choosing a mode per call site is how a
/// plaintext eventually gets written 0644 — so there is one answer.
const SECRET_MODE: u32 = 0o600;

fn identities(env: &dyn Environment) -> Result<AgeIdentities, AppError> {
    let ids = AgeIdentities::discover(env)?;
    if ids.is_empty() {
        let unsupported = AgeIdentities::unsupported_sources(env);
        let detail = if unsupported.is_empty() {
            format!(
                "Set SOPS_AGE_KEY or SOPS_AGE_KEY_FILE, or place a key at {}.",
                crate::keys::expected_key_path(env)
            )
        } else {
            // Naming this matters: the operator *has* configured a key source, we
            // just do not read it. Reporting "no key" would send them looking for
            // a file that was never the problem.
            format!(
                "{} is set, but this build does not read it (age identities only come from SOPS_AGE_KEY, SOPS_AGE_KEY_FILE, or the default key file).",
                unsupported.join(" and ")
            )
        };
        return Err(AppError::NoIdentity { detail });
    }
    Ok(ids)
}

/// Load, unwrap, decrypt, verify. The shared prefix of every read path.
fn open(inv: &Invocation, env: &dyn Environment) -> Result<(SopsFile, DataKey, IvStash), AppError> {
    let path = file_of(inv)?;
    let src = read(env, path)?;
    let mut f = SopsFile::load_encrypted(&src)?;
    if let Some(indent) = inv.indent {
        f.indent = indent;
    }
    let key = f.data_key(&identities(env)?)?;
    let mut stash = IvStash::new();
    let unverified = f.decrypt(&key, &mut stash)?;
    if inv.ignore_mac {
        // The escape exists because a file whose MAC broke on a hand-edited
        // `lastmodified` is still recoverable, and refusing outright would make us
        // less useful than what we replace. It is spelled out loudly here and in
        // `Unverified`'s own API so it cannot be taken by accident.
        let _ = unverified.into_inner_ignoring_mac();
    } else {
        unverified
            .verify_recording(&key, Some(&mut stash))
            .map_err(FileError::from)?;
    }
    Ok((f, key, stash))
}

fn decrypt(
    inv: &Invocation,
    env: &dyn Environment,
    out: &mut dyn std::io::Write,
) -> Result<Outcome, AppError> {
    let (f, _, _) = open(inv, env)?;
    let body = match &inv.extract {
        Some(path) => extract(&f.tree, path)?,
        None => f.render_plain()?,
    };
    match (&inv.output, inv.in_place) {
        (Some(target), _) => {
            env.write_file_atomic(target, &body, SECRET_MODE)
                .map_err(|e| AppError::Io {
                    path: target.display().to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Outcome::ok_with(format!(
                "decrypted to {}",
                target.display()
            )))
        }
        (None, true) => {
            let path = file_of(inv)?;
            env.write_file_atomic(path, &body, SECRET_MODE)
                .map_err(|e| AppError::Io {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Outcome::ok_with(format!(
                "decrypted {} in place",
                path.display()
            )))
        }
        (None, false) => {
            write_all(out, &body)?;
            Ok(Outcome::ok())
        }
    }
}

fn encrypt(
    inv: &Invocation,
    env: &dyn Environment,
    out: &mut dyn std::io::Write,
) -> Result<Outcome, AppError> {
    let path = file_of(inv)?;
    let src = read(env, path)?;
    let tree = SopsFile::load_plain(&src)?;

    // Recipients: the command line first, then the config's matching rule. Both
    // empty is a refusal, not a warning — a file with no recipients can never be
    // decrypted by anyone, which is unrecoverable rather than inconvenient.
    let (recipients, rule) = resolve_recipients(inv, env, path)?;
    if recipients.is_empty() {
        return Err(AppError::NoRecipients);
    }

    let key = DataKey::generate().map_err(FileError::from)?;
    let wrapped = wrap_for_age_recipients(&key, &recipients)?;
    let mut f = SopsFile {
        tree,
        metadata: Metadata::from_wrapped(wrapped, "", ""),
        indent: inv
            .indent
            .unwrap_or_else(|| crate::file::detect_indent(&src).unwrap_or(4)),
    };
    apply_selector_options(&mut f.metadata, inv, rule.as_ref());

    let mut stash = IvStash::new();
    let stats = f.encrypt(&key, &mut stash, &env.now_rfc3339())?;
    let body = f.render()?;

    let summary = format!(
        "encrypted {} leaf/leaves for {} recipient(s); {} left in the clear",
        stats.encrypted,
        recipients.len(),
        stats.cleared
    );
    match (&inv.output, inv.in_place) {
        (Some(target), _) => {
            env.write_file_atomic(target, &body, SECRET_MODE)
                .map_err(|e| AppError::Io {
                    path: target.display().to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Outcome::ok_with(summary))
        }
        (None, true) => {
            env.write_file_atomic(path, &body, SECRET_MODE)
                .map_err(|e| AppError::Io {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Outcome::ok_with(summary))
        }
        (None, false) => {
            write_all(out, &body)?;
            Ok(Outcome::ok())
        }
    }
}

/// Shreds the `edit` scratch directory on every exit path, including the early
/// `return` and any `?`.
///
/// A `Drop` impl rather than a call at the end of the function, because `edit` has
/// four exits and only one of them reaches the end.
struct ScratchGuard<'e> {
    env: &'e dyn Environment,
    dir: std::path::PathBuf,
}

impl Drop for ScratchGuard<'_> {
    fn drop(&mut self) {
        // Errors swallowed deliberately: this also runs during unwinding, and a
        // panic in `drop` while already panicking aborts the process. That the
        // shred happened is asserted by a test, not by a log line here.
        let _ = self.env.shred_dir(&self.dir);
    }
}

fn edit(inv: &Invocation, env: &dyn Environment) -> Result<Outcome, AppError> {
    let path = file_of(inv)?;
    let (mut f, key, mut stash) = open(inv, env)?;
    let before = f.render_plain()?;

    // The plaintext has to reach a filesystem for an editor to open it. That is a
    // real exposure: 0600 in a 0700 directory, shredded afterwards, but a *disk*
    // nonetheless on darwin where there is no per-user tmpfs to prefer.
    // only-mitigated, not unrepresentable.
    //
    // ★ "SHREDDED AFTERWARDS" IS A `Drop` GUARD, NOT A LINE AT THE END.
    //
    // The first version of this function said "removed afterwards" in a comment
    // and removed nothing. Measured on cid 2026-08-19: **92 leftover scratch
    // directories, 3 holding a fully decrypted copy of the operator's
    // `users/drzzln/secrets.yaml`.** Three of the four exits below skip any
    // trailing cleanup — the early `return Ok(unchanged())`, and either `?` on the
    // re-encrypt or on the write-back — so a cleanup statement at the end of the
    // function is wrong by construction, not by oversight.
    let dir = env.secure_temp_dir().map_err(|e| AppError::Io {
        path: "<secure temp dir>".to_string(),
        reason: e.to_string(),
    })?;
    let _scratch_guard = ScratchGuard {
        env,
        dir: dir.clone(),
    };
    let scratch = dir.join(path.file_name().map_or_else(
        || std::ffi::OsString::from("edit.yaml"),
        std::ffi::OsStr::to_os_string,
    ));
    env.write_file_atomic(&scratch, &before, SECRET_MODE)
        .map_err(|e| AppError::Io {
            path: scratch.display().to_string(),
            reason: e.to_string(),
        })?;

    let changed = env.edit_file(&scratch).map_err(|e| AppError::Io {
        path: scratch.display().to_string(),
        reason: e.to_string(),
    })?;
    let after = read(env, &scratch)?;

    if !changed || after == before {
        // sops's documented exit 200. cofre's SOPS backend branches on this exact
        // value, so it is contract rather than cosmetics.
        return Ok(Outcome::unchanged());
    }

    f.tree = SopsFile::load_plain(&after)?;
    let stats = f.encrypt(&key, &mut stash, &env.now_rfc3339())?;
    let body = f.render()?;
    env.write_file_atomic(path, &body, SECRET_MODE)
        .map_err(|e| AppError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
    Ok(Outcome::ok_with(format!(
        "re-encrypted {} leaf/leaves",
        stats.encrypted
    )))
}

fn rotate(
    inv: &Invocation,
    env: &dyn Environment,
    out: &mut dyn std::io::Write,
) -> Result<Outcome, AppError> {
    let path = file_of(inv)?;
    let (mut f, _old_key, _) = open(inv, env)?;

    // A rotation is the one operation that must NOT reuse the IV stash. The point
    // is a new data key with every value re-encrypted under it; carrying the old
    // nonces forward would pair a fresh key with reused nonces, which is the one
    // GCM misuse that actually breaks confidentiality.
    let fresh_stash = &mut IvStash::new();
    let new_key = DataKey::generate().map_err(FileError::from)?;

    // Same recipients, new data key. Re-wrapping for a *different* set is
    // `updatekeys`' job; conflating them is how a rotate quietly changes who can
    // read a file.
    let recipients: Vec<String> = f
        .metadata
        .age_keys()
        .into_iter()
        .map(|k| k.recipient)
        .collect();
    if recipients.is_empty() {
        return Err(AppError::NoRecipients);
    }
    f.metadata
        .rewrap(wrap_for_age_recipients(&new_key, &recipients)?)
        .map_err(FileError::from)?;

    let stats = f.encrypt(&new_key, fresh_stash, &env.now_rfc3339())?;
    let body = f.render()?;
    let summary = format!(
        "rotated the data key; re-encrypted {} leaf/leaves for {} recipient(s)",
        stats.encrypted,
        recipients.len()
    );

    if inv.in_place || inv.output.is_some() {
        let target = inv.output.as_deref().unwrap_or(path);
        env.write_file_atomic(target, &body, SECRET_MODE)
            .map_err(|e| AppError::Io {
                path: target.display().to_string(),
                reason: e.to_string(),
            })?;
        Ok(Outcome::ok_with(summary))
    } else {
        write_all(out, &body)?;
        Ok(Outcome::ok())
    }
}

fn update_keys(inv: &Invocation, env: &dyn Environment) -> Result<Outcome, AppError> {
    let path = file_of(inv)?;
    let src = read(env, path)?;
    let mut f = SopsFile::load_encrypted(&src)?;
    let key = f.data_key(&identities(env)?)?;

    let (recipients, _) = resolve_recipients(inv, env, path)?;
    if recipients.is_empty() {
        return Err(AppError::NoRecipients);
    }

    let before: Vec<String> = f
        .metadata
        .age_keys()
        .into_iter()
        .map(|k| k.recipient)
        .collect();
    if before == recipients {
        return Ok(Outcome::unchanged());
    }

    // The data key is unchanged and the tree is never walked, so **every leaf's
    // ciphertext, the MAC and `lastmodified` all stay exactly as they were**. Only
    // the wrapped copies of the data key change. That is what makes an
    // `updatekeys` diff readable — and it is why this function does not go through
    // `open()`: decrypting would be work with no purpose and a plaintext in memory
    // for no reason.
    f.metadata
        .rewrap(wrap_for_age_recipients(&key, &recipients)?)
        .map_err(FileError::from)?;

    let body = f.render()?;
    env.write_file_atomic(path, &body, SECRET_MODE)
        .map_err(|e| AppError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

    let added = recipients.iter().filter(|r| !before.contains(r)).count();
    let removed = before.iter().filter(|r| !recipients.contains(r)).count();
    Ok(Outcome::ok_with(format!(
        "re-wrapped the data key: {} recipient(s) added, {} removed, {} total",
        added,
        removed,
        recipients.len()
    )))
}

fn file_status(
    inv: &Invocation,
    env: &dyn Environment,
    out: &mut dyn std::io::Write,
) -> Result<Outcome, AppError> {
    let path = file_of(inv)?;
    let src = read(env, path)?;
    match SopsFile::load_encrypted(&src) {
        Ok(f) => {
            let providers: Vec<&str> = f.metadata.providers().iter().map(|p| p.field()).collect();
            let missing = f.metadata.unimplemented_providers();
            write_all(
                out,
                &format!(
                    "{}: encrypted (version {}, {} recipient(s) via {}, indent {}){}\n",
                    path.display(),
                    f.metadata.version,
                    f.metadata.keys().len(),
                    providers.join("+"),
                    f.indent,
                    if missing.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " — NOT decryptable by this build: {}",
                            missing
                                .iter()
                                .map(|p| p.field())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                ),
            )?;
            Ok(Outcome::ok())
        }
        Err(FileError::NotEncrypted) => {
            write_all(out, &format!("{}: not encrypted\n", path.display()))?;
            Ok(Outcome::ok())
        }
        Err(e) => Err(e.into()),
    }
}

/// Recipients from the command line, else from the matching `creation_rule`.
fn resolve_recipients(
    inv: &Invocation,
    env: &dyn Environment,
    path: &Path,
) -> Result<(Vec<String>, Option<crate::config::CreationRule>), AppError> {
    if !inv.age_recipients.is_empty() {
        return Ok((inv.age_recipients.clone(), None));
    }
    let cfg = match &inv.config {
        Some(explicit) => {
            let src = read(env, explicit)?;
            Some(SopsConfig::parse(&explicit.display().to_string(), &src)?)
        }
        None => SopsConfig::discover(env, path)?,
    };
    let Some(cfg) = cfg else {
        return Err(ConfigError::NoConfig {
            from: path.display().to_string(),
        }
        .into());
    };
    // The regex is matched against the path **as given on the command line**,
    // because that is what sops matches. `^secrets\.yaml$` therefore works from
    // the repo root and not from elsewhere — a quirk that keeps both tools
    // agreeing, and one worth knowing before blaming the tool.
    let file_key = path.to_string_lossy().to_string();
    let rule = cfg
        .rule_for(&file_key)
        .ok_or_else(|| ConfigError::NoMatchingRule {
            path: cfg.path.clone(),
            file: file_key.clone(),
        })?
        .clone();
    Ok((rule.age.clone(), Some(rule)))
}

/// Apply selector options, command line beating the config rule.
fn apply_selector_options(
    m: &mut Metadata,
    inv: &Invocation,
    rule: Option<&crate::config::CreationRule>,
) {
    let pick = |cli: &Option<String>, cfg: Option<&String>| -> Option<String> {
        cli.clone().or_else(|| cfg.cloned())
    };
    m.unencrypted_suffix = pick(
        &inv.unencrypted_suffix,
        rule.and_then(|r| r.unencrypted_suffix.as_ref()),
    );
    m.encrypted_suffix = pick(
        &inv.encrypted_suffix,
        rule.and_then(|r| r.encrypted_suffix.as_ref()),
    );
    m.unencrypted_regex = pick(
        &inv.unencrypted_regex,
        rule.and_then(|r| r.unencrypted_regex.as_ref()),
    );
    m.encrypted_regex = pick(
        &inv.encrypted_regex,
        rule.and_then(|r| r.encrypted_regex.as_ref()),
    );
    m.mac_only_encrypted = inv.mac_only_encrypted || rule.is_some_and(|r| r.mac_only_encrypted);

    // sops writes an explicit `unencrypted_suffix: _unencrypted` when nothing else
    // is configured, rather than leaving the field absent — visible in the
    // operator's own files. Reproduced so a freshly-encrypted file matches.
    if m.unencrypted_suffix.is_none()
        && m.encrypted_suffix.is_none()
        && m.unencrypted_regex.is_none()
        && m.encrypted_regex.is_none()
    {
        m.unencrypted_suffix = Some(suminuri_wire::DEFAULT_UNENCRYPTED_SUFFIX.to_string());
    }
}

/// `--extract '["a"]["b"][0]'` — sops's bracket path syntax.
fn extract(tree: &Value, path_expr: &str) -> Result<String, AppError> {
    let steps = parse_extract_path(path_expr).ok_or_else(|| AppError::BadExtractPath {
        path: path_expr.to_string(),
    })?;
    let mut current = tree;
    for step in &steps {
        current = match step {
            ExtractStep::Key(k) => current.get(k).ok_or_else(|| AppError::ExtractNotFound {
                path: path_expr.to_string(),
            })?,
            ExtractStep::Index(i) => match current {
                Value::Sequence(entries) => entries
                    .iter()
                    .filter_map(|e| match e {
                        suminuri_yaml::Entry::Value(v) => Some(v),
                        suminuri_yaml::Entry::Comment(_) => None,
                    })
                    .nth(*i)
                    .ok_or_else(|| AppError::ExtractNotFound {
                        path: path_expr.to_string(),
                    })?,
                _ => {
                    return Err(AppError::ExtractNotFound {
                        path: path_expr.to_string(),
                    });
                }
            },
        };
    }
    // A scalar extracts as its bare text with **no trailing newline**. Measured
    // against sops v3.12.1 rather than assumed: `sops -d --extract '["k"]'` of a
    // scalar emits exactly the value's bytes. The first version appended a
    // newline on the reasoning that "a shell substitution wants one" — which is
    // true and irrelevant, because `$(…)` strips trailing newlines either way,
    // while `> file` and any byte comparison do not. A collection extracts as
    // YAML, which does end in a newline because the emitter terminates lines.
    Ok(match current {
        Value::Scalar(s) => s.value.clone(),
        other => suminuri_yaml::emit(
            &suminuri_yaml::Document::single(other.clone()),
            suminuri_yaml::EmitOptions::default(),
        )
        .map_err(FileError::from)?,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ExtractStep {
    Key(String),
    Index(usize),
}

/// Parse `["a"]["b"][0]` into steps.
///
/// Strict: a malformed expression is `None` rather than a best-effort read. An
/// `--extract` that silently matched the wrong key would print the wrong secret.
fn parse_extract_path(expr: &str) -> Option<Vec<ExtractStep>> {
    let mut steps = Vec::new();
    let mut rest = expr.trim();
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        rest = rest.strip_prefix('[')?;
        let (inner, tail) = rest.split_once(']')?;
        let inner = inner.trim();
        if let Some(quoted) = inner.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            steps.push(ExtractStep::Key(quoted.to_string()));
        } else if let Some(quoted) = inner.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            steps.push(ExtractStep::Key(quoted.to_string()));
        } else {
            steps.push(ExtractStep::Index(inner.parse::<usize>().ok()?));
        }
        rest = tail;
    }
    Some(steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::parse as parse_args;
    use crate::env::MockEnvironment;

    fn inv(args: &[&str]) -> Invocation {
        parse_args(&args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).expect("parse args")
    }

    fn run_capture(args: &[&str], env: &dyn Environment) -> Result<(Outcome, String), AppError> {
        let mut out: Vec<u8> = Vec::new();
        let outcome = run(&inv(args), env, &mut out)?;
        Ok((outcome, String::from_utf8_lossy(&out).into_owned()))
    }

    /// A mock world: one identity, a `.sops.yaml` naming it, and a plaintext file.
    ///
    /// The identity is held on the struct rather than regenerated per call. The
    /// first version of this helper was a bare `fn world()` that generated a fresh
    /// key each time, so any test needing a *second* env — feed the ciphertext back
    /// in and read it out, which is most of them — silently got a stranger's key and
    /// failed with `NoUsableIdentity`. Nine tests at once, all from the helper.
    struct World {
        identity: age::x25519::Identity,
        recipient: String,
    }

    impl World {
        fn new() -> Self {
            let identity = age::x25519::Identity::generate();
            let recipient = identity.to_public().to_string();
            Self {
                identity,
                recipient,
            }
        }

        /// An env that can unwrap this world's files, seeded with `files`.
        fn env(&self, files: &[(&str, &str)]) -> MockEnvironment {
            use age::secrecy::ExposeSecret as _;
            let mut env = MockEnvironment::new()
                .with_var("SOPS_AGE_KEY", self.identity.to_string().expose_secret())
                .with_file(
                    "/repo/.sops.yaml",
                    &format!("creation_rules:\n  - age: {}\n", self.recipient),
                );
            for (path, contents) in files {
                env = env.with_file(path, contents);
            }
            env
        }

        /// The default plaintext plus a config, which is where most tests start.
        fn seeded(&self) -> MockEnvironment {
            self.env(&[("/repo/plain.yaml", PLAIN)])
        }
    }

    const PLAIN: &str = "alpha: one\ncount: 3\nenabled: true\n";

    #[test]
    fn encrypt_then_decrypt_through_the_cli_surface() {
        let w = World::new();
        let (outcome, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        assert_eq!(outcome.code, exit::OK);
        assert!(encrypted.contains("ENC[AES256_GCM,"));
        assert!(
            encrypted.contains("unencrypted_suffix: _unencrypted"),
            "sops writes this explicitly"
        );

        // Feed the ciphertext back in and read it out — same identity.
        let env2 = w.env(&[("/repo/enc.yaml", &encrypted)]);
        let (_, plain) = run_capture(&["-d", "/repo/enc.yaml"], &env2).expect("decrypt");
        assert_eq!(plain, PLAIN);
    }

    #[test]
    fn recipients_come_from_the_config_when_not_given() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        assert!(
            encrypted.contains(&w.recipient),
            "the config's recipient was used"
        );
    }

    #[test]
    fn encrypting_with_no_recipients_anywhere_is_refused() {
        use age::secrecy::ExposeSecret as _;
        let id = age::x25519::Identity::generate();
        let env = MockEnvironment::new()
            .with_var("SOPS_AGE_KEY", id.to_string().expose_secret())
            .with_file("/repo/plain.yaml", "k: v\n");
        let err = run_capture(&["-e", "/repo/plain.yaml"], &env).expect_err("must refuse");
        // No config found at all, which is a distinct message from "no rule matched".
        assert!(
            matches!(err, AppError::Config(ConfigError::NoConfig { .. })),
            "got {err}"
        );
    }

    #[test]
    fn in_place_encrypt_writes_the_file_with_a_private_mode() {
        let w = World::new();
        let env = w.seeded();
        let (outcome, _) = run_capture(&["-e", "-i", "/repo/plain.yaml"], &env).expect("encrypt");
        assert_eq!(outcome.code, exit::OK);
        let written = env.file("/repo/plain.yaml").expect("written");
        assert!(written.contains("ENC[AES256_GCM,"));
        assert_eq!(env.mode("/repo/plain.yaml"), Some(0o600));
    }

    #[test]
    fn extract_reads_one_value_as_bare_text() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        let env2 = w.env(&[("/repo/enc.yaml", &encrypted)]);
        let (_, v) = run_capture(&["-d", "--extract", "[\"alpha\"]", "/repo/enc.yaml"], &env2)
            .expect("extract");
        // No trailing newline. Measured against sops v3.12.1, which emits exactly
        // the value's bytes; `$(…)` strips a trailing newline either way, so the
        // "a shell substitution wants one" reasoning that produced the first
        // version of this was true and irrelevant — while `> file` and any byte
        // comparison do care.
        assert_eq!(v, "one");
    }

    #[test]
    fn extract_on_a_missing_key_is_named_not_empty() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        let env2 = w.env(&[("/repo/enc.yaml", &encrypted)]);
        let err = run_capture(&["-d", "--extract", "[\"nope\"]", "/repo/enc.yaml"], &env2)
            .expect_err("must fail");
        assert!(matches!(err, AppError::ExtractNotFound { .. }), "got {err}");
    }

    #[test]
    fn extract_paths_parse_the_way_sops_writes_them() {
        assert_eq!(
            parse_extract_path("[\"db\"][\"password\"]"),
            Some(vec![
                ExtractStep::Key("db".into()),
                ExtractStep::Key("password".into())
            ])
        );
        assert_eq!(
            parse_extract_path("[\"list\"][2]"),
            Some(vec![ExtractStep::Key("list".into()), ExtractStep::Index(2)])
        );
        assert_eq!(
            parse_extract_path("['single']"),
            Some(vec![ExtractStep::Key("single".into())])
        );
        // Malformed is None, never a best-effort guess.
        assert_eq!(parse_extract_path("db.password"), None);
        assert_eq!(parse_extract_path("[\"unclosed"), None);
        assert_eq!(parse_extract_path(""), None);
    }

    /// An unchanged edit must be exit 200, because cofre's SOPS backend branches on
    /// that exact value.
    #[test]
    fn an_unchanged_edit_is_exit_two_hundred() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        // No editor configured, so the mock leaves the scratch file alone.
        let env2 = w.env(&[("/repo/enc.yaml", &encrypted)]);
        let (outcome, _) = run_capture(&["/repo/enc.yaml"], &env2).expect("edit");
        assert_eq!(outcome.code, exit::FILE_HAS_NOT_CHANGED);
    }

    #[test]
    fn an_edit_that_changes_a_value_rewrites_the_file() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        let env2 = w
            .env(&[("/repo/enc.yaml", &encrypted)])
            .with_editor_writing("alpha: CHANGED\ncount: 3\nenabled: true\n", true);
        let (outcome, _) = run_capture(&["/repo/enc.yaml"], &env2).expect("edit");
        assert_eq!(outcome.code, exit::OK);

        let after = env2.file("/repo/enc.yaml").expect("rewritten");
        assert_ne!(after, encrypted);
        // and it still decrypts, to the edited value
        let env3 = w.env(&[("/repo/after.yaml", &after)]);
        let (_, plain) = run_capture(&["-d", "/repo/after.yaml"], &env3).expect("decrypt");
        assert_eq!(plain, "alpha: CHANGED\ncount: 3\nenabled: true\n");
    }

    /// The scratch directory `edit` decrypts into must be gone afterwards — on
    /// **every** exit path, not just the successful one.
    ///
    /// This is the test that was missing. Without it the code said "removed
    /// afterwards" in a comment and removed nothing, and the evidence was 92
    /// leftover directories on the operator's machine with three fully decrypted
    /// copies of a real fleet secret among them.
    #[test]
    fn the_edit_scratch_is_shredded_on_every_exit_path() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");

        // 1. The unchanged path — an early `return Ok(unchanged())`.
        let quiet = w.env(&[("/repo/enc.yaml", &encrypted)]);
        let (o, _) = run_capture(&["/repo/enc.yaml"], &quiet).expect("edit");
        assert_eq!(o.code, exit::FILE_HAS_NOT_CHANGED);
        assert!(
            quiet.was_shredded("/mock-tmp"),
            "unchanged path left the scratch behind"
        );
        assert!(
            quiet.file("/mock-tmp/enc.yaml").is_none(),
            "the plaintext scratch file survived the unchanged path"
        );

        // 2. The changed path — falls off the end.
        let edited = w
            .env(&[("/repo/enc.yaml", &encrypted)])
            .with_editor_writing("alpha: CHANGED\ncount: 3\nenabled: true\n", true);
        let (o, _) = run_capture(&["/repo/enc.yaml"], &edited).expect("edit");
        assert_eq!(o.code, exit::OK);
        assert!(
            edited.was_shredded("/mock-tmp"),
            "changed path left the scratch behind"
        );
        assert!(
            edited.file("/mock-tmp/enc.yaml").is_none(),
            "the plaintext scratch file survived the changed path"
        );

        // 3. The error path — the editor hands back something that will not parse,
        //    so `load_plain` fails with `?` and the function never reaches its end.
        //    This is the exit a trailing cleanup statement misses.
        let broken = w
            .env(&[("/repo/enc.yaml", &encrypted)])
            .with_editor_writing("a: [unclosed\n", true);
        assert!(
            run_capture(&["/repo/enc.yaml"], &broken).is_err(),
            "the fixture must actually fail to parse, or this asserts nothing"
        );
        assert!(
            broken.was_shredded("/mock-tmp"),
            "the ERROR path left the scratch behind"
        );
        assert!(
            broken.file("/mock-tmp/enc.yaml").is_none(),
            "the plaintext scratch file survived the error path"
        );
    }

    #[test]
    fn rotate_changes_every_ciphertext_and_still_decrypts() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        let env2 = w.env(&[("/repo/enc.yaml", &encrypted)]);
        let (_, rotated) = run_capture(&["rotate", "/repo/enc.yaml"], &env2).expect("rotate");

        // Every data line must differ: a new data key means new ciphertext.
        let before_values: Vec<&str> = encrypted.lines().filter(|l| l.contains("ENC[")).collect();
        let after_values: Vec<&str> = rotated.lines().filter(|l| l.contains("ENC[")).collect();
        assert_eq!(before_values.len(), after_values.len());
        for (b, a) in before_values.iter().zip(after_values.iter()) {
            assert_ne!(b, a, "a rotation must re-encrypt every value");
        }

        let env3 = w.env(&[("/repo/rot.yaml", &rotated)]);
        let (_, plain) = run_capture(&["-d", "/repo/rot.yaml"], &env3).expect("decrypt");
        assert_eq!(plain, PLAIN);
    }

    /// `updatekeys` re-wraps the data key and touches nothing else, which is what
    /// makes its diff readable.
    #[test]
    fn updatekeys_changes_only_the_wrapped_keys() {
        use age::secrecy::ExposeSecret as _;
        let w = World::new();
        // Encrypted for `w` alone.
        let (_, reenc) = run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");

        // Now a config naming a second recipient. `w` is still first, so it can
        // still unwrap — which is the only way `updatekeys` can re-wrap at all.
        let extra = age::x25519::Identity::generate().to_public().to_string();
        let env2 = MockEnvironment::new()
            .with_var("SOPS_AGE_KEY", w.identity.to_string().expose_secret())
            .with_file("/repo/enc.yaml", &reenc)
            .with_file(
                "/repo/.sops.yaml",
                &format!("creation_rules:\n  - age: {},{extra}\n", w.recipient),
            );

        let (outcome, _) =
            run_capture(&["updatekeys", "/repo/enc.yaml"], &env2).expect("updatekeys");
        assert_eq!(outcome.code, exit::OK);
        let after = env2.file("/repo/enc.yaml").expect("rewritten");

        // Every data line is untouched.
        for line in reenc
            .lines()
            .filter(|l| l.contains("ENC[") && !l.contains("mac:"))
        {
            assert!(after.contains(line), "updatekeys moved a data line: {line}");
        }
        // The MAC and lastmodified are untouched too.
        let mac_before = reenc
            .lines()
            .find(|l| l.trim_start().starts_with("mac:"))
            .expect("mac");
        assert!(after.contains(mac_before), "updatekeys must not re-MAC");
        // And there are now two recipients.
        assert_eq!(after.matches("- recipient: ").count(), 2);
    }

    #[test]
    fn updatekeys_with_the_same_recipients_is_exit_two_hundred() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        let env2 = w.env(&[("/repo/plain.yaml", &encrypted)]);
        let (outcome, _) =
            run_capture(&["updatekeys", "/repo/plain.yaml"], &env2).expect("updatekeys");
        assert_eq!(outcome.code, exit::FILE_HAS_NOT_CHANGED);
    }

    #[test]
    fn filestatus_distinguishes_encrypted_from_not() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        let env2 = w.env(&[("/repo/plain.yaml", PLAIN), ("/repo/enc.yaml", &encrypted)]);

        let (_, plain_status) =
            run_capture(&["filestatus", "/repo/plain.yaml"], &env2).expect("status");
        assert!(plain_status.contains("not encrypted"), "{plain_status}");

        let (_, enc_status) =
            run_capture(&["filestatus", "/repo/enc.yaml"], &env2).expect("status");
        assert!(enc_status.contains("encrypted"), "{enc_status}");
        assert!(
            enc_status.contains("1 recipient(s) via age"),
            "{enc_status}"
        );
    }

    /// The safety property the alias rests on. Refused *before* the file is read,
    /// so a half-honoured flag cannot have written anything.
    #[test]
    fn an_unsupported_flag_refuses_before_touching_the_file() {
        let w = World::new();
        let env = w.seeded();
        let err = run_capture(&["-e", "-i", "--pgp", "DEADBEEF", "/repo/plain.yaml"], &env)
            .expect_err("must refuse");
        assert!(
            matches!(err, AppError::UnsupportedFlags { .. }),
            "got {err}"
        );
        // The file is still plaintext.
        assert_eq!(env.file("/repo/plain.yaml").as_deref(), Some(PLAIN));
    }

    #[test]
    fn an_unimplemented_verb_is_refused_by_name() {
        let env = World::new().seeded();
        let err = run_capture(&["exec-env", "/repo/plain.yaml"], &env).expect_err("must refuse");
        assert!(
            matches!(err, AppError::UnimplementedVerb { .. }),
            "got {err}"
        );
        assert!(err.to_string().contains("exec-env"), "{err}");
    }

    #[test]
    fn a_missing_identity_names_the_source_it_expected() {
        let env = MockEnvironment::new()
            .with_var("HOME", "/home/op")
            .with_file(
                "/repo/enc.yaml",
                "k: v\nsops:\n    lastmodified: \"x\"\n    mac: m\n    version: 3.12.1\n",
            );
        let err = run_capture(&["-d", "/repo/enc.yaml"], &env).expect_err("must fail");
        assert!(matches!(err, AppError::NoIdentity { .. }), "got {err}");
        assert!(
            err.to_string()
                .contains("/home/op/.config/sops/age/keys.txt"),
            "{err}"
        );
    }

    /// A configured-but-unread identity source must not read as "no key".
    #[test]
    fn an_unread_identity_source_says_so_rather_than_claiming_no_key() {
        let env = MockEnvironment::new()
            .with_var("HOME", "/home/op")
            .with_var("SOPS_AGE_KEY_CMD", "pass show age")
            .with_file(
                "/repo/enc.yaml",
                "k: v\nsops:\n    lastmodified: \"x\"\n    mac: m\n    version: 3.12.1\n",
            );
        let err = run_capture(&["-d", "/repo/enc.yaml"], &env).expect_err("must fail");
        assert!(err.to_string().contains("SOPS_AGE_KEY_CMD"), "{err}");
        assert!(err.to_string().contains("does not read it"), "{err}");
    }

    #[test]
    fn help_and_version_need_no_file_and_no_key() {
        let env = MockEnvironment::new();
        let (o, h) = run_capture(&["--help"], &env).expect("help");
        assert_eq!(o.code, exit::OK);
        assert!(h.contains("suminuri"));
        let (o, v) = run_capture(&["--version"], &env).expect("version");
        assert_eq!(o.code, exit::OK);
        assert!(v.contains("墨塗り"));
    }

    #[test]
    fn ignore_mac_lets_a_broken_file_through_and_nothing_else_does() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        // Break the MAC by changing lastmodified, which is its AAD.
        let broken = encrypted.replace(
            "lastmodified: \"2026-08-18T00:00:00Z\"",
            "lastmodified: \"2026-08-18T00:00:01Z\"",
        );
        assert_ne!(
            broken, encrypted,
            "the fixture must actually have been broken"
        );
        let env2 = w.env(&[("/repo/broken.yaml", &broken)]);

        assert!(
            run_capture(&["-d", "/repo/broken.yaml"], &env2).is_err(),
            "must refuse by default"
        );
        let (o, plain) =
            run_capture(&["-d", "--ignore-mac", "/repo/broken.yaml"], &env2).expect("ignore-mac");
        assert_eq!(o.code, exit::OK);
        assert_eq!(plain, PLAIN);
    }
}
