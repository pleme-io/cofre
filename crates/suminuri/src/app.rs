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
    #[error("`{verb}` needs a path argument, e.g. suminuri {verb} f.yaml '[\"db\"][\"password\"]'")]
    MissingPath { verb: String },
    #[error("`set` needs a value argument; sops takes JSON, e.g. '\"text\"' or '42'")]
    MissingValue,
    #[error(
        "`set` value `{value}` is a JSON {kind}, and this build writes scalars only. Use `suminuri edit` for a composite, or upstream `sops set`."
    )]
    NonScalarValue { value: String, kind: String },
    #[error("`{value}` is not valid JSON for a value; a string needs its quotes, e.g. '\"text\"'")]
    BadValue { value: String },
    #[error(
        "cannot descend through `{at}` in `{path}`: that step names a {found}, not a mapping or sequence"
    )]
    PathNotTraversable {
        path: String,
        at: String,
        found: String,
    },
    #[error("`unset` found nothing at `{path}`; refusing to report success for a no-op")]
    UnsetNotFound { path: String },
    #[error(
        "`set` cannot create index {index} in `{path}`: a sequence grows by append only, and index {index} would leave a hole"
    )]
    SparseIndex { path: String, index: usize },
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
        Verb::Set => set_or_unset(inv, env, false),
        Verb::Unset => set_or_unset(inv, env, true),
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

/// Load, unwrap, decrypt and verify EVERY document in the stream.
///
/// The read-path sibling of `open`. A multi-document sops file is N independent
/// encrypted files sharing a byte stream — each with its own wrapped data key and
/// its own MAC — so each is opened on its own terms and a MAC failure anywhere
/// fails the whole read. See `SopsFile::load_encrypted_stream` for why only the
/// read path is multi-document.
fn open_stream(inv: &Invocation, env: &dyn Environment) -> Result<Vec<SopsFile>, AppError> {
    let path = file_of(inv)?;
    let src = read(env, path)?;
    let mut docs = SopsFile::load_encrypted_stream(&src)?;
    let ids = identities(env)?;
    if let Some(indent) = inv.indent {
        for f in &mut docs {
            f.indent = indent;
        }
    }

    // ONE data key and ONE MAC for the whole stream — see
    // `SopsFile::decrypt_stream` for the measurement behind that. The key comes
    // from the first document's metadata because every document carries a copy of
    // the same metadata; a per-document key would be a different file format.
    let key = docs
        .first()
        .ok_or(AppError::File(FileError::NotEncrypted))?
        .data_key(&ids)?;
    let mut stash = IvStash::new();
    let unverified = SopsFile::decrypt_stream(&mut docs, &key, &mut stash)?;
    {
        if inv.ignore_mac {
            let _ = unverified.into_inner_ignoring_mac();
        } else if unverified.leaves_fed() == 0 {
            // ★ AN EMPTY DOCUMENT IN A STREAM IS LEGITIMATE, AND THE STRICT PATH
            // REPORTED IT AS A MAC MISMATCH.
            //
            // Measured on the fleet's own
            // `clusters/plo/.../postgres-superset.yaml`: document 1 of 5 is two
            // comments and an empty mapping, which upstream renders as `{}`. It has
            // no MAC-eligible leaf, so the walk feeds nothing, and
            // `verify_recording`'s anti-vacuity refusal fired — surfacing as
            // "MAC mismatch", which sent me looking for corruption in a file that
            // was fine.
            //
            // Allowing it is NOT dropping the check. `verify_allowing_empty` still
            // runs `verify_mac_field_recording`, which decrypts the `mac:` field
            // with `lastmodified` as its AAD and compares it to what the walk
            // computed. So the guard being skipped here has real teeth behind it: a
            // walk that fed nothing because discovery BROKE would compute MAC(empty)
            // against a file whose sealed MAC covers actual leaves, and that
            // comparison fails. The only input that passes this path is a document
            // whose sealed MAC genuinely is the MAC of nothing.
            //
            // `open` (every write path) keeps the strict refusal: a single-document
            // file that decrypts to nothing is far more likely a bug than an intent.
            unverified
                .verify_allowing_empty(&key)
                .map_err(FileError::from)?;
        } else {
            unverified
                .verify_recording(&key, Some(&mut stash))
                .map_err(FileError::from)?;
        }
    }
    Ok(docs)
}

fn decrypt(
    inv: &Invocation,
    env: &dyn Environment,
    out: &mut dyn std::io::Write,
) -> Result<Outcome, AppError> {
    let docs = open_stream(inv, env)?;
    let body = match &inv.extract {
        Some(path) => {
            // A bracket path names a location inside ONE document, and a stream has
            // no rule for which. Refusing beats extracting from the first and
            // silently returning the wrong secret when a caller meant another.
            if docs.len() != 1 {
                return Err(AppError::File(FileError::MultiDocument {
                    docs: docs.len(),
                }));
            }
            extract(&docs[0].tree, path)?
        }
        None => {
            // `---` BETWEEN documents, never before the first. Measured against
            // upstream sops 3.12.1 on a real 5-document file: 4 separators, 155
            // lines, and the leading comment still first.
            let mut parts = Vec::with_capacity(docs.len());
            for f in &docs {
                parts.push(f.render_plain()?);
            }
            parts.join("---\n")
        }
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
    let steps = parse_sops_path(path_expr).ok_or_else(|| AppError::BadExtractPath {
        path: path_expr.to_string(),
    })?;
    let mut current = tree;
    for step in &steps {
        current = match step {
            PathStep::Key(k) => current.get(k).ok_or_else(|| AppError::ExtractNotFound {
                path: path_expr.to_string(),
            })?,
            PathStep::Index(i) => match current {
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
enum PathStep {
    Key(String),
    Index(usize),
}

/// Parse `["a"]["b"][0]` into steps.
///
/// Strict: a malformed expression is `None` rather than a best-effort read. An
/// `--extract` that silently matched the wrong key would print the wrong secret —
/// and now that `set` shares this parser, a best-effort read would *write* to the
/// wrong key, which is worse and unrecoverable.
fn parse_sops_path(expr: &str) -> Option<Vec<PathStep>> {
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
            steps.push(PathStep::Key(quoted.to_string()));
        } else if let Some(quoted) = inner.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            steps.push(PathStep::Key(quoted.to_string()));
        } else {
            steps.push(PathStep::Index(inner.parse::<usize>().ok()?));
        }
        rest = tail;
    }
    Some(steps)
}

/// `set <file> <path> <value>` and `unset <file> <path>`.
///
/// ★ WHY THESE SHARE ONE FUNCTION WITH `edit`'S SHAPE AND NOT ITS CODE
///
/// Both are `edit` with the editor replaced by a programmatic mutation, so they reuse
/// `open` (which yields the file, the data key **and the IV stash**) and `f.encrypt`.
/// The stash is the load-bearing part: it re-uses each untouched leaf's original
/// nonce, so writing one key leaves every other line byte-identical. Without it a
/// one-key `set` would rewrite every ciphertext in the file and a reviewer could not
/// see what changed — the same reason `rotate` deliberately does NOT reuse it.
///
/// ★ AND WHY THERE IS NO SCRATCH FILE HERE
///
/// `edit` must put plaintext on a disk for an editor to open. These verbs never do —
/// the mutation happens in the decrypted tree in memory. That removes the exposure
/// `edit` can only mitigate, so this path is strictly safer than the one it replaces
/// for the fleet's actual use (`tools/init-akeyless-dev.tlisp` shelling out to
/// `sops set`).
fn set_or_unset(
    inv: &Invocation,
    env: &dyn Environment,
    remove: bool,
) -> Result<Outcome, AppError> {
    let verb = if remove { "unset" } else { "set" };
    let path = file_of(inv)?;
    let path_expr = inv
        .path_expr
        .as_deref()
        .ok_or_else(|| AppError::MissingPath {
            verb: verb.to_string(),
        })?;
    let steps = parse_sops_path(path_expr).ok_or_else(|| AppError::BadExtractPath {
        path: path_expr.to_string(),
    })?;

    // Parse the value BEFORE decrypting anything. A malformed value should cost the
    // caller an error message, not a decrypt-then-fail that leaves the data key
    // material in this process for no reason.
    let new_value = if remove {
        None
    } else {
        let raw = inv.value_expr.as_deref().ok_or(AppError::MissingValue)?;
        Some(parse_json_scalar(raw)?)
    };

    let (mut f, key, mut stash) = open(inv, env)?;
    let before = f.render_plain()?;

    apply_mutation(&mut f.tree, &steps, path_expr, new_value)?;

    let after = f.render_plain()?;
    if after == before {
        // sops's documented exit 200, same contract `edit` honours: cofre's SOPS
        // backend branches on this exact value. Setting a key to what it already
        // holds is a no-op, and reporting it as a write would make every caller's
        // "did anything change" check lie.
        return Ok(Outcome::unchanged());
    }

    let stats = f.encrypt(&key, &mut stash, &env.now_rfc3339())?;
    let body = f.render()?;
    env.write_file_atomic(path, &body, SECRET_MODE)
        .map_err(|e| AppError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
    // ★ SAY WHAT CHANGED, NOT HOW MANY LEAVES THE ENCRYPTER VISITED.
    //
    // `stats.encrypted` is every leaf, because `f.encrypt` walks the whole tree —
    // and on a real fleet file that is 273. Reporting "re-encrypted 273 leaf/leaves"
    // after writing ONE key reads as mass churn and invites the operator to go
    // looking for a problem that is not there: the IV stash means the other 272 come
    // out byte-identical, which is the property `set` is built on. Verified on
    // nix/secrets.yaml (1381 lines): after a one-key `set`, the decrypted remainder
    // hashes identically to the original.
    // The arithmetic differs by verb and the off-by-one is easy to get wrong: after a
    // `set` the written leaf is still IN the tree, so `encrypted` counts it and the
    // others are `encrypted - 1`. After an `unset` the removed leaf is already gone,
    // so every leaf `encrypted` counted is an untouched one.
    let (touched, others) = if remove {
        ("removed", stats.encrypted)
    } else {
        ("wrote", stats.encrypted.saturating_sub(1))
    };
    Ok(Outcome::ok_with(format!(
        "{touched} {path_expr}; {others} other leaf/leaves unchanged"
    )))
}

/// Walk to the parent of the final step, then insert or remove.
///
/// Missing intermediate MAPPING keys are created, matching upstream `sops set`.
/// Missing sequence indices are refused — see `AppError::SparseIndex`.
fn apply_mutation(
    tree: &mut Value,
    steps: &[PathStep],
    path_expr: &str,
    new_value: Option<suminuri_yaml::Scalar>,
) -> Result<(), AppError> {
    let Some((last, parents)) = steps.split_last() else {
        return Err(AppError::BadExtractPath {
            path: path_expr.to_string(),
        });
    };

    let mut current = tree;
    for step in parents {
        current = descend(current, step, path_expr, new_value.is_some())?;
    }

    match (last, new_value) {
        (PathStep::Key(k), Some(scalar)) => {
            let items = as_mapping(current, path_expr, last)?;
            if let Some(slot) = items.iter_mut().find_map(|i| match i {
                suminuri_yaml::Item::Pair { key, value } if key == k => Some(value),
                _ => None,
            }) {
                *slot = Value::Scalar(scalar);
            } else {
                items.push(suminuri_yaml::Item::Pair {
                    key: k.clone(),
                    value: Value::Scalar(scalar),
                });
            }
            Ok(())
        }
        (PathStep::Key(k), None) => {
            let items = as_mapping(current, path_expr, last)?;
            let before = items.len();
            items.retain(|i| !matches!(i, suminuri_yaml::Item::Pair { key, .. } if key == k));
            if items.len() == before {
                Err(AppError::UnsetNotFound {
                    path: path_expr.to_string(),
                })
            } else {
                Ok(())
            }
        }
        (PathStep::Index(idx), Some(scalar)) => {
            let entries = as_sequence(current, path_expr, last)?;
            // Counted BEFORE the match: `value_slot` takes a mutable borrow that is
            // still live in the arms, so reading the length inside a guard is an
            // E0502. The append case needs the count, so it is taken up front.
            let n = value_count(entries);
            match value_slot(entries, *idx) {
                Some(slot) => {
                    *slot = Value::Scalar(scalar);
                    Ok(())
                }
                None if *idx == n => {
                    entries.push(suminuri_yaml::Entry::Value(Value::Scalar(scalar)));
                    Ok(())
                }
                None => Err(AppError::SparseIndex {
                    path: path_expr.to_string(),
                    index: *idx,
                }),
            }
        }
        (PathStep::Index(idx), None) => {
            let entries = as_sequence(current, path_expr, last)?;
            let mut seen = 0usize;
            let mut victim = None;
            for (pos, e) in entries.iter().enumerate() {
                if matches!(e, suminuri_yaml::Entry::Value(_)) {
                    if seen == *idx {
                        victim = Some(pos);
                        break;
                    }
                    seen += 1;
                }
            }
            match victim {
                Some(pos) => {
                    entries.remove(pos);
                    Ok(())
                }
                None => Err(AppError::UnsetNotFound {
                    path: path_expr.to_string(),
                }),
            }
        }
    }
}

/// One step down, creating a missing mapping key when we are writing.
fn descend<'t>(
    current: &'t mut Value,
    step: &PathStep,
    path_expr: &str,
    creating: bool,
) -> Result<&'t mut Value, AppError> {
    match step {
        PathStep::Key(k) => {
            let items = as_mapping(current, path_expr, step)?;
            let existing = items
                .iter()
                .any(|i| matches!(i, suminuri_yaml::Item::Pair { key, .. } if key == k));
            if !existing {
                if !creating {
                    return Err(AppError::UnsetNotFound {
                        path: path_expr.to_string(),
                    });
                }
                items.push(suminuri_yaml::Item::Pair {
                    key: k.clone(),
                    value: Value::Mapping(Vec::new()),
                });
            }
            items
                .iter_mut()
                .find_map(|i| match i {
                    suminuri_yaml::Item::Pair { key, value } if key == k => Some(value),
                    _ => None,
                })
                .ok_or_else(|| AppError::UnsetNotFound {
                    path: path_expr.to_string(),
                })
        }
        PathStep::Index(idx) => {
            let entries = as_sequence(current, path_expr, step)?;
            let n = value_count(entries);
            value_slot(entries, *idx).ok_or_else(|| {
                if creating && *idx >= n {
                    AppError::SparseIndex {
                        path: path_expr.to_string(),
                        index: *idx,
                    }
                } else {
                    AppError::UnsetNotFound {
                        path: path_expr.to_string(),
                    }
                }
            })
        }
    }
}

fn as_mapping<'t>(
    v: &'t mut Value,
    path_expr: &str,
    step: &PathStep,
) -> Result<&'t mut Vec<suminuri_yaml::Item>, AppError> {
    let found = describe(v);
    match v {
        Value::Mapping(items) => Ok(items),
        _ => Err(AppError::PathNotTraversable {
            path: path_expr.to_string(),
            at: step_label(step),
            found: found.to_string(),
        }),
    }
}

fn as_sequence<'t>(
    v: &'t mut Value,
    path_expr: &str,
    step: &PathStep,
) -> Result<&'t mut Vec<suminuri_yaml::Entry>, AppError> {
    let found = describe(v);
    match v {
        Value::Sequence(entries) => Ok(entries),
        _ => Err(AppError::PathNotTraversable {
            path: path_expr.to_string(),
            at: step_label(step),
            found: found.to_string(),
        }),
    }
}

fn describe(v: &Value) -> &'static str {
    match v {
        Value::Scalar(_) => "scalar",
        Value::Mapping(_) => "mapping",
        Value::Sequence(_) => "sequence",
    }
}

fn step_label(step: &PathStep) -> String {
    match step {
        PathStep::Key(k) => format!("[\"{k}\"]"),
        PathStep::Index(i) => format!("[{i}]"),
    }
}

/// Comments occupy positions in a sequence but are not values, so an index has to
/// count values only — otherwise `["list"][0]` means different things before and
/// after somebody adds a comment above the first entry.
fn value_count(entries: &[suminuri_yaml::Entry]) -> usize {
    entries
        .iter()
        .filter(|e| matches!(e, suminuri_yaml::Entry::Value(_)))
        .count()
}

fn value_slot(entries: &mut [suminuri_yaml::Entry], idx: usize) -> Option<&mut Value> {
    entries
        .iter_mut()
        .filter_map(|e| match e {
            suminuri_yaml::Entry::Value(v) => Some(v),
            suminuri_yaml::Entry::Comment(_) => None,
        })
        .nth(idx)
}

/// sops takes `set`'s value as JSON. This build accepts the SCALAR subset and
/// refuses composites by name.
///
/// ★ THE SCOPE IS MEASURED, NOT ARBITRARY. Every use of `sops set` found in the
/// fleet writes a scalar string: an auth key, an API key, a wireguard private key.
/// Supporting `{...}` and `[...]` would mean either a JSON parser (a net-new
/// dependency for a case nothing exercises) or routing the text through the YAML
/// parser, which has **no flow-style support** — it would parse `{"a":"b"}` as a
/// plain scalar containing braces and write that literal string into the file. A
/// wrong-but-successful write of a secret is the worst outcome available here, so
/// the composite case is refused rather than approximated.
fn parse_json_scalar(raw: &str) -> Result<suminuri_yaml::Scalar, AppError> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(AppError::BadValue {
            value: raw.to_string(),
        });
    }
    let kind = match t.as_bytes()[0] {
        b'{' => Some("object"),
        b'[' => Some("array"),
        _ => None,
    };
    if let Some(kind) = kind {
        return Err(AppError::NonScalarValue {
            value: raw.to_string(),
            kind: kind.to_string(),
        });
    }

    // A JSON string: strip the quotes and honour the escapes JSON defines. Anything
    // else is refused rather than passed through, because an unrecognised escape
    // silently written into a secret is undetectable downstream.
    //
    // ★ RED-RUN 2026-08-19: returning `t` unstripped here (the plausible off-by-one)
    // turns `both_binaries_set_a_key_to_the_same_result` red with
    // `want: alpha: '"differential"'` / `got: alpha: differential` — the oracle
    // reading OUR file sees the quotes we failed to strip. `unset` stays green,
    // correctly, since it parses no value.
    if let Some(body) = t.strip_prefix('"') {
        let body = body.strip_suffix('"').ok_or_else(|| AppError::BadValue {
            value: raw.to_string(),
        })?;
        let mut s = String::with_capacity(body.len());
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                s.push(c);
                continue;
            }
            match chars.next() {
                Some('"') => s.push('"'),
                Some('\\') => s.push('\\'),
                Some('/') => s.push('/'),
                Some('n') => s.push('\n'),
                Some('t') => s.push('\t'),
                Some('r') => s.push('\r'),
                Some('b') => s.push('\u{8}'),
                Some('f') => s.push('\u{c}'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    let cp = u32::from_str_radix(&hex, 16).map_err(|_| AppError::BadValue {
                        value: raw.to_string(),
                    })?;
                    s.push(char::from_u32(cp).ok_or_else(|| AppError::BadValue {
                        value: raw.to_string(),
                    })?);
                }
                _ => {
                    return Err(AppError::BadValue {
                        value: raw.to_string(),
                    });
                }
            }
        }
        return Ok(suminuri_yaml::Scalar::new(s));
    }

    // A bare token: a number, a boolean, or null. `Scalar::new` picks the style that
    // round-trips, so a numeric-looking string is not silently retyped.
    if t == "true" || t == "false" || t == "null" || t.parse::<f64>().is_ok() {
        return Ok(suminuri_yaml::Scalar::new(t));
    }

    // An unquoted word. sops would reject it as invalid JSON and so do we: accepting
    // it would make `sops set f '["k"]' hunter2` write `hunter2` while
    // `sops set f '["k"]' '"hunter2"'` writes the same thing, and then a caller who
    // forgot the quotes on `123` would get a number where they meant a string.
    Err(AppError::BadValue {
        value: raw.to_string(),
    })
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

    /// Encrypt PLAIN, then run `args` against the result, returning the file the
    /// run left behind. Every `set`/`unset` test needs this exact three-step dance.
    fn after_write(w: &World, args: &[&str]) -> Result<(Outcome, String), AppError> {
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        let env = w.env(&[("/repo/enc.yaml", &encrypted)]);
        let outcome = run_capture(args, &env).map(|(o, _)| o)?;
        let body = env
            .read_to_string(std::path::Path::new("/repo/enc.yaml"))
            .expect("file back");
        Ok((outcome, body))
    }

    fn decrypted(w: &World, body: &str) -> String {
        let env = w.env(&[("/repo/round.yaml", body)]);
        run_capture(&["-d", "/repo/round.yaml"], &env)
            .expect("decrypt")
            .1
    }

    #[test]
    fn set_writes_one_leaf_and_it_round_trips() {
        let w = World::new();
        let (outcome, body) =
            after_write(&w, &["set", "/repo/enc.yaml", "[\"alpha\"]", "\"two\""]).expect("set");
        assert_eq!(outcome.code, exit::OK);
        assert!(body.contains("ENC[AES256_GCM,"), "still encrypted");
        assert!(
            !body.contains("two"),
            "the new value must not appear in plaintext"
        );
        assert_eq!(
            decrypted(&w, &body),
            "alpha: two\ncount: 3\nenabled: true\n"
        );
    }

    #[test]
    fn set_creates_a_missing_nested_key() {
        let w = World::new();
        let (_, body) = after_write(
            &w,
            &[
                "set",
                "/repo/enc.yaml",
                "[\"db\"][\"handle\"]",
                "\"marker\"",
            ],
        )
        .expect("set");
        let plain = decrypted(&w, &body);
        assert!(plain.contains("db:"), "parent created: {plain}");
        // Deliberately NOT a credential-shaped fixture. `password: <literal>` is
        // exactly what the block-secrets pre-commit hook refuses, and it refused
        // this file when the fixture used one — correctly, since the hook cannot
        // tell a test's fake from a real leak. The key names are incidental to what
        // this test proves, so they moved rather than the hook being bypassed.
        assert!(plain.contains("handle:"));
        assert!(plain.contains("handle: marker"));
    }

    /// ★ THE PROPERTY THAT MAKES A ONE-KEY WRITE REVIEWABLE.
    ///
    /// Writing one leaf must leave every OTHER ciphertext byte-identical — that is
    /// what the IV stash buys. Without it a `set` rewrites every value in the file
    /// and no reviewer can see which one actually changed.
    #[test]
    fn set_leaves_untouched_leaves_byte_identical() {
        let w = World::new();
        let (_, encrypted) =
            run_capture(&["-e", "/repo/plain.yaml"], &w.seeded()).expect("encrypt");
        let env = w.env(&[("/repo/enc.yaml", &encrypted)]);
        run_capture(&["set", "/repo/enc.yaml", "[\"alpha\"]", "\"two\""], &env).expect("set");
        let after = env
            .read_to_string(std::path::Path::new("/repo/enc.yaml"))
            .expect("file back");

        let line = |s: &str, k: &str| -> String {
            s.lines()
                .find(|l| l.starts_with(k))
                .unwrap_or_default()
                .to_string()
        };
        assert_ne!(
            line(&encrypted, "alpha:"),
            line(&after, "alpha:"),
            "the written leaf must change"
        );
        assert_eq!(
            line(&encrypted, "count:"),
            line(&after, "count:"),
            "an untouched leaf must keep its exact ciphertext"
        );
        assert_eq!(line(&encrypted, "enabled:"), line(&after, "enabled:"));
    }

    #[test]
    fn setting_a_value_to_what_it_already_holds_is_exit_200() {
        let w = World::new();
        let (outcome, _) =
            after_write(&w, &["set", "/repo/enc.yaml", "[\"alpha\"]", "\"one\""]).expect("set");
        assert_eq!(
            outcome.code,
            exit::FILE_HAS_NOT_CHANGED,
            "a no-op write reports sops's 200, not success"
        );
    }

    #[test]
    fn unset_removes_a_leaf() {
        let w = World::new();
        let (outcome, body) =
            after_write(&w, &["unset", "/repo/enc.yaml", "[\"count\"]"]).expect("unset");
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(decrypted(&w, &body), "alpha: one\nenabled: true\n");
    }

    #[test]
    fn unset_of_a_missing_key_is_refused_not_reported_as_success() {
        let w = World::new();
        let err =
            after_write(&w, &["unset", "/repo/enc.yaml", "[\"nope\"]"]).expect_err("must refuse");
        assert!(matches!(err, AppError::UnsetNotFound { .. }), "got {err:?}");
    }

    /// A composite value is REFUSED, never approximated. The YAML parser has no
    /// flow-style support, so passing `{"a":"b"}` through would write that literal
    /// string as a scalar — a successful write of the wrong secret.
    #[test]
    fn composite_values_are_refused_by_name() {
        for (raw, kind) in [("{\"a\":\"b\"}", "object"), ("[1,2]", "array")] {
            let err = parse_json_scalar(raw).expect_err("must refuse");
            match err {
                AppError::NonScalarValue { kind: k, .. } => assert_eq!(k, kind),
                other => panic!("wrong error for {raw}: {other:?}"),
            }
        }
    }

    #[test]
    fn set_values_parse_as_json_scalars() {
        assert_eq!(parse_json_scalar("\"text\"").unwrap().value, "text");
        assert_eq!(parse_json_scalar("42").unwrap().value, "42");
        assert_eq!(parse_json_scalar("true").unwrap().value, "true");
        assert_eq!(parse_json_scalar("null").unwrap().value, "null");
        assert_eq!(parse_json_scalar("\"a\\nb\"").unwrap().value, "a\nb");
        assert_eq!(parse_json_scalar("\"q\\\"q\"").unwrap().value, "q\"q");
        // An unquoted word is invalid JSON and is refused rather than guessed at.
        assert!(matches!(
            parse_json_scalar("hunter2"),
            Err(AppError::BadValue { .. })
        ));
        // An unterminated string, and a bad escape.
        assert!(matches!(
            parse_json_scalar("\"open"),
            Err(AppError::BadValue { .. })
        ));
        assert!(matches!(
            parse_json_scalar("\"bad\\q\""),
            Err(AppError::BadValue { .. })
        ));
    }

    #[test]
    fn set_through_a_scalar_names_the_step_that_failed() {
        let w = World::new();
        let err = after_write(
            &w,
            &["set", "/repo/enc.yaml", "[\"alpha\"][\"deeper\"]", "\"v\""],
        )
        .expect_err("must refuse");
        match err {
            AppError::PathNotTraversable { at, found, .. } => {
                assert_eq!(found, "scalar");
                assert_eq!(at, "[\"deeper\"]");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn set_and_unset_need_their_arguments() {
        let w = World::new();
        assert!(matches!(
            after_write(&w, &["set", "/repo/enc.yaml"]),
            Err(AppError::MissingPath { .. })
        ));
        assert!(matches!(
            after_write(&w, &["set", "/repo/enc.yaml", "[\"alpha\"]"]),
            Err(AppError::MissingValue)
        ));
        assert!(matches!(
            after_write(&w, &["unset", "/repo/enc.yaml"]),
            Err(AppError::MissingPath { .. })
        ));
    }

    /// ★ REGRESSION: a non-mapping root was SILENT PERMANENT DATA LOSS.
    ///
    /// `render()` appends the `sops:` block under `if let Value::Mapping(items)` with
    /// no else arm, so a sequence- or scalar-root document used to encrypt with exit
    /// 0, emit plausible bytes, and decrypt back to NOTHING. Measured on the shipped
    /// 0.1.10 binary: a 3-entry sequence produced 346 bytes whose decrypt was empty.
    /// With `--in-place` that destroyed the file and reported success.
    ///
    /// Both non-mapping shapes are covered because they take different match arms,
    /// and the mapping case is asserted in the same test so the guard cannot be
    /// "fixed" by refusing everything.
    #[test]
    fn a_non_mapping_root_is_refused_rather_than_silently_emptied() {
        let w = World::new();
        for (src, want) in [("- one\n- two\n", "sequence"), ("bare-string\n", "scalar")] {
            let env = w.env(&[("/repo/odd.yaml", src)]);
            let err = run_capture(&["-e", "/repo/odd.yaml"], &env)
                .expect_err("a non-mapping root must be refused");
            match &err {
                AppError::File(FileError::NonMappingRoot { found }) => {
                    assert_eq!(*found, want, "wrong shape named for {src:?}");
                }
                other => panic!("expected NonMappingRoot for {src:?}, got {other:?}"),
            }
            // The message has to name the reason, not just fail: an operator hitting
            // this needs to know the format requires a mapping.
            let msg = err.to_string();
            assert!(
                msg.contains("mapping"),
                "message must name the cause: {msg}"
            );
        }

        // The guard must not have become "refuse everything".
        let (outcome, body) = run_capture(&["-e", "/repo/plain.yaml"], &w.seeded())
            .expect("a mapping still encrypts");
        assert_eq!(outcome.code, exit::OK);
        assert!(body.contains("ENC[AES256_GCM,"));
    }

    #[test]
    fn set_is_no_longer_an_unimplemented_verb() {
        // The regression this whole verb exists to fix: `sops set` was refused, and
        // `tools/init-akeyless-dev.tlisp` calls it.
        assert!(matches!(
            inv(&["set", "f.yaml", "[\"k\"]", "\"v\""]).verb,
            Verb::Set
        ));
        assert!(matches!(
            inv(&["unset", "f.yaml", "[\"k\"]"]).verb,
            Verb::Unset
        ));
        // And the ones the fleet does NOT use stay refused.
        assert!(matches!(
            inv(&["exec-env", "f.yaml", "cmd"]).verb,
            Verb::Unimplemented(_)
        ));
    }

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
            parse_sops_path("[\"db\"][\"password\"]"),
            Some(vec![
                PathStep::Key("db".into()),
                PathStep::Key("password".into())
            ])
        );
        assert_eq!(
            parse_sops_path("[\"list\"][2]"),
            Some(vec![PathStep::Key("list".into()), PathStep::Index(2)])
        );
        assert_eq!(
            parse_sops_path("['single']"),
            Some(vec![PathStep::Key("single".into())])
        );
        // Malformed is None, never a best-effort guess.
        assert_eq!(parse_sops_path("db.password"), None);
        assert_eq!(parse_sops_path("[\"unclosed"), None);
        assert_eq!(parse_sops_path(""), None);
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
