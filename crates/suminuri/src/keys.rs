//! Key providers — wrapping and unwrapping the data key.
//!
//! # Why the `age` crate rather than our own X25519
//!
//! age is a **wire format we must speak exactly**, not a capability we want to
//! own: the armored blob in `sops.age[].enc` has to be byte-compatible with what
//! `age`, `rage`, `sops` and Flux all produce and consume. That is the magma
//! posture — speak the wire, own the executor — and it is the same reason magma
//! links the Terraform provider protocol rather than reinventing it. Re-deriving
//! X25519 + HKDF + ChaCha20-Poly1305 + bech32 + the armor framing here would buy
//! nothing and risk a subtle incompatibility that only shows up on someone else's
//! file.
//!
//! What *is* ours is everything around it: which identities are consulted and in
//! what order, how a failure is reported, and the fact that a provider we cannot
//! serve is a **named refusal** rather than a dropped key.
//!
//! # The macOS divergence, reproduced deliberately
//!
//! sops's age keysource comments that `os.UserConfigDir()` ignores
//! `XDG_CONFIG_HOME` on macOS, "so we handle that manually" — and then honours it.
//! This fleet is darwin-primary, so *not* copying that would send us looking in
//! `~/Library/Application Support` while sops reads `~/.config`, and the two would
//! disagree about where the operator's key lives.

use suminuri_wire::{DataKey, KeyProvider, Metadata, WrappedKey};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("no age identity could decrypt this file's data key (tried {tried} identit{}, {recipients} recipient{})", if *tried == 1 { "y" } else { "ies" }, if *recipients == 1 { "" } else { "s" })]
    NoUsableIdentity { tried: usize, recipients: usize },

    #[error("the file declares no key at all, so nothing can ever decrypt it")]
    NoKeys,

    #[error(
        "this file needs {providers} but this build only unwraps age; refusing rather than guessing"
    )]
    UnimplementedProvider { providers: String },

    #[error("could not read the age key file {path}: {reason}")]
    KeyFileUnreadable { path: String, reason: String },

    #[error(
        "no age identity available: set SOPS_AGE_KEY, SOPS_AGE_KEY_FILE, or place keys at {expected}"
    )]
    NoIdentitySource { expected: String },

    // NOTE: the field is `origin`, not `source`. `source` is a magic field name
    // in thiserror — it wires the field up as `Error::source()`, which requires
    // `std::error::Error` and fails to compile for a `String`. The error message
    // says `as_dyn_error exists for &String but its trait bounds were not
    // satisfied`, which names the symptom and not the cause.
    #[error("an age identity in {origin} could not be parsed: {reason}")]
    BadIdentity { origin: String, reason: String },

    #[error("`{recipient}` is not a valid age recipient: {reason}")]
    BadRecipient { recipient: String, reason: String },

    #[error("age refused to wrap the data key for {recipient}: {reason}")]
    WrapFailed { recipient: String, reason: String },

    #[error(
        "the unwrapped data key is {got} bytes, not 32 — the wrapped blob is not a sops data key"
    )]
    WrongDataKeySize { got: usize },
}

/// Where an identity came from, for error messages that name the file the
/// operator has to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentitySource {
    Env(&'static str),
    File(String),
}

impl std::fmt::Display for IdentitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env(k) => write!(f, "${k}"),
            Self::File(p) => write!(f, "{p}"),
        }
    }
}

/// The age identities available to this process, with where each came from.
pub struct AgeIdentities {
    /// ★ `Box<dyn age::Identity>`, not `Vec<x25519::Identity>`.
    ///
    /// Widened 2026-08-29 so an SSH host key can be an identity. age models
    /// both `x25519::Identity` and `ssh::Identity` as `age::Identity`, and the
    /// unwrap path below already coerced to `&dyn age::Identity` — so the
    /// concrete type in this field was the only thing forbidding ssh keys, and
    /// it was never load-bearing.
    identities: Vec<Box<dyn age::Identity + Send + Sync>>,
    sources: Vec<IdentitySource>,
}

impl AgeIdentities {
    /// Collect identities the way sops does, in the same precedence order.
    ///
    /// `SOPS_AGE_KEY` first, then `SOPS_AGE_KEY_FILE`, then the default config
    /// path. `SOPS_AGE_KEY_CMD` and the SSH-key sources are **not** consulted —
    /// see [`Self::unsupported_sources`], which names them rather than letting
    /// their absence read as "no key found".
    pub fn discover(env: &dyn crate::env::Environment) -> Result<Self, KeyError> {
        let mut identities = Vec::new();
        let mut sources = Vec::new();

        if let Some(inline) = env.var("SOPS_AGE_KEY") {
            let n = parse_into(
                &inline,
                &mut identities,
                &IdentitySource::Env("SOPS_AGE_KEY"),
            )?;
            if n > 0 {
                sources.push(IdentitySource::Env("SOPS_AGE_KEY"));
            }
        }

        let explicit = env.var("SOPS_AGE_KEY_FILE");
        let candidates: Vec<String> = match explicit {
            Some(p) => vec![p],
            None => default_key_paths(env),
        };
        for path in candidates {
            match env.read_to_string(std::path::Path::new(&path)) {
                Ok(contents) => {
                    let src = IdentitySource::File(path.clone());
                    let n = parse_into(&contents, &mut identities, &src)?;
                    if n > 0 {
                        sources.push(src);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(KeyError::KeyFileUnreadable {
                        path,
                        reason: e.to_string(),
                    });
                }
            }
        }

        Ok(Self {
            // ★ Boxed HERE rather than in `parse_into`, which genuinely parses
            // `AGE-SECRET-KEY-` lines and should keep its concrete type. The
            // widening exists so OTHER identity kinds can join the same
            // vector — it is not a change to how age keys are read.
            identities: identities
                .into_iter()
                .map(|i| Box::new(i) as Box<dyn age::Identity + Send + Sync>)
                .collect(),
            sources,
        })
    }

    /// Build identities from EXPLICIT paths, including SSH host keys.
    ///
    /// ── ★ WHY THIS IS SEPARATE FROM `discover` ─────────────────────────
    ///
    /// `discover` reads the environment the way sops does and deliberately
    /// does not consult SSH sources — [`Self::unsupported_sources`] names them
    /// so their absence never reads as "no key found". That contract is
    /// unchanged and this does not touch it.
    ///
    /// This is for a caller that already KNOWS which files to use because
    /// something told it: `sops-install-secrets`' manifest names `ageKeyFile`
    /// and `ageSshKeyPaths` outright. Discovery would be the wrong mechanism —
    /// there is nothing to discover.
    ///
    /// **On a NixOS node the ssh path is the interesting one:** the manifest
    /// names `/etc/ssh/ssh_host_ed25519_key`, the same file sshd serves as a
    /// host key. The node's ssh host identity IS its decryption identity.
    ///
    /// # Errors
    /// [`KeyError`] only if a named, readable age file parses as no identity.
    /// An UNREADABLE path is SKIPPED, not fatal: a node can boot before
    /// `/var/lib` is mounted while its ssh host key is already present.
    pub fn from_paths(
        env: &dyn crate::env::Environment,
        age_key_files: &[String],
        ssh_key_files: &[String],
    ) -> Result<Self, KeyError> {
        let mut identities: Vec<Box<dyn age::Identity + Send + Sync>> = Vec::new();
        let mut sources = Vec::new();

        for p in age_key_files {
            let Ok(contents) = env.read_to_string(std::path::Path::new(p)) else {
                continue;
            };
            let src = IdentitySource::File(p.clone());
            let mut parsed = Vec::new();
            if parse_into(&contents, &mut parsed, &src)? > 0 {
                identities.extend(
                    parsed
                        .into_iter()
                        .map(|i| Box::new(i) as Box<dyn age::Identity + Send + Sync>),
                );
                sources.push(src);
            }
        }

        for p in ssh_key_files {
            let Ok(contents) = env.read_to_string(std::path::Path::new(p)) else {
                continue;
            };
            let Ok(id) = age::ssh::Identity::from_buffer(
                std::io::BufReader::new(contents.as_bytes()),
                Some(p.clone()),
            ) else {
                continue;
            };
            // ★ `Unsupported` is a SUCCESS value from age — an unusable key
            // comes back as a variant, not an Err. Pushing it would hand the
            // node an identity that silently decrypts nothing.
            if matches!(id, age::ssh::Identity::Unsupported(_)) {
                continue;
            }
            identities.push(Box::new(id));
            sources.push(IdentitySource::File(p.clone()));
        }

        Ok(Self { identities, sources })
    }

    /// The identity sources sops supports that this build does not.
    ///
    /// Reported when no identity is found, so the operator sees "we do not read
    /// `SOPS_AGE_KEY_CMD`" instead of a bare "no key". A silent gap here would
    /// look exactly like a missing key file.
    #[must_use]
    pub fn unsupported_sources(env: &dyn crate::env::Environment) -> Vec<&'static str> {
        [
            "SOPS_AGE_KEY_CMD",
            "SOPS_AGE_SSH_PRIVATE_KEY_FILE",
            "SOPS_AGE_SSH_PRIVATE_KEY_CMD",
        ]
        .into_iter()
        .filter(|k| env.var(k).is_some())
        .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Where the identities came from. Diagnostics only; never the keys.
    #[must_use]
    pub fn sources(&self) -> &[IdentitySource] {
        &self.sources
    }
}

impl std::fmt::Debug for AgeIdentities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AgeIdentities({} identities from {:?})",
            self.identities.len(),
            self.sources
        )
    }
}

fn parse_into(
    contents: &str,
    out: &mut Vec<age::x25519::Identity>,
    source: &IdentitySource,
) -> Result<usize, KeyError> {
    let mut n = 0;
    for line in contents.lines() {
        let line = line.trim();
        if !line.starts_with("AGE-SECRET-KEY-") {
            continue;
        }
        let id = line
            .parse::<age::x25519::Identity>()
            .map_err(|e| KeyError::BadIdentity {
                origin: source.to_string(),
                reason: e.to_string(),
            })?;
        out.push(id);
        n += 1;
    }
    Ok(n)
}

/// The default key-file locations, in the order sops checks them.
///
/// `XDG_CONFIG_HOME` is honoured **on every platform**, which is what sops does
/// after working around Go's macOS behaviour. The `~/Library/Application Support`
/// path is included as a fallback because that is where Go's `UserConfigDir`
/// points on darwin, so a key placed there by some other tool is still found.
fn default_key_paths(env: &dyn crate::env::Environment) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(xdg) = env.var("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        paths.push(format!("{xdg}/sops/age/keys.txt"));
    }
    if let Some(home) = env.var("HOME").filter(|v| !v.is_empty()) {
        paths.push(format!("{home}/.config/sops/age/keys.txt"));
        if cfg!(target_os = "macos") {
            paths.push(format!(
                "{home}/Library/Application Support/sops/age/keys.txt"
            ));
        }
    }
    paths.dedup();
    paths
}

/// The path an error message should suggest when no identity was found.
#[must_use]
pub fn expected_key_path(env: &dyn crate::env::Environment) -> String {
    default_key_paths(env)
        .first()
        .cloned()
        .unwrap_or_else(|| "$HOME/.config/sops/age/keys.txt".to_string())
}

/// Unwrap a file's data key.
///
/// Tries every age recipient against every identity, in file order — which is
/// what `--decryption-order`'s default is. A provider this build cannot unwrap is
/// refused **before** any attempt, so the failure names the provider rather than
/// reporting "no usable identity" for a file that never had an age key.
pub fn unwrap_data_key(
    metadata: &Metadata,
    identities: &AgeIdentities,
) -> Result<DataKey, KeyError> {
    if metadata.keys().is_empty() {
        return Err(KeyError::NoKeys);
    }
    let age_keys = metadata.keys_for(KeyProvider::Age);
    if age_keys.is_empty() {
        let missing = metadata.unimplemented_providers();
        if !missing.is_empty() {
            return Err(KeyError::UnimplementedProvider {
                providers: missing
                    .iter()
                    .map(|p| p.field())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        return Err(KeyError::NoKeys);
    }

    for wrapped in &age_keys {
        let armored = age::armor::ArmoredReader::new(wrapped.enc().as_bytes());
        let Ok(decryptor) = age::Decryptor::new(armored) else {
            continue;
        };
        let Ok(mut reader) = decryptor.decrypt(
            identities
                .identities
                .iter()
                .map(|i| &**i as &dyn age::Identity),
        ) else {
            continue;
        };
        let mut out = Zeroizing::new(Vec::new());
        use std::io::Read as _;
        if reader.read_to_end(&mut out).is_err() {
            continue;
        }
        if out.len() != DataKey::LEN {
            return Err(KeyError::WrongDataKeySize { got: out.len() });
        }
        return DataKey::from_bytes(&out)
            .map_err(|_| KeyError::WrongDataKeySize { got: out.len() });
    }

    Err(KeyError::NoUsableIdentity {
        tried: identities.len(),
        recipients: age_keys.len(),
    })
}

/// Wrap a data key for a set of age recipients.
///
/// Returns [`WrappedKey`]s, which is the only way to build a [`Metadata`] — so a
/// recipient list can never outrun the ciphertext that backs it.
pub fn wrap_for_age_recipients(
    key: &DataKey,
    recipients: &[String],
) -> Result<Vec<WrappedKey>, KeyError> {
    let mut out = Vec::with_capacity(recipients.len());
    for r in recipients {
        let parsed = r
            .parse::<age::x25519::Recipient>()
            .map_err(|e| KeyError::BadRecipient {
                recipient: r.clone(),
                reason: e.to_string(),
            })?;
        let mut armored: Vec<u8> = Vec::new();
        {
            use std::io::Write as _;
            let writer = age::armor::ArmoredWriter::wrap_output(
                &mut armored,
                age::armor::Format::AsciiArmor,
            )
            .map_err(|e| KeyError::WrapFailed {
                recipient: r.clone(),
                reason: e.to_string(),
            })?;
            // `with_recipients` takes an iterator of `&dyn Recipient` and returns a
            // Result — not a Vec<Box<_>> and not an Option, which is what the
            // 0.9-era examples show.
            let recipients: [&dyn age::Recipient; 1] = [&parsed];
            let mut enc = age::Encryptor::with_recipients(recipients.into_iter())
                .map_err(|e| KeyError::WrapFailed {
                    recipient: r.clone(),
                    reason: e.to_string(),
                })?
                .wrap_output(writer)
                .map_err(|e| KeyError::WrapFailed {
                    recipient: r.clone(),
                    reason: e.to_string(),
                })?;
            enc.write_all(key.expose())
                .map_err(|e| KeyError::WrapFailed {
                    recipient: r.clone(),
                    reason: e.to_string(),
                })?;
            let finished = enc.finish().map_err(|e| KeyError::WrapFailed {
                recipient: r.clone(),
                reason: e.to_string(),
            })?;
            finished.finish().map_err(|e| KeyError::WrapFailed {
                recipient: r.clone(),
                reason: e.to_string(),
            })?;
        }
        let armor = String::from_utf8_lossy(&armored).into_owned();
        // sops stores the armored blob with a trailing newline, which is what
        // makes go-yaml render it as a literal block rather than a quoted string
        // full of `\n` escapes.
        let armor = if armor.ends_with('\n') {
            armor
        } else {
            format!("{armor}\n")
        };
        out.push(WrappedKey::age(r, armor));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;

    /// A throwaway identity generated in-process. Never written to disk.
    fn fresh() -> (age::x25519::Identity, String) {
        let id = age::x25519::Identity::generate();
        let recipient = id.to_public().to_string();
        (id, recipient)
    }

    #[test]
    fn wrap_then_unwrap_round_trips_the_data_key() {
        let (id, recipient) = fresh();
        let key = DataKey::generate().expect("generate");
        let wrapped = wrap_for_age_recipients(&key, &[recipient.clone()]).expect("wrap");
        assert_eq!(wrapped.len(), 1);
        assert!(
            wrapped[0]
                .enc()
                .starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
        );
        assert!(
            wrapped[0].enc().ends_with('\n'),
            "the trailing newline makes it a literal block"
        );

        let meta = Metadata::from_wrapped(wrapped, "2026-08-18T00:00:00Z", "mac");
        let ids = AgeIdentities {
            identities: vec![Box::new(id)],
            sources: vec![],
        };
        let back = unwrap_data_key(&meta, &ids).expect("unwrap");
        assert_eq!(back.expose(), key.expose());
    }

    #[test]
    fn a_stranger_cannot_unwrap() {
        let (_, recipient) = fresh();
        let (stranger, _) = fresh();
        let key = DataKey::generate().expect("generate");
        let meta = Metadata::from_wrapped(
            wrap_for_age_recipients(&key, &[recipient]).expect("wrap"),
            "2026-08-18T00:00:00Z",
            "mac",
        );
        let ids = AgeIdentities {
            identities: vec![Box::new(stranger)],
            sources: vec![],
        };
        let err = unwrap_data_key(&meta, &ids).expect_err("must refuse");
        assert!(
            matches!(
                err,
                KeyError::NoUsableIdentity {
                    tried: 1,
                    recipients: 1
                }
            ),
            "got {err}"
        );
        // The message carries the denominator, so "no key" is distinguishable
        // from "no recipients".
        assert!(err.to_string().contains("1 identity"), "{err}");
    }

    /// Any one of several recipients suffices — the multi-recipient shape the
    /// fleet's shared `secrets.yaml` uses.
    #[test]
    fn any_one_of_several_recipients_suffices() {
        let (id_a, rec_a) = fresh();
        let (_, rec_b) = fresh();
        let (_, rec_c) = fresh();
        let key = DataKey::generate().expect("generate");
        let meta = Metadata::from_wrapped(
            wrap_for_age_recipients(&key, &[rec_a, rec_b, rec_c]).expect("wrap"),
            "2026-08-18T00:00:00Z",
            "mac",
        );
        assert_eq!(meta.age_keys().len(), 3);
        let ids = AgeIdentities {
            identities: vec![Box::new(id_a)],
            sources: vec![],
        };
        assert_eq!(
            unwrap_data_key(&meta, &ids).expect("unwrap").expose(),
            key.expose()
        );
    }

    #[test]
    fn a_file_with_no_keys_is_named_as_such() {
        // `Metadata::from_wrapped` accepts an empty set on construction (a file
        // being built), but unwrapping one is a distinct, named failure.
        let meta = Metadata::from_wrapped(vec![], "2026-08-18T00:00:00Z", "mac");
        let ids = AgeIdentities {
            identities: vec![],
            sources: vec![],
        };
        assert!(matches!(
            unwrap_data_key(&meta, &ids),
            Err(KeyError::NoKeys)
        ));
    }

    #[test]
    fn a_kms_only_file_names_the_provider_rather_than_blaming_the_identity() {
        let meta = Metadata::from_wrapped(
            vec![WrappedKey::opaque(
                KeyProvider::AwsKms,
                "arn:aws:kms:…",
                "CiA…",
                None,
            )],
            "2026-08-18T00:00:00Z",
            "mac",
        );
        let ids = AgeIdentities {
            identities: vec![],
            sources: vec![],
        };
        let err = unwrap_data_key(&meta, &ids).expect_err("must refuse");
        assert!(
            matches!(err, KeyError::UnimplementedProvider { .. }),
            "got {err}"
        );
        assert!(err.to_string().contains("kms"), "{err}");
    }

    #[test]
    fn an_invalid_recipient_is_named() {
        let key = DataKey::generate().expect("generate");
        let err = wrap_for_age_recipients(&key, &["not-an-age-key".into()]).expect_err("refuse");
        assert!(matches!(err, KeyError::BadRecipient { .. }), "got {err}");
    }

    #[test]
    fn sops_age_key_env_is_read_first() {
        let (id, _) = fresh();
        let secret = id.to_string();
        let env = MockEnvironment::new().with_var("SOPS_AGE_KEY", &secret.expose_secret_for_test());
        let ids = AgeIdentities::discover(&env).expect("discover");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids.sources(), &[IdentitySource::Env("SOPS_AGE_KEY")]);
    }

    #[test]
    fn a_key_file_is_read_and_its_path_recorded() {
        let (id, _) = fresh();
        let env = MockEnvironment::new()
            .with_var("HOME", "/home/op")
            .with_file(
                "/home/op/.config/sops/age/keys.txt",
                &id.to_string().expose_secret_for_test(),
            );
        let ids = AgeIdentities::discover(&env).expect("discover");
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids.sources(),
            &[IdentitySource::File(
                "/home/op/.config/sops/age/keys.txt".into()
            )]
        );
    }

    /// XDG_CONFIG_HOME must win, on every platform. sops works around Go ignoring
    /// it on macOS; a fleet that is darwin-primary would otherwise look in a
    /// different directory than sops does.
    #[test]
    fn xdg_config_home_takes_precedence_over_home() {
        let (id, _) = fresh();
        let env = MockEnvironment::new()
            .with_var("XDG_CONFIG_HOME", "/xdg")
            .with_var("HOME", "/home/op")
            .with_file(
                "/xdg/sops/age/keys.txt",
                &id.to_string().expose_secret_for_test(),
            );
        let ids = AgeIdentities::discover(&env).expect("discover");
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids.sources(),
            &[IdentitySource::File("/xdg/sops/age/keys.txt".into())]
        );
    }

    #[test]
    fn a_missing_key_file_is_not_an_error_just_an_absence() {
        let env = MockEnvironment::new().with_var("HOME", "/home/op");
        let ids = AgeIdentities::discover(&env).expect("discover");
        assert!(ids.is_empty());
    }

    /// An identity source sops honours and we do not must be *named*, or its
    /// absence looks like a missing key.
    #[test]
    fn an_unsupported_identity_source_is_reported() {
        let env = MockEnvironment::new().with_var("SOPS_AGE_KEY_CMD", "pass show age");
        assert_eq!(
            AgeIdentities::unsupported_sources(&env),
            vec!["SOPS_AGE_KEY_CMD"]
        );
    }

    #[test]
    fn a_malformed_identity_names_its_source() {
        let env = MockEnvironment::new().with_var("SOPS_AGE_KEY", "AGE-SECRET-KEY-NOTVALID");
        let err = AgeIdentities::discover(&env).expect_err("must refuse");
        assert!(matches!(err, KeyError::BadIdentity { .. }), "got {err}");
        assert!(err.to_string().contains("SOPS_AGE_KEY"), "{err}");
    }

    #[test]
    fn debug_never_prints_an_identity() {
        let (id, _) = fresh();
        let ids = AgeIdentities {
            identities: vec![Box::new(id)],
            sources: vec![],
        };
        let shown = format!("{ids:?}");
        assert!(
            !shown.contains("AGE-SECRET-KEY"),
            "leaked an identity: {shown}"
        );
    }

    // ── from_paths: explicit identities, including SSH host keys ─────────

    fn generated_ssh_key() -> String {
        // ★ Generated in-process and dropped. Never written to disk, never
        // committed — the pre-commit guard refuses key fixtures, correctly:
        // a scanner cannot tell a fixture from the real thing.
        let k = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("generate");
        k.to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .to_string()
    }

    #[test]
    fn from_paths_accepts_an_ssh_host_key_as_an_identity() {
        // THE capability this adds. On a NixOS node the manifest names
        // /etc/ssh/ssh_host_ed25519_key -- the same file sshd serves as a host
        // key -- so the node's ssh host identity IS its decryption identity.
        let env = MockEnvironment::new()
            .with_file("/etc/ssh/ssh_host_ed25519_key", &generated_ssh_key());
        let ids =
            AgeIdentities::from_paths(&env, &[], &["/etc/ssh/ssh_host_ed25519_key".into()])
                .expect("from_paths");
        assert_eq!(ids.len(), 1, "the ssh host key must become an identity");
    }

    #[test]
    fn from_paths_keeps_age_files_before_ssh_keys() {
        // Order is part of the contract: a node holding both must behave the
        // same as upstream, or a rebuild that used to succeed starts failing
        // on a file whose recipients include only one of them.
        let (id, _) = fresh();
        let env = MockEnvironment::new()
            .with_file("/k/age.txt", &id.to_string().expose_secret_for_test())
            .with_file("/etc/ssh/host", &generated_ssh_key());
        let ids = AgeIdentities::from_paths(
            &env,
            &["/k/age.txt".into()],
            &["/etc/ssh/host".into()],
        )
        .expect("from_paths");
        assert_eq!(ids.len(), 2);
        assert_eq!(ids.sources()[0], IdentitySource::File("/k/age.txt".into()));
        assert_eq!(ids.sources()[1], IdentitySource::File("/etc/ssh/host".into()));
    }

    #[test]
    fn an_unreadable_path_is_skipped_not_fatal() {
        // A node can boot before /var/lib is mounted while its ssh host key is
        // already there. Refusing outright would make that a hard failure.
        let env = MockEnvironment::new().with_file("/etc/ssh/host", &generated_ssh_key());
        let ids = AgeIdentities::from_paths(
            &env,
            &["/var/lib/sops-nix/key.txt".into()],
            &["/etc/ssh/host".into()],
        )
        .expect("an absent age file must not be fatal");
        assert_eq!(ids.len(), 1, "the ssh key must still be usable");
    }

    #[test]
    fn naming_nothing_yields_no_identities_rather_than_an_error() {
        let env = MockEnvironment::new();
        let ids = AgeIdentities::from_paths(&env, &[], &[]).expect("no error");
        assert!(ids.is_empty());
    }
}

/// Test-only helper so the age crate's `SecretString` can seed a mock env without
/// adding a `secrecy` dependency to the crate proper.
#[cfg(test)]
trait ExposeForTest {
    fn expose_secret_for_test(&self) -> String;
}

#[cfg(test)]
impl ExposeForTest for age::secrecy::SecretString {
    fn expose_secret_for_test(&self) -> String {
        use age::secrecy::ExposeSecret as _;
        self.expose_secret().to_string()
    }
}
