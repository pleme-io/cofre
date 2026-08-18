//! A whole file: parse, lift the metadata, walk, verify, render.
//!
//! This is where the two crates meet, and where the ordering constraints that are
//! invisible in either half alone get enforced:
//!
//! 1. **The `sops:` block is lifted out before the walk**, because the metadata is
//!    outside the MAC. Walking it would hash the ciphertext of the MAC field into
//!    the MAC, which cannot converge.
//! 2. **`lastmodified` is set before the MAC is sealed**, because it is the MAC
//!    field's AAD. Sealing first and stamping after produces a file whose MAC
//!    cannot be decrypted — the failure mode `Metadata::lastmodified`'s doc
//!    comment warns about, reached from the other side.
//! 3. **The metadata is appended last** when rendering, so `sops:` is the final
//!    key. sops does the same (`branch = append(branch, TreeItem{SopsMetadataKey})`),
//!    and key order is MAC-relevant for every *other* key, so the position is not
//!    a cosmetic choice.

use crate::keys::{AgeIdentities, KeyError, unwrap_data_key};
use crate::metabridge::{self, MetaError};
use crate::walk::{Direction, WalkCtx, WalkStats, walk};
use suminuri_wire::{
    DataKey, IvStash, MacAccumulator, Metadata, Unverified, WireError, seal_mac_field,
};
use suminuri_yaml::{Document, EmitOptions, Item, Value, YamlError};

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error(transparent)]
    Yaml(#[from] YamlError),
    #[error(transparent)]
    Meta(#[from] MetaError),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("this file has no `sops:` metadata block — it is not encrypted")]
    NotEncrypted,
    #[error("this file already has a `sops:` metadata block — it is already encrypted")]
    AlreadyEncrypted,
    #[error("multi-document streams are not supported for this operation ({docs} documents found)")]
    MultiDocument { docs: usize },
    #[error(
        "`key_groups` / Shamir secret sharing is not implemented; refusing rather than rewriting the file without it"
    )]
    KeyGroupsUnsupported,
}

/// A loaded file, split into the data tree and its metadata.
///
/// `Debug` is hand-written, not derived. Between a decrypt and a re-encrypt the
/// `tree` field holds **every plaintext in the file**, and this is exactly the
/// type someone reaches for `{:?}` on while debugging a MAC failure over a real
/// secrets file. A derive would print the lot.
pub struct SopsFile {
    /// The document root with the `sops:` key removed.
    pub tree: Value,
    pub metadata: Metadata,
    /// The indent the file was written with, so a re-render matches it.
    pub indent: usize,
}

impl std::fmt::Debug for SopsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SopsFile")
            .field("tree", &"***")
            .field("recipients", &self.metadata.keys().len())
            .field("lastmodified", &self.metadata.lastmodified)
            .field("indent", &self.indent)
            .finish()
    }
}

impl SopsFile {
    /// Load an already-encrypted file.
    pub fn load_encrypted(src: &str) -> Result<Self, FileError> {
        let doc = suminuri_yaml::parse(src)?;
        if doc.roots.len() != 1 {
            return Err(FileError::MultiDocument {
                docs: doc.roots.len(),
            });
        }
        let mut tree = doc
            .roots
            .into_iter()
            .next()
            .unwrap_or(Value::Mapping(Vec::new()));
        let sops = tree.remove("sops").ok_or(FileError::NotEncrypted)?;
        // Refused rather than silently dropped: re-rendering a key-group file
        // without its groups would strip every recipient's access.
        if sops.get("key_groups").is_some() {
            return Err(FileError::KeyGroupsUnsupported);
        }
        let metadata = metabridge::from_tree(&sops)?;
        Ok(Self {
            tree,
            metadata,
            indent: detect_indent(src).unwrap_or(4),
        })
    }

    /// Load a plaintext file that is about to be encrypted.
    pub fn load_plain(src: &str) -> Result<Value, FileError> {
        let doc = suminuri_yaml::parse(src)?;
        if doc.roots.len() != 1 {
            return Err(FileError::MultiDocument {
                docs: doc.roots.len(),
            });
        }
        let tree = doc
            .roots
            .into_iter()
            .next()
            .unwrap_or(Value::Mapping(Vec::new()));
        if tree.get("sops").is_some() {
            return Err(FileError::AlreadyEncrypted);
        }
        Ok(tree)
    }

    /// Unwrap the data key using the identities available.
    pub fn data_key(&self, identities: &AgeIdentities) -> Result<DataKey, FileError> {
        Ok(unwrap_data_key(&self.metadata, identities)?)
    }

    /// Decrypt in place, returning the tree behind an [`Unverified`] marker.
    ///
    /// The marker is the point: the decrypted tree is *in* `self` either way — it
    /// has to be, the walk mutates it — but the caller cannot obtain a *statement
    /// that it is authentic* without calling `verify`. What the wrapper carries is
    /// the permission to trust it, plus the stats needed to prove the check was
    /// not vacuous.
    pub fn decrypt(
        &mut self,
        key: &DataKey,
        stash: &mut IvStash,
    ) -> Result<Unverified<WalkStats>, FileError> {
        let selector = self.metadata.selector()?;
        let mut mac = MacAccumulator::new(self.metadata.mac_only_encrypted);
        let mut ctx = WalkCtx {
            direction: Direction::Decrypt,
            key,
            selector: &selector,
            mac: &mut mac,
            stash,
            stats: WalkStats::default(),
        };
        let stats = walk(&mut self.tree, &mut ctx)?;
        let fed = mac.leaves_fed();
        let computed = mac.finish();
        Ok(Unverified::new(
            stats,
            computed,
            self.metadata.mac.clone(),
            self.metadata.lastmodified.clone(),
            fed,
        ))
    }

    /// Encrypt in place and stamp a fresh `lastmodified` + `mac`.
    ///
    /// `stash` should be the one filled by a preceding [`Self::decrypt`] when this
    /// is a re-encrypt, so unchanged values keep their ciphertext and the diff
    /// stays small.
    pub fn encrypt(
        &mut self,
        key: &DataKey,
        stash: &mut IvStash,
        now: &str,
    ) -> Result<WalkStats, FileError> {
        let selector = self.metadata.selector()?;
        let mut mac = MacAccumulator::new(self.metadata.mac_only_encrypted);
        let mut ctx = WalkCtx {
            direction: Direction::Encrypt,
            key,
            selector: &selector,
            mac: &mut mac,
            stash,
            stats: WalkStats::default(),
        };
        let stats = walk(&mut self.tree, &mut ctx)?;
        let computed = mac.finish();

        // Order matters: the timestamp is the MAC field's AAD, so it is stamped
        // first and then sealed against. Reversing these two lines produces a file
        // whose MAC field cannot be opened.
        self.metadata.lastmodified = now.to_string();
        // Reuse the MAC field's own IV when the MAC is unchanged, so a no-op
        // re-encrypt leaves even the metadata line byte-identical.
        let mac_iv = stash.recall(
            &suminuri_wire::Plaintext::string(computed.as_hex()),
            &suminuri_wire::mac_field_aad(now),
        );
        self.metadata.mac = seal_mac_field(key, &computed, now, mac_iv)?;
        Ok(stats)
    }

    /// Render the file, appending the `sops:` block last.
    pub fn render(&self) -> Result<String, FileError> {
        let mut root = self.tree.clone();
        if let Value::Mapping(items) = &mut root {
            items.push(Item::Pair {
                key: "sops".into(),
                value: metabridge::to_tree(&self.metadata),
            });
        }
        Ok(suminuri_yaml::emit(
            &Document::single(root),
            EmitOptions {
                indent: self.indent,
            },
        )?)
    }

    /// Render just the decrypted data, with no metadata — `sops --decrypt`'s
    /// output.
    pub fn render_plain(&self) -> Result<String, FileError> {
        Ok(suminuri_yaml::emit(
            &Document::single(self.tree.clone()),
            EmitOptions {
                indent: self.indent,
            },
        )?)
    }
}

/// The indent width a file was written with: the first nesting step.
///
/// Read from the file rather than assumed, because `--indent 2` is a real option
/// and re-rendering a 2-indent file at 4 would rewrite every line.
#[must_use]
pub fn detect_indent(src: &str) -> Option<usize> {
    let mut previous = 0usize;
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let col = line.len() - trimmed.len();
        if col > previous {
            return Some(col - previous);
        }
        previous = col;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::wrap_for_age_recipients;

    fn fresh() -> (age::x25519::Identity, String) {
        let id = age::x25519::Identity::generate();
        (id.clone(), id.to_public().to_string())
    }

    fn identities(ids: Vec<age::x25519::Identity>) -> AgeIdentities {
        // Round-trip through the env seam so the test uses the same construction
        // path production does, rather than a private constructor.
        use age::secrecy::ExposeSecret as _;
        let joined = ids
            .iter()
            .map(|i| i.to_string().expose_secret().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let env = crate::env::MockEnvironment::new().with_var("SOPS_AGE_KEY", &joined);
        AgeIdentities::discover(&env).expect("discover")
    }

    /// Build an encrypted file from plaintext, end to end.
    fn encrypt_fresh(plain: &str, recipient: &str) -> (String, DataKey) {
        let tree = SopsFile::load_plain(plain).expect("load plain");
        let key = DataKey::generate().expect("key");
        let wrapped = wrap_for_age_recipients(&key, &[recipient.to_string()]).expect("wrap");
        let mut f = SopsFile {
            tree,
            metadata: Metadata::from_wrapped(wrapped, "", ""),
            indent: detect_indent(plain).unwrap_or(4),
        };
        f.metadata.unencrypted_suffix = Some(suminuri_wire::DEFAULT_UNENCRYPTED_SUFFIX.to_string());
        let mut stash = IvStash::new();
        f.encrypt(&key, &mut stash, "2026-08-18T00:00:00Z")
            .expect("encrypt");
        (f.render().expect("render"), key)
    }

    const PLAIN: &str = "alpha: one\ncount: 3\nenabled: true\nnested:\n    deep: v\n";

    #[test]
    fn a_file_we_encrypt_we_can_decrypt() {
        let (_, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);
        assert!(encrypted.contains("sops:"));
        assert!(encrypted.contains("ENC[AES256_GCM,"));
        assert!(encrypted.contains("lastmodified: \"2026-08-18T00:00:00Z\""));
    }

    #[test]
    fn the_round_trip_verifies_its_mac_and_reproduces_the_plaintext() {
        let (id, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);

        let mut f = SopsFile::load_encrypted(&encrypted).expect("load");
        let ids = identities(vec![id]);
        let key = f.data_key(&ids).expect("data key");
        let mut stash = IvStash::new();
        let unverified = f.decrypt(&key, &mut stash).expect("decrypt");
        assert_eq!(
            unverified.leaves_fed(),
            4,
            "alpha, count, enabled, nested.deep"
        );
        let stats = unverified.verify(&key).expect("MAC must verify");
        assert_eq!(stats.leaves, 4);
        assert_eq!(f.render_plain().expect("render"), PLAIN);
    }

    /// The `sops:` block must not be walked, or the MAC could never converge.
    #[test]
    fn the_metadata_block_is_outside_the_walk() {
        let (id, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);
        let mut f = SopsFile::load_encrypted(&encrypted).expect("load");
        assert!(f.tree.get("sops").is_none(), "the metadata was lifted out");
        let ids = identities(vec![id]);
        let key = f.data_key(&ids).expect("data key");
        let mut stash = IvStash::new();
        let u = f.decrypt(&key, &mut stash).expect("decrypt");
        // 4 data leaves, not 4 + however many metadata scalars there are.
        assert_eq!(u.leaves_fed(), 4);
        u.verify(&key).expect("verify");
    }

    /// A no-op edit must be a byte-identical file. This is the property that makes
    /// the format reviewable in git, and it needs the IV stash *and* the MAC
    /// field's own IV to be reused.
    #[test]
    fn a_decrypt_then_reencrypt_is_byte_identical() {
        let (id, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);

        let mut f = SopsFile::load_encrypted(&encrypted).expect("load");
        let ids = identities(vec![id]);
        let key = f.data_key(&ids).expect("data key");
        let mut stash = IvStash::new();
        // `verify_recording` rather than `verify`: the MAC field's own IV has to
        // land in the stash too, or every data line matches and the `mac:` line
        // alone moves. Upstream gets this from sharing one Cipher across the
        // leaves and the MAC.
        f.decrypt(&key, &mut stash)
            .expect("decrypt")
            .verify_recording(&key, Some(&mut stash))
            .expect("verify");
        f.encrypt(&key, &mut stash, "2026-08-18T00:00:00Z")
            .expect("re-encrypt");
        assert_eq!(
            f.render().expect("render"),
            encrypted,
            "an unchanged file must not churn"
        );
    }

    #[test]
    fn a_changed_value_changes_only_its_own_line() {
        let (id, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);
        let mut f = SopsFile::load_encrypted(&encrypted).expect("load");
        let ids = identities(vec![id]);
        let key = f.data_key(&ids).expect("data key");
        let mut stash = IvStash::new();
        f.decrypt(&key, &mut stash)
            .expect("decrypt")
            .verify_recording(&key, Some(&mut stash))
            .expect("verify");

        // Change one leaf.
        if let Some(v) = f.tree.get_mut("alpha") {
            *v = Value::Scalar(suminuri_yaml::Scalar::new("CHANGED"));
        }
        f.encrypt(&key, &mut stash, "2026-08-18T00:00:00Z")
            .expect("re-encrypt");
        let after = f.render().expect("render");

        let differing = encrypted
            .lines()
            .zip(after.lines())
            .filter(|(a, b)| a != b)
            .count();
        // The changed value, and the mac line. Nothing else.
        assert_eq!(differing, 2, "only the edited leaf and the MAC should move");
        assert!(
            after
                .lines()
                .next()
                .unwrap_or("")
                .starts_with("alpha: ENC[")
        );
    }

    #[test]
    fn a_plaintext_file_is_refused_by_load_encrypted() {
        let err = SopsFile::load_encrypted(PLAIN).expect_err("must refuse");
        assert!(matches!(err, FileError::NotEncrypted), "got {err}");
    }

    #[test]
    fn an_encrypted_file_is_refused_by_load_plain() {
        let (_, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);
        let err = SopsFile::load_plain(&encrypted).expect_err("must refuse");
        assert!(matches!(err, FileError::AlreadyEncrypted), "got {err}");
    }

    /// A key-group file must be refused, not re-rendered without its groups —
    /// which would strip every recipient's access.
    #[test]
    fn a_key_group_file_is_refused_rather_than_stripped() {
        let src = "\
k: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]
sops:
    key_groups:
        - age:
            - recipient: age1abc
              enc: armored
    shamir_threshold: 2
    lastmodified: \"2026-08-18T00:00:00Z\"
    mac: ENC[AES256_GCM,data:a,iv:b,tag:c,type:str]
    version: 3.12.1
";
        let err = SopsFile::load_encrypted(src).expect_err("must refuse");
        assert!(matches!(err, FileError::KeyGroupsUnsupported), "got {err}");
    }

    #[test]
    fn the_indent_of_the_source_file_is_preserved() {
        let two = "outer:\n  inner: v\n";
        let (_, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(two, &recipient);
        assert!(
            encrypted.contains("\n  inner: ENC["),
            "indent 2 preserved: {encrypted}"
        );
        let f = SopsFile::load_encrypted(&encrypted).expect("load");
        assert_eq!(f.indent, 2);
    }

    #[test]
    fn a_stranger_gets_a_named_refusal_not_a_panic() {
        let (_, recipient) = fresh();
        let (stranger, _) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);
        let f = SopsFile::load_encrypted(&encrypted).expect("load");
        let err = f
            .data_key(&identities(vec![stranger]))
            .expect_err("must refuse");
        assert!(
            matches!(err, FileError::Key(KeyError::NoUsableIdentity { .. })),
            "got {err}"
        );
    }

    /// Tampering with a ciphertext must be caught. AES-GCM catches it at the leaf;
    /// this asserts the failure surfaces rather than being swallowed.
    #[test]
    fn a_tampered_leaf_fails_the_decrypt() {
        let (id, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);
        // Flip one base64 character inside the first ciphertext body.
        let idx = encrypted.find("data:").expect("a data field") + 5;
        let mut bytes = encrypted.into_bytes();
        bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).expect("utf8");

        let mut f = SopsFile::load_encrypted(&tampered).expect("load");
        let key = f.data_key(&identities(vec![id])).expect("data key");
        let mut stash = IvStash::new();
        let err = f.decrypt(&key, &mut stash).expect_err("must fail");
        assert!(
            matches!(err, FileError::Wire(WireError::AeadOpen)),
            "got {err}"
        );
    }

    /// A `mac` that does not match must fail *verification* specifically — the
    /// leaves still decrypt, which is exactly why the check is a separate step.
    #[test]
    fn a_tampered_mac_field_fails_verification_not_decryption() {
        let (id, recipient) = fresh();
        let (encrypted, _) = encrypt_fresh(PLAIN, &recipient);
        let mut f = SopsFile::load_encrypted(&encrypted).expect("load");
        f.metadata.lastmodified = "2026-08-18T00:00:01Z".to_string();

        let key = f.data_key(&identities(vec![id])).expect("data key");
        let mut stash = IvStash::new();
        let u = f.decrypt(&key, &mut stash).expect("leaves still decrypt");
        let err = u.verify(&key).expect_err("but verification must fail");
        assert_eq!(
            err,
            WireError::MacUndecryptable,
            "the AAD changed with the timestamp"
        );
    }

    #[test]
    fn multi_document_files_are_refused_with_a_count() {
        let err = SopsFile::load_plain("a: 1\n---\nb: 2\n").expect_err("must refuse");
        assert!(
            matches!(err, FileError::MultiDocument { docs: 2 }),
            "got {err}"
        );
    }
}
