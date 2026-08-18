//! The `sops:` block — and the one invariant that makes this crate worth having
//! rather than a serde struct.
//!
//! # The declared-vs-actual gap, and why it is typed away here
//!
//! Only a *current* recipient of a file can re-wrap its data key. So adding a
//! recipient to `.sops.yaml` does nothing on its own: somebody holding an
//! existing key has to run `sops updatekeys` before the ciphertext learns about
//! it. Until then the declaration and the file disagree, and **nothing says so**
//! — every tool reads the recipient list straight out of the file it is already
//! decrypting.
//!
//! This is not hypothetical. The operator's own `nix/.sops.yaml` declared an
//! admin-recovery co-recipient for `users/gabi/secrets.yaml` on 2026-07-24 and
//! it never took effect; the file carried exactly one recipient for two weeks
//! while the config claimed two, and the divergence was found by reading, not by
//! any check. The comment that eventually removed it says so outright: "a
//! DECLARATION THAT DISAGREES WITH THE CIPHERTEXT for two weeks".
//!
//! So [`Metadata`] does not have settable key arrays. It is built by
//! [`Metadata::from_wrapped`] from the set of [`WrappedKey`]s that actually
//! exist, and the arrays are a *projection* of that set. A `Metadata` whose
//! `age:` list names a recipient with no wrapped key has no constructor —
//! **truly-unrep**, in the sense `UNREPRESENTABILITY.md` reserves for an absent
//! code path rather than a guarded one.
//!
//! What this does *not* do is police `.sops.yaml`. Comparing a config's declared
//! recipients against a file's actual ones is a different job, done by the
//! reconciler a layer up; this type just makes the *emitted file* incapable of
//! lying about itself.
//!
//! # Field order is part of the format
//!
//! go-yaml marshals a struct in declaration order, so the field order in the
//! struct below **is** the byte order in every sops file ever written. It is not
//! alphabetical and must not be sorted. Two upstream inconsistencies are
//! reproduced deliberately: inside a `key_groups` entry, `hc_vault` and `age`
//! lack `omitempty` and therefore emit even when empty, while at top level they
//! do not.

use crate::WireError;
use serde::{Deserialize, Serialize};

/// A key provider that can wrap the data key.
///
/// Present as a **closed enum** even for the providers we do not yet implement,
/// because ★★ MODULARIZE, DON'T DELETE cuts both ways: a provider we cannot
/// serve should be a *named refusal*, not an unparseable file. A `sops` file
/// carrying KMS keys must round-trip through us intact even when we cannot
/// unwrap it, or aliasing us over `sops` would corrupt files on write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyProvider {
    /// X25519 age recipients. **Implemented.**
    Age,
    /// PGP fingerprints, via gpg. Declared, not implemented.
    Pgp,
    /// AWS KMS ARNs. Declared, not implemented.
    AwsKms,
    /// GCP KMS resource IDs. Declared, not implemented.
    GcpKms,
    /// HuaweiCloud KMS key IDs. Declared, not implemented.
    HuaweiKms,
    /// Azure Key Vault URLs. Declared, not implemented.
    AzureKeyVault,
    /// HashiCorp Vault transit URIs. Declared, not implemented.
    HcVault,
}

impl KeyProvider {
    /// The `sops.<field>` name this provider's keys live under.
    #[must_use]
    pub fn field(self) -> &'static str {
        match self {
            Self::Age => "age",
            Self::Pgp => "pgp",
            Self::AwsKms => "kms",
            Self::GcpKms => "gcp_kms",
            Self::HuaweiKms => "hckms",
            Self::AzureKeyVault => "azure_kv",
            Self::HcVault => "hc_vault",
        }
    }

    /// The `--decryption-order` token for this provider.
    #[must_use]
    pub fn order_token(self) -> &'static str {
        match self {
            Self::Age => "age",
            Self::Pgp => "pgp",
            Self::AwsKms => "kms",
            Self::GcpKms => "gcp_kms",
            Self::HuaweiKms => "hckms",
            Self::AzureKeyVault => "azure_kv",
            Self::HcVault => "hc_vault",
        }
    }

    /// Whether this build can actually unwrap a data key for this provider.
    ///
    /// A typed `false` rather than a missing variant: the file still parses, the
    /// key still round-trips, and the refusal is nameable at the point a caller
    /// needs a data key. That is the difference between "we do not support KMS"
    /// and "we corrupt KMS files".
    #[must_use]
    pub fn is_implemented(self) -> bool {
        matches!(self, Self::Age)
    }
}

/// One recipient's wrapped copy of the data key.
///
/// The pairing of "who" with "the bytes only they can open" is the whole point:
/// a `WrappedKey` cannot exist without its ciphertext, which is why deriving the
/// metadata's recipient lists from a set of these closes the declared-vs-actual
/// gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    provider: KeyProvider,
    /// The recipient identifier as it appears in the file: an age recipient, a
    /// PGP fingerprint, a KMS ARN, …
    recipient: String,
    /// The wrapped data key, verbatim. For age this is a fully armored age file.
    enc: String,
    /// `created_at`, for the providers that carry one. age does not.
    created_at: Option<String>,
}

impl WrappedKey {
    /// An age recipient plus its armored wrapped key.
    #[must_use]
    pub fn age(recipient: impl Into<String>, enc: impl Into<String>) -> Self {
        Self {
            provider: KeyProvider::Age,
            recipient: recipient.into(),
            enc: enc.into(),
            created_at: None,
        }
    }

    /// A key for a provider we do not unwrap, preserved so the file round-trips.
    #[must_use]
    pub fn opaque(
        provider: KeyProvider,
        recipient: impl Into<String>,
        enc: impl Into<String>,
        created_at: Option<String>,
    ) -> Self {
        Self {
            provider,
            recipient: recipient.into(),
            enc: enc.into(),
            created_at,
        }
    }

    #[must_use]
    pub fn provider(&self) -> KeyProvider {
        self.provider
    }

    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// The wrapped key bytes as they appear on the wire.
    ///
    /// Not a secret in itself — it is ciphertext, and it ships in the file.
    #[must_use]
    pub fn enc(&self) -> &str {
        &self.enc
    }

    #[must_use]
    pub fn created_at(&self) -> Option<&str> {
        self.created_at.as_deref()
    }
}

/// An `age` entry in the `sops.age` array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgeKey {
    pub recipient: String,
    pub enc: String,
}

/// The `sops:` metadata block.
///
/// Field order below is byte order in the file — see the module docs. Key arrays
/// are private and derived; see [`Metadata::from_wrapped`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// Every recipient's wrapped data key. The single source the arrays project
    /// from, so a declared recipient without a wrapped key cannot be built.
    keys: Vec<WrappedKey>,
    /// Shamir threshold, when key groups are in use.
    pub shamir_threshold: Option<u32>,
    /// `lastmodified`, kept **verbatim** as it appeared in the file.
    ///
    /// Not a parsed timestamp, and deliberately so: this string is the AAD of the
    /// `mac` field, so any normalisation we applied on the way through — `Z`
    /// becoming `+00:00`, a dropped fractional second — would silently make a
    /// valid file unreadable.
    pub lastmodified: String,
    /// The `mac` field, still in its `ENC[…]` form.
    pub mac: String,
    pub unencrypted_suffix: Option<String>,
    pub encrypted_suffix: Option<String>,
    pub unencrypted_regex: Option<String>,
    pub encrypted_regex: Option<String>,
    pub unencrypted_comment_regex: Option<String>,
    pub encrypted_comment_regex: Option<String>,
    pub mac_only_encrypted: bool,
    pub version: String,
}

impl Metadata {
    /// Build metadata from the keys that actually exist.
    ///
    /// This is the only constructor. There is no `Metadata { age: … }` literal
    /// available to a caller and no setter for a recipient list, which is what
    /// makes "declared recipients disagree with the ciphertext" unrepresentable
    /// in an emitted file.
    #[must_use]
    pub fn from_wrapped(
        keys: Vec<WrappedKey>,
        lastmodified: impl Into<String>,
        mac: impl Into<String>,
    ) -> Self {
        Self {
            keys,
            shamir_threshold: None,
            lastmodified: lastmodified.into(),
            mac: mac.into(),
            unencrypted_suffix: None,
            encrypted_suffix: None,
            unencrypted_regex: None,
            encrypted_regex: None,
            unencrypted_comment_regex: None,
            encrypted_comment_regex: None,
            mac_only_encrypted: false,
            version: crate::FORMAT_VERSION.to_string(),
        }
    }

    /// Every wrapped key, in file order.
    #[must_use]
    pub fn keys(&self) -> &[WrappedKey] {
        &self.keys
    }

    /// The wrapped keys for one provider, in file order — the projection the
    /// `sops.<provider>` array is emitted from.
    #[must_use]
    pub fn keys_for(&self, provider: KeyProvider) -> Vec<&WrappedKey> {
        self.keys
            .iter()
            .filter(|k| k.provider == provider)
            .collect()
    }

    /// The `sops.age` array, derived.
    #[must_use]
    pub fn age_keys(&self) -> Vec<AgeKey> {
        self.keys_for(KeyProvider::Age)
            .into_iter()
            .map(|k| AgeKey {
                recipient: k.recipient.clone(),
                enc: k.enc.clone(),
            })
            .collect()
    }

    /// Every provider present in this file, sorted for a stable report.
    #[must_use]
    pub fn providers(&self) -> Vec<KeyProvider> {
        let mut ps: Vec<_> = self.keys.iter().map(|k| k.provider).collect();
        ps.sort_unstable();
        ps.dedup();
        ps
    }

    /// The providers this file needs that this build cannot unwrap.
    ///
    /// Empty means every key in the file is one we could open given the right
    /// identity. Non-empty is a *refusal to name*, not a reason to guess.
    #[must_use]
    pub fn unimplemented_providers(&self) -> Vec<KeyProvider> {
        self.providers()
            .into_iter()
            .filter(|p| !p.is_implemented())
            .collect()
    }

    /// Replace the key set — a rekey or `updatekeys`.
    ///
    /// Takes the whole set rather than offering `add`/`remove`, so the arrays
    /// stay a projection of one atomically-replaced truth. Refuses an empty set:
    /// a file with no wrapped keys can never be decrypted by anyone, and
    /// producing one is how a rekey bug becomes permanent data loss.
    pub fn rewrap(&mut self, keys: Vec<WrappedKey>) -> Result<(), WireError> {
        if keys.is_empty() {
            return Err(WireError::DataKeyLength(0));
        }
        self.keys = keys;
        Ok(())
    }

    /// Build the compiled selector for this file's policy.
    ///
    /// Falls back to sops's default (`_unencrypted`) when nothing is configured,
    /// matching upstream's defaulting of `UnencryptedSuffix`.
    pub fn selector(&self) -> Result<crate::selector::EncryptionSelector, WireError> {
        let s = crate::selector::EncryptionSelector::new(
            self.unencrypted_suffix.as_deref(),
            self.encrypted_suffix.as_deref(),
            self.unencrypted_regex.as_deref(),
            self.encrypted_regex.as_deref(),
            self.unencrypted_comment_regex.as_deref(),
            self.encrypted_comment_regex.as_deref(),
        )?;
        Ok(if s.is_unconfigured() {
            crate::selector::EncryptionSelector::default_policy()
        } else {
            s
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Metadata {
        Metadata::from_wrapped(
            vec![
                WrappedKey::age(
                    "age1aaa",
                    "-----BEGIN AGE ENCRYPTED FILE-----\nA\n-----END AGE ENCRYPTED FILE-----\n",
                ),
                WrappedKey::age(
                    "age1bbb",
                    "-----BEGIN AGE ENCRYPTED FILE-----\nB\n-----END AGE ENCRYPTED FILE-----\n",
                ),
            ],
            "2026-08-18T00:00:00Z",
            "ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]",
        )
    }

    #[test]
    fn recipient_lists_are_projections_of_the_wrapped_keys() {
        let m = meta();
        let age = m.age_keys();
        assert_eq!(age.len(), 2);
        assert_eq!(age[0].recipient, "age1aaa");
        assert_eq!(age[1].recipient, "age1bbb");
    }

    /// The gabi defect, as a test. There is no way to *write* this state, so the
    /// test asserts the shape of the API rather than catching a bad value: the
    /// only route to a recipient list is through keys that carry ciphertext.
    #[test]
    fn a_recipient_cannot_exist_without_its_wrapped_key() {
        let m = meta();
        for k in m.age_keys() {
            assert!(
                !k.enc.is_empty(),
                "a projected recipient always carries its wrapped key"
            );
        }
        // Adding a recipient means adding a WrappedKey, which requires the
        // ciphertext. `rewrap` takes the whole set; there is no `add_recipient`.
        let mut m2 = meta();
        m2.rewrap(vec![WrappedKey::age(
            "age1ccc",
            "-----BEGIN AGE ENCRYPTED FILE-----\nC\n-----END AGE ENCRYPTED FILE-----\n",
        )])
        .expect("rewrap");
        assert_eq!(m2.age_keys().len(), 1);
        assert_eq!(m2.age_keys()[0].recipient, "age1ccc");
    }

    /// A file nobody can decrypt is the one rekey outcome that is unrecoverable.
    #[test]
    fn rewrapping_to_nothing_is_refused() {
        let mut m = meta();
        assert!(m.rewrap(vec![]).is_err());
        assert_eq!(m.age_keys().len(), 2, "the refusal left the file intact");
    }

    #[test]
    fn an_unimplemented_provider_is_named_not_dropped() {
        let mut m = meta();
        m.rewrap(vec![
            WrappedKey::age("age1aaa", "enc"),
            WrappedKey::opaque(
                KeyProvider::AwsKms,
                "arn:aws:kms:us-east-2:1:key/abc",
                "CiA…",
                Some("2026-01-01T00:00:00Z".into()),
            ),
        ])
        .expect("rewrap");
        assert_eq!(m.unimplemented_providers(), vec![KeyProvider::AwsKms]);
        // and the key is still there to be written back out
        assert_eq!(m.keys_for(KeyProvider::AwsKms).len(), 1);
        assert_eq!(
            m.keys_for(KeyProvider::AwsKms)[0].created_at(),
            Some("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn an_all_age_file_has_nothing_unimplemented() {
        assert!(meta().unimplemented_providers().is_empty());
    }

    #[test]
    fn provider_field_names_match_the_wire() {
        assert_eq!(KeyProvider::Age.field(), "age");
        assert_eq!(KeyProvider::AwsKms.field(), "kms");
        assert_eq!(KeyProvider::GcpKms.field(), "gcp_kms");
        assert_eq!(KeyProvider::HuaweiKms.field(), "hckms");
        assert_eq!(KeyProvider::AzureKeyVault.field(), "azure_kv");
        assert_eq!(KeyProvider::HcVault.field(), "hc_vault");
        assert_eq!(KeyProvider::Pgp.field(), "pgp");
    }

    #[test]
    fn lastmodified_is_kept_verbatim() {
        // Deliberately a shape a normaliser would "improve".
        let m =
            Metadata::from_wrapped(vec![WrappedKey::age("a", "e")], "2026-08-18T00:00:00Z", "m");
        assert_eq!(m.lastmodified, "2026-08-18T00:00:00Z");
    }

    #[test]
    fn an_unconfigured_file_gets_the_default_policy() {
        let s = meta().selector().expect("selector");
        assert!(
            !s.is_unconfigured(),
            "must have fallen back to the _unencrypted default"
        );
    }
}
