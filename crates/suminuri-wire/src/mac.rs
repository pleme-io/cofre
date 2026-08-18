//! The file MAC — and it is a bare SHA-512, not an HMAC.
//!
//! That is worth saying twice, because "MAC" reads as "keyed" to anyone who has
//! met one before. `sops.go` imports `crypto/sha512` and calls `sha512.New()`;
//! there is no key in the construction at all. The *integrity* comes from the
//! second step: the resulting digest string is itself AES-GCM-encrypted under
//! the data key, with `sops.lastmodified` as its AAD. So the file is bound to
//! its own timestamp, and only a holder of the data key can produce a MAC field
//! that verifies.
//!
//! ```text
//! digest      = SHA512( [sha256("sops") if mac_only_encrypted] ||
//!                       ToBytes(leaf₀) || ToBytes(leaf₁) || … )
//! sops.mac    = ENC[…,type:str]  of  UPPERCASE_HEX(digest),  AAD = RFC3339(lastmodified)
//! ```
//!
//! Three rules the accumulator encodes:
//!
//! - **order matters.** Leaves are fed in tree-walk order, so reordering two
//!   mapping keys invalidates the file. This is why the YAML layer must preserve
//!   key order and cannot round-trip through a `HashMap`.
//! - **comments never contribute.** Both `Encrypt` and `Decrypt` guard the
//!   `hash.Write` with "only add to MAC if not a comment", even when the comment
//!   itself is encrypted.
//! - **the `sops:` block is outside the MAC.** The metadata key is never walked,
//!   which is what lets the MAC field live inside the structure it covers.

use crate::WireError;
use crate::aad::Aad;
use crate::cipher::{DataKey, Iv, decrypt_leaf_as_string, encrypt_leaf};
use crate::leaf::{EncryptedLeaf, Plaintext};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

/// `sha256(b"sops")`, the pre-seed for a `mac_only_encrypted` digest.
///
/// It exists so a MAC computed with the setting on can never collide with one
/// computed with it off — otherwise flipping the flag on a file whose every leaf
/// happens to be encrypted would produce the same digest, and the two policies
/// would be indistinguishable. Upstream calls it `MACOnlyEncryptedInitialization`
/// and documents the derivation as `echo -n sops | sha256sum`.
pub const MAC_ONLY_ENCRYPTED_SEED: [u8; 32] = [
    0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0x0b,
    0x0b, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6, 0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69,
];

/// A computed file MAC: 128 uppercase hex characters.
///
/// The inner string is private and [`PartialEq`] routes through
/// `subtle::ConstantTimeEq`, so there is no non-constant-time way to compare two
/// of these. Upstream uses Go's `!=`; the verdict is identical and the timing
/// channel is gone — a strict improvement that costs nothing at the wire.
#[derive(Clone)]
pub struct Mac(String);

impl Mac {
    /// The uppercase-hex rendering, for writing into the file.
    ///
    /// A MAC is not a secret — it ships in the file, encrypted only to bind it to
    /// the data key — so exposing the string is fine. Comparing it as a plain
    /// string is what is prevented, and that is done by making [`PartialEq`] the
    /// only comparison available.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Adopt a MAC recovered from a file's decrypted `mac` field.
    #[must_use]
    pub fn from_file(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// Whether this MAC is the empty string, which upstream reports as "no MAC"
    /// rather than as a mismatch against nothing.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        self.0.is_empty()
    }
}

impl PartialEq for Mac {
    fn eq(&self, other: &Self) -> bool {
        // Length is public (always 128 for a real MAC), so an early length
        // check leaks nothing and keeps the byte compare well-defined.
        self.0.len() == other.0.len() && self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for Mac {}

impl std::fmt::Debug for Mac {
    /// Elided in the middle. A MAC is not secret, but a full 128-char digest in
    /// a log line is noise, and printing both ends is what makes a mismatch
    /// eyeball-comparable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.len() > 24 {
            write!(f, "Mac({}…{})", &self.0[..16], &self.0[self.0.len() - 8..])
        } else {
            write!(f, "Mac({})", self.0)
        }
    }
}

/// Accumulates leaf plaintexts into a file MAC, in walk order.
///
/// Construct with [`MacAccumulator::new`], feed every non-comment leaf the
/// selector said to include, then [`MacAccumulator::finish`].
pub struct MacAccumulator {
    hash: Sha512,
    mac_only_encrypted: bool,
    fed: usize,
}

impl MacAccumulator {
    /// Start a MAC. `mac_only_encrypted` pre-seeds the digest and changes which
    /// leaves the caller should feed.
    #[must_use]
    pub fn new(mac_only_encrypted: bool) -> Self {
        let mut hash = Sha512::new();
        if mac_only_encrypted {
            hash.update(MAC_ONLY_ENCRYPTED_SEED);
        }
        Self {
            hash,
            mac_only_encrypted,
            fed: 0,
        }
    }

    /// Whether this accumulator is in `mac_only_encrypted` mode, so a walker can
    /// ask rather than thread the flag separately.
    #[must_use]
    pub fn mac_only_encrypted(&self) -> bool {
        self.mac_only_encrypted
    }

    /// Feed one leaf.
    ///
    /// The caller owns the two policy decisions — comments are excluded, and
    /// under `mac_only_encrypted` only leaves that end up encrypted count —
    /// because both depend on the selector, which lives a layer up.
    pub fn feed(&mut self, plaintext: &Plaintext) {
        self.hash.update(plaintext.mac_bytes());
        self.fed += 1;
    }

    /// How many leaves were fed. **The denominator.**
    ///
    /// A MAC over zero leaves is a perfectly valid SHA-512 and will happily
    /// match another MAC over zero leaves, so a walker that silently stopped
    /// finding leaves would verify green while checking nothing. Callers that
    /// gate on this MAC should assert the count is what they expect — the same
    /// anti-vacuity discipline the fleet's Nix gates carry.
    #[must_use]
    pub fn leaves_fed(&self) -> usize {
        self.fed
    }

    /// Finish the digest. `fmt.Sprintf("%X", …)` — uppercase, 128 chars.
    #[must_use]
    pub fn finish(self) -> Mac {
        use std::fmt::Write as _;
        let digest = self.hash.finalize();
        Mac(digest.iter().fold(String::with_capacity(128), |mut s, b| {
            let _ = write!(s, "{b:02X}");
            s
        }))
    }
}

/// The AAD under which the `sops.mac` field itself is encrypted: the RFC 3339
/// rendering of `sops.lastmodified`, verbatim from the file.
///
/// Taking the string straight from the file rather than re-formatting a parsed
/// timestamp is deliberate — any normalisation we applied (a `Z` becoming
/// `+00:00`, a dropped fractional second) would change the AAD and make a valid
/// file unreadable. Upstream computes it from a parsed `time.Time`, which is why
/// hand-editing `lastmodified` invalidates a file.
#[must_use]
pub fn mac_field_aad(lastmodified_verbatim: &str) -> Aad {
    // The MAC field's AAD is not a path, so it is built through the
    // crate-private `Aad::field` rather than through `AadPath` — the one
    // legitimate second source of an `Aad`, reachable only from here.
    Aad::field(lastmodified_verbatim)
}

/// Decrypt a file's `mac` field and compare it against a recomputed MAC.
///
/// Returns the file's MAC on success so a caller can report both sides.
pub fn verify_mac_field(
    key: &DataKey,
    mac_field: &str,
    lastmodified_verbatim: &str,
    computed: &Mac,
) -> Result<Mac, WireError> {
    verify_mac_field_recording(key, mac_field, lastmodified_verbatim, computed, None)
}

/// [`verify_mac_field`], recording the MAC field's own IV into a stash.
///
/// Upstream gets this for free: the `mac` field goes through the **same `Cipher`
/// instance** as every leaf, so decrypting it populates that Cipher's stash and a
/// later re-encrypt of an unchanged MAC reproduces the identical line. Splitting
/// the MAC out into free functions here lost that for nothing, and the symptom was
/// subtle — a no-op re-encrypt whose every *data* line was byte-identical and
/// whose `mac:` line alone had moved.
///
/// It only bites when the timestamp is unchanged too, since `lastmodified` is the
/// AAD: a normal `edit` stamps a new one and the line legitimately changes. The
/// cases where it matters are a same-second re-encrypt and a fixed-clock test —
/// and a property that holds only when nobody looks closely is not a property.
pub fn verify_mac_field_recording(
    key: &DataKey,
    mac_field: &str,
    lastmodified_verbatim: &str,
    computed: &Mac,
    stash: Option<&mut crate::cipher::IvStash>,
) -> Result<Mac, WireError> {
    let leaf = EncryptedLeaf::parse(mac_field).map_err(|_| WireError::MacUndecryptable)?;
    let aad = mac_field_aad(lastmodified_verbatim);
    let stored =
        decrypt_leaf_as_string(key, &leaf, &aad, stash).map_err(|_| WireError::MacUndecryptable)?;
    let stored = Mac::from_file(stored.as_str());
    if stored == *computed {
        Ok(stored)
    } else {
        Err(WireError::MacMismatch)
    }
}

/// Encrypt a computed MAC into the `sops.mac` field value.
pub fn seal_mac_field(
    key: &DataKey,
    mac: &Mac,
    lastmodified_verbatim: &str,
    iv: Option<Iv>,
) -> Result<String, WireError> {
    let aad = mac_field_aad(lastmodified_verbatim);
    let pt = Plaintext::string(mac.as_hex());
    let leaf = encrypt_leaf(key, &pt, &aad, iv)?.ok_or(WireError::MacUndecryptable)?;
    Ok(leaf.render())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seed_is_sha256_of_the_word_sops() {
        use sha2::Sha256;
        let mut h = Sha256::new();
        h.update(b"sops");
        assert_eq!(h.finalize().as_slice(), MAC_ONLY_ENCRYPTED_SEED);
    }

    #[test]
    fn digest_is_128_uppercase_hex_chars() {
        let mut acc = MacAccumulator::new(false);
        acc.feed(&Plaintext::string("a"));
        let mac = acc.finish();
        assert_eq!(mac.as_hex().len(), 128);
        assert!(
            mac.as_hex()
                .chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        );
    }

    /// The known-answer test. SHA-512 of the single byte "a", uppercase, is a
    /// published constant — so this pins the digest to the algorithm rather than
    /// to our own implementation of it.
    #[test]
    fn known_answer_for_a_single_leaf() {
        let mut acc = MacAccumulator::new(false);
        acc.feed(&Plaintext::string("a"));
        assert_eq!(
            acc.finish().as_hex(),
            "1F40FC92DA241694750979EE6CF582F2D5D7D28E18335DE05ABC54D0560E0F5302860C652BF08D560252AA5E74210546F369FBBBCE8C12CFC7957B2652FE9A75"
        );
    }

    #[test]
    fn the_seed_changes_the_digest() {
        let plain = {
            let mut a = MacAccumulator::new(false);
            a.feed(&Plaintext::string("x"));
            a.finish()
        };
        let seeded = {
            let mut a = MacAccumulator::new(true);
            a.feed(&Plaintext::string("x"));
            a.finish()
        };
        assert_ne!(plain, seeded, "the seed exists precisely to separate these");
    }

    /// Order is part of the file's integrity. If this ever passes, the YAML
    /// layer is free to reorder keys and it is not.
    #[test]
    fn order_changes_the_digest() {
        let ab = {
            let mut a = MacAccumulator::new(false);
            a.feed(&Plaintext::string("a"));
            a.feed(&Plaintext::string("b"));
            a.finish()
        };
        let ba = {
            let mut a = MacAccumulator::new(false);
            a.feed(&Plaintext::string("b"));
            a.feed(&Plaintext::string("a"));
            a.finish()
        };
        assert_ne!(ab, ba);
    }

    /// The concatenation is unseparated, which means `["ab"]` and `["a","b"]`
    /// collide. That is upstream's behaviour and it is reproduced knowingly —
    /// documented here so nobody "fixes" it and breaks every existing file.
    #[test]
    fn concatenation_is_unseparated_upstream_collision_included() {
        let joined = {
            let mut a = MacAccumulator::new(false);
            a.feed(&Plaintext::string("ab"));
            a.finish()
        };
        let split = {
            let mut a = MacAccumulator::new(false);
            a.feed(&Plaintext::string("a"));
            a.feed(&Plaintext::string("b"));
            a.finish()
        };
        assert_eq!(joined, split, "reproduced, not endorsed");
    }

    #[test]
    fn the_denominator_is_reported() {
        let mut acc = MacAccumulator::new(false);
        assert_eq!(acc.leaves_fed(), 0);
        acc.feed(&Plaintext::string("a"));
        acc.feed(&Plaintext::string("b"));
        assert_eq!(acc.leaves_fed(), 2);
    }

    #[test]
    fn mac_field_round_trips_and_binds_to_lastmodified() {
        let key = DataKey::from_bytes(&[3u8; 32]).expect("32");
        let mut acc = MacAccumulator::new(false);
        acc.feed(&Plaintext::string("value"));
        let mac = acc.finish();
        let ts = "2026-08-18T12:00:00Z";

        let field = seal_mac_field(&key, &mac, ts, None).expect("seal");
        assert_eq!(
            verify_mac_field(&key, &field, ts, &mac).expect("verify"),
            mac
        );

        // A different timestamp is a different AAD, so the field will not open —
        // which is exactly why hand-editing lastmodified breaks a file.
        assert_eq!(
            verify_mac_field(&key, &field, "2026-08-18T12:00:01Z", &mac),
            Err(WireError::MacUndecryptable)
        );
    }

    #[test]
    fn a_changed_leaf_is_a_mismatch_not_an_undecryptable_field() {
        let key = DataKey::from_bytes(&[3u8; 32]).expect("32");
        let ts = "2026-08-18T12:00:00Z";
        let original = {
            let mut a = MacAccumulator::new(false);
            a.feed(&Plaintext::string("before"));
            a.finish()
        };
        let field = seal_mac_field(&key, &original, ts, None).expect("seal");
        let tampered = {
            let mut a = MacAccumulator::new(false);
            a.feed(&Plaintext::string("after"));
            a.finish()
        };
        assert_eq!(
            verify_mac_field(&key, &field, ts, &tampered),
            Err(WireError::MacMismatch)
        );
    }

    #[test]
    fn debug_elides_the_middle() {
        let mut acc = MacAccumulator::new(false);
        acc.feed(&Plaintext::string("a"));
        let shown = format!("{:?}", acc.finish());
        assert!(shown.starts_with("Mac(1F40FC92DA241694…"), "got {shown}");
    }
}
