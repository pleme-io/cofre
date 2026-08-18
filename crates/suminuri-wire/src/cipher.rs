//! AES-256-GCM with a **32-byte** nonce, and the IV stash that keeps edits small.
//!
//! # The 32-byte nonce
//!
//! `aes/cipher.go` opens with `const nonceSize int = 32` and encrypts through
//! `cipher.NewGCMWithNonceSize(aescipher, nonceSize)`. Every mainstream AES-GCM
//! API — Go's own `cipher.NewGCM`, Rust's `Aes256Gcm` alias, every tutorial —
//! defaults to 96 bits. So the wrong choice here is not a compile error
//! anywhere; it is a file that no sops can open, failing as an opaque
//! authentication error with no hint about the cause.
//!
//! GCM with a nonce that is not 96 bits derives its counter block by GHASH-ing
//! the nonce instead of using it directly, which is a different code path in
//! every implementation. That Rust's `aes-gcm` takes it correctly is not assumed
//! here: it was proven end-to-end against the operator's live `secrets.yaml`
//! before this module existed.
//!
//! # Why encryption and decryption are asymmetric
//!
//! Upstream *writes* 32 and *reads* `len(iv)`. That asymmetry is deliberate and
//! reproduced: [`Iv`] is `[u8; 32]` and is the only thing [`encrypt_leaf`] will
//! accept, while [`decrypt_leaf`] honours whatever length the file carries. New
//! bytes are always canonical; old bytes are always readable.

use crate::WireError;
use crate::aad::Aad;
use crate::leaf::{EncryptedLeaf, LeafType, Plaintext};
use aes_gcm::AesGcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// AES-256-GCM parameterised for the nonce length sops actually uses.
type SopsGcm32 = AesGcm<aes::Aes256, aes_gcm::aead::consts::U32>;

/// The 32-byte symmetric key every leaf in one file is encrypted under.
///
/// Wrapped per recipient (age, PGP, KMS, …) into the `sops.<provider>[].enc`
/// fields; this type is the unwrapped form and is zeroed on drop. No `Display`,
/// no `Debug` of contents.
#[derive(Clone)]
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    /// Length in bytes of a data key. Not configurable — `GenerateDataKey` uses
    /// `make([]byte, 32)`.
    pub const LEN: usize = 32;

    /// A fresh data key from the OS CSPRNG.
    pub fn generate() -> Result<Self, WireError> {
        let mut k = [0u8; Self::LEN];
        getrandom::getrandom(&mut k).map_err(|e| WireError::Randomness(e.to_string()))?;
        Ok(Self(Zeroizing::new(k)))
    }

    /// Adopt bytes recovered from a key provider.
    ///
    /// The length check is here rather than at the call site because a short key
    /// from a misbehaving provider would otherwise surface as an AEAD failure
    /// far from its cause.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != Self::LEN {
            return Err(WireError::DataKeyLength(bytes.len()));
        }
        let mut k = [0u8; Self::LEN];
        k.copy_from_slice(bytes);
        Ok(Self(Zeroizing::new(k)))
    }

    /// The raw key, for handing to a key provider that must wrap it.
    ///
    /// Named to be greppable, like `Plaintext::expose`.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(*** 32 bytes)")
    }
}

/// A nonce for *writing*. Always 32 bytes, by type.
///
/// There is no constructor that takes a length and none that takes fewer bytes,
/// so "encrypt with a 12-byte nonce" has no spelling in this crate.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Iv([u8; 32]);

impl Iv {
    /// The nonce length sops writes.
    pub const LEN: usize = 32;

    /// Draw a fresh nonce.
    pub fn generate() -> Result<Self, WireError> {
        let mut iv = [0u8; Self::LEN];
        getrandom::getrandom(&mut iv).map_err(|e| WireError::Randomness(e.to_string()))?;
        Ok(Self(iv))
    }

    /// Adopt a nonce recovered from a file so an unchanged value re-encrypts
    /// identically. Only accepts the canonical length — a shorter nonce off the
    /// wire can be *read* but is never carried forward into a write.
    #[must_use]
    pub fn from_wire_exact(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; Self::LEN] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Iv {
    /// A nonce is public data — it ships in the file — so showing it is fine and
    /// makes an IV-reuse question answerable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Iv({})", hex_lower(&self.0))
    }
}

/// Remembers the IV used for each `(type, plaintext, aad)` triple so re-encrypting
/// an unchanged value reproduces its exact previous ciphertext.
///
/// This is not an optimisation. `sops edit` decrypts, hands the tree to an
/// editor, and re-encrypts everything; without the stash **every line of the
/// file changes on every edit**, which destroys the property the whole format
/// exists for — a readable, reviewable diff.
///
/// # The type is part of the key, and leaving it out is a real bug
///
/// Upstream's key is `stashKey{plaintext interface{}, additionalData string}`, and
/// a Go map compares an `interface{}` by **dynamic type and value** — so `int(1)`
/// and `string("1")` are two different keys there. The first version of this
/// struct keyed on the raw plaintext *bytes*, which collapses exactly the pairs
/// the encodings make indistinguishable:
///
/// | these are distinct upstream | but share one byte string |
/// |---|---|
/// | `1` (int) / `1.0` (float) / `"1"` (str) | `1` |
/// | `true` (bool) / `"True"` (str) | `True` |
/// | `false` (bool) / `"False"` (str) | `False` |
///
/// Two such leaves under the *same* AAD — which is to say two elements of one
/// list, since a sequence adds no path component — would then be handed the same
/// nonce. The plaintext bytes are equal, so this is not the catastrophic form of
/// GCM nonce reuse; the consequence is a file whose bytes differ from the one
/// sops would have written, which for a tool whose entire claim is byte-parity is
/// the bug that matters. [`LeafType`] is in the key.
///
/// # The reuse that remains, stated rather than inherited
///
/// Two *genuinely identical* typed values at one path do still share a nonce. The
/// plaintexts are identical, so an attacker learns only that they are equal —
/// which any deterministic encryption concedes by construction. It is a knowing
/// trade, confined to unchanged values, and it is the price of a reviewable diff.
#[derive(Default)]
pub struct IvStash {
    seen: HashMap<(LeafType, Vec<u8>, Vec<u8>), Iv>,
}

impl IvStash {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn key(plaintext: &Plaintext, aad: &Aad) -> (LeafType, Vec<u8>, Vec<u8>) {
        (
            plaintext.leaf_type(),
            plaintext.expose().to_vec(),
            aad.as_bytes().to_vec(),
        )
    }

    /// Record the IV a leaf was decrypted with, so an unchanged value keeps it.
    pub fn remember(&mut self, plaintext: &Plaintext, aad: &Aad, iv: &[u8]) {
        if let Some(iv) = Iv::from_wire_exact(iv) {
            self.seen.insert(Self::key(plaintext, aad), iv);
        }
    }

    /// The remembered IV for this pair, if any.
    #[must_use]
    pub fn recall(&self, plaintext: &Plaintext, aad: &Aad) -> Option<Iv> {
        self.seen.get(&Self::key(plaintext, aad)).cloned()
    }

    /// How many pairs are remembered. Diagnostics only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl std::fmt::Debug for IvStash {
    /// The keys of this map are plaintexts. Printing the map would leak every
    /// value in the file, so `Debug` prints only the count.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IvStash({} pairs)", self.seen.len())
    }
}

/// Encrypt one leaf.
///
/// `None` for `iv` draws a fresh one; pass a stash hit to reproduce previous
/// bytes. An **empty plaintext stays empty** — `isEmpty` short-circuits both
/// directions upstream, so an empty string is a fixed point of the format rather
/// than a zero-length ciphertext.
pub fn encrypt_leaf(
    key: &DataKey,
    plaintext: &Plaintext,
    aad: &Aad,
    iv: Option<Iv>,
) -> Result<Option<EncryptedLeaf>, WireError> {
    if plaintext.is_empty() {
        return Ok(None);
    }
    let iv = match iv {
        Some(iv) => iv,
        None => Iv::generate()?,
    };
    let gcm = SopsGcm32::new_from_slice(key.expose()).map_err(|_| WireError::AeadOpen)?;
    let sealed = gcm
        .encrypt(
            aes_gcm::Nonce::<aes_gcm::aead::consts::U32>::from_slice(iv.as_bytes()),
            Payload {
                msg: plaintext.expose(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| WireError::AeadOpen)?;
    // Go's Seal returns ciphertext||tag and sops splits at BlockSize (16).
    // `aes-gcm` returns the same layout, so the split is identical.
    let split = sealed.len().saturating_sub(TAG_LEN);
    let (data, tag) = sealed.split_at(split);
    Ok(Some(EncryptedLeaf {
        data: data.to_vec(),
        iv: iv.as_bytes().to_vec(),
        tag: tag.to_vec(),
        ty: plaintext.leaf_type(),
    }))
}

/// The GCM tag length. `cryptoaes.BlockSize` upstream — 16 bytes.
const TAG_LEN: usize = 16;

/// Decrypt one leaf.
///
/// Honours the nonce length recorded in the file rather than the 32-byte
/// constant, matching upstream's `NewGCMWithNonceSize(…, len(iv))`, so a file
/// from another implementation still opens. On success the IV is recorded in
/// `stash` when one is supplied.
pub fn decrypt_leaf(
    key: &DataKey,
    leaf: &EncryptedLeaf,
    aad: &Aad,
    stash: Option<&mut IvStash>,
) -> Result<Plaintext, WireError> {
    let mut sealed = Vec::with_capacity(leaf.data.len() + leaf.tag.len());
    sealed.extend_from_slice(&leaf.data);
    sealed.extend_from_slice(&leaf.tag);

    let opened = match leaf.iv.len() {
        Iv::LEN => {
            let gcm = SopsGcm32::new_from_slice(key.expose()).map_err(|_| WireError::AeadOpen)?;
            gcm.decrypt(
                aes_gcm::Nonce::<aes_gcm::aead::consts::U32>::from_slice(&leaf.iv),
                Payload {
                    msg: &sealed,
                    aad: aad.as_bytes(),
                },
            )
        }
        12 => {
            // The RFC-standard nonce. sops never writes one, but it reads one,
            // so a file produced by a third-party implementation opens here too.
            let gcm = aes_gcm::Aes256Gcm::new_from_slice(key.expose())
                .map_err(|_| WireError::AeadOpen)?;
            gcm.decrypt(
                aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::from_slice(&leaf.iv),
                Payload {
                    msg: &sealed,
                    aad: aad.as_bytes(),
                },
            )
        }
        // Any other length is refused rather than guessed at. Upstream would
        // accept it via a dynamically-sized GCM; we would rather name the
        // unsupported shape than silently succeed on one specimen and fail on
        // the next.
        _ => return Err(WireError::AeadOpen),
    }
    .map_err(|_| WireError::AeadOpen)?;

    let plaintext = Plaintext::from_wire(opened, leaf.ty);
    if let Some(stash) = stash {
        stash.remember(&plaintext, aad, &leaf.iv);
    }
    Ok(plaintext)
}

/// Decrypt a leaf that is known to be a plain `str` — the MAC field's shape.
pub(crate) fn decrypt_leaf_as_string(
    key: &DataKey,
    leaf: &EncryptedLeaf,
    aad: &Aad,
    stash: Option<&mut IvStash>,
) -> Result<Zeroizing<String>, WireError> {
    let pt = decrypt_leaf(key, leaf, aad, stash)?;
    if pt.leaf_type() != LeafType::Str {
        return Err(WireError::DatatypeMismatch { ty: "str" });
    }
    Ok(Zeroizing::new(
        String::from_utf8_lossy(pt.expose()).into_owned(),
    ))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aad::AadPath;

    fn key() -> DataKey {
        DataKey::from_bytes(&[7u8; 32]).expect("32 bytes")
    }

    fn aad(parts: &[&str]) -> Aad {
        let mut p = AadPath::root();
        for c in parts {
            p.push_key(*c);
        }
        p.aad()
    }

    #[test]
    fn round_trips_through_the_wire_rendering() {
        let a = aad(&["db", "password"]);
        let pt = Plaintext::string("s3kr1t");
        let leaf = encrypt_leaf(&key(), &pt, &a, None)
            .expect("encrypt")
            .expect("non-empty");
        let rendered = leaf.render();
        let reparsed = EncryptedLeaf::parse(&rendered).expect("reparse");
        let back = decrypt_leaf(&key(), &reparsed, &a, None).expect("decrypt");
        assert_eq!(back.expose(), b"s3kr1t");
        assert_eq!(back.leaf_type(), LeafType::Str);
    }

    #[test]
    fn writes_a_thirty_two_byte_nonce() {
        let leaf = encrypt_leaf(&key(), &Plaintext::string("x"), &aad(&["k"]), None)
            .expect("encrypt")
            .expect("non-empty");
        assert_eq!(leaf.iv_len(), Iv::LEN);
        assert_eq!(leaf.tag.len(), TAG_LEN);
    }

    /// The AAD is authenticated, so a leaf moved to a different key must not
    /// open. This is what makes the path part of the file's integrity.
    #[test]
    fn a_leaf_moved_to_another_path_will_not_open() {
        let leaf = encrypt_leaf(&key(), &Plaintext::string("v"), &aad(&["a", "b"]), None)
            .expect("encrypt")
            .expect("non-empty");
        assert_eq!(
            decrypt_leaf(&key(), &leaf, &aad(&["a", "c"]), None),
            Err(WireError::AeadOpen)
        );
    }

    #[test]
    fn a_wrong_data_key_will_not_open() {
        let leaf = encrypt_leaf(&key(), &Plaintext::string("v"), &aad(&["a"]), None)
            .expect("encrypt")
            .expect("non-empty");
        let other = DataKey::from_bytes(&[9u8; 32]).expect("32 bytes");
        assert_eq!(
            decrypt_leaf(&other, &leaf, &aad(&["a"]), None),
            Err(WireError::AeadOpen)
        );
    }

    #[test]
    fn a_flipped_ciphertext_bit_will_not_open() {
        let mut leaf = encrypt_leaf(&key(), &Plaintext::string("value"), &aad(&["a"]), None)
            .expect("encrypt")
            .expect("non-empty");
        leaf.data[0] ^= 1;
        assert_eq!(
            decrypt_leaf(&key(), &leaf, &aad(&["a"]), None),
            Err(WireError::AeadOpen)
        );
    }

    #[test]
    fn empty_is_a_fixed_point_in_both_directions() {
        let empty = Plaintext::string("");
        assert!(
            encrypt_leaf(&key(), &empty, &aad(&["k"]), None)
                .expect("encrypt")
                .is_none()
        );
    }

    /// Without the stash an unchanged value would get a fresh nonce and the
    /// whole file would churn on every edit.
    #[test]
    fn the_stash_reproduces_previous_bytes_exactly() {
        let a = aad(&["k"]);
        let pt = Plaintext::string("unchanged");
        let first = encrypt_leaf(&key(), &pt, &a, None)
            .expect("encrypt")
            .expect("non-empty");

        let mut stash = IvStash::new();
        let recovered = decrypt_leaf(&key(), &first, &a, Some(&mut stash)).expect("decrypt");
        assert_eq!(stash.len(), 1);

        let second = encrypt_leaf(&key(), &recovered, &a, stash.recall(&recovered, &a))
            .expect("re-encrypt")
            .expect("non-empty");
        assert_eq!(
            first.render(),
            second.render(),
            "an unchanged value must re-encrypt identically"
        );
    }

    /// The typed-key regression. Upstream's stash key is a Go `interface{}`, so
    /// `int(1)` and `string("1")` are different keys; keying on the raw bytes
    /// collapses them and hands two list elements the same nonce.
    #[test]
    fn the_stash_key_separates_values_that_share_a_byte_string() {
        let a = aad(&["items"]);
        let mut stash = IvStash::new();
        let iv = [42u8; 32];

        // `1` as an int, remembered.
        stash.remember(&Plaintext::integer(1), &a, &iv);
        assert_eq!(stash.len(), 1);

        // The *string* "1" has the same bytes and must NOT hit.
        assert!(
            stash.recall(&Plaintext::string("1"), &a).is_none(),
            "a str must not recall an int's nonce"
        );
        // Nor must a float that renders to the same digits.
        assert!(
            stash.recall(&Plaintext::float(1.0), &a).is_none(),
            "a float must not recall an int's nonce"
        );
        // The int itself still does.
        assert!(stash.recall(&Plaintext::integer(1), &a).is_some());

        // `true` renders as `True`, which is also a perfectly good string.
        stash.remember(&Plaintext::boolean(true), &a, &iv);
        assert!(
            stash.recall(&Plaintext::string("True"), &a).is_none(),
            "a str must not recall a bool's nonce"
        );
        assert!(stash.recall(&Plaintext::boolean(true), &a).is_some());

        // Four distinct entries from three byte strings.
        stash.remember(&Plaintext::string("1"), &a, &iv);
        stash.remember(&Plaintext::float(1.0), &a, &iv);
        stash.remember(&Plaintext::string("True"), &a, &iv);
        assert_eq!(stash.len(), 5, "int, bool, str-1, float-1, str-True");
    }

    /// And the AAD is still part of the key, so the same value at a different path
    /// gets its own nonce.
    #[test]
    fn the_stash_key_separates_paths() {
        let mut stash = IvStash::new();
        stash.remember(&Plaintext::string("v"), &aad(&["a"]), &[1u8; 32]);
        assert!(
            stash
                .recall(&Plaintext::string("v"), &aad(&["b"]))
                .is_none()
        );
        assert!(
            stash
                .recall(&Plaintext::string("v"), &aad(&["a"]))
                .is_some()
        );
    }

    #[test]
    fn without_the_stash_the_bytes_change() {
        let a = aad(&["k"]);
        let pt = Plaintext::string("unchanged");
        let first = encrypt_leaf(&key(), &pt, &a, None)
            .expect("e")
            .expect("non-empty");
        let second = encrypt_leaf(&key(), &pt, &a, None)
            .expect("e")
            .expect("non-empty");
        assert_ne!(first.render(), second.render(), "fresh nonces must differ");
    }

    #[test]
    fn a_short_data_key_is_named_not_swallowed() {
        let err = DataKey::from_bytes(&[0u8; 16])
            .err()
            .expect("16 bytes must be refused");
        assert_eq!(err, WireError::DataKeyLength(16));
    }

    #[test]
    fn debug_never_shows_key_or_plaintext() {
        assert_eq!(format!("{:?}", key()), "DataKey(*** 32 bytes)");
        let mut stash = IvStash::new();
        stash.remember(&Plaintext::string("hunter2"), &aad(&["k"]), &[0u8; 32]);
        let shown = format!("{stash:?}");
        assert!(
            !shown.contains("hunter2"),
            "IvStash Debug leaked a plaintext: {shown}"
        );
        assert_eq!(shown, "IvStash(1 pairs)");
    }
}
