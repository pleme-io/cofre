//! `suminuri-wire` — 墨塗り, "ink-blacked": the sops-compatible encrypted-file
//! wire format as a **typed border**.
//!
//! A 墨塗り document is one whose *structure stays readable* while each *value*
//! is blacked out in place. That is exactly what a sops file is, and it is the
//! whole reason the format exists rather than encrypting the file as a blob:
//! the keys, the shape and the diff survive.
//!
//! # What this crate is
//!
//! The pure half. It owns the bytes-on-disk contract and nothing else — no
//! filesystem, no clock, no randomness beyond IV generation, no key providers,
//! no CLI. Everything that touches the outside world lives behind the
//! `Environment` seam in `suminuri` proper.
//!
//! Every claim encoded here was **measured** against the sops v3 Go source and
//! then proven end-to-end against the operator's own live files: 272 leaves of
//! `nix/secrets.yaml` decrypt with a byte-exact MAC, and the one file whose data
//! key is not ours is *refused* rather than silently passed. The full spec, with
//! the file:line citations behind each rule, is `docs/WIRE-FORMAT.md`.
//!
//! # The illegal states that have no code path here
//!
//! Named first, then removed — the ordering `UNREPRESENTABILITY.md` §IV asks for.
//!
//! 1. **A 12-byte nonce.** sops uses a **32-byte** GCM nonce ([`Iv::LEN`]).
//!    Every mainstream AES-GCM API defaults to 12, so the wrong choice compiles,
//!    runs, and produces a file nothing can open. Here [`Iv::generate`] is the
//!    only way to make an IV for encryption and it is `[u8; 32]` by type — there
//!    is no constructor that takes a length. *truly-unrep.*
//! 2. **An AAD built by hand.** The additional authenticated data is the leaf's
//!    dotted path joined by `:` with a **trailing** `:`, and sequence indices are
//!    **excluded**. [`Aad`] has no `From<String>`; the only way to get one is
//!    [`AadPath::aad`], which always appends the colon, and [`AadPath`] has no
//!    method that takes an index. *truly-unrep (absent method).*
//! 3. **Using a tree whose MAC was never checked.** Decryption yields
//!    [`Unverified<T>`], whose only safe exit is [`Unverified::verify`]. The
//!    `--ignore-mac` escape exists but is spelled
//!    [`Unverified::into_inner_ignoring_mac`] — one greppable token, never a
//!    default. *truly-unrep for the accidental case.*
//! 4. **A MAC compared in non-constant time.** Upstream compares with Go's `!=`.
//!    [`Mac`]'s inner string is private and its [`PartialEq`] routes through
//!    `subtle::ConstantTimeEq`, so there is no other comparison to reach for.
//!    Same verdict, no timing signal. *truly-unrep.*
//! 5. **Declared recipients that disagree with the wrapped keys.** This is not a
//!    hypothetical: `nix/.sops.yaml` carried a declared admin-recovery recipient
//!    for `users/gabi/secrets.yaml` for two weeks that was never in the
//!    ciphertext, because only a current recipient can re-wrap a data key.
//!    [`Metadata`]'s key arrays are **derived** from the [`WrappedKey`] set via
//!    [`Metadata::from_wrapped`] — they are not independently settable, so a
//!    declaration that outruns the ciphertext cannot be emitted. *truly-unrep.*
//! 6. **A plaintext in a `String`.** Leaf plaintext is [`Plaintext`], which
//!    holds `Zeroizing<Vec<u8>>`, has no `Display`, no `Deref<str>`, and prints
//!    `Plaintext(*** N bytes)` under `Debug`. Reading it takes the greppable
//!    [`Plaintext::expose`]. *parse-time-rejected — an author can still call
//!    `expose()`; the ceiling is that Rust cannot forbid a named call (C1).*
//!
//! # What is deliberately reproduced rather than fixed
//!
//! Two upstream quirks are bugs we must speak anyway, because the wire is the
//! wire (the magma posture: speak the wire, own the executor).
//!
//! - **AAD path collision.** Keys are joined unescaped, so `{"a:b": {"c": v}}`
//!   and `{"a": {"b:c": v}}` produce the same AAD. Reproduced; flagged by
//!   [`AadPath::has_ambiguous_component`] so a caller *can* refuse.
//! - **IV reuse by design.** [`IvStash`] re-uses the IV recorded for a
//!   `(plaintext, aad)` pair so an unchanged value re-encrypts to identical
//!   bytes — which is what keeps `edit` diffs small. Without it every edit
//!   rewrites every line.

#![forbid(unsafe_code)]

mod aad;
mod cipher;
mod leaf;
mod mac;
mod metadata;
mod selector;
mod verified;

pub use aad::{Aad, AadPath};
pub use cipher::{DataKey, Iv, IvStash, decrypt_leaf, encrypt_leaf};
pub use leaf::{EncryptedLeaf, LeafType, Plaintext, format_go_float_f};
pub use mac::{
    MAC_ONLY_ENCRYPTED_SEED, Mac, MacAccumulator, mac_field_aad, seal_mac_field, verify_mac_field,
};
pub use metadata::{AgeKey, KeyProvider, Metadata, WrappedKey};
pub use selector::{DEFAULT_UNENCRYPTED_SUFFIX, EncryptionSelector, Selection, regex_is_match};
pub use verified::Unverified;

/// Everything that can go wrong inside the wire border.
///
/// Note what is *absent*: there is no `Other(String)` arm and no
/// `#[from] anyhow::Error`. A new failure mode has to be named here, which is
/// what keeps a caller's `match` honest.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// The value is not in `ENC[AES256_GCM,…]` form at all.
    #[error("value is not a suminuri/sops encrypted leaf")]
    NotAnEncryptedLeaf,

    /// One of the three base64 fields did not decode.
    #[error("base64 field `{field}` did not decode")]
    Base64 { field: &'static str },

    /// The `type:` tag is not one sops can produce or consume.
    #[error("unknown leaf datatype `{0}`")]
    UnknownDatatype(String),

    /// AES-GCM refused to open the leaf. Deliberately carries no detail: the
    /// distinction between "wrong key" and "tampered bytes" is exactly the
    /// oracle an attacker wants.
    #[error("could not open leaf with AES-256-GCM")]
    AeadOpen,

    /// The recovered bytes are not a valid rendering of the declared type.
    #[error("leaf declared type `{ty}` but its plaintext does not parse as one")]
    DatatypeMismatch { ty: &'static str },

    /// The data key is not 32 bytes.
    #[error("data key must be 32 bytes, got {0}")]
    DataKeyLength(usize),

    /// The MAC recorded in the file does not match the recomputed one.
    #[error("MAC mismatch — the file's contents do not match its recorded MAC")]
    MacMismatch,

    /// The walk fed NOTHING to the MAC, so a comparison would prove nothing about
    /// the contents.
    ///
    /// Distinct from [`WireError::MacMismatch`] on purpose. It was reported as a
    /// mismatch until 2026-08-19, and that cost real diagnosis time on a file that
    /// was not corrupt at all: document 1 of a real 5-document fleet file is two
    /// comments and an empty mapping, which legitimately has no MAC-eligible leaf.
    /// An error that names the wrong cause sends the reader hunting for corruption.
    ///
    /// A caller that genuinely expects an empty document uses
    /// `Unverified::verify_allowing_empty`, which still verifies the MAC FIELD's own
    /// seal — so allowing empty is not the same as skipping the check.
    #[error(
        "nothing was fed to the MAC, so verifying it would prove nothing about this document's contents. If the document is genuinely empty, that is expected — see verify_allowing_empty."
    )]
    NothingToVerify,

    /// The MAC field itself would not decrypt, which usually means the data key
    /// is wrong or `lastmodified` was edited by hand.
    #[error("could not decrypt the MAC field (wrong data key, or lastmodified was edited)")]
    MacUndecryptable,

    /// A mapping key was not a string. sops cannot represent one.
    #[error("mapping key is not a string; suminuri and sops both require string keys")]
    NonStringKey,

    /// A selector regex from the metadata did not compile.
    #[error("selector regex `{pattern}` is not valid: {reason}")]
    BadSelectorRegex { pattern: String, reason: String },

    /// An encrypted comment would match `unencrypted_comment_regex`, which would
    /// make the file permanently undecryptable. Upstream refuses too.
    #[error(
        "an encrypted comment matches unencrypted_comment_regex; the file would never decrypt again"
    )]
    SelfDefeatingCommentRegex,

    /// No randomness available for an IV.
    #[error("could not draw randomness for an IV: {0}")]
    Randomness(String),
}

/// The sops format version this crate writes into `sops.version`.
///
/// We claim the format version, not our own release version, because the field
/// is read by real sops to decide how to parse. Measured against the binary in
/// the operator's profile.
pub const FORMAT_VERSION: &str = "3.12.1";
