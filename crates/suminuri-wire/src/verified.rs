//! `Unverified<T>` — the type that makes "I forgot to check the MAC" impossible
//! to write by accident.
//!
//! Upstream's shape is a boolean and an early return:
//!
//! ```go
//! if !opts.IgnoreMac {
//!     if fileMac != computedMac { return … MacMismatch }
//! }
//! return dataKey, nil            // the tree is already decrypted either way
//! ```
//!
//! The tree exists, decrypted, before the check — so every later line is one
//! `if` away from operating on unauthenticated data, and nothing in the type of
//! the value records whether the check happened. That is fine in a codebase where
//! one function owns the whole path, and it is exactly the shape that rots once a
//! second caller appears.
//!
//! Here the decrypted value comes back wrapped. The only way to get at it is
//! [`Unverified::verify`], which needs the MAC to match, or
//! [`Unverified::into_inner_ignoring_mac`] — the `--ignore-mac` escape, named so
//! a reviewer greps for one token rather than noticing a missing branch.
//!
//! The ceiling, stated: this is **truly-unrep for the accidental case** — there
//! is no code path that reaches the value without one of those two calls. It is
//! not unrepresentable in the absolute sense, because Rust cannot forbid a caller
//! from *choosing* the named escape (C1: no dependent types to encode "and the
//! operator authorised it"). What it buys is that the unsafe path can never be
//! the *default* or the *silent* one.

use crate::WireError;
use crate::cipher::{DataKey, IvStash};
use crate::mac::{Mac, verify_mac_field_recording};

/// A decrypted value whose file MAC has not been checked yet.
///
/// Carries everything the check needs so a caller cannot be asked for the MAC
/// inputs at some later point where they are no longer in scope.
#[must_use = "an Unverified value is unauthenticated until you call verify()"]
pub struct Unverified<T> {
    inner: T,
    computed: Mac,
    mac_field: String,
    lastmodified: String,
    leaves_fed: usize,
}

impl<T> Unverified<T> {
    /// Wrap a freshly-decrypted value together with its MAC inputs.
    pub fn new(
        inner: T,
        computed: Mac,
        mac_field: impl Into<String>,
        lastmodified: impl Into<String>,
        leaves_fed: usize,
    ) -> Self {
        Self {
            inner,
            computed,
            mac_field: mac_field.into(),
            lastmodified: lastmodified.into(),
            leaves_fed,
        }
    }

    /// The MAC recomputed from the decrypted contents.
    pub fn computed_mac(&self) -> &Mac {
        &self.computed
    }

    /// How many leaves went into the recomputed MAC. **The denominator.**
    ///
    /// A MAC over zero leaves matches another MAC over zero leaves, so a walker
    /// that silently stopped finding leaves would verify green while checking
    /// nothing. [`Unverified::verify`] refuses that case outright; this getter
    /// lets a caller assert a specific expected count on top.
    pub fn leaves_fed(&self) -> usize {
        self.leaves_fed
    }

    /// Check the MAC and release the value.
    ///
    /// Refuses a zero-leaf verification as vacuous. That is a deliberate
    /// divergence from upstream, which would happily verify an empty walk: the
    /// only file that legitimately has no leaves is an empty document, and
    /// treating one as authenticated is how a broken walker reads as a green
    /// gate. A caller that genuinely wants to accept an empty document can say so
    /// with [`Unverified::verify_allowing_empty`].
    pub fn verify(self, key: &DataKey) -> Result<T, WireError> {
        self.verify_recording(key, None)
    }

    /// [`Unverified::verify`], recording the MAC field's own IV into `stash`.
    ///
    /// Pass the same stash the decrypt walk filled. Upstream gets this for free
    /// because the `mac` field shares one `Cipher` with every leaf; without it a
    /// no-op re-encrypt leaves every data line untouched and moves the `mac:`
    /// line alone.
    pub fn verify_recording(
        self,
        key: &DataKey,
        stash: Option<&mut IvStash>,
    ) -> Result<T, WireError> {
        if self.leaves_fed == 0 {
            return Err(WireError::MacMismatch);
        }
        verify_mac_field_recording(
            key,
            &self.mac_field,
            &self.lastmodified,
            &self.computed,
            stash,
        )?;
        Ok(self.inner)
    }

    /// [`Unverified::verify`] without the anti-vacuity refusal, for the genuinely
    /// empty document.
    pub fn verify_allowing_empty(self, key: &DataKey) -> Result<T, WireError> {
        verify_mac_field_recording(
            key,
            &self.mac_field,
            &self.lastmodified,
            &self.computed,
            None,
        )?;
        Ok(self.inner)
    }

    /// The `--ignore-mac` escape.
    ///
    /// Deliberately verbose. sops offers `--ignore-mac` and real operators need
    /// it — a file whose MAC broke because someone hand-edited `lastmodified` is
    /// still recoverable, and refusing outright would make us *less* useful than
    /// what we replace. So the escape exists; it is just impossible to take
    /// without typing its name.
    pub fn into_inner_ignoring_mac(self) -> T {
        self.inner
    }

    /// Map the wrapped value without unwrapping it, so a caller can keep
    /// transforming a still-unauthenticated tree without losing the marker.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Unverified<U> {
        Unverified {
            inner: f(self.inner),
            computed: self.computed,
            mac_field: self.mac_field,
            lastmodified: self.lastmodified,
            leaves_fed: self.leaves_fed,
        }
    }
}

impl<T> std::fmt::Debug for Unverified<T> {
    /// Never prints the wrapped value — it is decrypted plaintext, and this type
    /// is most likely to be `Debug`-printed exactly when someone is debugging a
    /// MAC failure over a real file.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unverified")
            .field("computed", &self.computed)
            .field("leaves_fed", &self.leaves_fed)
            .field("value", &"***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::Plaintext;
    use crate::mac::{MacAccumulator, seal_mac_field};

    fn key() -> DataKey {
        DataKey::from_bytes(&[5u8; 32]).expect("32")
    }

    fn wrapped(contents: &[&str], ts: &str) -> (Unverified<Vec<String>>, DataKey) {
        let k = key();
        let mut acc = MacAccumulator::new(false);
        for c in contents {
            acc.feed(&Plaintext::string(*c));
        }
        let fed = acc.leaves_fed();
        let mac = acc.finish();
        let field = seal_mac_field(&k, &mac, ts, None).expect("seal");
        let tree: Vec<String> = contents.iter().map(|s| (*s).to_string()).collect();
        (Unverified::new(tree, mac, field, ts, fed), k)
    }

    #[test]
    fn a_matching_mac_releases_the_value() {
        let (u, k) = wrapped(&["a", "b"], "2026-08-18T00:00:00Z");
        assert_eq!(u.verify(&k).expect("verify"), vec!["a", "b"]);
    }

    #[test]
    fn a_wrong_key_does_not_release_the_value() {
        let (u, _) = wrapped(&["a"], "2026-08-18T00:00:00Z");
        let other = DataKey::from_bytes(&[6u8; 32]).expect("32");
        assert_eq!(u.verify(&other), Err(WireError::MacUndecryptable));
    }

    /// The anti-vacuity refusal. Without it, a walker that found no leaves would
    /// compute the empty digest, match another empty digest, and report success.
    #[test]
    fn a_zero_leaf_verification_is_refused_as_vacuous() {
        let (u, k) = wrapped(&[], "2026-08-18T00:00:00Z");
        assert_eq!(u.leaves_fed(), 0);
        assert_eq!(u.verify(&k), Err(WireError::MacMismatch));
    }

    #[test]
    fn an_explicitly_empty_document_can_still_be_accepted() {
        let (u, k) = wrapped(&[], "2026-08-18T00:00:00Z");
        assert!(u.verify_allowing_empty(&k).is_ok());
    }

    #[test]
    fn the_ignore_mac_escape_works_and_is_named() {
        let (u, _) = wrapped(&["a"], "2026-08-18T00:00:00Z");
        assert_eq!(u.into_inner_ignoring_mac(), vec!["a"]);
    }

    #[test]
    fn map_preserves_the_marker_and_the_denominator() {
        let (u, k) = wrapped(&["a", "b"], "2026-08-18T00:00:00Z");
        let mapped = u.map(|v| v.len());
        assert_eq!(mapped.leaves_fed(), 2);
        assert_eq!(mapped.verify(&k).expect("verify"), 2);
    }

    #[test]
    fn debug_never_prints_the_wrapped_value() {
        let (u, _) = wrapped(&["hunter2"], "2026-08-18T00:00:00Z");
        let shown = format!("{u:?}");
        assert!(
            !shown.contains("hunter2"),
            "Unverified Debug leaked plaintext: {shown}"
        );
        assert!(shown.contains("leaves_fed: 1"));
    }
}
