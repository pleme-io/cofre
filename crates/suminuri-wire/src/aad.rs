//! The additional authenticated data — a leaf's path, and the exact rules for
//! building it.
//!
//! `sops.go`'s walker does this and only this:
//!
//! ```go
//! pathString := strings.Join(path, ":") + ":"
//! ```
//!
//! Two details in that one line decide whether a file we write can ever be read
//! by real sops, and both are easy to get wrong in the helpful direction:
//!
//! - the **trailing colon** is part of the AAD, and
//! - **sequence indices are not in the path at all** — `walkSlice` recurses with
//!   `path` unchanged, so every element of a list authenticates under its
//!   parent key's path.
//!
//! An implementation that appends `[0]`, `.0` or `:0` produces ciphertext that
//! sops rejects with an opaque GCM error, miles from the cause. So this module
//! offers no way to do it: [`AadPath`] has exactly one push, and it takes a key.

/// The finished AAD string for one leaf. Opaque on purpose.
///
/// There is no `From<String>`, no `new`, and no `Deref<Target = str>` — the only
/// way to obtain one is [`AadPath::aad`]. That is what makes rule 2 of the crate
/// docs structural rather than advisory.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Aad(String);

impl Aad {
    /// The bytes fed to AES-GCM as additional authenticated data.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The one sanctioned AAD that is **not** a leaf path: the `sops.mac` field
    /// authenticates under the verbatim `lastmodified` string.
    ///
    /// `pub(crate)` on purpose. Rule 2 of the crate docs — "no AAD built by
    /// hand" — is about *leaf* AADs, and this is genuinely a different thing, so
    /// the escape exists; keeping it crate-private and reachable only through
    /// the named [`crate::mac::mac_field_aad`] means the invariant still holds
    /// for every caller outside this crate, with exactly one auditable
    /// exception rather than an open constructor.
    pub(crate) fn field(literal: &str) -> Self {
        Self(literal.to_string())
    }
}

impl std::fmt::Debug for Aad {
    /// An AAD is a *path*, not a secret — printing it is how a decrypt failure
    /// becomes diagnosable. Shown quoted so a trailing colon is visible.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Aad({:?})", self.0)
    }
}

/// The stack of string mapping keys from the document root down to a leaf.
///
/// Push on the way down, pop on the way back up. Descending into a *sequence*
/// pushes nothing, which is not an omission — see the module docs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AadPath {
    components: Vec<String>,
}

impl AadPath {
    /// A path at the document root.
    #[must_use]
    pub fn root() -> Self {
        Self::default()
    }

    /// Descend into a mapping under `key`.
    pub fn push_key(&mut self, key: impl Into<String>) {
        self.components.push(key.into());
    }

    /// Ascend back out of the last mapping.
    pub fn pop(&mut self) {
        self.components.pop();
    }

    /// Run `f` with `key` pushed, restoring the path afterwards even if `f`
    /// returns early.
    ///
    /// The manual push/pop pair is the shape that goes wrong under `?`, so the
    /// walker uses this instead.
    pub fn within<T>(&mut self, key: impl Into<String>, f: impl FnOnce(&mut Self) -> T) -> T {
        self.push_key(key);
        let out = f(self);
        self.pop();
        out
    }

    /// The number of mapping keys from the root.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// The components, for the selector rules — which test *every* component,
    /// not just the leaf's own key.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Build the AAD for a leaf at this path.
    ///
    /// Exactly `strings.Join(path, ":") + ":"`.
    ///
    /// Written as a join-then-append rather than a push-each-with-separator loop,
    /// because the two disagree at depth 0: Go's `Join` over an empty slice is
    /// `""`, so the AAD at the root is a **bare `":"`**, whereas the loop form
    /// produces `""`. That is not a degenerate case nobody reaches — a
    /// **top-level comment** has an empty path, because `walkBranch` passes
    /// `item.Key` to `walkValue` with `path` unchanged. The loop form was the
    /// first version of this function and the depth-0 test is what caught it.
    #[must_use]
    pub fn aad(&self) -> Aad {
        let mut s = self.components.join(":");
        s.push(':');
        Aad(s)
    }

    /// Whether any component contains `:`, which makes this path's AAD
    /// ambiguous with a differently-nested document.
    ///
    /// Upstream neither escapes nor detects this. We reproduce the encoding —
    /// the wire is the wire — but we can at least *tell* a caller, so refusing
    /// is a policy decision made in the open instead of a silent collision.
    #[must_use]
    pub fn has_ambiguous_component(&self) -> bool {
        self.components.iter().any(|c| c.contains(':'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_colon_is_part_of_the_aad() {
        let mut p = AadPath::root();
        p.push_key("a");
        p.push_key("b");
        assert_eq!(p.aad().as_bytes(), b"a:b:");
    }

    #[test]
    fn root_aad_is_a_bare_colon() {
        assert_eq!(AadPath::root().aad().as_bytes(), b":");
    }

    #[test]
    fn within_restores_the_path() {
        let mut p = AadPath::root();
        p.push_key("outer");
        let inner = p.within("inner", |p| p.aad());
        assert_eq!(inner.as_bytes(), b"outer:inner:");
        assert_eq!(p.aad().as_bytes(), b"outer:");
    }

    /// The regression this whole module exists to prevent. A sequence adds no
    /// component, so both elements of `attic.age[..]` share one AAD — which is
    /// what let the probe decrypt the operator's real `sops.age` array.
    #[test]
    fn sequence_descent_adds_nothing() {
        let mut p = AadPath::root();
        p.push_key("age");
        let first = p.aad();
        // Descending into element 0, then element 1, changes nothing at all:
        // there is no method here that could.
        let second = p.aad();
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.as_bytes(), b"age:");
    }

    #[test]
    fn ambiguity_is_reported_not_escaped() {
        let mut p = AadPath::root();
        p.push_key("a:b");
        p.push_key("c");
        assert!(p.has_ambiguous_component());
        // and the encoding is still the upstream one, collision included
        assert_eq!(p.aad().as_bytes(), b"a:b:c:");

        let mut q = AadPath::root();
        q.push_key("a");
        q.push_key("b:c");
        assert_eq!(
            q.aad().as_bytes(),
            p.aad().as_bytes(),
            "the upstream collision, reproduced"
        );
    }

    #[test]
    fn debug_shows_the_trailing_colon() {
        let mut p = AadPath::root();
        p.push_key("k");
        assert_eq!(format!("{:?}", p.aad()), r#"Aad("k:")"#);
    }
}
