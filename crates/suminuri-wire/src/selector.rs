//! Which leaves get encrypted — `sops.go`'s `shouldBeEncrypted`, reproduced
//! exactly including its order-dependence.
//!
//! Six stages run in a fixed order and **each one overwrites the last**, so this
//! is not a set of independent filters that could be reordered or combined with
//! `&&`. Two of the stages (`encrypted_suffix`, `encrypted_regex`) begin by
//! resetting the verdict to `false`, which means a later stage can *un-exempt*
//! something an earlier one exempted. Getting the order wrong yields a file that
//! encrypts the wrong subset — and the failure is silent, because such a file is
//! internally consistent and verifies against its own MAC.
//!
//! Two traps worth naming, both measured from the source rather than the docs:
//!
//! - the suffix and regex tests run against **every component of the path**, not
//!   just the leaf's own key. A parent named `foo_unencrypted` silently exempts
//!   its entire subtree.
//! - the regexes are **unanchored** Go RE2 (`regexp.Match`, no `^…$` added), so
//!   `encrypted_regex: "data"` matches `metadata` too. Rust's `regex` crate is
//!   the same syntax family and the same unanchored semantics, which is why it
//!   is the right dependency and a PCRE would not be.

use crate::WireError;
use crate::aad::AadPath;
use regex::Regex;

/// The verdict for one leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Encrypt this leaf, and count it toward the MAC either way.
    Encrypt,
    /// Leave this leaf in the clear. Under `mac_only_encrypted` it also drops out
    /// of the MAC.
    Clear,
}

impl Selection {
    #[must_use]
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Encrypt)
    }
}

/// The compiled form of a file's encryption policy.
///
/// Built once per file from the metadata so the regexes compile once instead of
/// per leaf, and so a bad pattern is a named error at load time rather than a
/// silently-non-matching regex at walk time. Upstream calls `regexp.Match` per
/// leaf and **discards the compile error** (`matched, _ :=`), so an invalid
/// pattern there behaves as "never matches" — which is the round-up this type
/// removes.
#[derive(Debug, Default)]
pub struct EncryptionSelector {
    unencrypted_suffix: Option<String>,
    encrypted_suffix: Option<String>,
    unencrypted_regex: Option<Regex>,
    encrypted_regex: Option<Regex>,
    unencrypted_comment_regex: Option<Regex>,
    encrypted_comment_regex: Option<Regex>,
}

/// sops's default when no selector at all is configured.
pub const DEFAULT_UNENCRYPTED_SUFFIX: &str = "_unencrypted";

/// An unanchored regex match, or `false` on a pattern that does not compile.
///
/// Exported so `.sops.yaml`'s `path_regex` matching uses the **same engine** the
/// selectors do. Both are reproducing Go RE2 semantics, and two regex crates in
/// one tool would be two subtly different answers to the same question.
///
/// The swallowed compile error is upstream's behaviour: `regexp.MatchString`'s
/// error is discarded at every sops call site, so a bad pattern matches nothing.
/// Where the pattern is a file's own *policy* that silence is a real hazard, which
/// is why [`EncryptionSelector::new`] compiles up front and refuses instead — this
/// entry point is for the config's `path_regex`, where falling through to the next
/// rule is at least visible.
#[must_use]
pub fn regex_is_match(pattern: &str, text: &str) -> bool {
    Regex::new(pattern).is_ok_and(|re| re.is_match(text))
}

impl EncryptionSelector {
    /// Compile a policy. Every field is the metadata field of the same name;
    /// `None`/empty means "not configured", matching upstream's `""` test.
    pub fn new(
        unencrypted_suffix: Option<&str>,
        encrypted_suffix: Option<&str>,
        unencrypted_regex: Option<&str>,
        encrypted_regex: Option<&str>,
        unencrypted_comment_regex: Option<&str>,
        encrypted_comment_regex: Option<&str>,
    ) -> Result<Self, WireError> {
        let compile = |p: Option<&str>| -> Result<Option<Regex>, WireError> {
            match p.filter(|s| !s.is_empty()) {
                None => Ok(None),
                Some(p) => Regex::new(p)
                    .map(Some)
                    .map_err(|e| WireError::BadSelectorRegex {
                        pattern: p.to_string(),
                        reason: e.to_string(),
                    }),
            }
        };
        Ok(Self {
            unencrypted_suffix: unencrypted_suffix
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            encrypted_suffix: encrypted_suffix
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            unencrypted_regex: compile(unencrypted_regex)?,
            encrypted_regex: compile(encrypted_regex)?,
            unencrypted_comment_regex: compile(unencrypted_comment_regex)?,
            encrypted_comment_regex: compile(encrypted_comment_regex)?,
        })
    }

    /// The policy a file gets when nothing is configured: `_unencrypted` as the
    /// exempting suffix, everything else encrypted.
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            unencrypted_suffix: Some(DEFAULT_UNENCRYPTED_SUFFIX.to_string()),
            ..Self::default()
        }
    }

    /// Whether any selector is configured at all.
    ///
    /// Used to decide whether to fall back to [`Self::default_policy`], which is
    /// what upstream does by defaulting `UnencryptedSuffix` when the whole set is
    /// empty.
    #[must_use]
    pub fn is_unconfigured(&self) -> bool {
        self.unencrypted_suffix.is_none()
            && self.encrypted_suffix.is_none()
            && self.unencrypted_regex.is_none()
            && self.encrypted_regex.is_none()
            && self.unencrypted_comment_regex.is_none()
            && self.encrypted_comment_regex.is_none()
    }

    /// Whether `unencrypted_comment_regex` is set, which the encrypt path needs
    /// to know so it can refuse a self-defeating file.
    #[must_use]
    pub fn has_unencrypted_comment_regex(&self) -> bool {
        self.unencrypted_comment_regex.is_some()
    }

    /// Whether a rendered encrypted comment would match
    /// `unencrypted_comment_regex` — which would make the file permanently
    /// undecryptable, because the comment would be skipped on the way back in.
    /// Upstream refuses too.
    #[must_use]
    pub fn encrypted_comment_would_be_skipped(&self, rendered: &str) -> bool {
        self.unencrypted_comment_regex
            .as_ref()
            .is_some_and(|r| r.is_match(rendered))
    }

    /// Decide one leaf.
    ///
    /// `comments_stack` is the stack of active comment sets, innermost last —
    /// the shape upstream threads through its walker so that a comment can turn
    /// encryption on or off for the values that follow it. `is_comment` says
    /// whether the leaf *is itself* a comment, which only stage 6 cares about.
    #[must_use]
    pub fn select(
        &self,
        path: &AadPath,
        comments_stack: &[Vec<String>],
        is_comment: bool,
    ) -> Selection {
        let components = path.components();
        let mut encrypted = true;

        // 1. unencrypted_suffix — any component ending with it exempts the leaf.
        if let Some(suffix) = &self.unencrypted_suffix {
            if components.iter().any(|c| c.ends_with(suffix.as_str())) {
                encrypted = false;
            }
        }

        // 2. encrypted_suffix — resets to false, then opts specific paths back in.
        if let Some(suffix) = &self.encrypted_suffix {
            encrypted = components.iter().any(|c| c.ends_with(suffix.as_str()));
        }

        // 3. unencrypted_regex — any matching component exempts.
        if let Some(re) = &self.unencrypted_regex {
            if components.iter().any(|c| re.is_match(c)) {
                encrypted = false;
            }
        }

        // 4. encrypted_regex — resets to false, then opts back in.
        if let Some(re) = &self.encrypted_regex {
            encrypted = components.iter().any(|c| re.is_match(c));
        }

        // 5. unencrypted_comment_regex — any active comment matching exempts.
        if let Some(re) = &self.unencrypted_comment_regex {
            if comments_stack.iter().flatten().any(|c| re.is_match(c)) {
                encrypted = false;
            }
        }

        // 6. encrypted_comment_regex — resets to false, then opts back in, with
        //    one carve-out: when the leaf is itself a comment, the *last line of
        //    the innermost comment set* is skipped. That is the leaf's own text,
        //    and without the carve-out a comment matching the regex would
        //    trivially encrypt itself.
        if let Some(re) = &self.encrypted_comment_regex {
            let last_set = comments_stack.len().saturating_sub(1);
            let last_line = comments_stack
                .last()
                .map_or(0, |s| s.len().saturating_sub(1));
            encrypted = comments_stack.iter().enumerate().any(|(i, set)| {
                set.iter().enumerate().any(|(j, c)| {
                    let is_own_text = is_comment && i == last_set && j == last_line;
                    !is_own_text && re.is_match(c)
                })
            });
        }

        if encrypted {
            Selection::Encrypt
        } else {
            Selection::Clear
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(parts: &[&str]) -> AadPath {
        let mut p = AadPath::root();
        for c in parts {
            p.push_key(*c);
        }
        p
    }

    fn sel(s: &EncryptionSelector, parts: &[&str]) -> Selection {
        s.select(&path(parts), &[], false)
    }

    #[test]
    fn everything_is_encrypted_by_default() {
        let s = EncryptionSelector::default();
        assert_eq!(sel(&s, &["a", "b"]), Selection::Encrypt);
    }

    #[test]
    fn the_default_policy_exempts_the_underscore_suffix() {
        let s = EncryptionSelector::default_policy();
        assert_eq!(sel(&s, &["port_unencrypted"]), Selection::Clear);
        assert_eq!(sel(&s, &["port"]), Selection::Encrypt);
    }

    /// The trap: the suffix test runs over *every* path component, so a parent
    /// exempts its whole subtree. Not documented upstream; read off the loop.
    #[test]
    fn a_suffixed_parent_exempts_its_whole_subtree() {
        let s = EncryptionSelector::default_policy();
        assert_eq!(
            sel(&s, &["metadata_unencrypted", "deeply", "nested"]),
            Selection::Clear
        );
    }

    #[test]
    fn encrypted_suffix_inverts_the_default() {
        let s =
            EncryptionSelector::new(None, Some("_enc"), None, None, None, None).expect("compile");
        assert_eq!(sel(&s, &["password_enc"]), Selection::Encrypt);
        assert_eq!(
            sel(&s, &["hostname"]),
            Selection::Clear,
            "encrypted_suffix resets to false"
        );
    }

    /// Stage order is load-bearing: stage 4 resets the verdict, so it can
    /// re-encrypt something stage 3 exempted. Reordering the stages breaks this.
    #[test]
    fn a_later_stage_overrides_an_earlier_exemption() {
        let s = EncryptionSelector::new(None, None, Some("^pub"), Some("^public_key$"), None, None)
            .expect("compile");
        // stage 3 exempts (matches ^pub), stage 4 resets and opts back in
        assert_eq!(sel(&s, &["public_key"]), Selection::Encrypt);
        // stage 3 exempts, stage 4 resets and does not opt back in
        assert_eq!(sel(&s, &["published"]), Selection::Clear);
    }

    /// Go's `regexp.Match` is unanchored and Rust's `is_match` is too. If this
    /// ever fails, someone added `^…$` and every existing file's subset changed.
    #[test]
    fn regexes_are_unanchored_like_go() {
        let s =
            EncryptionSelector::new(None, None, None, Some("data"), None, None).expect("compile");
        assert_eq!(
            sel(&s, &["metadata"]),
            Selection::Encrypt,
            "substring match, as upstream"
        );
    }

    /// Upstream discards the regex compile error and treats a bad pattern as
    /// "never matches" — a silently wrong subset. Here it is named at load time.
    #[test]
    fn a_bad_regex_is_named_at_load_time() {
        let err = EncryptionSelector::new(None, None, Some("(unclosed"), None, None, None)
            .err()
            .expect("must refuse");
        assert!(
            matches!(err, WireError::BadSelectorRegex { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn an_active_comment_can_exempt_a_value() {
        let s = EncryptionSelector::new(None, None, None, None, Some("plaintext"), None)
            .expect("compile");
        let stack = vec![vec!["this one is plaintext on purpose".to_string()]];
        assert_eq!(s.select(&path(&["k"]), &stack, false), Selection::Clear);
        assert_eq!(s.select(&path(&["k"]), &[], false), Selection::Encrypt);
    }

    /// Stage 6's carve-out: a comment does not encrypt *itself* just by matching.
    #[test]
    fn a_comment_matching_the_encrypt_regex_does_not_encrypt_itself() {
        let s =
            EncryptionSelector::new(None, None, None, None, None, Some("SECRET")).expect("compile");
        let own = vec![vec!["SECRET below".to_string()]];
        assert_eq!(
            s.select(&path(&["k"]), &own, true),
            Selection::Clear,
            "the comment's own last line is skipped"
        );
        assert_eq!(
            s.select(&path(&["k"]), &own, false),
            Selection::Encrypt,
            "but the value that follows it is encrypted"
        );
    }

    #[test]
    fn a_self_defeating_comment_regex_is_detectable() {
        let s = EncryptionSelector::new(None, None, None, None, Some("^ENC\\["), Some("x"))
            .expect("compile");
        assert!(s.has_unencrypted_comment_regex());
        assert!(s.encrypted_comment_would_be_skipped("ENC[AES256_GCM,data:…]"));
        assert!(!s.encrypted_comment_would_be_skipped("a normal comment"));
    }

    #[test]
    fn is_unconfigured_distinguishes_empty_from_set() {
        assert!(EncryptionSelector::default().is_unconfigured());
        assert!(!EncryptionSelector::default_policy().is_unconfigured());
        // an empty string is "not configured", matching upstream's `!= ""` test
        assert!(
            EncryptionSelector::new(Some(""), Some(""), Some(""), None, None, None)
                .expect("compile")
                .is_unconfigured()
        );
    }
}
