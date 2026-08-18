//! The tree model — sops's `TreeBranch`, in Rust.
//!
//! Shaped after `sops.TreeBranch = []TreeItem{Key, Value}` rather than after a
//! generic YAML value, for one reason: in sops's model a **comment is a tree
//! item**, not a node attribute. That is what allows `encrypted_comment_regex`
//! to encrypt a comment the same way it encrypts a value, and it is why the model
//! here has an [`Item::Comment`] arm instead of a `comment: Option<String>` field
//! hanging off a pair.
//!
//! Ordering is a `Vec`, not a map. See the crate docs: order is integrity, so it
//! is the data structure rather than a promise about one.

/// How a scalar was written, preserved so a round-trip does not requote.
///
/// go-yaml decides style from its resolver — a plain `2026-08-14T00:06:29Z` would
/// resolve as a timestamp, so it emits `lastmodified: "2026-08-14T00:06:29Z"`
/// double-quoted. Reproducing that decision in general means reproducing the
/// resolver; preserving the *parsed* style makes it unnecessary for every value
/// that was already in the file, which is all of them on a re-encrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarStyle {
    /// `key: value`
    Plain,
    /// `key: 'value'`
    SingleQuoted,
    /// `key: "value"`
    DoubleQuoted,
    /// `key: |` followed by an indented block. The armored age keys use this.
    Literal,
    /// `key: >` folded block.
    Folded,
}

impl ScalarStyle {
    /// The style go-yaml would pick for a value we are creating fresh.
    ///
    /// Only the cases the sops metadata block actually produces are decided here;
    /// everything else stays [`ScalarStyle::Plain`] and is covered by the
    /// round-trip of an existing style. The honest limit: this is **not** a port
    /// of go-yaml's resolver, so a *newly minted* value whose text happens to
    /// resolve as a YAML 1.1 scalar type we do not enumerate would be emitted
    /// plain where go-yaml would quote it.
    #[must_use]
    pub fn for_new_value(value: &str) -> Self {
        if needs_double_quoting(value) {
            Self::DoubleQuoted
        } else {
            Self::Plain
        }
    }
}

/// Whether a fresh plain scalar would be misread and therefore needs quoting.
///
/// Two *different* questions hide behind "does this need quotes", and conflating
/// them corrupts documents in opposite directions:
///
/// - **A value we are creating** is known to be a *string*. If its text would
///   resolve as a bool, a number or a timestamp, it must be quoted or it comes
///   back as the wrong type. `lastmodified` is this case on every single write.
/// - **A value that was already plain in the file** was plain for a reason: `1`
///   meant the integer 1. Quoting it on the way out changes its type and its MAC
///   contribution. Only the *structural* hazards apply there.
///
/// This function answers the first question and is used for new values and keys.
/// [`plain_is_structurally_unsafe`] answers the second. The first round of
/// round-trip tests failed precisely because this one was used for both, turning
/// `a: 1` into `a: "1"`.
fn needs_double_quoting(v: &str) -> bool {
    if plain_is_structurally_unsafe(v) {
        return true;
    }
    // Resolvable-as-non-string: YAML 1.1 bools, null, numbers, timestamps.
    let lower = v.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "y" | "n"
            | "yes"
            | "no"
            | "true"
            | "false"
            | "on"
            | "off"
            | "null"
            | "~"
            | ".nan"
            | ".inf"
            | "-.inf"
    ) {
        return true;
    }
    if v.parse::<i64>().is_ok() || v.parse::<f64>().is_ok() {
        return true;
    }
    // An RFC 3339 / YAML timestamp: digits and `-` up to a `T`, then a time.
    // This is the case `lastmodified` hits on every single write.
    looks_like_timestamp(v)
}

/// Whether a plain scalar would not survive a reparse *as text at all* —
/// independent of what type it resolves to.
///
/// This is the promotion test for a value that was parsed plain and then changed:
/// its type resolution was already the document's business, but a leading `#` or
/// an embedded `: ` would break the document itself.
#[must_use]
pub fn plain_is_structurally_unsafe(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    v.starts_with([
        '-', '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@',
        '`',
    ]) || v.starts_with(' ')
        || v.ends_with(' ')
        || v.contains(": ")
        || v.contains(" #")
        || v.contains('\n')
}

fn looks_like_timestamp(v: &str) -> bool {
    // `YYYY-MM-DD` optionally followed by `T…`/` …`. Cheap shape test rather than
    // a date parse: the question is only "would YAML resolve this as a
    // timestamp", and YAML's own regex is this loose too.
    let b = v.as_bytes();
    if b.len() < 10 {
        return false;
    }
    b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
}

/// A scalar leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar {
    pub value: String,
    pub style: ScalarStyle,
}

impl Scalar {
    /// A scalar preserving the style it was parsed with.
    #[must_use]
    pub fn parsed(value: impl Into<String>, style: ScalarStyle) -> Self {
        Self {
            value: value.into(),
            style,
        }
    }

    /// A freshly-created scalar, styled the way go-yaml would style it.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let style = ScalarStyle::for_new_value(&value);
        Self { value, style }
    }

    /// A literal block scalar — the shape the armored age keys use.
    #[must_use]
    pub fn literal(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            style: ScalarStyle::Literal,
        }
    }
}

/// A value in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Scalar(Scalar),
    /// An ordered mapping. Order is integrity — see the crate docs.
    Mapping(Vec<Item>),
    Sequence(Vec<Entry>),
}

impl Value {
    /// Look up a key in a mapping.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Mapping(items) => items.iter().find_map(|i| match i {
                Item::Pair { key: k, value } if k == key => Some(value),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Look up a key in a mapping, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        match self {
            Self::Mapping(items) => items.iter_mut().find_map(|i| match i {
                Item::Pair { key: k, value } if k == key => Some(value),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Remove a key from a mapping, returning its value.
    ///
    /// Used to lift the `sops:` block out before walking, since the metadata is
    /// outside the MAC.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let Self::Mapping(items) = self else {
            return None;
        };
        let idx = items
            .iter()
            .position(|i| matches!(i, Item::Pair { key: k, .. } if k == key))?;
        match items.remove(idx) {
            Item::Pair { value, .. } => Some(value),
            Item::Comment(_) => None,
        }
    }

    /// Append a key/value pair to a mapping. No-op on a non-mapping.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        if let Self::Mapping(items) = self {
            items.push(Item::Pair {
                key: key.into(),
                value,
            });
        }
    }

    /// The scalar text, if this is a scalar.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Scalar(s) => Some(&s.value),
            _ => None,
        }
    }

    /// Whether any comment item appears anywhere in this subtree.
    ///
    /// The parser refuses comments up front, so this is a belt-and-braces check
    /// for a tree built programmatically.
    #[must_use]
    pub fn contains_comments(&self) -> bool {
        match self {
            Self::Scalar(_) => false,
            Self::Mapping(items) => items.iter().any(|i| match i {
                Item::Comment(_) => true,
                Item::Pair { value, .. } => value.contains_comments(),
            }),
            Self::Sequence(entries) => entries.iter().any(|e| match e {
                Entry::Comment(_) => true,
                Entry::Value(v) => v.contains_comments(),
            }),
        }
    }
}

/// An item in a mapping: either a key/value pair or a standalone comment.
///
/// The comment arm is what makes this sops's model rather than a generic one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A comment line, body **without** the leading `#` — matching the store's
    /// `commentLine[1:]`.
    Comment(String),
    Pair {
        key: String,
        value: Value,
    },
}

/// An entry in a sequence: a value, or a comment between values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Comment(String),
    Value(Value),
}

/// A whole YAML stream: one or more documents.
///
/// sops emits one document per tree branch, appending the `sops:` metadata key to
/// each — so a multi-document file gets a metadata block per document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub roots: Vec<Value>,
}

impl Document {
    #[must_use]
    pub fn single(root: Value) -> Self {
        Self { roots: vec![root] }
    }

    /// The one root, when there is exactly one. Most sops files.
    #[must_use]
    pub fn root(&self) -> Option<&Value> {
        if self.roots.len() == 1 {
            self.roots.first()
        } else {
            None
        }
    }

    pub fn root_mut(&mut self) -> Option<&mut Value> {
        if self.roots.len() == 1 {
            self.roots.first_mut()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timestamp_is_quoted_because_yaml_would_resolve_it() {
        // The exact value from the operator's file, which sops writes quoted.
        assert_eq!(
            ScalarStyle::for_new_value("2026-08-14T00:06:29Z"),
            ScalarStyle::DoubleQuoted
        );
    }

    #[test]
    fn the_other_metadata_values_stay_plain() {
        // Read off `nix/secrets.yaml`: `version: 3.12.1`, `unencrypted_suffix: _unencrypted`.
        assert_eq!(ScalarStyle::for_new_value("3.12.1"), ScalarStyle::Plain);
        assert_eq!(
            ScalarStyle::for_new_value("_unencrypted"),
            ScalarStyle::Plain
        );
        // And an ENC[...] value, the overwhelming majority of every file.
        assert_eq!(
            ScalarStyle::for_new_value("ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]"),
            ScalarStyle::Plain
        );
        // An age recipient.
        assert_eq!(
            ScalarStyle::for_new_value(
                "age1q3tep4cc4d89y0ajd9ywafmarq69202z3za48rhcdra0ya579ews56awfd"
            ),
            ScalarStyle::Plain
        );
    }

    #[test]
    fn values_that_would_reparse_as_non_strings_are_quoted() {
        for v in [
            "true", "False", "yes", "no", "on", "off", "null", "~", "42", "1.5", "-0", "",
        ] {
            assert_eq!(
                ScalarStyle::for_new_value(v),
                ScalarStyle::DoubleQuoted,
                "{v:?} must be quoted or it reparses as a non-string"
            );
        }
    }

    #[test]
    fn structurally_unsafe_plain_scalars_are_quoted() {
        for v in [
            "- leading dash",
            "#hash",
            " leading space",
            "trailing ",
            "a: b",
            "x #y",
            "a\nb",
        ] {
            assert_eq!(
                ScalarStyle::for_new_value(v),
                ScalarStyle::DoubleQuoted,
                "{v:?} cannot be a plain scalar"
            );
        }
    }

    #[test]
    fn mapping_lookup_skips_comment_items() {
        let m = Value::Mapping(vec![
            Item::Comment(" a note".into()),
            Item::Pair {
                key: "k".into(),
                value: Value::Scalar(Scalar::new("v")),
            },
        ]);
        assert_eq!(m.get("k").and_then(Value::as_str), Some("v"));
        assert!(m.get("nope").is_none());
        assert!(m.contains_comments());
    }

    #[test]
    fn remove_lifts_a_key_out_and_preserves_the_rest_in_order() {
        let mut m = Value::Mapping(vec![
            Item::Pair {
                key: "a".into(),
                value: Value::Scalar(Scalar::new("1")),
            },
            Item::Pair {
                key: "sops".into(),
                value: Value::Mapping(vec![]),
            },
            Item::Pair {
                key: "b".into(),
                value: Value::Scalar(Scalar::new("2")),
            },
        ]);
        assert!(m.remove("sops").is_some());
        let Value::Mapping(items) = &m else {
            panic!("still a mapping")
        };
        assert_eq!(items.len(), 2);
        assert_eq!(m.get("a").and_then(Value::as_str), Some("1"));
        assert_eq!(m.get("b").and_then(Value::as_str), Some("2"));
    }

    #[test]
    fn a_comment_free_tree_reports_no_comments() {
        let m = Value::Mapping(vec![Item::Pair {
            key: "k".into(),
            value: Value::Sequence(vec![Entry::Value(Value::Scalar(Scalar::new("v")))]),
        }]);
        assert!(!m.contains_comments());
    }
}
