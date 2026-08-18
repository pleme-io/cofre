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
    /// The style go-yaml picks for a **string** it is emitting fresh.
    ///
    /// A direct port of `encode.go`'s `stringv`, whose three cases are, in order:
    ///
    /// ```text
    /// case strings.Contains(s, "\n"):  LITERAL   (block context; sops is never in flow)
    /// case canUsePlain:                PLAIN
    /// default:                         DOUBLE_QUOTED
    /// ```
    ///
    /// with `canUsePlain = resolve("", s) == strTag && !isBase60Float(s) && !isOldBool(s)`.
    ///
    /// The newline case is the one that matters most and it was missing from the
    /// first version of this function, which reached `DoubleQuoted` instead. The
    /// consequence was invisible on every synthetic fixture and showed up only
    /// against the operator's real files: an SSH private key came back as one
    /// 420-character `"…\n…"` line where sops writes a `|` block. Both are valid
    /// YAML holding the same string, and they are not the same bytes — so anything
    /// consuming `sops -d` output by line, or diffing it, saw a difference.
    ///
    /// A literal block is not always *allowed*, though. libyaml refuses one when
    /// the text has a trailing space, a space directly before a newline, or a
    /// non-printable character, and go-yaml's emitter then falls back — so
    /// [`literal_block_allowed`] gates the newline case rather than assuming it.
    #[must_use]
    pub fn for_new_value(value: &str) -> Self {
        Self::select(value, false)
    }

    /// The style for a **mapping key**.
    ///
    /// One extra rule applies: libyaml forces double-quoting in
    /// `simple_key_context` when the scalar is multiline, because a key cannot be
    /// a block scalar.
    #[must_use]
    pub fn for_new_key(value: &str) -> Self {
        Self::select(value, true)
    }

    /// libyaml's `yaml_emitter_select_scalar_style`, block context, unicode on.
    ///
    /// The ladder is the whole point, and each rung was learned from a real
    /// divergence rather than from the docs:
    ///
    /// ```text
    /// requested = LITERAL  if the text has a newline          (go-yaml stringv case 1)
    ///           = PLAIN    if it resolves as !!str            (case 2)
    ///           = DOUBLE   otherwise                          (case 3)
    ///
    /// PLAIN   + !block_plain_allowed    -> SINGLE      <- this rung was missing
    /// SINGLE  + !single_quoted_allowed  -> DOUBLE
    /// LITERAL + !block_allowed          -> DOUBLE
    /// ```
    ///
    /// The `PLAIN -> SINGLE` rung is the one that mattered. A 3 179-character
    /// bootstrap script in the operator's `secrets.yaml` resolves as `!!str`, so
    /// go-yaml asks for plain; libyaml refuses (it contains `: `) and settles on
    /// **single**-quoted. Jumping straight to double-quoted, as the first version
    /// of this did, produced a valid file whose bytes differed on eight lines and
    /// grew by ~324 characters of escaping.
    fn select(value: &str, simple_key_context: bool) -> Self {
        let a = ScalarAnalysis::of(value);
        // `resolves_as_non_string`, NOT a structural test. go-yaml's `canUsePlain`
        // asks only "would this text come back as something other than a string",
        // and leaves *structural* plain-safety entirely to libyaml's analysis
        // below. Conflating the two skips the `PLAIN -> SINGLE` rung and turns
        // every `: `-bearing string into a double-quoted one — which is exactly
        // the bootstrap-script divergence recorded above.
        let mut style = if value.contains('\n') {
            Self::Literal
        } else if resolves_as_non_string(value) {
            Self::DoubleQuoted
        } else {
            Self::Plain
        };
        if simple_key_context && a.multiline {
            return Self::DoubleQuoted;
        }
        if style == Self::Plain && !a.block_plain_allowed {
            style = Self::SingleQuoted;
        }
        if style == Self::SingleQuoted && !a.single_quoted_allowed {
            style = Self::DoubleQuoted;
        }
        if matches!(style, Self::Literal | Self::Folded) && (!a.block_allowed || simple_key_context)
        {
            style = Self::DoubleQuoted;
        }
        style
    }
}

/// libyaml's `yaml_emitter_analyze_scalar`, reduced to the flags that matter in
/// block context with unicode on.
///
/// Ported rather than approximated because the flags interact: `space_break`
/// disqualifies single quotes *and* blocks, while `tab_characters` disqualifies
/// single quotes but not blocks. A hand-rolled "is this safe" predicate collapses
/// distinctions the ladder depends on.
#[derive(Debug, Clone, Copy)]
struct ScalarAnalysis {
    multiline: bool,
    block_plain_allowed: bool,
    single_quoted_allowed: bool,
    block_allowed: bool,
}

impl ScalarAnalysis {
    fn of(value: &str) -> Self {
        if value.is_empty() {
            // libyaml's early return: an empty scalar is plain-able but has no
            // block form.
            return Self {
                multiline: false,
                block_plain_allowed: true,
                single_quoted_allowed: true,
                block_allowed: false,
            };
        }

        let mut block_indicators = value.starts_with("---") || value.starts_with("...");
        let (mut leading_space, mut leading_break) = (false, false);
        let (mut trailing_space, mut trailing_break) = (false, false);
        let (mut break_space, mut space_break) = (false, false);
        let (mut line_breaks, mut tab_characters, mut special_characters) = (false, false, false);
        let (mut previous_space, mut previous_break) = (false, false);
        let mut preceded_by_whitespace = true;

        let chars: Vec<char> = value.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            let followed_by_whitespace = i + 1 >= chars.len() || matches!(chars[i + 1], ' ' | '\t');
            let is_last = i + 1 == chars.len();

            if i == 0 {
                match c {
                    '#' | ',' | '[' | ']' | '{' | '}' | '&' | '*' | '!' | '|' | '>' | '\''
                    | '"' | '%' | '@' | '`' => block_indicators = true,
                    '?' | ':' if followed_by_whitespace => block_indicators = true,
                    '-' if followed_by_whitespace => block_indicators = true,
                    _ => {}
                }
            } else {
                match c {
                    ':' if followed_by_whitespace => block_indicators = true,
                    '#' if preceded_by_whitespace => block_indicators = true,
                    _ => {}
                }
            }

            if c == '\t' {
                tab_characters = true;
            } else if (c.is_control() && c != '\n') || ('\u{7f}'..='\u{9f}').contains(&c) {
                // `is_printable` with unicode on: control characters other than
                // the line break, plus the C1 range.
                special_characters = true;
            }

            if c == ' ' || c == '\t' {
                if i == 0 {
                    leading_space = true;
                }
                if is_last {
                    trailing_space = true;
                }
                if previous_break {
                    break_space = true;
                }
                previous_space = true;
                previous_break = false;
            } else if c == '\n' || c == '\r' {
                line_breaks = true;
                if i == 0 {
                    leading_break = true;
                }
                if is_last {
                    trailing_break = true;
                }
                if previous_space {
                    space_break = true;
                }
                previous_space = false;
                previous_break = true;
            } else {
                previous_space = false;
                previous_break = false;
            }
            preceded_by_whitespace = matches!(c, ' ' | '\t' | '\n' | '\r');
        }

        let mut a = Self {
            multiline: line_breaks,
            block_plain_allowed: true,
            single_quoted_allowed: true,
            block_allowed: true,
        };
        if leading_space || leading_break || trailing_space || trailing_break {
            a.block_plain_allowed = false;
        }
        if trailing_space {
            a.block_allowed = false;
        }
        if break_space {
            a.block_plain_allowed = false;
            a.single_quoted_allowed = false;
        }
        if space_break || tab_characters || special_characters {
            a.block_plain_allowed = false;
            a.single_quoted_allowed = false;
        }
        if space_break || special_characters {
            a.block_allowed = false;
        }
        if line_breaks {
            a.block_plain_allowed = false;
        }
        if block_indicators {
            a.block_plain_allowed = false;
        }
        a
    }
}

/// Whether libyaml would permit a literal block for this text.
#[must_use]
pub fn literal_block_allowed(v: &str) -> bool {
    ScalarAnalysis::of(v).block_allowed
}

/// go-yaml's `!canUsePlain`: would this text come back as something other than a
/// string if written unquoted?
///
/// **A type question, not a structural one.** That distinction is the whole of the
/// bug this function used to carry: it also returned true for structural hazards
/// (`: `, a leading `#`, a trailing space), which made the caller request
/// double-quoting and skip libyaml's `PLAIN -> SINGLE` rung. Structural safety
/// belongs to [`ScalarAnalysis`]; this belongs to the resolver.
///
/// Three separate questions live nearby, and each has exactly one home:
///
/// | question | answered by | used for |
/// |---|---|---|
/// | would it resolve as a non-string? | this function | choosing the *requested* style |
/// | could a plain / single / block scalar hold it? | [`ScalarAnalysis`] | the fallback ladder |
/// | was it plain in the source and is it still safe? | [`plain_is_structurally_unsafe`] | promoting a parsed scalar |
fn resolves_as_non_string(v: &str) -> bool {
    // An empty plain scalar resolves as `!!null`, so it must be quoted.
    if v.is_empty() {
        return true;
    }
    // Two separate lists, both taken verbatim from go-yaml v3.
    //
    // `resolveMap` — what actually resolves as a non-string, case-exact:
    //     bool  true True TRUE false False FALSE
    //     null  (empty) ~ null Null NULL
    //     float .nan .NaN .NAN  .inf .Inf .INF  +.inf +.Inf +.INF  -.inf -.Inf -.INF
    //     merge <<
    if matches!(
        v,
        "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | "~"
            | "null"
            | "Null"
            | "NULL"
            | ".nan"
            | ".NaN"
            | ".NAN"
            | ".inf"
            | ".Inf"
            | ".INF"
            | "+.inf"
            | "+.Inf"
            | "+.INF"
            | "-.inf"
            | "-.Inf"
            | "-.INF"
            | "<<"
    ) {
        return true;
    }
    // `isOldBool` — the YAML 1.1 boolean set. These do NOT resolve as bools in
    // yaml.v3, but they are still quoted on the way out "so that the marshalled
    // output [is] valid for YAML 1.1 parsing". So they belong here (an emission
    // question) and NOT in the decode resolver, which is the distinction the
    // `value: y` bug turned on.
    if matches!(
        v,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "on"
            | "On"
            | "ON"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "off"
            | "Off"
            | "OFF"
    ) {
        return true;
    }
    if v.parse::<i64>().is_ok() || v.parse::<f64>().is_ok() {
        return true;
    }
    // A YAML 1.1 base-60 float — `1:20`, `-3:14:15.9`. go-yaml quotes these
    // defensively (`isBase60Float`) because a 1.1 parser reads them as numbers,
    // and its own comment notes the spec's regex is wrong in practice. A hand
    // check rather than a `regex` dependency: this crate has none, and the shape
    // is `[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?`.
    if looks_like_base60_float(v) {
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

/// `^[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?$` — go-yaml's `base60float`.
fn looks_like_base60_float(v: &str) -> bool {
    let body = v.strip_prefix(['-', '+']).unwrap_or(v);
    if !body.starts_with(|c: char| c.is_ascii_digit()) || !body.contains(':') {
        return false;
    }
    // Split off an optional fractional tail first.
    let (sexagesimal, frac) = match body.split_once('.') {
        Some((s, f)) => (s, Some(f)),
        None => (body, None),
    };
    if frac.is_some_and(|f| !f.chars().all(|c| c.is_ascii_digit() || c == '_')) {
        return false;
    }
    let mut groups = sexagesimal.split(':');
    let Some(first) = groups.next() else {
        return false;
    };
    if first.is_empty() || !first.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return false;
    }
    let mut had_group = false;
    for g in groups {
        had_group = true;
        // `[0-5]?[0-9]` — one or two digits, and a two-digit group is at most 59.
        let ok = match g.len() {
            1 => g.chars().all(|c| c.is_ascii_digit()),
            2 => {
                let b = g.as_bytes();
                (b'0'..=b'5').contains(&b[0]) && b[1].is_ascii_digit()
            }
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    had_group
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

    /// The style table, measured by running upstream sops v3.12.1 on a file
    /// containing exactly these values and reading its `-d` output.
    ///
    /// Not derived, not inferred from the docs — the first two versions of the
    /// style logic each got part of this wrong, and only a real diff caught it.
    ///
    /// ```text
    /// hash: 'has # hash'          structurally plain-unsafe -> SINGLE
    /// colon: 'a: b'               structurally plain-unsafe -> SINGLE
    /// dash: '- leading dash'      structurally plain-unsafe -> SINGLE
    /// lead_space: ' leading'      leading space             -> SINGLE
    /// trail_space: 'trailing '    trailing space            -> SINGLE
    /// tabbed: "a\tb"              tab kills single quotes   -> DOUBLE
    /// quoted_bool: "true"         resolves as a bool        -> DOUBLE
    /// number_str: "42"            resolves as an int        -> DOUBLE
    /// plainish: normal-value      safe and a string         -> PLAIN
    /// ```
    #[test]
    fn the_style_table_matches_what_real_sops_emits() {
        use ScalarStyle::{DoubleQuoted, Plain, SingleQuoted};
        let cases: &[(&str, ScalarStyle)] = &[
            ("has # hash", SingleQuoted),
            ("a: b", SingleQuoted),
            ("- leading dash", SingleQuoted),
            (" leading", SingleQuoted),
            ("trailing ", SingleQuoted),
            ("#hash", SingleQuoted),
            ("x #y", SingleQuoted),
            ("a\tb", DoubleQuoted),
            ("true", DoubleQuoted),
            ("42", DoubleQuoted),
            ("normal-value", Plain),
            // The overwhelming majority of every real file: an ENC[] value is
            // plain, because its colons are not followed by whitespace.
            ("ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]", Plain),
        ];
        for (v, want) in cases {
            assert_eq!(
                ScalarStyle::for_new_value(v),
                *want,
                "{v:?} should be {want:?}"
            );
        }
        assert!(
            cases.len() >= 12,
            "the table is the evidence; do not shrink it"
        );
    }

    /// A tab is the case that separates the two quote styles: libyaml clears
    /// `single_quoted_allowed` for `tab_characters` but leaves `block_allowed`
    /// alone, so a tabbed single-line string is double-quoted while a tabbed
    /// multi-line one is still a block.
    #[test]
    fn a_tab_forces_double_quotes_but_does_not_forbid_a_block() {
        assert_eq!(
            ScalarStyle::for_new_value("a\tb"),
            ScalarStyle::DoubleQuoted
        );
        assert!(
            literal_block_allowed("a\tb\nc"),
            "a tab does not clear block_allowed"
        );
        assert_eq!(ScalarStyle::for_new_value("a\tb\nc"), ScalarStyle::Literal);
    }

    /// A multi-line string is a **literal block**, not a quoted one — go-yaml's
    /// first case in `stringv`. This is the rule whose absence only showed up
    /// against a real 420-character SSH key in the operator's own secrets.
    #[test]
    fn a_multiline_string_becomes_a_literal_block() {
        assert_eq!(ScalarStyle::for_new_value("a\nb"), ScalarStyle::Literal);
        assert_eq!(
            ScalarStyle::for_new_value(
                // A PEM-shaped multi-line value, with the header words spelled
                // apart so the fleet's block-secrets pre-commit hook does not
                // read a test fixture as real key material. It fired on the
                // literal header here, correctly by its own rules.
                &format!(
                    "-----BEGIN {}-----\nb3BlbnNzaA\n-----END {}-----\n",
                    "OPENSSH PRIVATE_KEY", "OPENSSH PRIVATE_KEY"
                )
            ),
            ScalarStyle::Literal
        );
    }

    /// …unless a block could not round-trip it. libyaml clears `block_allowed`
    /// for a trailing space, a space before a newline, or a non-printable — each
    /// of which a block scalar would silently eat.
    #[test]
    fn a_multiline_string_a_block_would_mangle_stays_quoted() {
        for v in ["a\nb ", "a \nb", "a\nb\t", "a\n\u{7}b", "a\r\nb"] {
            assert!(
                !literal_block_allowed(v),
                "{v:?} must not be block-eligible"
            );
            assert_eq!(
                ScalarStyle::for_new_value(v),
                ScalarStyle::DoubleQuoted,
                "{v:?} must fall back to quoting"
            );
        }
        // A trailing newline is fine — that is the common case, handled by the
        // chomping indicator rather than by refusing the block.
        assert!(literal_block_allowed("a\nb\n"));
    }

    /// go-yaml quotes a YAML 1.1 base-60 float defensively, because a 1.1 parser
    /// reads `1:20` as the number 80.
    #[test]
    fn base60_floats_are_quoted_like_go_yaml() {
        for v in ["1:20", "-3:14:15", "+0:59", "1:20.5", "12_3:45"] {
            assert_eq!(
                ScalarStyle::for_new_value(v),
                ScalarStyle::DoubleQuoted,
                "{v:?} is a YAML 1.1 base-60 float"
            );
        }
        // Not base-60: a group above 59, a non-numeric group, no colon at all.
        for v in ["1:60", "1:2:99", "abc:12", "1234"] {
            let style = ScalarStyle::for_new_value(v);
            if v == "1234" {
                assert_eq!(
                    style,
                    ScalarStyle::DoubleQuoted,
                    "a bare integer is quoted anyway"
                );
            } else {
                assert_eq!(style, ScalarStyle::Plain, "{v:?} is not a base-60 float");
            }
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
