//! Leaf plaintext and the `ENC[…]` rendering around it.
//!
//! The rendering is fixed by `aes/cipher.go`:
//!
//! ```text
//! ENC[AES256_GCM,data:<b64std>,iv:<b64std>,tag:<b64std>,type:<t>]
//! ```
//!
//! Three things about it are load-bearing and none are guessable:
//!
//! - base64 is **`StdEncoding`** — padded, `+/` alphabet, not URL-safe.
//! - the upstream regex is anchored **only at the start**, so trailing bytes
//!   after `]` are ignored. We match that, because a file real sops accepts must
//!   not be one we reject.
//! - the type tag decides how the recovered bytes become a value, and two of the
//!   renderings are Python's rather than Go's or Rust's: booleans are
//!   `True`/`False`, floats are shortest-round-trip with no exponent.

use crate::WireError;
use base64::Engine as _;
use zeroize::Zeroizing;

/// The datatype tag carried in `type:`.
///
/// A closed enum, so adding a variant is a compile error at every match — which
/// is the point. Upstream's `default:` arm returns a runtime error instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeafType {
    Str,
    Int,
    Float,
    Bool,
    /// Decrypt-only in practice. `Cipher.Encrypt` has no `[]byte` arm, so sops
    /// itself never *writes* `type:bytes`; only Python-era files carry it. We
    /// read it and never emit it, which is why there is no `Plaintext` variant
    /// that renders back to it.
    Bytes,
    Time,
    Comment,
}

impl LeafType {
    /// The exact token that goes into `type:`.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Str => "str",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Bytes => "bytes",
            Self::Time => "time",
            Self::Comment => "comment",
        }
    }

    fn parse(tag: &str) -> Result<Self, WireError> {
        match tag {
            "str" => Ok(Self::Str),
            "int" => Ok(Self::Int),
            "float" => Ok(Self::Float),
            "bool" => Ok(Self::Bool),
            "bytes" => Ok(Self::Bytes),
            "time" => Ok(Self::Time),
            "comment" => Ok(Self::Comment),
            other => Err(WireError::UnknownDatatype(other.to_string())),
        }
    }
}

/// A leaf's plaintext bytes, together with the type they render as.
///
/// No `Display`, no `Deref<Target = str>`, no `AsRef<str>`, no `Into<String>`,
/// and a `Debug` that prints a length rather than content. Reading the bytes
/// takes [`Plaintext::expose`] — deliberately one greppable token, so a review
/// searches for a presence instead of noticing an absence. Same discipline as
/// `cofre_secret::Secret`, applied to a value that arrives from a *file* rather
/// than from an operator.
#[derive(Clone)]
pub struct Plaintext {
    bytes: Zeroizing<Vec<u8>>,
    ty: LeafType,
}

impl Plaintext {
    /// Wrap bytes that are already the canonical rendering for `ty`.
    ///
    /// Used on the decrypt path, where the bytes came out of GCM and the type
    /// came off the wire.
    #[must_use]
    pub fn from_wire(bytes: Vec<u8>, ty: LeafType) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            ty,
        }
    }

    /// A `type:str` leaf.
    #[must_use]
    pub fn string(s: impl Into<String>) -> Self {
        Self {
            bytes: Zeroizing::new(s.into().into_bytes()),
            ty: LeafType::Str,
        }
    }

    /// A `type:int` leaf. Rendered by Go's `strconv.Itoa`, which for the 64-bit
    /// `int` in play is just decimal — matching Rust's `i64` `Display`.
    #[must_use]
    pub fn integer(v: i64) -> Self {
        Self {
            bytes: Zeroizing::new(v.to_string().into_bytes()),
            ty: LeafType::Int,
        }
    }

    /// A `type:float` leaf.
    ///
    /// Go uses `strconv.FormatFloat(v, 'f', -1, 64)`: shortest representation
    /// that round-trips, **never** exponent notation, and — the comment in
    /// `cipher.go` says so outright — no zero padding after the point, because
    /// the Python implementation didn't pad. Rust's `{}` for `f64` is also
    /// shortest-round-trip, but it *will* reach for exponent form on extreme
    /// magnitudes, so those are rendered positionally by hand.
    #[must_use]
    pub fn float(v: f64) -> Self {
        Self {
            bytes: Zeroizing::new(format_go_float(v).into_bytes()),
            ty: LeafType::Float,
        }
    }

    /// A `type:bool` leaf. `True`/`False` — Python titlecase, as `cipher.go`
    /// notes explicitly. Writing Rust's `true`/`false` here changes the MAC.
    #[must_use]
    pub fn boolean(v: bool) -> Self {
        let s: &[u8] = if v { b"True" } else { b"False" };
        Self {
            bytes: Zeroizing::new(s.to_vec()),
            ty: LeafType::Bool,
        }
    }

    /// A `type:comment` leaf. The stored body excludes the leading `#`, which the
    /// YAML store strips with `commentLine[1:]`.
    #[must_use]
    pub fn comment(body: impl Into<String>) -> Self {
        Self {
            bytes: Zeroizing::new(body.into().into_bytes()),
            ty: LeafType::Comment,
        }
    }

    /// The declared type.
    #[must_use]
    pub fn leaf_type(&self) -> LeafType {
        self.ty
    }

    /// Length in bytes. Safe to log; it is what `Debug` prints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the value is empty — which the format treats as a fixed point in
    /// both directions (see [`EncryptedLeaf::render`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The plaintext bytes. Named to be searched for.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes this leaf contributes to the MAC.
    ///
    /// `sops.ToBytes` over the *plaintext*, which for every type we can emit is
    /// the same canonical rendering already held here — so this is the identity.
    /// It exists as a named method anyway, because the MAC contribution and the
    /// stored bytes are conceptually two different questions and a future type
    /// could separate them.
    #[must_use]
    pub fn mac_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Check the bytes really are a valid rendering of the declared type.
    ///
    /// Not called on the hot decrypt path — sops does not validate either, and a
    /// file it accepts must not be one we reject. Offered for `filestatus`-style
    /// inspection and for tests.
    pub fn validate(&self) -> Result<(), WireError> {
        let s = || String::from_utf8_lossy(&self.bytes);
        match self.ty {
            LeafType::Str | LeafType::Bytes | LeafType::Comment => Ok(()),
            LeafType::Int => s()
                .parse::<i64>()
                .map(|_| ())
                .map_err(|_| WireError::DatatypeMismatch { ty: "int" }),
            LeafType::Float => s()
                .parse::<f64>()
                .map(|_| ())
                .map_err(|_| WireError::DatatypeMismatch { ty: "float" }),
            LeafType::Bool => match self.bytes.as_slice() {
                b"True" | b"False" => Ok(()),
                _ => Err(WireError::DatatypeMismatch { ty: "bool" }),
            },
            LeafType::Time => Ok(()),
        }
    }
}

impl std::fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Plaintext(*** {} bytes, {})",
            self.bytes.len(),
            self.ty.tag()
        )
    }
}

impl PartialEq for Plaintext {
    /// Constant-time in the bytes.
    ///
    /// A plaintext comparison is a secret comparison — the obvious place it
    /// happens is "did this value change?" during an edit, where a timing signal
    /// leaks a prefix length. Length and type are not secret (the length ships in
    /// the ciphertext), so short-circuiting on those leaks nothing and keeps the
    /// byte compare well-defined.
    fn eq(&self, other: &Self) -> bool {
        self.ty == other.ty
            && self.bytes.len() == other.bytes.len()
            && bool::from(subtle::ConstantTimeEq::ct_eq(
                self.bytes.as_slice(),
                other.bytes.as_slice(),
            ))
    }
}

impl Eq for Plaintext {}

/// Go's `strconv.FormatFloat(v, 'f', -1, 64)`.
///
/// `'f'` forbids exponent form at any magnitude, and `-1` asks for the shortest
/// digit string that round-trips. Rust's `{}` gives the same shortest digits but
/// switches to `1e300`-style output past a threshold, so the exponent case is
/// expanded positionally from the shortest form rather than re-derived — which
/// keeps the digits identical to Go's.
fn format_go_float(v: f64) -> String {
    let shortest = format!("{v}");
    if !shortest.contains(['e', 'E']) {
        return shortest;
    }
    let (mantissa, exp) = shortest
        .split_once(['e', 'E'])
        .unwrap_or((shortest.as_str(), "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", mantissa),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits: String = format!("{int_part}{frac_part}");
    // Where the point sits, counted from the left of `digits`.
    let point = i32::try_from(int_part.len()).unwrap_or(0) + exp;
    let out = if point <= 0 {
        format!(
            "0.{}{}",
            "0".repeat(usize::try_from(-point).unwrap_or(0)),
            digits
        )
    } else if usize::try_from(point).unwrap_or(0) >= digits.len() {
        let pad = usize::try_from(point).unwrap_or(0) - digits.len();
        format!("{digits}{}", "0".repeat(pad))
    } else {
        let at = usize::try_from(point).unwrap_or(0);
        format!("{}.{}", &digits[..at], &digits[at..])
    };
    format!("{sign}{out}")
}

/// A parsed `ENC[…]` leaf: the three base64 fields plus the type tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedLeaf {
    pub(crate) data: Vec<u8>,
    pub(crate) iv: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) ty: LeafType,
}

impl EncryptedLeaf {
    /// Whether a string even looks like an encrypted leaf.
    ///
    /// Cheap prefix test, used to decide whether a scalar is ciphertext or a
    /// value that was left in the clear by a selector rule.
    #[must_use]
    pub fn looks_encrypted(s: &str) -> bool {
        s.starts_with("ENC[AES256_GCM,data:")
    }

    /// Parse the wire rendering.
    ///
    /// Hand-split rather than regex-matched: the fields are positional and
    /// delimiter-separated, and `.split_once` on each delimiter in order is both
    /// faster and — more usefully — impossible to get subtly wrong the way a
    /// greedy `(.+)` group can. Upstream's regex is unanchored at the end, so
    /// trailing bytes are ignored here too.
    pub fn parse(s: &str) -> Result<Self, WireError> {
        let rest = s
            .strip_prefix("ENC[AES256_GCM,data:")
            .ok_or(WireError::NotAnEncryptedLeaf)?;
        let (data, rest) = rest
            .split_once(",iv:")
            .ok_or(WireError::NotAnEncryptedLeaf)?;
        let (iv, rest) = rest
            .split_once(",tag:")
            .ok_or(WireError::NotAnEncryptedLeaf)?;
        let (tag, rest) = rest
            .split_once(",type:")
            .ok_or(WireError::NotAnEncryptedLeaf)?;
        // Upstream's `^ENC\[…\]` has no `$`; everything past the bracket is
        // ignored rather than rejected.
        let ty = rest.split_once(']').map_or(rest, |(t, _)| t);
        Ok(Self {
            data: b64(data, "data")?,
            iv: b64(iv, "iv")?,
            tag: b64(tag, "tag")?,
            ty: LeafType::parse(ty)?,
        })
    }

    /// Render back to the wire.
    #[must_use]
    pub fn render(&self) -> String {
        let e = base64::engine::general_purpose::STANDARD;
        let mut out = String::with_capacity(
            32 + (self.data.len() + self.iv.len() + self.tag.len()) * 4 / 3 + 8,
        );
        out.push_str("ENC[AES256_GCM,data:");
        out.push_str(&e.encode(&self.data));
        out.push_str(",iv:");
        out.push_str(&e.encode(&self.iv));
        out.push_str(",tag:");
        out.push_str(&e.encode(&self.tag));
        out.push_str(",type:");
        out.push_str(self.ty.tag());
        out.push(']');
        out
    }

    /// The declared type.
    #[must_use]
    pub fn leaf_type(&self) -> LeafType {
        self.ty
    }

    /// The nonce actually on the wire.
    ///
    /// Decryption honours this length rather than the 32-byte constant, exactly
    /// as `cipher.go` does with `cipher.NewGCMWithNonceSize(…, len(iv))` — so a
    /// file written by some other implementation still opens.
    #[must_use]
    pub fn iv_len(&self) -> usize {
        self.iv.len()
    }
}

fn b64(s: &str, field: &'static str) -> Result<Vec<u8>, WireError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| WireError::Base64 { field })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real leaf lifted from the operator's `nix/secrets.yaml`
    /// (`akeyless_base_test.admin_access_id`) — already-encrypted bytes, so
    /// nothing secret is committed here, and it is a genuine specimen rather
    /// than a hand-built one.
    const SPECIMEN: &str = "ENC[AES256_GCM,data:+s0vLJR7FqRk1dW3+LymL5aTHh4=,iv:irJYGNHV08Ey6RyO5YfqeaNCjLg8vWcdxoQvtnYCR40=,tag:Ax+kskUPjI/gXKq6WEPTxA==,type:str]";

    #[test]
    fn parses_a_real_specimen() {
        let leaf = EncryptedLeaf::parse(SPECIMEN).expect("parse");
        assert_eq!(leaf.leaf_type(), LeafType::Str);
        assert_eq!(leaf.iv_len(), 32, "sops nonces are 32 bytes, not 12");
        assert_eq!(leaf.tag.len(), 16);
    }

    #[test]
    fn render_round_trips_byte_exactly() {
        let leaf = EncryptedLeaf::parse(SPECIMEN).expect("parse");
        assert_eq!(leaf.render(), SPECIMEN);
    }

    #[test]
    fn trailing_bytes_after_the_bracket_are_ignored_like_upstream() {
        let with_junk = format!("{SPECIMEN} and then some");
        let a = EncryptedLeaf::parse(SPECIMEN).expect("parse");
        let b = EncryptedLeaf::parse(&with_junk).expect("parse with junk");
        assert_eq!(a, b);
    }

    #[test]
    fn a_plain_value_is_not_mistaken_for_ciphertext() {
        assert!(!EncryptedLeaf::looks_encrypted("hello"));
        assert!(!EncryptedLeaf::looks_encrypted(
            "ENC[SOMETHING_ELSE,data:x]"
        ));
        assert!(EncryptedLeaf::looks_encrypted(SPECIMEN));
        assert_eq!(
            EncryptedLeaf::parse("hello"),
            Err(WireError::NotAnEncryptedLeaf)
        );
    }

    #[test]
    fn unknown_datatype_is_named_not_swallowed() {
        let bad = SPECIMEN.replace("type:str", "type:quaternion");
        assert_eq!(
            EncryptedLeaf::parse(&bad),
            Err(WireError::UnknownDatatype("quaternion".into()))
        );
    }

    #[test]
    fn bad_base64_names_its_field() {
        let bad = SPECIMEN.replace("iv:irJY", "iv:!!!!");
        assert_eq!(
            EncryptedLeaf::parse(&bad),
            Err(WireError::Base64 { field: "iv" })
        );
    }

    #[test]
    fn booleans_use_python_titlecase() {
        assert_eq!(Plaintext::boolean(true).expose(), b"True");
        assert_eq!(Plaintext::boolean(false).expose(), b"False");
    }

    #[test]
    fn floats_match_go_formatfloat_f_minus_one() {
        // shortest round-trip, no trailing zeros
        assert_eq!(Plaintext::float(1.5).expose(), b"1.5");
        assert_eq!(Plaintext::float(1.0).expose(), b"1");
        assert_eq!(Plaintext::float(-0.25).expose(), b"-0.25");
        // 'f' forbids exponent form at any magnitude
        assert_eq!(Plaintext::float(1e21).expose(), b"1000000000000000000000");
        assert_eq!(Plaintext::float(1e-7).expose(), b"0.0000001");
        assert_eq!(Plaintext::float(-1.5e-7).expose(), b"-0.00000015");
    }

    #[test]
    fn debug_never_shows_the_value() {
        let p = Plaintext::string("hunter2");
        let shown = format!("{p:?}");
        assert!(
            !shown.contains("hunter2"),
            "Debug leaked the plaintext: {shown}"
        );
        assert_eq!(shown, "Plaintext(*** 7 bytes, str)");
    }

    #[test]
    fn validate_catches_a_mislabelled_leaf() {
        let lying = Plaintext::from_wire(b"not-a-number".to_vec(), LeafType::Int);
        assert_eq!(
            lying.validate(),
            Err(WireError::DatatypeMismatch { ty: "int" })
        );
        // Rust's own bool spelling is exactly the thing that must be rejected.
        let rusty = Plaintext::from_wire(b"true".to_vec(), LeafType::Bool);
        assert_eq!(
            rusty.validate(),
            Err(WireError::DatatypeMismatch { ty: "bool" })
        );
        assert_eq!(Plaintext::boolean(true).validate(), Ok(()));
    }
}
