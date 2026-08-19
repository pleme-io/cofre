//! The tree walk — the one algorithm both directions share.
//!
//! `sops.go` has two near-identical walkers, `Tree.Encrypt` and `Tree.Decrypt`,
//! that differ only in which way the cipher runs. The order they visit leaves in,
//! the selector they consult, what they feed the MAC, and the comment stack they
//! maintain are all the same — and the *shared* part is where a divergence would
//! be invisible, because either direction alone is self-consistent. So there is
//! one walker here, parameterised by direction.
//!
//! # The asymmetry that is not a bug
//!
//! MAC bytes and YAML text are **not the same rendering** for three of the seven
//! datatypes, and conflating them silently changes the MAC:
//!
//! | type | MAC bytes / `ENC[]` plaintext | YAML text after decrypt |
//! |---|---|---|
//! | `bool` | `True` / `False` (Python titlecase) | `true` / `false` (go-yaml's bool) |
//! | `float` | `FormatFloat(v, 'f', -1, 64)` — never an exponent | `FormatFloat(v, 'g', -1, 64)` — exponent when short |
//! | `str` | the raw bytes | plain / single / double / literal, by go-yaml's ladder |
//!
//! Both non-string rows were found the same way: not by reading the spec, but by
//! decrypting the operator's real `secrets.yaml` with both binaries and diffing.
//!
//! - **`bool`** — sops hashes `True` because the Python implementation did, then
//!   hands Go a `bool`, which go-yaml writes as `true`.
//! - **`float`** — the `ENC[]` plaintext is `'f'` (positional, always), but
//!   `encode.go`'s `floatv` renders with `'g'`. A `client_id` of
//!   `608800001149` therefore stores as those twelve digits and *decrypts* as
//!   `6.08800001149e+11`. Seventeen characters against twenty-one, on one line of
//!   a 1382-line file.
//!
//! An implementation that used one spelling for both produces a file that either
//! fails its own MAC or decrypts to the wrong text.

use suminuri_wire::{
    AadPath, DataKey, EncryptedLeaf, EncryptionSelector, IvStash, LeafType, MacAccumulator,
    Plaintext, Selection, WireError, decrypt_leaf, encrypt_leaf,
};
use suminuri_yaml::{Entry, Item, Scalar, ScalarStyle, Value};

/// What a walk did. Reported so a caller can assert a denominator instead of
/// trusting that a walk which found nothing was a walk over nothing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WalkStats {
    /// Leaves visited, whatever the selector decided.
    pub leaves: usize,
    /// Leaves the selector said to encrypt.
    pub encrypted: usize,
    /// Leaves left in the clear.
    pub cleared: usize,
    /// Leaves fed to the MAC. Under `mac_only_encrypted` this is `encrypted`;
    /// otherwise it is `leaves` minus any comments.
    pub macced: usize,
}

/// Which way the cipher runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// Everything the walk needs, gathered so the recursive functions take one
/// parameter instead of six.
pub struct WalkCtx<'a> {
    pub direction: Direction,
    pub key: &'a DataKey,
    pub selector: &'a EncryptionSelector,
    pub mac: &'a mut MacAccumulator,
    /// On decrypt this is filled in; on encrypt it is consulted, so an unchanged
    /// value reproduces its previous ciphertext byte for byte.
    pub stash: &'a mut IvStash,
    pub stats: WalkStats,
}

/// Walk a document root, encrypting or decrypting every selected leaf in place.
pub fn walk(root: &mut Value, ctx: &mut WalkCtx<'_>) -> Result<WalkStats, WireError> {
    let mut path = AadPath::root();
    let mut comments: Vec<Vec<String>> = Vec::new();
    walk_value(root, &mut path, &mut comments, ctx)?;
    Ok(ctx.stats)
}

fn walk_value(
    value: &mut Value,
    path: &mut AadPath,
    comments: &mut Vec<Vec<String>>,
    ctx: &mut WalkCtx<'_>,
) -> Result<(), WireError> {
    match value {
        Value::Scalar(_) => visit_scalar(value, path, comments, false, ctx),
        Value::Mapping(items) => walk_mapping(items, path, comments, ctx),
        Value::Sequence(entries) => walk_sequence(entries, path, comments, ctx),
    }
}

fn walk_mapping(
    items: &mut [Item],
    path: &mut AadPath,
    comments: &mut Vec<Vec<String>>,
    ctx: &mut WalkCtx<'_>,
) -> Result<(), WireError> {
    // A fresh comment set per collection, pushed then popped — `walkBranch`'s
    // `commentsStack = append(commentsStack, []string{})`.
    comments.push(Vec::new());
    let result = (|| {
        for item in items {
            match item {
                Item::Comment(body) => {
                    // A comment joins the active set *before* being visited, so a
                    // comment can enable its own encryption via a prior comment.
                    if let Some(set) = comments.last_mut() {
                        set.push(body.clone());
                    }
                    visit_comment(body, path, comments, ctx)?;
                }
                Item::Pair { key, value } => {
                    // A non-comment value clears the active comment set once
                    // visited, so a comment governs only what immediately follows.
                    let key = key.clone();
                    path.push_key(key);
                    let r = walk_value(value, path, comments, ctx);
                    path.pop();
                    r?;
                    if let Some(set) = comments.last_mut() {
                        set.clear();
                    }
                }
            }
        }
        Ok(())
    })();
    comments.pop();
    result
}

fn walk_sequence(
    entries: &mut [Entry],
    path: &mut AadPath,
    comments: &mut Vec<Vec<String>>,
    ctx: &mut WalkCtx<'_>,
) -> Result<(), WireError> {
    comments.push(Vec::new());
    let result = (|| {
        for entry in entries {
            match entry {
                Entry::Comment(body) => {
                    if let Some(set) = comments.last_mut() {
                        set.push(body.clone());
                    }
                    visit_comment(body, path, comments, ctx)?;
                }
                Entry::Value(v) => {
                    // No `push_key` here. `walkSlice` recurses with the path
                    // unchanged, so every element authenticates under its parent
                    // key. See `suminuri_wire::aad`.
                    walk_value(v, path, comments, ctx)?;
                    if let Some(set) = comments.last_mut() {
                        set.clear();
                    }
                }
            }
        }
        Ok(())
    })();
    comments.pop();
    result
}

fn visit_comment(
    body: &mut String,
    path: &AadPath,
    comments: &[Vec<String>],
    ctx: &mut WalkCtx<'_>,
) -> Result<(), WireError> {
    let selection = ctx.selector.select(path, comments, true);
    ctx.stats.leaves += 1;
    if selection.is_encrypted() {
        ctx.stats.encrypted += 1;
    } else {
        ctx.stats.cleared += 1;
    }
    // A comment never contributes to the MAC, in either direction — the
    // `if !ok` guard around `hash.Write` in both of sops's walkers.
    //
    // ★ THE SELECTOR GATES ENCRYPT ONLY, AND THE ASYMMETRY IS THE WHOLE POINT.
    //
    // This guard used to sit here, above the `match`, so it skipped DECRYPT too.
    // Measured 2026-08-19 against the fleet's real corpus: four k8s files came back
    // with `#ENC[AES256_GCM,…,type:comment]` where upstream sops returned the
    // plaintext, because those comments sit at a path the selector calls clear —
    // so we refused to decrypt a comment the file plainly says is encrypted.
    //
    // The two directions ask different questions. On ENCRYPT the selector is the
    // authority: it is a policy decision about what *should* be protected, and a
    // comment outside the encrypted region must stay readable. On DECRYPT the FILE
    // is the authority: a `type:comment` leaf is a fact about what was done, and a
    // policy that has since changed cannot un-encrypt bytes already on disk. Gating
    // decrypt on the selector makes any file whose rules moved permanently
    // unreadable by us while upstream reads it fine.
    //
    // Decrypting unconditionally is safe rather than lax: `EncryptedLeaf::parse`
    // only matches a real `ENC[AES256_GCM,…]` envelope, and `decrypt_leaf` verifies
    // the GCM tag against the AAD, so a plain comment that merely looks unusual
    // cannot be mangled — it falls through and keeps its text.
    let aad = path.aad();
    match ctx.direction {
        Direction::Encrypt => {
            if !selection.is_encrypted() {
                return Ok(());
            }
            let pt = Plaintext::comment(body.clone());
            let iv = ctx.stash.recall(&pt, &aad);
            if let Some(leaf) = encrypt_leaf(ctx.key, &pt, &aad, iv)? {
                let rendered = leaf.render();
                // Upstream refuses this too: an encrypted comment that matches
                // `unencrypted_comment_regex` would be skipped on the way back
                // in, so the file could never be decrypted again.
                if ctx.selector.encrypted_comment_would_be_skipped(&rendered) {
                    return Err(WireError::SelfDefeatingCommentRegex);
                }
                *body = rendered;
            }
        }
        Direction::Decrypt => {
            // "Assume the comment was not encrypted in the first place" — sops
            // warns and keeps the text rather than failing, because files written
            // by older versions carry plain comments in encrypted position.
            if let Ok(leaf) = EncryptedLeaf::parse(body) {
                if let Ok(pt) = decrypt_leaf(ctx.key, &leaf, &aad, Some(ctx.stash)) {
                    *body = String::from_utf8_lossy(pt.expose()).into_owned();
                }
            }
        }
    }
    Ok(())
}

fn visit_scalar(
    value: &mut Value,
    path: &AadPath,
    comments: &[Vec<String>],
    is_comment: bool,
    ctx: &mut WalkCtx<'_>,
) -> Result<(), WireError> {
    let Value::Scalar(scalar) = value else {
        return Ok(());
    };

    // ★ A YAML NULL IS NOT A LEAF, IN EITHER DIRECTION.
    //
    // sops's `walkValue` has `case nil: return nil, nil` — a nil returns before
    // reaching `onLeaves`, which is where both the cipher and the MAC live. So a
    // null is touched by neither, and it is not counted.
    //
    // Missing this made one real fleet file unreadable:
    // `operators/nexus-monitor/k8s/github-credentials.yaml` has
    // `password: null` inside `stringData`, which its `encrypted_regex` selects —
    // so we tried to parse `null` as an `ENC[…]` envelope and failed with "value is
    // not a suminuri/sops encrypted leaf" on a file upstream reads fine.
    //
    // STYLE IS PART OF THE TEST. A plain `null` is the YAML null; a quoted
    // `"null"` is the four-character string and IS a leaf. Ignoring the style here
    // would silently stop encrypting any secret whose value happens to be the text
    // "null" — a far worse bug than the one being fixed.
    // ★ RED-RUN 2026-08-19: replacing this condition with `false` turns the corpus
    // gate red on exactly two files — `git-ssh-secret.yaml` and
    // `github-credentials.yaml` — each reported as "we refused a file upstream
    // read". Both carry a `null` inside an encrypted region.
    if scalar.style == ScalarStyle::Plain
        && matches!(scalar.value.as_str(), "null" | "Null" | "NULL" | "~")
    {
        return Ok(());
    }

    let selection = ctx.selector.select(path, comments, is_comment);
    ctx.stats.leaves += 1;
    match selection {
        Selection::Encrypt => ctx.stats.encrypted += 1,
        Selection::Clear => ctx.stats.cleared += 1,
    }
    let aad = path.aad();

    match ctx.direction {
        Direction::Encrypt => {
            let pt = plaintext_from_yaml(scalar);
            // Feed the MAC *before* encrypting, over the plaintext — and only
            // when the policy says this leaf counts.
            if !ctx.mac.mac_only_encrypted() || selection.is_encrypted() {
                ctx.mac.feed(&pt);
                ctx.stats.macced += 1;
            }
            if selection.is_encrypted() {
                let iv = ctx.stash.recall(&pt, &aad);
                match encrypt_leaf(ctx.key, &pt, &aad, iv)? {
                    // An empty value is a fixed point: it stays the empty string
                    // rather than becoming a zero-length ciphertext.
                    None => *scalar = Scalar::parsed(String::new(), ScalarStyle::Plain),
                    Some(leaf) => {
                        *scalar = Scalar::parsed(leaf.render(), ScalarStyle::Plain);
                    }
                }
            }
        }
        Direction::Decrypt => {
            let pt = if selection.is_encrypted() {
                if scalar.value.is_empty() {
                    // The empty fixed point, coming back.
                    Plaintext::string(String::new())
                } else {
                    let leaf = EncryptedLeaf::parse(&scalar.value)?;
                    let pt = decrypt_leaf(ctx.key, &leaf, &aad, Some(ctx.stash))?;
                    *scalar = yaml_from_plaintext(&pt);
                    pt
                }
            } else {
                plaintext_from_yaml(scalar)
            };
            // Feed the MAC over the *decrypted* value, so the recomputed digest
            // matches the one taken at encrypt time.
            if !ctx.mac.mac_only_encrypted() || selection.is_encrypted() {
                ctx.mac.feed(&pt);
                ctx.stats.macced += 1;
            }
        }
    }
    Ok(())
}

/// A YAML scalar as a typed plaintext, resolving its YAML 1.1 type the way sops's
/// store does.
///
/// A **quoted** scalar is always a string, whatever its text — that is what
/// quoting means, and it is why the style is carried through the tree rather than
/// discarded at parse time. An unquoted `true` is a bool; a quoted `"true"` is the
/// four-character string.
fn plaintext_from_yaml(scalar: &Scalar) -> Plaintext {
    if scalar.style != ScalarStyle::Plain {
        return Plaintext::string(scalar.value.clone());
    }
    let v = &scalar.value;
    // go-yaml v3's `resolveMap`, exactly. Six bool spellings and no more:
    //
    //   {true,  boolTag, ["true", "True", "TRUE"]}
    //   {false, boolTag, ["false", "False", "FALSE"]}
    //   {nil,   nullTag, ["", "~", "null", "Null", "NULL"]}
    //
    // **`y`, `yes`, `on`, `n`, `no`, `off` are STRINGS here.** yaml.v3 dropped
    // YAML 1.1's boolean set; `isOldBool` exists only to keep *quoting* them on
    // the way out, which is a different question and a different function. The
    // first version of this resolver accepted the 1.1 set, so a plaintext
    // `value: y` was encrypted as `type:bool` and came back as `true` — a value
    // changed by a round-trip, caught by the differential and by nothing else.
    //
    // Matching is case-exact, not case-folded: `TRUE` is a bool and `tRuE` is a
    // string, because the table lists spellings rather than a predicate.
    match v.as_str() {
        "true" | "True" | "TRUE" => return Plaintext::boolean(true),
        "false" | "False" | "FALSE" => return Plaintext::boolean(false),
        // A null leaf has no `ENC[]` spelling — `Cipher.Encrypt` has no nil arm
        // and `walkValue` returns nil unchanged — so it stays a string here and
        // the selector-driven walk leaves it alone.
        _ => {}
    }
    if let Ok(i) = v.parse::<i64>() {
        return Plaintext::integer(i);
    }
    // Only after the integer test: `3` is an int, `3.0` is a float, and Go's
    // resolver tries int first too.
    if let Ok(f) = v.parse::<f64>() {
        // Reject the forms Rust parses but YAML does not resolve as a number, so
        // `inf` stays a string.
        if v.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | 'e' | 'E'))
        {
            return Plaintext::float(f);
        }
    }
    Plaintext::string(v.clone())
}

/// A decrypted plaintext rendered back as a YAML scalar.
///
/// The `bool` arm is the asymmetry the module docs warn about: the MAC saw
/// `True`, and the YAML gets `true`, because sops hands go-yaml a Go `bool`.
fn yaml_from_plaintext(pt: &Plaintext) -> Scalar {
    let text = String::from_utf8_lossy(pt.expose()).into_owned();
    match pt.leaf_type() {
        // A string is styled by go-yaml's resolver: plain when it reads back as
        // the same string, quoted when it would not.
        LeafType::Str | LeafType::Bytes | LeafType::Comment => Scalar::new(text),
        LeafType::Int | LeafType::Time => Scalar::parsed(text, ScalarStyle::Plain),
        // `'g'`, not the `'f'` the ciphertext holds. See the module docs.
        LeafType::Float => Scalar::parsed(
            text.parse::<f64>().map_or(text.clone(), format_go_float_g),
            ScalarStyle::Plain,
        ),
        LeafType::Bool => Scalar::parsed(
            if text == "True" { "true" } else { "false" },
            ScalarStyle::Plain,
        ),
    }
}

/// `strconv.FormatFloat(v, 'g', -1, 64)` — how go-yaml **renders** a float.
///
/// Deliberately *not* the same function as `suminuri_wire::format_go_float_f`,
/// which is how sops **encrypts** one. `'f'` never uses an exponent; `'g'` does
/// once the value is short enough in exponent form. So a single float has two
/// spellings across one file's lifetime, and using either for both jobs is a bug
/// — see the module docs for the real `client_id` that proved it.
///
/// It lives here rather than in `suminuri-yaml` because this is the only place
/// both spellings are needed at once, and duplicating the `'f'` formatter to give
/// `suminuri-yaml` a local copy would have been the second copy of a shape that
/// already exists.
#[must_use]
pub fn format_go_float_g(v: f64) -> String {
    if v.is_nan() {
        return ".nan".to_string();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            ".inf".to_string()
        } else {
            "-.inf".to_string()
        };
    }
    if v == 0.0 {
        // Preserves a negative zero, which Go does too.
        return if v.is_sign_negative() {
            "-0".to_string()
        } else {
            "0".to_string()
        };
    }

    // Go's `'g'` uses `%e` when the decimal exponent is below -4 or **at least 6**.
    //
    // Six is a literal constant, not a function of the value: `ftoa.go` sets
    // `eprec = 6` unconditionally when the precision is "shortest" (`prec < 0`),
    // with the comment "if precision was the shortest possible, use precision 6
    // for this decision". An earlier version used the significant-digit count
    // instead — a plausible reading that gets `1234567` right and
    // `608863452348.1149` wrong, because 11 >= 6 but 11 < 16.
    //
    // Measured against Go 1.25.10 rather than inferred:
    //   999999            -> 999999                  (exp 5)
    //   1234567           -> 1.234567e+06            (exp 6)
    //   0.0001            -> 0.0001                  (exp -4)
    //   0.00001           -> 1e-05                   (exp -5)
    //   608863452348.1149 -> 6.088634523481149e+11   (exp 11)
    //
    // The digits come from Rust's `{:e}`, which is shortest-round-trip and
    // therefore produces the *same* digit string Go's Ryu does. Two things are
    // deliberately not done here:
    //
    // - **No `v / 10f64.powi(exp)` to get the mantissa.** That division is
    //   inexact, and it cost the last digit: `…481149e+11` came out as
    //   `…481148e+11` — one character wrong on one line of a 1382-line file, which
    //   is exactly the kind of error a smaller test never surfaces.
    // - **No `log10().floor()` to get the exponent.** `log10(1e-5)` is
    //   `-5.000000000000001`, so the floor is `-6` and the whole branch flips.
    //   `{:e}`'s exponent is exact.
    let sci = format!("{v:e}");
    let (mantissa, exp_text) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp: i32 = exp_text.parse().unwrap_or(0);

    if exp < -4 || exp >= 6 {
        // `d.ddde±dd`: sign always present, at least two exponent digits.
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exp.abs())
    } else {
        // Rust's `Display` for `f64` never uses exponent notation, so this is
        // already Go's `%f` rendering of the shortest digits.
        format!("{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DataKey {
        DataKey::from_bytes(&[11u8; 32]).expect("32")
    }

    fn run(root: &mut Value, direction: Direction, mac_only: bool) -> (WalkStats, String) {
        let selector = EncryptionSelector::default_policy();
        let mut mac = MacAccumulator::new(mac_only);
        let mut stash = IvStash::new();
        let mut ctx = WalkCtx {
            direction,
            key: &key(),
            selector: &selector,
            mac: &mut mac,
            stash: &mut stash,
            stats: WalkStats::default(),
        };
        let stats = walk(root, &mut ctx).expect("walk");
        (stats, mac.finish().as_hex().to_string())
    }

    fn tree(src: &str) -> Value {
        suminuri_yaml::parse(src)
            .expect("parse")
            .root()
            .cloned()
            .expect("root")
    }

    fn render(v: &Value) -> String {
        suminuri_yaml::emit(
            &suminuri_yaml::Document::single(v.clone()),
            suminuri_yaml::EmitOptions::default(),
        )
        .expect("emit")
    }

    /// The core property: encrypt then decrypt is the identity on the text, and
    /// both directions compute the same MAC.
    /// go-yaml's float rendering, pinned against values measured from Go 1.25.10.
    ///
    /// The `608863452348.1149` row is the real `client_id` from the operator's
    /// `secrets.yaml`. It is here because it is the value that caught two separate
    /// bugs — the wrong exponent threshold, then a one-digit rounding error from
    /// computing the mantissa by division.
    #[test]
    fn float_rendering_matches_gos_g_format() {
        let cases: &[(f64, &str)] = &[
            (608_863_452_348.1149, "6.088634523481149e+11"),
            (1.5, "1.5"),
            (1.0, "1"),
            (999_999.0, "999999"),
            (1_234_567.0, "1.234567e+06"),
            (1e6, "1e+06"),
            (1e21, "1e+21"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (123_456.0, "123456"),
            (0.25, "0.25"),
            (-1.5, "-1.5"),
        ];
        for (v, want) in cases {
            assert_eq!(&format_go_float_g(*v), want, "g-format of {v}");
        }
        assert_eq!(format_go_float_g(f64::NAN), ".nan");
        assert_eq!(format_go_float_g(f64::INFINITY), ".inf");
        assert_eq!(format_go_float_g(f64::NEG_INFINITY), "-.inf");
        assert_eq!(format_go_float_g(0.0), "0");
        assert_eq!(format_go_float_g(-0.0), "-0");
    }

    /// The two spellings are genuinely different, and both are needed. If this
    /// ever passes trivially, one of them has been made to do the other's job.
    #[test]
    fn the_two_float_spellings_diverge_where_they_must() {
        let v = 608_863_452_348.1149;
        assert_eq!(suminuri_wire::format_go_float_f(v), "608863452348.1149");
        assert_eq!(format_go_float_g(v), "6.088634523481149e+11");
        assert_ne!(suminuri_wire::format_go_float_f(v), format_go_float_g(v));
        // …and agree where they should, so the split is not gratuitous.
        for v in [1.5, 0.25, 123_456.0] {
            assert_eq!(suminuri_wire::format_go_float_f(v), format_go_float_g(v));
        }
    }

    #[test]
    fn encrypt_then_decrypt_is_the_identity_and_the_macs_agree() {
        let src = "alpha: one\ncount: 3\nratio: 1.5\nenabled: true\nnested:\n    deep: v\n";
        let mut t = tree(src);
        let (enc_stats, mac_at_encrypt) = run(&mut t, Direction::Encrypt, false);
        assert_eq!(enc_stats.leaves, 5);
        assert_eq!(enc_stats.encrypted, 5);
        assert_eq!(enc_stats.macced, 5);
        assert!(render(&t).contains("ENC[AES256_GCM,"));

        let (dec_stats, mac_at_decrypt) = run(&mut t, Direction::Decrypt, false);
        assert_eq!(dec_stats.leaves, 5);
        assert_eq!(
            mac_at_encrypt, mac_at_decrypt,
            "the MAC must survive the round trip"
        );
        assert_eq!(render(&t), src, "and so must the text");
    }

    /// The bool asymmetry, pinned. If `yaml_from_plaintext` ever writes `True`,
    /// this fails — and so would every real file's round-trip.
    #[test]
    fn a_bool_hashes_as_titlecase_but_renders_lowercase() {
        let mut t = tree("enabled: true\ndisabled: false\n");
        let (_, mac_encrypt) = run(&mut t, Direction::Encrypt, false);
        let (_, mac_decrypt) = run(&mut t, Direction::Decrypt, false);
        assert_eq!(mac_encrypt, mac_decrypt);
        assert_eq!(render(&t), "enabled: true\ndisabled: false\n");

        // And the MAC really did see the titlecase spelling.
        let mut acc = MacAccumulator::new(false);
        acc.feed(&Plaintext::boolean(true));
        acc.feed(&Plaintext::boolean(false));
        assert_eq!(acc.finish().as_hex(), mac_encrypt);
    }

    /// A quoted scalar is a string even when its text reads as a bool. Losing the
    /// style at parse time would change this leaf's type, its MAC bytes, and its
    /// rendering.
    #[test]
    fn a_quoted_true_is_a_string_not_a_bool() {
        let mut t = tree("quoted: \"true\"\nbare: true\n");
        let (_, mac) = run(&mut t, Direction::Encrypt, false);
        let mut acc = MacAccumulator::new(false);
        acc.feed(&Plaintext::string("true"));
        acc.feed(&Plaintext::boolean(true));
        assert_eq!(acc.finish().as_hex(), mac);
        run(&mut t, Direction::Decrypt, false);
        assert_eq!(render(&t), "quoted: \"true\"\nbare: true\n");
    }

    #[test]
    fn the_selector_leaves_exempt_leaves_alone() {
        let mut t = tree("covered: hide-me\nport_unencrypted: 8080\n");
        let (stats, _) = run(&mut t, Direction::Encrypt, false);
        assert_eq!(stats.encrypted, 1);
        assert_eq!(stats.cleared, 1);
        let out = render(&t);
        assert!(
            out.contains("port_unencrypted: 8080"),
            "left in the clear: {out}"
        );
        assert!(out.contains("covered: ENC[AES256_GCM,"));
    }

    /// Under `mac_only_encrypted` a cleared leaf drops out of the MAC entirely.
    #[test]
    fn mac_only_encrypted_excludes_cleared_leaves() {
        let mut t = tree("covered: hide-me\nport_unencrypted: 8080\n");
        let (stats, mac) = run(&mut t, Direction::Encrypt, true);
        assert_eq!(stats.macced, 1, "only the encrypted leaf counted");
        let mut acc = MacAccumulator::new(true);
        acc.feed(&Plaintext::string("hide-me"));
        assert_eq!(acc.finish().as_hex(), mac);
    }

    /// A sequence's elements share their parent key's AAD — and on a *fresh*
    /// encrypt they still get different IVs, so their ciphertexts differ.
    ///
    /// That combination is not obvious and the first draft of this test asserted
    /// the opposite. The stash is populated by **decrypt only** (upstream:
    /// `c.stash[…] = iv` appears in `Cipher.Decrypt`, never in `Encrypt`), so on a
    /// first encryption there is nothing to recall and each leaf draws its own
    /// nonce. Verified against real sops v3.12.1 on `items: [same, same]`: two
    /// different `iv:` values.
    ///
    /// The shared AAD is what makes the *decrypt* side work — both elements
    /// authenticate under `items:` — and it is why the operator's three-element
    /// `sops.age` array opens at all.
    #[test]
    fn sequence_elements_share_one_aad_but_not_one_iv() {
        let mut t = tree("items:\n    - same\n    - same\n");
        run(&mut t, Direction::Encrypt, false);
        let out = render(&t);
        let values: Vec<&str> = out.lines().filter(|l| l.contains("ENC[")).collect();
        assert_eq!(values.len(), 2);
        assert_ne!(
            values[0], values[1],
            "fresh encrypt: no stash, so distinct nonces"
        );

        // Both nonetheless decrypt, which is the property the shared AAD buys.
        let (stats, _) = run(&mut t, Direction::Decrypt, false);
        assert_eq!(stats.leaves, 2);
        assert_eq!(render(&t), "items:\n    - same\n    - same\n");
    }

    /// The stash is what keeps an edit's diff small: re-encrypting after a decrypt
    /// must reproduce the previous ciphertext exactly.
    #[test]
    fn a_decrypt_then_encrypt_reproduces_the_ciphertext() {
        let mut t = tree("a: one\nb: two\n");
        let selector = EncryptionSelector::default_policy();
        let k = key();

        // First encryption, fresh IVs.
        let mut mac = MacAccumulator::new(false);
        let mut stash = IvStash::new();
        let mut ctx = WalkCtx {
            direction: Direction::Encrypt,
            key: &k,
            selector: &selector,
            mac: &mut mac,
            stash: &mut stash,
            stats: WalkStats::default(),
        };
        walk(&mut t, &mut ctx).expect("encrypt");
        let first = render(&t);

        // Decrypt, filling one stash, then re-encrypt through that same stash.
        let mut mac2 = MacAccumulator::new(false);
        let mut shared = IvStash::new();
        let mut ctx2 = WalkCtx {
            direction: Direction::Decrypt,
            key: &k,
            selector: &selector,
            mac: &mut mac2,
            stash: &mut shared,
            stats: WalkStats::default(),
        };
        walk(&mut t, &mut ctx2).expect("decrypt");
        assert_eq!(shared.len(), 2);

        let mut mac3 = MacAccumulator::new(false);
        let mut ctx3 = WalkCtx {
            direction: Direction::Encrypt,
            key: &k,
            selector: &selector,
            mac: &mut mac3,
            stash: &mut shared,
            stats: WalkStats::default(),
        };
        walk(&mut t, &mut ctx3).expect("re-encrypt");
        assert_eq!(
            render(&t),
            first,
            "an unchanged file must re-encrypt to identical bytes"
        );
    }

    #[test]
    fn an_empty_value_is_a_fixed_point() {
        let mut t = tree("empty: \"\"\nfull: v\n");
        run(&mut t, Direction::Encrypt, false);
        let out = render(&t);
        assert!(
            out.contains("empty: \"\""),
            "an empty value stays empty: {out}"
        );
        run(&mut t, Direction::Decrypt, false);
        assert_eq!(render(&t), "empty: \"\"\nfull: v\n");
    }

    #[test]
    fn a_wrong_key_fails_the_decrypt_rather_than_producing_garbage() {
        let mut t = tree("a: one\n");
        run(&mut t, Direction::Encrypt, false);

        let selector = EncryptionSelector::default_policy();
        let other = DataKey::from_bytes(&[99u8; 32]).expect("32");
        let mut mac = MacAccumulator::new(false);
        let mut stash = IvStash::new();
        let mut ctx = WalkCtx {
            direction: Direction::Decrypt,
            key: &other,
            selector: &selector,
            mac: &mut mac,
            stash: &mut stash,
            stats: WalkStats::default(),
        };
        assert_eq!(walk(&mut t, &mut ctx), Err(WireError::AeadOpen));
    }

    #[test]
    fn the_walk_reports_its_denominator() {
        let mut t = tree("a: 1\nb:\n    c: 2\n    d: 3\n");
        let (stats, _) = run(&mut t, Direction::Encrypt, false);
        assert_eq!(stats.leaves, 3, "a, b.c, b.d");
        assert_eq!(stats.macced, 3);
    }
}
