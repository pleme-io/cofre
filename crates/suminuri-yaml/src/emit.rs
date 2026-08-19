//! Emission — bytes that match go-yaml v3's.
//!
//! # Line wrapping is off, and that is measured not assumed
//!
//! libyaml wraps at `best_width`, default 80, and that would reflow every long
//! `ENC[…]` value. go-yaml does not, because of an initialisation order in
//! `emitterc.go` that is easy to misread:
//!
//! ```text
//! best_width starts at -1                       (apic.go:111)
//! if best_width >= 0 && best_width <= best_indent*2 { best_width = 80 }   // skipped: -1 < 0
//! if best_width < 0 { best_width = 1<<31 - 1 }                            // taken
//! ```
//!
//! So unless a caller invokes `SetWidth` — sops never does — the effective width
//! is `i32::MAX` and **nothing ever wraps**. The `= 80` line is a decoy: it only
//! fires for a caller who explicitly asked for an absurdly small width. That is
//! why every 400-character ciphertext in the operator's file sits on one line,
//! and why this emitter has no wrapping logic at all.
//!
//! # What is byte-exact, and what is not
//!
//! Byte-exact and proven against the operator's three real files: block mapping
//! layout, the block-sequence indent rule ([`crate::Indenter`]), plain scalars,
//! double-quoted scalars, literal block scalars with their chomping indicator,
//! key order, and the absence of wrapping.
//!
//! Not attempted, and refused rather than guessed: comments (see the crate docs),
//! anchors, aliases, explicit tags, and flow style. A tree that cannot round-trip
//! is refused at *parse* time, so the emitter never meets one.

use crate::YamlError;
use crate::indent::Indenter;
use crate::tree::{Document, Entry, Item, Scalar, ScalarStyle, Value};

/// Emitter settings.
#[derive(Debug, Clone, Copy)]
pub struct EmitOptions {
    /// go-yaml's `best_indent`. sops's default is 4 (`stores/yaml.IndentDefault`),
    /// overridable with `--indent`.
    pub indent: usize,
}

impl Default for EmitOptions {
    fn default() -> Self {
        Self { indent: 4 }
    }
}

/// Render a document to YAML.
pub fn emit(doc: &Document, opts: EmitOptions) -> Result<String, YamlError> {
    let mut out = String::new();
    for (i, root) in doc.roots.iter().enumerate() {
        if i > 0 {
            // Second and later documents carry an explicit start marker; the
            // first is implicit, which is why a single-document file has no
            // leading `---`.
            out.push_str("---\n");
        }
        // No pre-increase here. go-yaml reaches the root node with `indent == -1`
        // and it is the root *collection's own* increase that turns the sentinel
        // into column 0 (`emit_document_content` → `emit_node` →
        // `emit_block_mapping_key(first)` → `increase_indent`). Incrementing here
        // as well shifts the whole document one level right — which is exactly
        // what every round-trip test caught on the first run.
        let mut ind = Indenter::new(opts.indent);
        emit_value(root, &mut ind, &mut out, Context::Root)?;
    }
    Ok(out)
}

/// Where a value sits, which decides whether it opens on the current line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    /// The document root.
    Root,
    /// The value half of `key:` — a scalar continues the line, a collection
    /// starts a new one.
    MappingValue,
    /// The first node inside a `- ` item, which continues the dash's line.
    SequenceItem,
}

fn emit_value(
    value: &Value,
    ind: &mut Indenter,
    out: &mut String,
    ctx: Context,
) -> Result<(), YamlError> {
    match value {
        Value::Scalar(s) => {
            emit_scalar(s, ind, out, ctx);
            Ok(())
        }
        Value::Mapping(items) => emit_mapping(items, ind, out, ctx),
        Value::Sequence(entries) => emit_sequence(entries, ind, out, ctx),
    }
}

fn emit_mapping(
    items: &[Item],
    ind: &mut Indenter,
    out: &mut String,
    ctx: Context,
) -> Result<(), YamlError> {
    // ★ A MAPPING WITH NO *PAIRS* IS EMPTY EVEN IF IT HOLDS COMMENTS.
    //
    // go-yaml emits an empty block mapping as a flow `{}`, since a block mapping
    // with no keys has no representation — and comments do not give it one. Missed
    // at first because the guard tested `items.is_empty()`, which a comments-only
    // mapping fails: document 0 of the fleet's
    // `clusters/plo/.../postgres-superset.yaml` is exactly two comments and no
    // keys, and upstream renders it as the two comment lines FOLLOWED BY `{}`.
    // We emitted the comments and then nothing, one line short.
    //
    // So the comments are written first, at this collection's indent, and then the
    // `{}` that stands for the keyless mapping.
    if !items.iter().any(|i| matches!(i, Item::Pair { .. })) {
        for item in items {
            if let Item::Comment(body) = item {
                push_indent(out, ind.column());
                emit_comment(body, out);
            }
        }
        match ctx {
            Context::MappingValue | Context::SequenceItem => out.push_str(" {}\n"),
            Context::Root => out.push_str("{}\n"),
        }
        return Ok(());
    }

    // A collection under `key:` starts on the next line; the first node inside a
    // `- ` item continues the dash's line.
    if ctx == Context::MappingValue {
        out.push('\n');
    }
    ind.increase(ctx == Context::SequenceItem, false);

    for (i, item) in items.iter().enumerate() {
        match item {
            Item::Comment(body) => {
                // A comment occupies its own line at the collection's indent. It
                // cannot share the dash's line inside a `- ` item, so when it is
                // the first thing in a sequence item the dash's line is closed
                // first — matching what go-yaml does with a head comment on the
                // first key of a nested mapping.
                if i == 0 && ctx == Context::SequenceItem {
                    out.push('\n');
                }
                push_indent(out, ind.column());
                emit_comment(body, out);
            }
            Item::Pair { key, value } => {
                // The first pair inside a `- ` item continues the dash's line;
                // every other pair is indented.
                let inline_after_dash = i == 0 && ctx == Context::SequenceItem;
                if inline_after_dash {
                    // The dash was written without its separator, so the first
                    // key supplies it: `- recipient: …`, not `-recipient: …`.
                    out.push(' ');
                } else {
                    push_indent(out, ind.column());
                }
                emit_key(key, out);
                out.push(':');
                emit_value(value, ind, out, Context::MappingValue)?;
            }
        }
    }

    ind.decrease();
    Ok(())
}

fn emit_sequence(
    entries: &[Entry],
    ind: &mut Indenter,
    out: &mut String,
    ctx: Context,
) -> Result<(), YamlError> {
    if entries.is_empty() {
        match ctx {
            Context::MappingValue | Context::SequenceItem => out.push_str(" []\n"),
            Context::Root => out.push_str("[]\n"),
        }
        return Ok(());
    }

    if ctx == Context::MappingValue {
        out.push('\n');
    }
    // `compact_seq` is always false for a sops file: go-yaml's
    // `compact_sequence_indent` is a bool left at its zero value unless a caller
    // opts in with `CompactSeqIndent()`, and sops does not. So the sequence takes
    // the round-up branch and the dash lands one full level in.
    ind.increase(ctx == Context::SequenceItem, false);

    for entry in entries {
        match entry {
            Entry::Comment(body) => {
                push_indent(out, ind.column());
                emit_comment(body, out);
            }
            Entry::Value(v) => {
                push_indent(out, ind.column());
                out.push('-');
                emit_value(v, ind, out, Context::SequenceItem)?;
            }
        }
    }

    ind.decrease();
    Ok(())
}

/// One comment line: `#` then the stored body, which by construction excludes the
/// leading `#` (the store's `commentLine[1:]`).
///
/// The body is written verbatim — never trimmed, never re-spaced. `# note` and
/// `#note` differ by one byte of body and a byte comparison against upstream sees
/// it, so normalising here would be a silent rewrite of the operator's text. A
/// bare `#` line has an empty body and emits as `#`.
fn emit_comment(body: &str, out: &mut String) {
    out.push('#');
    out.push_str(body);
    out.push('\n');
}

/// A mapping key.
///
/// `for_new_key`, not `for_new_value`: libyaml's `simple_key_context` forces
/// double-quoting for a multiline scalar, because a key cannot be a block scalar.
/// A key also cannot be single-quoted-by-fallback in the same way a value can, so
/// anything not plain-safe is double-quoted here.
fn emit_key(key: &str, out: &mut String) {
    match ScalarStyle::for_new_key(key) {
        ScalarStyle::Plain => out.push_str(key),
        ScalarStyle::SingleQuoted => {
            out.push('\'');
            out.push_str(&key.replace('\'', "''"));
            out.push('\'');
        }
        _ => push_double_quoted(out, key),
    }
}

fn emit_scalar(s: &Scalar, ind: &mut Indenter, out: &mut String, ctx: Context) {
    match s.style {
        ScalarStyle::Literal | ScalarStyle::Folded => {
            emit_block_scalar(s, ind, out, ctx);
        }
        ScalarStyle::DoubleQuoted => {
            open_inline(out, ctx);
            push_double_quoted(out, &s.value);
            out.push('\n');
        }
        ScalarStyle::SingleQuoted => {
            open_inline(out, ctx);
            out.push('\'');
            out.push_str(&s.value.replace('\'', "''"));
            out.push('\'');
            out.push('\n');
        }
        ScalarStyle::Plain => {
            // Promote only on a *structural* hazard — an edit that replaced
            // `port: 8080` with a `#`-bearing string, say. Deliberately NOT the
            // `for_new_value` test: a scalar that was plain in the source was
            // plain on purpose, so `a: 1` must stay `a: 1` and not become
            // `a: "1"`, which would change both its YAML type and its MAC
            // contribution. Using the wrong predicate here is what the
            // round-trip tests caught.
            //
            // The promotion target follows libyaml's ladder rather than jumping to
            // double quotes: a plain-unsafe scalar becomes *single*-quoted when
            // single quotes can hold it, which is what go-yaml emits.
            open_inline(out, ctx);
            if crate::tree::plain_is_structurally_unsafe(&s.value) {
                match ScalarStyle::for_new_value(&s.value) {
                    ScalarStyle::SingleQuoted => {
                        out.push('\'');
                        out.push_str(&s.value.replace('\'', "''"));
                        out.push('\'');
                    }
                    _ => push_double_quoted(out, &s.value),
                }
            } else {
                out.push_str(&s.value);
            }
            out.push('\n');
        }
    }
}

/// Write the separator that puts a scalar on the current line.
fn open_inline(out: &mut String, ctx: Context) {
    match ctx {
        // after `key:` or after `-`
        Context::MappingValue | Context::SequenceItem => out.push(' '),
        Context::Root => {}
    }
}

/// A literal (`|`) or folded (`>`) block scalar, with go-yaml's chomping hints.
fn emit_block_scalar(s: &Scalar, ind: &mut Indenter, out: &mut String, ctx: Context) {
    let marker = if s.style == ScalarStyle::Literal {
        '|'
    } else {
        '>'
    };
    open_inline(out, ctx);
    out.push(marker);

    // Chomping indicator, from `yaml_emitter_write_block_scalar_hints`:
    //   no trailing newline      -> `-` (strip)
    //   exactly one              -> none (clip, the default)
    //   more than one            -> `+` (keep)
    // The armored age keys end with exactly one, which is why every real sops
    // file shows a bare `enc: |`.
    let trailing = s.value.chars().rev().take_while(|c| *c == '\n').count();
    match trailing {
        0 => out.push('-'),
        1 => {}
        _ => out.push('+'),
    }
    // An explicit indentation indicator is required when the first line begins
    // with a space, because the block's indent would otherwise be ambiguous.
    if s.value.starts_with(' ') {
        // The body indent relative to the parent, as a single digit.
        let rel = ind.width().min(9);
        out.push(char::from_digit(u32::try_from(rel).unwrap_or(4), 10).unwrap_or('4'));
    }
    out.push('\n');

    // ★ A BLOCK SCALAR INSIDE A `- ` ITEM TAKES THE SEQUENCE INDENT RULE.
    //
    // go-yaml's `increase_indent_compact` is `cur + 2` when the node is a sequence
    // item and `best * ((cur + best) / best)` otherwise, and this call passed
    // `false` unconditionally — so a `- |` script body came out at the rounded-up
    // column instead of dash + 2. Measured on the fleet's
    // `dns-infrastructure/vaultwarden-deployment.yaml`, whose dash sits at 28:
    // upstream emits the body at 30, we emitted 32, which is exactly
    // `4 * ((28 + 4) / 4)`. The arithmetic matching that formula is what identified
    // the wrong branch rather than a guess at "off by two".
    ind.increase(ctx == Context::SequenceItem, false);
    let body_indent = ind.column();
    // Split on '\n' and drop the trailing empty piece so the chomping indicator,
    // not a blank line, carries the final newline.
    let mut lines: Vec<&str> = s.value.split('\n').collect();
    if s.value.ends_with('\n') {
        lines.pop();
    }
    for line in lines {
        if line.is_empty() {
            // A blank line inside a block scalar is emitted bare — indenting it
            // would add trailing whitespace that a reparse would keep.
            out.push('\n');
        } else {
            push_indent(out, body_indent);
            out.push_str(line);
            out.push('\n');
        }
    }
    ind.decrease();
}

fn push_indent(out: &mut String, columns: usize) {
    for _ in 0..columns {
        out.push(' ');
    }
}

/// Double-quoted escaping, matching go-yaml with `unicode = true`.
///
/// With unicode on, printable non-ASCII passes through as UTF-8 rather than being
/// escaped to `\uXXXX` — `encode.go` calls `yaml_emitter_set_unicode(…, true)`, so
/// escaping non-ASCII here would diverge on any file with an accented character.
fn push_double_quoted(out: &mut String, v: &str) {
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\u{1b}' => out.push_str("\\e"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format_escape(c as u32));
            }
            // ★ NON-BMP CHARACTERS ARE ESCAPED `\UXXXXXXXX`; BMP ONES ARE NOT.
            //
            // Not a style choice — it falls out of libyaml's `IS_PRINTABLE`, which
            // enumerates FIRST BYTES: `0x20..=0x7E` (ASCII) and `0xC2..=0xEF`
            // (2- and 3-byte sequences, i.e. the BMP). `0xF0..=0xF4` — every 4-byte
            // sequence, i.e. everything above U+FFFF — is absent, so libyaml calls
            // it unprintable and `yaml_emitter_write_double_quoted` escapes it.
            //
            // The corpus is what proved the split rather than the macro reading
            // alone: `clusters/plo/.../superset-database-setup.yaml` contains both
            // `✓` (U+2713, BMP) and `🔧` (U+1F527, non-BMP), and upstream emits the
            // first literally and the second as `\U0001F527`. A rule that escaped
            // all non-ASCII would have broken the `✓`, and one that escaped nothing
            // broke the `🔧`; only this boundary reproduces both.
            c if (c as u32) > 0xFFFF => {
                out.push_str("\\U");
                for shift in (0..8).rev() {
                    let nibble = ((c as u32) >> (shift * 4)) & 0xF;
                    out.push(
                        char::from_digit(nibble, 16)
                            .unwrap_or('0')
                            .to_ascii_uppercase(),
                    );
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn format_escape(cp: u32) -> String {
    // `\xNN` for the C0 range, which is the only range that reaches here.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hi = HEX[((cp >> 4) & 0xf) as usize] as char;
    let lo = HEX[(cp & 0xf) as usize] as char;
    let mut s = String::with_capacity(4);
    s.push('\\');
    s.push('x');
    s.push(hi);
    s.push(lo);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    fn round_trip(src: &str) -> String {
        let doc = parse(src).expect("parse");
        emit(&doc, EmitOptions::default()).expect("emit")
    }

    #[test]
    fn a_flat_mapping_round_trips_byte_exactly() {
        let src = "a: 1\nb: two\nc: \"2026-08-14T00:06:29Z\"\n";
        assert_eq!(round_trip(src), src);
    }

    #[test]
    fn a_nested_mapping_indents_by_four() {
        let src = "outer:\n    inner:\n        leaf: v\n";
        assert_eq!(round_trip(src), src);
    }

    /// The whole reason this crate exists. libyaml emits `    -   recipient:`;
    /// go-yaml emits `        - recipient:`. This is that difference, pinned.
    #[test]
    fn a_block_sequence_of_mappings_matches_go_yaml_not_libyaml() {
        let src = "\
sops:
    age:
        - recipient: age1aaa
          enc: x
        - recipient: age1bbb
          enc: y
";
        assert_eq!(round_trip(src), src);
        let out = round_trip(src);
        assert!(
            out.contains("        - recipient: age1aaa"),
            "go-yaml shape"
        );
        assert!(!out.contains("    -   recipient"), "not the libyaml shape");
    }

    #[test]
    fn a_literal_block_keeps_its_marker_and_body_indent() {
        let src = "\
sops:
    age:
        - recipient: age1aaa
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+
            -----END AGE ENCRYPTED FILE-----
";
        assert_eq!(round_trip(src), src);
    }

    #[test]
    fn chomping_indicators_follow_the_trailing_newline_count() {
        // exactly one trailing newline -> clip, no indicator
        let one = Scalar::literal("a\nb\n");
        // none -> strip
        let none = Scalar::literal("a\nb");
        // two -> keep
        let two = Scalar::literal("a\nb\n\n");
        let render = |s: Scalar| {
            let doc = Document::single(Value::Mapping(vec![Item::Pair {
                key: "k".into(),
                value: Value::Scalar(s),
            }]));
            emit(&doc, EmitOptions::default()).expect("emit")
        };
        assert_eq!(render(one), "k: |\n    a\n    b\n");
        assert_eq!(render(none), "k: |-\n    a\n    b\n");
        assert_eq!(render(two), "k: |+\n    a\n    b\n\n");
    }

    /// go-yaml's effective width is i32::MAX, so a 400-char ciphertext stays on
    /// one line. If wrapping ever creeps in, every fleet file reflows.
    #[test]
    fn long_scalars_are_never_wrapped() {
        let long = format!(
            "ENC[AES256_GCM,data:{},iv:x,tag:y,type:str]",
            "A".repeat(400)
        );
        let src = format!("k: {long}\n");
        let out = round_trip(&src);
        assert_eq!(out, src);
        assert_eq!(out.lines().count(), 1, "one line, no wrapping");
    }

    #[test]
    fn multi_document_streams_get_a_marker_after_the_first() {
        let src = "a: 1\n---\nb: 2\n";
        assert_eq!(round_trip(src), src);
    }

    #[test]
    fn empty_collections_use_flow_form() {
        let doc = Document::single(Value::Mapping(vec![
            Item::Pair {
                key: "m".into(),
                value: Value::Mapping(vec![]),
            },
            Item::Pair {
                key: "s".into(),
                value: Value::Sequence(vec![]),
            },
        ]));
        assert_eq!(
            emit(&doc, EmitOptions::default()).expect("emit"),
            "m: {}\ns: []\n"
        );
    }

    #[test]
    fn a_plain_value_that_stopped_being_safe_gets_promoted_not_corrupted() {
        // A value parsed plain, then replaced with one that cannot be plain.
        // Promoted to *single* quotes, which is what real sops emits for this
        // exact value — libyaml's `PLAIN -> SINGLE` rung, not a jump to double.
        let doc = Document::single(Value::Mapping(vec![Item::Pair {
            key: "k".into(),
            value: Value::Scalar(Scalar::parsed("has # hash", ScalarStyle::Plain)),
        }]));
        let out = emit(&doc, EmitOptions::default()).expect("emit");
        assert_eq!(out, "k: 'has # hash'\n");
        // and it survives a reparse, which the un-promoted form would not
        assert_eq!(
            parse(&out)
                .expect("reparse")
                .root()
                .and_then(|r| r.get("k"))
                .and_then(Value::as_str),
            Some("has # hash")
        );
    }

    #[test]
    fn double_quote_escaping_matches_go_yaml_with_unicode_on() {
        let doc = Document::single(Value::Mapping(vec![Item::Pair {
            key: "k".into(),
            value: Value::Scalar(Scalar::parsed("a\"b\\c\nd\té", ScalarStyle::DoubleQuoted)),
        }]));
        let out = emit(&doc, EmitOptions::default()).expect("emit");
        assert_eq!(
            out, "k: \"a\\\"b\\\\c\\nd\\té\"\n",
            "é passes through: unicode is on"
        );
    }

    #[test]
    fn an_indent_of_two_shifts_everything_consistently() {
        let src = "outer:\n  inner:\n    leaf: v\n";
        let doc = parse(src).expect("parse");
        assert_eq!(emit(&doc, EmitOptions { indent: 2 }).expect("emit"), src);
    }

    /// A hand-built comment is now EMITTED rather than refused. The old assertion
    /// (`CommentsUnsupported`) existed only because the parser could never produce
    /// one; now that it can, losing it on the way out would be the actual defect.
    #[test]
    fn a_comment_in_a_hand_built_tree_is_emitted() {
        let doc = Document::single(Value::Mapping(vec![
            Item::Comment(" note".into()),
            Item::Pair {
                key: "k".into(),
                value: Value::Scalar(Scalar::new("v")),
            },
        ]));
        let out = emit(&doc, EmitOptions::default()).expect("comments emit now");
        assert_eq!(out, "# note\nk: v\n");
    }
}
