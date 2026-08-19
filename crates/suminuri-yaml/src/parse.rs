//! Parsing, via libyaml's event stream.
//!
//! The events give structure, order, scalar *style* and source marks — everything
//! the tree model needs except comments, which libyaml discards at the scanner.
//!
//! # Comments are recovered by line correlation, not by the event stream
//!
//! Since libyaml will not report them, whole-line comments are scanned out of the
//! source separately (keeping their 1-based line numbers) and re-inserted as
//! [`Item::Comment`] / [`Entry::Comment`] while the events are consumed: before
//! pushing any item that starts on line L, every unconsumed comment above L is
//! attached first.
//!
//! **That is deliberately yaml.v3's *head comment* rule, which is what sops
//! itself gets.** A comment binds to the item that FOLLOWS it, so it is emitted at
//! that item's indentation — even when the source had it indented differently,
//! e.g. a comment trailing a nested block binds to the next outer key and comes
//! back one level out. Upstream sops re-indents it exactly the same way, and
//! matching *upstream* is the contract here, not matching the original bytes. The
//! differential over the real corpus is what settles this.
//!
//! Two shapes are still refused rather than guessed at:
//!
//! * a **trailing** comment on a content line (`key: value # note`) — sops's tree
//!   has no item for one, so it cannot round-trip. Measured 2026-08-19: ZERO of
//!   the fleet's 171 encrypted files carry one, so refusing costs nothing and
//!   silently dropping it would be a real loss.
//! * anchors, aliases and explicit tags, as before.
//!
//! # What this corrected
//!
//! `YamlError::CommentsUnsupported` used to refuse EVERY commented document, on
//! the stated grounds that comments "are part of the MAC". They are not, and this
//! crate's sibling already said so — `suminuri::walk::visit_comment` carries the
//! measured note *"A comment never contributes to the MAC, in either direction —
//! the `if !ok` guard around `hash.Write` in both of sops's walkers."* Confirmed
//! independently by altering one comment character in a real encrypted file and
//! watching upstream sops still decrypt it. The refusal was blocking **96 of 171**
//! fleet files on a false premise.

use crate::YamlError;
use crate::tree::{Document, Entry, Item, Scalar, ScalarStyle, Value};
use libyaml_safer::{EventData, Parser};
use std::io::BufRead;

/// Parse a YAML stream into an ordered tree.
pub fn parse(input: &str) -> Result<Document, YamlError> {
    if let Some(line) = trailing_comment_line(input) {
        return Err(YamlError::TrailingCommentUnsupported { line });
    }
    let mut comments = PendingComments::scan(input);

    let mut bytes = input.as_bytes();
    let mut parser = Parser::new();
    parser.set_input(&mut bytes);

    let mut roots: Vec<Value> = Vec::new();
    loop {
        let event = parser
            .parse()
            .map_err(|e| YamlError::Parse(e.to_string()))?;
        match event.data {
            EventData::StreamEnd => break,
            EventData::DocumentStart { .. } => {
                roots.push(parse_node(&mut parser, &mut comments)?);
            }
            _ => {}
        }
    }

    // Comments after the last item in the stream have no following item to bind
    // to, so they land at the end of the last document. Without this they would be
    // dropped — the exact failure this whole change exists to remove.
    let tail = comments.drain_rest();
    if !tail.is_empty() {
        // A stream that is ONLY comments produces no `DocumentStart` at all, so
        // there is no root to bind to — libyaml sees no node. Synthesise the empty
        // mapping that such a document is, rather than refusing: the emitter renders
        // it as the comment lines followed by `{}`, which is what go-yaml does. This
        // is not a sops file (it has no `sops:` key, so `SopsFile` rejects it), but
        // `parse` is a general YAML entry point and losing the comments here would
        // be the same silent drop this change exists to remove.
        if roots.is_empty() {
            roots.push(Value::Mapping(Vec::new()));
        }
        match roots.last_mut() {
            Some(Value::Mapping(items)) => {
                items.extend(tail.into_iter().map(Item::Comment));
            }
            Some(Value::Sequence(entries)) => {
                entries.extend(tail.into_iter().map(Entry::Comment));
            }
            // A scalar root cannot hold an item. `SopsFile::encrypt` refuses a
            // non-mapping root anyway, so nothing downstream could read it.
            _ => {
                return Err(YamlError::TrailingCommentUnsupported {
                    line: comments.last_line,
                });
            }
        }
    }

    Ok(Document { roots })
}

/// Whole-line comments scanned out of the source, consumed in order as the event
/// stream advances.
struct PendingComments {
    /// `(1-based line, source indent, body without the leading `#`)`, in order.
    ///
    /// The indent is load-bearing, not diagnostic. A comment with no item after it
    /// inside a nested block belongs to THAT block (yaml.v3 calls it a foot
    /// comment), and only its indentation says so. Without it such a comment was
    /// hoisted to the root — which moved its emitted column AND its AAD path, so a
    /// `type:comment` leaf then failed its GCM tag and came out as raw ciphertext.
    /// Measured on four real k8s files before this was added.
    items: Vec<(u64, usize, String)>,
    next: usize,
    last_line: u64,
}

impl PendingComments {
    fn scan(input: &str) -> Self {
        let mut items = Vec::new();
        let mut last_line = 0;
        for (line_no, raw) in comment_scan(input) {
            last_line = line_no;
            let indent = raw.len() - raw.trim_start().len();
            // Body without the leading `#`, matching the store's `commentLine[1:]`.
            let trimmed = raw.trim_start();
            let body = trimmed.strip_prefix('#').unwrap_or(trimmed).to_string();
            items.push((line_no, indent, body));
        }
        Self {
            items,
            next: 0,
            last_line,
        }
    }

    /// Every unconsumed comment strictly above `line`, at any indent.
    ///
    /// Used for a HEAD comment: it binds to the item that follows, so the item's
    /// own column decides where it lands and the comment's own indent is ignored.
    fn drain_before(&mut self, line: u64) -> Vec<String> {
        let mut out = Vec::new();
        while let Some((l, _, body)) = self.items.get(self.next) {
            if *l >= line {
                break;
            }
            out.push(body.clone());
            self.next += 1;
        }
        out
    }

    /// Unconsumed comments above `line` that are indented at least `min_indent` —
    /// a collection claiming its FOOT comments as it closes.
    ///
    /// Stops at the first comment shallower than `min_indent`: that one belongs to
    /// an outer collection, and taking it would pull an outer head comment inward.
    /// Because the scan is ordered, stopping (rather than skipping) preserves the
    /// invariant that `items[next..]` is exactly what is still unplaced.
    fn drain_foot(&mut self, line: u64, min_indent: usize) -> Vec<String> {
        let mut out = Vec::new();
        while let Some((l, ind, body)) = self.items.get(self.next) {
            if *l >= line || *ind < min_indent {
                break;
            }
            out.push(body.clone());
            self.next += 1;
        }
        out
    }

    fn drain_rest(&mut self) -> Vec<String> {
        let out: Vec<String> = self.items[self.next..]
            .iter()
            .map(|(_, _, b)| b.clone())
            .collect();
        self.next = self.items.len();
        out
    }
}

/// Read one node, having just consumed the event that opens it or the parent's
/// position. Pulls the next event itself.
fn parse_node<R: BufRead>(
    parser: &mut Parser<R>,
    comments: &mut PendingComments,
) -> Result<Value, YamlError> {
    let event = parser
        .parse()
        .map_err(|e| YamlError::Parse(e.to_string()))?;
    let line = event.start_mark.line + 1;
    match event.data {
        EventData::Scalar {
            value,
            style,
            anchor,
            tag,
            ..
        } => {
            reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
            Ok(Value::Scalar(Scalar::parsed(value, map_style(style))))
        }
        EventData::MappingStart { anchor, tag, .. } => {
            reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
            parse_mapping(parser, comments)
        }
        EventData::SequenceStart { anchor, tag, .. } => {
            reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
            parse_sequence(parser, comments)
        }
        EventData::Alias { .. } => Err(YamlError::AnchorsUnsupported { line }),
        // An empty document: `---` with nothing after it.
        EventData::DocumentEnd { .. } => Ok(Value::Mapping(Vec::new())),
        other => Err(YamlError::Parse(format!(
            "unexpected event where a node was expected: {other:?}"
        ))),
    }
}

fn parse_mapping<R: BufRead>(
    parser: &mut Parser<R>,
    comments: &mut PendingComments,
) -> Result<Value, YamlError> {
    let mut items: Vec<Item> = Vec::new();
    // The column of this mapping's own keys, learned from the first one. A foot
    // comment must be indented at least this far to belong here.
    let mut own_column: Option<usize> = None;
    loop {
        let event = parser
            .parse()
            .map_err(|e| YamlError::Parse(e.to_string()))?;
        let line = event.start_mark.line + 1;
        match event.data {
            EventData::MappingEnd => {
                if let Some(col) = own_column {
                    items.extend(
                        comments
                            .drain_foot(line, col)
                            .into_iter()
                            .map(Item::Comment),
                    );
                }
                return Ok(Value::Mapping(items));
            }
            EventData::Scalar {
                value, anchor, tag, ..
            } => {
                // A mapping key. sops requires it to be a string, which a scalar
                // always is at this layer — the refusal below is for the
                // structural cases (a nested mapping or sequence used as a key).
                reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
                own_column.get_or_insert(usize::try_from(event.start_mark.column).unwrap_or(0));
                // Head comments bind to THIS key, so they are attached before it.
                // Note the drain happens before `parse_node` recurses: the nested
                // value's own items must not steal a comment that sits above the
                // key introducing them.
                items.extend(comments.drain_before(line).into_iter().map(Item::Comment));
                let value_node = parse_node(parser, comments)?;
                items.push(Item::Pair {
                    key: value,
                    value: value_node,
                });
            }
            EventData::MappingStart { .. } | EventData::SequenceStart { .. } => {
                return Err(YamlError::NonStringKey { line });
            }
            EventData::Alias { .. } => return Err(YamlError::AnchorsUnsupported { line }),
            other => {
                return Err(YamlError::Parse(format!(
                    "unexpected event inside a mapping: {other:?}"
                )));
            }
        }
    }
}

fn parse_sequence<R: BufRead>(
    parser: &mut Parser<R>,
    comments: &mut PendingComments,
) -> Result<Value, YamlError> {
    let mut entries: Vec<Entry> = Vec::new();
    loop {
        // A sequence needs a one-event lookahead to spot its end, so unlike
        // `parse_mapping` it cannot delegate straight to `parse_node`.
        let event = parser
            .parse()
            .map_err(|e| YamlError::Parse(e.to_string()))?;
        let line = event.start_mark.line + 1;
        match event.data {
            EventData::SequenceEnd => return Ok(Value::Sequence(entries)),
            EventData::Scalar {
                value,
                style,
                anchor,
                tag,
                ..
            } => {
                reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
                entries.extend(comments.drain_before(line).into_iter().map(Entry::Comment));
                entries.push(Entry::Value(Value::Scalar(Scalar::parsed(
                    value,
                    map_style(style),
                ))));
            }
            EventData::MappingStart { anchor, tag, .. } => {
                reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
                entries.extend(comments.drain_before(line).into_iter().map(Entry::Comment));
                entries.push(Entry::Value(parse_mapping(parser, comments)?));
            }
            EventData::SequenceStart { anchor, tag, .. } => {
                reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
                entries.extend(comments.drain_before(line).into_iter().map(Entry::Comment));
                entries.push(Entry::Value(parse_sequence(parser, comments)?));
            }
            EventData::Alias { .. } => return Err(YamlError::AnchorsUnsupported { line }),
            other => {
                return Err(YamlError::Parse(format!(
                    "unexpected event inside a sequence: {other:?}"
                )));
            }
        }
    }
}

fn reject_anchor_or_tag(
    anchor: Option<&str>,
    tag: Option<&str>,
    line: u64,
) -> Result<(), YamlError> {
    if anchor.is_some() {
        return Err(YamlError::AnchorsUnsupported { line });
    }
    if tag.is_some() {
        return Err(YamlError::TagsUnsupported { line });
    }
    Ok(())
}

fn map_style(style: libyaml_safer::ScalarStyle) -> ScalarStyle {
    use libyaml_safer::ScalarStyle as S;
    match style {
        S::SingleQuoted => ScalarStyle::SingleQuoted,
        S::DoubleQuoted => ScalarStyle::DoubleQuoted,
        S::Literal => ScalarStyle::Literal,
        S::Folded => ScalarStyle::Folded,
        // `Plain`, `Any`, and any variant a future libyaml-safer adds. The enum
        // is `#[non_exhaustive]`, so this arm is required rather than optional —
        // and plain is the right default: it is what `Any` means to an emitter.
        _ => ScalarStyle::Plain,
    }
}

/// Every whole-line comment, as `(1-based line, raw line)`, in source order.
///
/// A deliberately conservative scan. A `#` inside a quoted scalar or a literal
/// block body is *not* a comment, so the scanner tracks quoting and block-scalar
/// context — a naive "does the line contain #" would treat every file whose
/// ciphertext happens to contain a `#` as commented, which is most of them.
///
/// This is the shared walk behind both [`comment_scan`] and
/// [`trailing_comment_line`]: one scanner, so the set of lines called "a comment"
/// cannot disagree between the collector and the refusal check.
fn scan_lines(input: &str) -> impl Iterator<Item = (u64, &str, CommentKind)> {
    let mut block_indent: Option<usize> = None;
    input.lines().enumerate().filter_map(move |(idx, raw)| {
        let line_no = u64::try_from(idx).unwrap_or(u64::MAX).saturating_add(1);
        let indent = raw.len() - raw.trim_start().len();
        let trimmed = raw.trim_start();

        // Inside a literal/folded block, every line at greater indent is body.
        if let Some(open_at) = block_indent {
            if trimmed.is_empty() || indent > open_at {
                return None;
            }
            block_indent = None;
        }

        if trimmed.is_empty() {
            return None;
        }
        if trimmed.starts_with('#') {
            return Some((line_no, raw, CommentKind::WholeLine));
        }

        // Does this line open a block scalar? Checked BEFORE the trailing-hash test
        // so `key: | # note` is not mistaken for a trailing comment.
        //
        // ★ A BLOCK CAN OPEN AS A BARE SEQUENCE ENTRY, AND MISSING THAT DUPLICATED
        // AN OPERATOR'S COMMENTS.
        //
        // The first version only looked after a `:` — `key: |` — so `- |` was
        // invisible, and every `#` line inside such a block was scanned as a YAML
        // comment. libyaml still parsed the block correctly, so those lines stayed
        // in the scalar AND were re-inserted as tree comments: the same text twice,
        // once in the script and once above it. Found on the fleet's
        // `dns-infrastructure/vaultwarden-deployment.yaml:327`, a `- |` shell script
        // whose `# Create backup` came out duplicated.
        //
        // So: strip any leading `- ` markers (a block can be nested several
        // sequence levels deep), then take what follows an optional `key:`, and
        // check for `|`/`>` with their optional chomping/indent indicators.
        let mut head = trimmed;
        while let Some(rest) = head.strip_prefix("- ") {
            head = rest.trim_start();
        }
        let after_key = match head.rsplit_once(':') {
            Some((_, tail)) => tail.trim(),
            None => head.trim(),
        };
        let opens_block = after_key.starts_with('|') || after_key.starts_with('>');

        let trailing = unquoted_hash(trimmed).is_some_and(|col| {
            // YAML only starts a comment at a `#` preceded by whitespace.
            col > 0 && trimmed.as_bytes()[col - 1].is_ascii_whitespace()
        });

        if opens_block {
            block_indent = Some(indent);
        }

        if trailing {
            Some((line_no, raw, CommentKind::Trailing))
        } else {
            None
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentKind {
    /// The line's first non-space character is `#`.
    WholeLine,
    /// A `#` after content on the same line — unrepresentable in sops's tree.
    Trailing,
}

/// The whole-line comments, which become tree items.
fn comment_scan(input: &str) -> impl Iterator<Item = (u64, &str)> {
    scan_lines(input)
        .filter_map(|(l, raw, kind)| (kind == CommentKind::WholeLine).then_some((l, raw)))
}

/// The 1-based line of the first TRAILING comment, if any.
///
/// Refused rather than dropped: sops's tree has an item for a comment LINE and no
/// place at all for a comment that shares a line with content, so round-tripping
/// one is not possible in either implementation. Measured 2026-08-19 across the
/// fleet's 171 encrypted files: zero carry one, so this refusal has no cost and
/// exists to keep a silent loss impossible if that ever changes.
fn trailing_comment_line(input: &str) -> Option<u64> {
    scan_lines(input).find_map(|(l, _, kind)| (kind == CommentKind::Trailing).then_some(l))
}

/// Byte offset of the first `#` that is not inside a quoted scalar.
fn unquoted_hash(line: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_double => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return Some(i),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_ordered_mapping() {
        let doc = parse("b: 2\na: 1\nc: 3\n").expect("parse");
        let Some(Value::Mapping(items)) = doc.root() else {
            panic!("mapping root")
        };
        let keys: Vec<&str> = items
            .iter()
            .filter_map(|i| match i {
                Item::Pair { key, .. } => Some(key.as_str()),
                Item::Comment(_) => None,
            })
            .collect();
        assert_eq!(keys, vec!["b", "a", "c"], "source order, not sorted");
    }

    #[test]
    fn preserves_scalar_style() {
        let doc =
            parse("plain: v\nquoted: \"2026-08-14T00:06:29Z\"\nsingle: 'x'\n").expect("parse");
        let root = doc.root().expect("root");
        let style = |k: &str| match root.get(k) {
            Some(Value::Scalar(s)) => s.style,
            _ => panic!("scalar at {k}"),
        };
        assert_eq!(style("plain"), ScalarStyle::Plain);
        assert_eq!(style("quoted"), ScalarStyle::DoubleQuoted);
        assert_eq!(style("single"), ScalarStyle::SingleQuoted);
    }

    #[test]
    fn parses_a_literal_block_as_literal() {
        let doc = parse("enc: |\n    line one\n    line two\n").expect("parse");
        let Some(Value::Scalar(s)) = doc.root().and_then(|r| r.get("enc")) else {
            panic!("scalar")
        };
        assert_eq!(s.style, ScalarStyle::Literal);
        assert_eq!(s.value, "line one\nline two\n");
    }

    #[test]
    fn parses_a_sequence_of_mappings() {
        let doc =
            parse("age:\n    - recipient: a\n      enc: x\n    - recipient: b\n      enc: y\n")
                .expect("parse");
        let Some(Value::Sequence(entries)) = doc.root().and_then(|r| r.get("age")) else {
            panic!("sequence")
        };
        assert_eq!(entries.len(), 2);
        let Entry::Value(first) = &entries[0] else {
            panic!("value entry")
        };
        assert_eq!(first.get("recipient").and_then(Value::as_str), Some("a"));
    }

    /// Whole-line comments are now PARSED, not refused. This test used to assert
    /// the opposite — `CommentsUnsupported` for all three inputs — on the false
    /// premise that comments feed the MAC. They do not, and that refusal was making
    /// 96 of the fleet's 171 encrypted files unreadable by its own `sops`.
    #[test]
    fn whole_line_comments_are_parsed_into_tree_items() {
        for src in [
            "# a note\nk: v\n",
            "a: 1\nb: 2\n   # indented\nc: 3\n",
            "# only comments\n",
        ] {
            assert!(parse(src).is_ok(), "should parse: {src:?}");
        }

        // The one comment shape that still cannot round-trip, refused by name with
        // its line rather than dropped.
        assert_eq!(
            parse("k: v   # trailing\n"),
            Err(YamlError::TrailingCommentUnsupported { line: 1 })
        );
    }

    /// The false-positive that would make the refusal useless: a `#` inside
    /// ciphertext or a quoted string is not a comment. Most real values contain
    /// base64 that can hold anything.
    #[test]
    fn a_hash_inside_a_value_is_not_a_comment() {
        assert!(parse("k: \"has # inside\"\n").is_ok());
        assert!(parse("k: 'also # inside'\n").is_ok());
        assert!(
            parse("k: no-space#here\n").is_ok(),
            "a # not preceded by space is not a comment"
        );
    }

    /// A literal block's body is data, so a `#` there must not trip the scan —
    /// and armored age keys are literal blocks in every real sops file.
    #[test]
    fn a_hash_inside_a_literal_block_is_not_a_comment() {
        let src = "enc: |\n    -----BEGIN AGE ENCRYPTED FILE-----\n    ab#cd\n    -----END AGE ENCRYPTED FILE-----\n";
        assert!(
            parse(src).is_ok(),
            "a # in block-scalar body is body, not a comment"
        );
    }

    #[test]
    fn an_anchor_is_refused_not_expanded() {
        let err = parse("a: &anc 1\nb: *anc\n").expect_err("must refuse");
        assert!(
            matches!(err, YamlError::AnchorsUnsupported { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_parse_error_is_named() {
        let err = parse("a: [unclosed\n").expect_err("must fail");
        assert!(matches!(err, YamlError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn multi_document_streams_keep_every_root() {
        let doc = parse("a: 1\n---\nb: 2\n").expect("parse");
        assert_eq!(doc.roots.len(), 2);
        assert!(
            doc.root().is_none(),
            "root() is only for the single-document case"
        );
    }
}
