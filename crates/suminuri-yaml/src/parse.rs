//! Parsing, via libyaml's event stream.
//!
//! The events give structure, order, scalar *style* and source marks — everything
//! the tree model needs except comments, which libyaml discards at the scanner.
//! Rather than silently lose them, the input is scanned for a comment line first
//! and a commented document is [`YamlError::CommentsUnsupported`]. See the crate
//! docs for why dropping them would be worse than refusing.

use crate::YamlError;
use crate::tree::{Document, Entry, Item, Scalar, ScalarStyle, Value};
use libyaml_safer::{EventData, Parser};
use std::io::BufRead;

/// Parse a YAML stream into an ordered tree.
pub fn parse(input: &str) -> Result<Document, YamlError> {
    if let Some(line) = first_comment_line(input) {
        return Err(YamlError::CommentsUnsupported { line });
    }

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
                roots.push(parse_node(&mut parser)?);
            }
            _ => {}
        }
    }
    Ok(Document { roots })
}

/// Read one node, having just consumed the event that opens it or the parent's
/// position. Pulls the next event itself.
fn parse_node<R: BufRead>(parser: &mut Parser<R>) -> Result<Value, YamlError> {
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
            parse_mapping(parser)
        }
        EventData::SequenceStart { anchor, tag, .. } => {
            reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
            parse_sequence(parser)
        }
        EventData::Alias { .. } => Err(YamlError::AnchorsUnsupported { line }),
        // An empty document: `---` with nothing after it.
        EventData::DocumentEnd { .. } => Ok(Value::Mapping(Vec::new())),
        other => Err(YamlError::Parse(format!(
            "unexpected event where a node was expected: {other:?}"
        ))),
    }
}

fn parse_mapping<R: BufRead>(parser: &mut Parser<R>) -> Result<Value, YamlError> {
    let mut items: Vec<Item> = Vec::new();
    loop {
        let event = parser
            .parse()
            .map_err(|e| YamlError::Parse(e.to_string()))?;
        let line = event.start_mark.line + 1;
        match event.data {
            EventData::MappingEnd => return Ok(Value::Mapping(items)),
            EventData::Scalar {
                value, anchor, tag, ..
            } => {
                // A mapping key. sops requires it to be a string, which a scalar
                // always is at this layer — the refusal below is for the
                // structural cases (a nested mapping or sequence used as a key).
                reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
                let value_node = parse_node(parser)?;
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

fn parse_sequence<R: BufRead>(parser: &mut Parser<R>) -> Result<Value, YamlError> {
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
                entries.push(Entry::Value(Value::Scalar(Scalar::parsed(
                    value,
                    map_style(style),
                ))));
            }
            EventData::MappingStart { anchor, tag, .. } => {
                reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
                entries.push(Entry::Value(parse_mapping(parser)?));
            }
            EventData::SequenceStart { anchor, tag, .. } => {
                reject_anchor_or_tag(anchor.as_deref(), tag.as_deref(), line)?;
                entries.push(Entry::Value(parse_sequence(parser)?));
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

/// The 1-based line number of the first comment, if any.
///
/// A deliberately conservative scan. A `#` inside a quoted scalar or a literal
/// block body is *not* a comment, so the scanner tracks quoting and block-scalar
/// context — a naive "does the line contain #" would refuse every file whose
/// ciphertext happens to contain a `#`, which is most of them.
fn first_comment_line(input: &str) -> Option<u64> {
    let mut block_indent: Option<usize> = None;
    for (idx, raw) in input.lines().enumerate() {
        let line_no = u64::try_from(idx).unwrap_or(u64::MAX).saturating_add(1);
        let indent = raw.len() - raw.trim_start().len();
        let trimmed = raw.trim_start();

        // Inside a literal/folded block, every line at greater indent is body.
        if let Some(open_at) = block_indent {
            if trimmed.is_empty() || indent > open_at {
                continue;
            }
            block_indent = None;
        }

        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            return Some(line_no);
        }
        if let Some(col) = unquoted_hash(trimmed) {
            // YAML only starts a comment at a `#` preceded by whitespace.
            if col > 0 && trimmed.as_bytes()[col - 1].is_ascii_whitespace() {
                return Some(line_no);
            }
        }
        // Does this line open a block scalar? `key: |`, `key: >`, with optional
        // indicators like `|-`, `>2`.
        if let Some(after) = trimmed.rsplit(':').next() {
            let a = after.trim();
            if a.starts_with('|') || a.starts_with('>') {
                block_indent = Some(indent);
            }
        }
    }
    None
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

    #[test]
    fn a_comment_is_refused_with_its_line_number() {
        assert_eq!(
            parse("# a note\nk: v\n"),
            Err(YamlError::CommentsUnsupported { line: 1 })
        );
        assert_eq!(
            parse("k: v   # trailing\n"),
            Err(YamlError::CommentsUnsupported { line: 1 })
        );
        assert_eq!(
            parse("a: 1\nb: 2\n   # indented\nc: 3\n"),
            Err(YamlError::CommentsUnsupported { line: 3 })
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
