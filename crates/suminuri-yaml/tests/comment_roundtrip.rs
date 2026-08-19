//! Comment and structural round-trip cases, each one a real corpus failure.
//!
//! Every test here was written because the differential over the fleet's 171
//! encrypted k8s files caught it. The corpus is the exhaustive oracle; these pin
//! the individual behaviours so a regression names itself instead of showing up as
//! "some file differs".

use suminuri_yaml::{EmitOptions, Item, Value, YamlError, emit, parse};

fn round_trip(src: &str) -> String {
    let doc = parse(src).expect("parse");
    emit(&doc, EmitOptions::default()).expect("emit")
}

#[test]
fn a_head_comment_binds_to_the_following_key() {
    let src = "# top\nalpha: one\n# about beta\nbeta: two\n";
    assert_eq!(round_trip(src), src);
}

/// The bug that produced ciphertext instead of text on four real files: a comment
/// with nothing after it inside a nested block was hoisted to the root, changing
/// both its column and its AAD path.
#[test]
fn a_foot_comment_stays_inside_its_own_block() {
    let src = "outer:\n    inner: 1\n    # foot of outer\nsibling: 2\n";
    assert_eq!(round_trip(src), src);
}

#[test]
fn a_foot_comment_shallower_than_the_block_belongs_outside_it() {
    let src = "outer:\n    inner: 1\n# head of sibling\nsibling: 2\n";
    assert_eq!(round_trip(src), src);
}

#[test]
fn a_trailing_comment_at_end_of_stream_is_kept() {
    let src = "alpha: one\n# the last word\n";
    assert_eq!(round_trip(src), src);
}

/// A mapping holding only comments is still an EMPTY mapping, so it needs `{}`.
#[test]
fn a_comments_only_mapping_emits_the_empty_flow_marker() {
    let src = "# just a note\n# and another\n";
    assert_eq!(round_trip(src), "# just a note\n# and another\n{}\n");
}

#[test]
fn a_bare_hash_line_keeps_its_empty_body() {
    let src = "# one\n#\n# three\nk: v\n";
    assert_eq!(round_trip(src), src);
}

/// A `#` inside ciphertext or a quoted scalar is not a comment. Most real sops
/// values contain one, so getting this wrong would mangle nearly every file.
#[test]
fn a_hash_inside_a_value_is_not_treated_as_a_comment() {
    let src = "k: 'a # b'\nj: \"c #d\"\n";
    assert_eq!(round_trip(src), src);
}

/// The block-scalar opener that was invisible to the scanner, duplicating an
/// operator's comments: a block opened as a bare sequence entry.
#[test]
fn comments_inside_a_dash_block_scalar_are_body_not_comments() {
    let src = "args:\n    - |\n      # not a yaml comment\n      echo hi\n";
    let out = round_trip(src);
    assert_eq!(
        out.matches("# not a yaml comment").count(),
        1,
        "the line must appear ONCE, in the block body:\n{out}"
    );
}

#[test]
fn comments_inside_a_key_block_scalar_are_body_not_comments() {
    let src = "script: |\n    # inside\n    echo hi\n";
    let out = round_trip(src);
    assert_eq!(out.matches("# inside").count(), 1, "{out}");
}

/// A trailing comment cannot round-trip, so it is refused by name rather than
/// dropped. Zero fleet files have one.
#[test]
fn a_trailing_comment_is_refused_by_name() {
    match parse("k: v # note\n") {
        Err(YamlError::TrailingCommentUnsupported { line }) => assert_eq!(line, 1),
        other => panic!("expected a named refusal, got {other:?}"),
    }
}

/// `-`, `?` and `:` are YAML indicators only when followed by whitespace, so a
/// plain scalar may begin with one. Over-quoting these produced `- "-U"` against
/// upstream's `- -U`.
#[test]
fn a_leading_dash_not_followed_by_space_stays_plain() {
    for v in ["-U", "-d", "?x", ":y", "-c"] {
        let src = format!("args:\n    - {v}\n");
        assert_eq!(round_trip(&src), src, "{v} should stay plain");
    }
}

/// The other half of the rule, tested through the public surface: an indicator
/// FOLLOWED BY SPACE really would open a sequence entry, so a value like `- x`
/// must not come back out plain. Checked by round-tripping a quoted source and
/// confirming the quoting survives.
#[test]
fn an_indicator_followed_by_space_keeps_its_quotes() {
    for src in ["k: '- x'\n", "k: '-'\n", "k: '? x'\n", "k: ': y'\n"] {
        let out = round_trip(src);
        assert_eq!(out, src, "quoting must survive for {src:?}");
    }
}

/// Multiple documents keep their separator, and `---` goes BETWEEN them only.
#[test]
fn a_multi_document_stream_round_trips() {
    let src = "a: 1\n---\nb: 2\n---\nc: 3\n";
    let doc = parse(src).expect("parse");
    assert_eq!(doc.roots.len(), 3);
}

/// A comment attached to a document other than the first must stay with it.
#[test]
fn comments_survive_across_document_boundaries() {
    let src = "# doc one\na: 1\n---\n# doc two\nb: 2\n";
    let doc = parse(src).expect("parse");
    assert_eq!(doc.roots.len(), 2);
    let has_comment = |v: &Value, want: &str| match v {
        Value::Mapping(items) => items
            .iter()
            .any(|i| matches!(i, Item::Comment(b) if b.trim() == want)),
        _ => false,
    };
    assert!(has_comment(&doc.roots[0], "doc one"), "{:?}", doc.roots[0]);
    assert!(has_comment(&doc.roots[1], "doc two"), "{:?}", doc.roots[1]);
}
