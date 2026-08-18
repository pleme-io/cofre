//! `suminuri-yaml` — an **ordered** YAML tree, and an emitter that reproduces
//! go-yaml v3's bytes.
//!
//! # Why this crate exists at all
//!
//! Two properties of the sops format make every off-the-shelf Rust YAML crate
//! the wrong tool, and neither is negotiable:
//!
//! **Order is integrity.** The file MAC is a SHA-512 over leaf plaintexts *in
//! walk order*, so a tree that round-trips through any hash map produces a
//! different MAC and a file nothing can verify. `serde_yaml`'s `Mapping` happens
//! to preserve order; `HashMap`-backed models do not; and none of them promise
//! it as a contract. Here order is the data structure — a `Vec` of pairs — so it
//! cannot be lost by a refactor.
//!
//! **Bytes are the diff.** sops exists so a secret file can be reviewed in git.
//! If re-encrypting reflows the file, every edit is a whole-file diff and the
//! format's entire reason for being is gone. So the emitter's job is not "emit
//! valid YAML", it is "emit *the same* YAML go-yaml v3 would".
//!
//! # The measured divergence, and its exact rule
//!
//! Re-emitting the operator's real files through Rust's `libyaml-safer` matched
//! go-yaml on every line except block-sequence items:
//!
//! ```text
//! go-yaml v3 :         - recipient: age1q3tep…     dash at indent×depth, content right after "- "
//! libyaml    :     -   recipient: age1q3tep…       dash at parent indent, content padded to indent
//! ```
//!
//! That is not a bug in either — go-yaml *deliberately* forked libyaml here, and
//! left the reason in a comment in `emitterc.go`:
//!
//! ```text
//! } else if !indentless {
//!     // [Go] This was changed so that indentations are more regular.
//!     if states[len-1] == BLOCK_SEQUENCE_ITEM_STATE {
//!         // The first indent inside a sequence will just skip the "- " indicator.
//!         indent += 2
//!     } else {
//!         indent = best_indent * ((indent + best_indent) / best_indent)   // integer division
//!         if compact_seq { indent -= 2 }
//!     }
//! }
//! ```
//!
//! `compact_sequence_indent` is a `bool` field left at its zero value unless a
//! caller opts in with `CompactSeqIndent()`, and sops never does — so for every
//! sops file `compact_seq` is `false` and the rule reduces to those two lines.
//! [`Indenter`] is that arithmetic and nothing else, checked against the columns
//! of the operator's real `secrets.yaml`:
//!
//! | node | before | rule | after | observed column |
//! |---|---|---|---|---|
//! | `sops:` children | 0 | `4·((0+4)/4)` | 4 | 4 ✓ |
//! | `age:` sequence | 4 | `4·((4+4)/4)` | 8 | 8 (the dash) ✓ |
//! | item mapping | 8 | sequence item → `+2` | 10 | 10 (`recipient:`) ✓ |
//! | `enc:` block scalar | 10 | `4·((10+4)/4)` | 12 | 12 (the armor) ✓ |
//!
//! # What this crate refuses rather than mangles
//!
//! **A file containing comments is refused, not silently stripped.** sops turns
//! each comment line into a tree *item* so it can be encrypted like any value,
//! which means comments participate in the walk and — under
//! `encrypted_comment_regex` — in the ciphertext. libyaml's event API does not
//! surface them, so this crate cannot yet round-trip them. Dropping them would
//! delete an operator's comments *and* change the file's MAC, so
//! [`YamlError::CommentsUnsupported`] names the gap instead.
//!
//! That is a deliberate `refused`, distinct from a `found` or an `empty` — the
//! `kotae` discipline. It costs nothing on this fleet: all three encrypted files
//! in the nix repo carry zero comments (measured 2026-08-18).

#![forbid(unsafe_code)]

mod emit;
mod indent;
mod parse;
mod tree;

pub use emit::{EmitOptions, emit};
pub use indent::Indenter;
pub use parse::parse;
pub use tree::{Document, Entry, Item, Scalar, ScalarStyle, Value, literal_block_allowed};

/// Everything that can go wrong in the YAML layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum YamlError {
    /// libyaml could not parse the input.
    #[error("YAML parse error: {0}")]
    Parse(String),

    /// The emitter could not write.
    #[error("YAML emit error: {0}")]
    Emit(String),

    /// The document contains comments, which this crate will not silently drop.
    ///
    /// See the crate docs: comments are *tree items* in sops's model, so losing
    /// them changes the file's MAC as well as its text.
    #[error(
        "line {line}: this document contains comments, and suminuri-yaml will not silently drop them (they are part of the MAC). Use upstream sops for this file, or open the comment-round-trip gap."
    )]
    CommentsUnsupported { line: u64 },

    /// A mapping key was not a scalar string. sops requires string keys.
    #[error("line {line}: mapping key is not a string; sops requires string keys")]
    NonStringKey { line: u64 },

    /// An anchor or alias was used. sops's own tree model has no representation
    /// for one, so a file using them cannot round-trip through *either*
    /// implementation — naming it beats emitting a silently-expanded document.
    #[error("line {line}: YAML anchors and aliases are not representable in the sops tree model")]
    AnchorsUnsupported { line: u64 },

    /// A scalar carried an explicit tag, which changes how it resolves.
    #[error("line {line}: explicit YAML tags are not supported")]
    TagsUnsupported { line: u64 },
}
