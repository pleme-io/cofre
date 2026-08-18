//! `suminuri` — 墨塗り, the pleme-io-native sops-compatible encrypted-file tool.
//!
//! The library half. [`crate::file::SopsFile`] is the whole operation surface;
//! the binary in `main.rs` is a thin argv translation over it, which is the split
//! that lets every behaviour be tested against [`crate::env::MockEnvironment`]
//! rather than against a real filesystem holding real secrets.
//!
//! Layering, bottom up:
//!
//! | crate / module | owns |
//! |---|---|
//! | `suminuri-wire` | the bytes on disk: `ENC[]`, the 32-byte-nonce GCM, the AAD, the MAC, the metadata invariant |
//! | `suminuri-yaml` | the ordered tree and a go-yaml-v3-byte-compatible emitter |
//! | [`env`] | the `Environment` seam — every side effect, mockable |
//! | [`keys`] | age wrap/unwrap, identity discovery, named refusals for the providers we do not serve |
//! | [`metabridge`] | the `sops:` block ↔ typed metadata projection, in go-yaml's field order |
//! | [`walk`] | the one walker both directions share |
//! | [`file`] | a whole file: lift metadata, walk, verify, render |

#![forbid(unsafe_code)]

pub mod app;
pub mod cli;
pub mod config;
pub mod env;
pub mod file;
pub mod keys;
pub mod metabridge;
pub mod walk;

pub use file::{FileError, SopsFile};
pub use keys::{AgeIdentities, KeyError};
