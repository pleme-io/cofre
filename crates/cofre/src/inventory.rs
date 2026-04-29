//! Attested inventory artifact — `cofre inventory` output.
//!
//! Each entry is `(name, backend_id, blake3(value || salt))`. The salt
//! is per-secret (random + recorded) so the BLAKE3 hash is non-trivial
//! but deterministic given the same value+salt — used for tamper
//! detection only, NEVER for verification of the value itself.
//!
//! The inventory NEVER contains the value. It MAY be checked into git
//! safely; an attacker who steals the inventory cannot reconstruct
//! the secret.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub name: String,
    pub backend: String,
    /// 16-byte salt (32 hex chars), random per-entry, generated on
    /// first inventory write and persisted across reads.
    pub salt_hex: String,
    /// BLAKE3(value bytes || salt bytes), as 64-char hex.
    pub value_hash_hex: String,
    /// ISO-8601 RFC 3339 timestamp of last apply.
    pub last_applied_utc: String,
    pub rotation: cofre_types::RotationPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub plan: String,
    pub entries: Vec<InventoryEntry>,
}
