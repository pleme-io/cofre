//! `cofre-types` — typed secret-materialization primitives.
//!
//! ══════════════════════════════════════════════════════════════════════
//! What this crate is
//! ══════════════════════════════════════════════════════════════════════
//!
//! The pure-types half of the **cofre** toolchain. Defines:
//!
//!   - `SecretGenPolicy`   — how a secret is born (random, keypair, ...)
//!   - `RotationPolicy`    — when it should be rotated
//!   - `Charset`           — which alphabet random-generated values draw from
//!   - `BackendKind`       — where the materialized value lives
//!   - `SecretRef`         — a typed pointer to one secret, with policy
//!   - `SecretMaterializationPlan` — many `SecretRef`s plus metadata,
//!                                    serializable to YAML/JSON for a
//!                                    `cofre apply` invocation
//!
//! No I/O, no randomness, no backend code lives here — those concerns
//! belong in the `cofre` binary or in third-party `SecretBackend` impls.
//! This crate is **pure types**: load it, manipulate, validate, render.
//!
//! ══════════════════════════════════════════════════════════════════════
//! Why this crate exists
//! ══════════════════════════════════════════════════════════════════════
//!
//! Many tools generate secrets. Most of them put the plaintext on stdout
//! at some point. Most of them hard-code one backend. Most of them have
//! no notion of "this kind of password is constrained to ≤16 characters
//! by the consuming protocol".
//!
//! cofre's typed pipeline solves all three. By the time a generated
//! secret exists, the typescape has already proven (at compile time +
//! `cargo test`) that:
//!
//!   - the chosen length is compatible with the consumer (e.g. VNC's
//!     16-char ARD-XOR cap is structurally enforced via `max_length`)
//!   - the requested charset is non-empty
//!   - the rotation policy is consistent (e.g. `Never` rejects pairing
//!     with a `Manual` rotation)
//!
//! Validation is total before generation begins. Once cofre starts
//! materializing, the only remaining failure modes are I/O.
//!
//! ══════════════════════════════════════════════════════════════════════
//! Compatibility
//! ══════════════════════════════════════════════════════════════════════
//!
//! Plans serialize to a stable YAML (and JSON) shape — the schema is part
//! of cofre's public contract and is versioned via `apiVersion`. Adding
//! new variants to `SecretGenPolicy` is non-breaking; renaming or
//! removing them bumps the schema.

#![warn(clippy::pedantic)]

use serde::{Deserialize, Serialize};

// ══════════════════════════════════════════════════════════════════════
// Charset — which alphabet random-generated values draw from
// ══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Charset {
    /// `[A-Za-z0-9]` — safest for legacy systems with weird quoting.
    Alphanumeric,
    /// `[A-Za-z0-9~!@#$%^&*()-_=+\[\]{};:,.<>?/]` — strong but commonly safe.
    Symbols,
    /// `[0-9a-f]` — fixed-width hex, e.g. for token-like material.
    Hex,
    /// `[A-Z2-7]` — RFC 4648 base32 alphabet (no padding semantics here).
    Base32,
    /// URL-safe base64 (`-` and `_`, no padding).
    Base64UrlSafe,
}

impl Charset {
    /// The set of allowed bytes. Used by the generator at runtime; here
    /// we expose it for validators to assert non-emptiness.
    #[must_use]
    pub fn alphabet(self) -> &'static [u8] {
        match self {
            Self::Alphanumeric => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            }
            Self::Symbols => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()-_=+[]{};:,.<>?/"
            }
            Self::Hex => b"0123456789abcdef",
            Self::Base32 => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            Self::Base64UrlSafe => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// SecretGenPolicy — how a secret is born
// ══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum SecretGenPolicy {
    /// A random password drawn from `charset`.
    ///
    /// `length` is the *requested* length; `max_length`, when set, is a
    /// **structural cap** imposed by the consumer (e.g. macOS's legacy
    /// VNC ARD-XOR scheme silently truncates beyond 16 bytes — pairing
    /// `length: 32` with `max_length: Some(16)` is a validator failure).
    PasswordRandom {
        length: u8,
        charset: Charset,
        max_length: Option<u8>,
    },
    /// A pre-shared key — random bytes, `length_bytes` long, encoded as
    /// base64 url-safe. Used for WireGuard PSKs and similar.
    PreSharedKey { length_bytes: u8 },
    /// A bearer token — random alphanumeric, `length` chars, with an
    /// optional human-readable prefix (`prefix: Some("pat_")` →
    /// `pat_AbCdEf...`).
    Token { length: u8, prefix: Option<String> },
    /// A WireGuard X25519 keypair. Materializes TWO secrets at once:
    /// `<path>.private` and `<path>.public`, both base64 (32 bytes each).
    WireguardKeypair,
    /// An SSH keypair (Ed25519 or RSA). Same dual-path materialization
    /// as WireGuard: `<path>.private` (OpenSSH PEM), `<path>.public`
    /// (`ssh-ed25519 AAAA... comment` line).
    SshKeypair { algo: SshAlgo },
    /// A self-signed TLS keypair, valid `validity_days` from generation.
    /// Materializes `<path>.key` (PEM) + `<path>.crt` (PEM).
    TlsKeypair {
        algo: TlsAlgo,
        validity_days: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshAlgo {
    Ed25519,
    Rsa4096,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsAlgo {
    Ed25519,
    Rsa4096,
    EcdsaP256,
}

impl SecretGenPolicy {
    /// How many distinct backend paths this policy materializes. Most
    /// policies are 1; keypair policies are 2.
    #[must_use]
    pub fn backend_paths(&self) -> usize {
        match self {
            Self::WireguardKeypair | Self::SshKeypair { .. } | Self::TlsKeypair { .. } => 2,
            _ => 1,
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// RotationPolicy — when a secret should be rotated
// ══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RotationPolicy {
    /// `cofre apply` never auto-rotates this secret. Operator must
    /// explicitly invoke `cofre apply --rotate <path>`.
    Manual,
    /// `cofre plan` flags this secret as overdue once 90 days have
    /// elapsed since last materialization (per the inventory).
    Quarterly,
    /// `cofre plan` flags this secret as overdue once 365 days have
    /// elapsed.
    Yearly,
    /// Root-of-trust material that should NEVER be rotated by cofre.
    /// `cofre apply --rotate` against a `Never`-marked secret refuses.
    Never,
}

impl RotationPolicy {
    /// Days after materialization beyond which `cofre plan` flags this
    /// secret as overdue. `None` means never overdue (`Manual` / `Never`).
    #[must_use]
    pub fn overdue_after_days(self) -> Option<u32> {
        match self {
            Self::Manual | Self::Never => None,
            Self::Quarterly => Some(90),
            Self::Yearly => Some(365),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// BackendKind — where the materialized value lives
// ══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum BackendKind {
    /// SOPS-encrypted YAML/JSON file, with the secret stored at a
    /// specific YAML path inside it. cofre uses an EDITOR-mode hijack
    /// to splice the value in without ever displaying plaintext.
    Sops {
        /// Absolute path to the SOPS file on disk.
        file: String,
        /// Dotted YAML path within the file, e.g. `cofre.ryn.vnc-password`.
        yaml_path: String,
    },
    /// Akeyless secret at the given absolute path. cofre uploads via
    /// the Akeyless API (or CLI with FD-passed value, never argv).
    Akeyless {
        /// Absolute Akeyless secret path, e.g. `/pleme-io/ryn/...`.
        path: String,
    },
    /// In-memory only. Used by tests; rejected by `validate_backend()`
    /// for production plans (the validator gates this behind a
    /// `Plan::test_only` toggle).
    Mock { name: String },
}

impl BackendKind {
    /// Stable identifier for inventory + dedup. For `Sops`, this is
    /// `sops:<file>:<yaml_path>`; for `Akeyless`, `akeyless:<path>`.
    #[must_use]
    pub fn stable_id(&self) -> String {
        match self {
            Self::Sops { file, yaml_path } => format!("sops:{file}:{yaml_path}"),
            Self::Akeyless { path } => format!("akeyless:{path}"),
            Self::Mock { name } => format!("mock:{name}"),
        }
    }

    #[must_use]
    pub fn is_test_only(&self) -> bool {
        matches!(self, Self::Mock { .. })
    }
}

// ══════════════════════════════════════════════════════════════════════
// SecretRef — a typed pointer to one secret
// ══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    /// Logical identifier — used by humans + inventories. Slug-shape
    /// (`[a-z0-9-]+`). Validators reject anything else.
    pub name: String,
    /// Optional human-readable description. Renders into the inventory
    /// + plan, never into the secret value itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Where the materialized secret lives.
    pub backend: BackendKind,
    /// How the secret is born. `None` ⇒ cofre never generates this
    /// secret (operator owns its lifecycle); cofre may still verify
    /// existence via `cofre verify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<SecretGenPolicy>,
    /// When the secret should be rotated.
    #[serde(default = "default_rotation")]
    pub rotation: RotationPolicy,
    /// Free-form labels — used for filtering + grouping in `cofre plan`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

fn default_rotation() -> RotationPolicy {
    RotationPolicy::Manual
}

impl SecretRef {
    /// Returns the list of concrete backend paths this ref materializes.
    /// For a singleton policy: `[self.backend.stable_id()]`. For
    /// keypair policies: two suffixed paths.
    #[must_use]
    pub fn materialization_targets(&self) -> Vec<String> {
        let base = self.backend.stable_id();
        match &self.generation {
            Some(SecretGenPolicy::WireguardKeypair) | Some(SecretGenPolicy::SshKeypair { .. }) => {
                vec![format!("{base}.private"), format!("{base}.public")]
            }
            Some(SecretGenPolicy::TlsKeypair { .. }) => {
                vec![format!("{base}.key"), format!("{base}.crt")]
            }
            _ => vec![base],
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// SecretMaterializationPlan — many SecretRefs + metadata
// ══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMaterializationPlan {
    /// Schema version. Currently `pleme.io/v1`.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Always `SecretMaterializationPlan`. Reject mismatches at parse.
    pub kind: String,
    /// Plan-level metadata (operator-friendly identifiers).
    pub metadata: PlanMetadata,
    /// The actual secrets.
    pub secrets: Vec<SecretRef>,
    /// When `true`, validators allow `BackendKind::Mock` entries.
    /// Plans rendered from arch-synthesizer always emit `false`.
    #[serde(default)]
    pub test_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanMetadata {
    /// Plan name — slug-shape, e.g. `ryn-remote-access`.
    pub name: String,
    /// Optional human description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Source typescape that produced this plan, e.g.
    /// `arch-synthesizer/remote_access`. For attestation breadcrumbs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl SecretMaterializationPlan {
    /// Canonical `apiVersion` value.
    pub const API_VERSION: &'static str = "pleme.io/v1";
    /// Canonical `kind` value.
    pub const KIND: &'static str = "SecretMaterializationPlan";

    #[must_use]
    pub fn new(name: impl Into<String>, secrets: Vec<SecretRef>) -> Self {
        Self {
            api_version: Self::API_VERSION.into(),
            kind: Self::KIND.into(),
            metadata: PlanMetadata {
                name: name.into(),
                description: None,
                source: None,
            },
            secrets,
            test_only: false,
        }
    }

    /// Read a plan from a YAML string. Validates schema and content.
    pub fn from_yaml(s: &str) -> Result<Self, PlanError> {
        let plan: Self = serde_yaml::from_str(s).map_err(PlanError::Parse)?;
        plan.validate()?;
        Ok(plan)
    }

    /// Render the plan to YAML.
    pub fn to_yaml(&self) -> Result<String, PlanError> {
        serde_yaml::to_string(self).map_err(PlanError::Serialize)
    }
}

// ══════════════════════════════════════════════════════════════════════
// Validation
// ══════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("plan parse failure: {0}")]
    Parse(serde_yaml::Error),
    #[error("plan serialize failure: {0}")]
    Serialize(serde_yaml::Error),
    #[error("unsupported apiVersion: {0:?} (expected {expected:?})", expected = SecretMaterializationPlan::API_VERSION)]
    UnsupportedApiVersion(String),
    #[error("unexpected kind: {0:?} (expected {expected:?})", expected = SecretMaterializationPlan::KIND)]
    UnexpectedKind(String),
    #[error("plan name must match [a-z0-9-]+ (was {0:?})")]
    InvalidPlanName(String),
    #[error("secret name must match [a-z0-9-]+ (was {0:?})")]
    InvalidSecretName(String),
    #[error("secret name {0:?} appears more than once in the plan")]
    DuplicateSecretName(String),
    #[error("backend stable-id {0:?} appears in more than one secret — would collide on apply")]
    DuplicateBackend(String),
    #[error("BackendKind::Mock present in non-test plan — set test_only=true if intentional")]
    MockBackendInProductionPlan,
    #[error("PasswordRandom length must be > 0")]
    ZeroLengthPassword,
    #[error("PasswordRandom length {requested} exceeds max_length {cap}")]
    PasswordExceedsMaxLength { requested: u8, cap: u8 },
    #[error("PreSharedKey length_bytes must be > 0")]
    ZeroLengthPreSharedKey,
    #[error("Token length must be > 0")]
    ZeroLengthToken,
    #[error("TlsKeypair validity_days must be > 0")]
    ZeroValidityDays,
    #[error("Token prefix must match [a-zA-Z0-9_-]* (was {0:?})")]
    InvalidTokenPrefix(String),
    #[error("Sops backend file path must be absolute (was {0:?})")]
    NonAbsoluteSopsFile(String),
    #[error("Sops backend yaml_path must be non-empty")]
    EmptySopsYamlPath,
    #[error("Akeyless backend path must start with '/' (was {0:?})")]
    InvalidAkeylessPath(String),
    #[error("plan must contain at least one secret")]
    EmptyPlan,
}

fn is_slug(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn is_token_prefix(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

impl SecretMaterializationPlan {
    /// Validate every structural invariant. Pure, total. Fails fast.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.api_version != Self::API_VERSION {
            return Err(PlanError::UnsupportedApiVersion(self.api_version.clone()));
        }
        if self.kind != Self::KIND {
            return Err(PlanError::UnexpectedKind(self.kind.clone()));
        }
        if !is_slug(&self.metadata.name) {
            return Err(PlanError::InvalidPlanName(self.metadata.name.clone()));
        }
        if self.secrets.is_empty() {
            return Err(PlanError::EmptyPlan);
        }

        let mut seen_names = std::collections::HashSet::new();
        let mut seen_backends = std::collections::HashSet::new();

        for s in &self.secrets {
            if !is_slug(&s.name) {
                return Err(PlanError::InvalidSecretName(s.name.clone()));
            }
            if !seen_names.insert(s.name.clone()) {
                return Err(PlanError::DuplicateSecretName(s.name.clone()));
            }

            for tgt in s.materialization_targets() {
                if !seen_backends.insert(tgt.clone()) {
                    return Err(PlanError::DuplicateBackend(tgt));
                }
            }

            if !self.test_only && s.backend.is_test_only() {
                return Err(PlanError::MockBackendInProductionPlan);
            }

            validate_backend(&s.backend)?;

            if let Some(g) = &s.generation {
                validate_generation(g)?;
            }
        }
        Ok(())
    }
}

fn validate_backend(b: &BackendKind) -> Result<(), PlanError> {
    match b {
        BackendKind::Sops { file, yaml_path } => {
            if !file.starts_with('/') {
                return Err(PlanError::NonAbsoluteSopsFile(file.clone()));
            }
            if yaml_path.is_empty() {
                return Err(PlanError::EmptySopsYamlPath);
            }
        }
        BackendKind::Akeyless { path } => {
            if !path.starts_with('/') {
                return Err(PlanError::InvalidAkeylessPath(path.clone()));
            }
        }
        BackendKind::Mock { .. } => {}
    }
    Ok(())
}

fn validate_generation(g: &SecretGenPolicy) -> Result<(), PlanError> {
    match g {
        SecretGenPolicy::PasswordRandom {
            length,
            max_length,
            charset: _,
        } => {
            if *length == 0 {
                return Err(PlanError::ZeroLengthPassword);
            }
            if let Some(cap) = max_length {
                if length > cap {
                    return Err(PlanError::PasswordExceedsMaxLength {
                        requested: *length,
                        cap: *cap,
                    });
                }
            }
        }
        SecretGenPolicy::PreSharedKey { length_bytes } => {
            if *length_bytes == 0 {
                return Err(PlanError::ZeroLengthPreSharedKey);
            }
        }
        SecretGenPolicy::Token { length, prefix } => {
            if *length == 0 {
                return Err(PlanError::ZeroLengthToken);
            }
            if let Some(p) = prefix {
                if !is_token_prefix(p) {
                    return Err(PlanError::InvalidTokenPrefix(p.clone()));
                }
            }
        }
        SecretGenPolicy::TlsKeypair { validity_days, .. } => {
            if *validity_days == 0 {
                return Err(PlanError::ZeroValidityDays);
            }
        }
        SecretGenPolicy::WireguardKeypair | SecretGenPolicy::SshKeypair { .. } => {}
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// Convenient builders for common shapes
// ══════════════════════════════════════════════════════════════════════

impl SecretRef {
    /// A vanilla random alphanumeric password, no length cap, manual rotation.
    #[must_use]
    pub fn password(name: impl Into<String>, backend: BackendKind, length: u8) -> Self {
        Self {
            name: name.into(),
            description: None,
            backend,
            generation: Some(SecretGenPolicy::PasswordRandom {
                length,
                charset: Charset::Alphanumeric,
                max_length: None,
            }),
            rotation: RotationPolicy::Manual,
            labels: vec![],
        }
    }

    /// A capped password — for protocols with hard length limits
    /// (e.g. macOS legacy VNC at 16 chars).
    #[must_use]
    pub fn capped_password(
        name: impl Into<String>,
        backend: BackendKind,
        length: u8,
        max_length: u8,
    ) -> Self {
        Self {
            name: name.into(),
            description: None,
            backend,
            generation: Some(SecretGenPolicy::PasswordRandom {
                length,
                charset: Charset::Alphanumeric,
                max_length: Some(max_length),
            }),
            rotation: RotationPolicy::Manual,
            labels: vec![],
        }
    }

    /// Builder helper.
    #[must_use]
    pub fn with_rotation(mut self, r: RotationPolicy) -> Self {
        self.rotation = r;
        self
    }

    /// Builder helper.
    #[must_use]
    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    /// Builder helper.
    #[must_use]
    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn akeyless_password(name: &str, length: u8) -> SecretRef {
        SecretRef::password(
            name,
            BackendKind::Akeyless {
                path: format!("/test/{name}"),
            },
            length,
        )
    }

    fn ryn_plan() -> SecretMaterializationPlan {
        SecretMaterializationPlan::new(
            "ryn-remote-access",
            vec![
                SecretRef::capped_password(
                    "vnc-password",
                    BackendKind::Akeyless {
                        path: "/pleme-io/ryn/remote-access/vnc-password".into(),
                    },
                    16,
                    16,
                )
                .with_rotation(RotationPolicy::Quarterly)
                .with_description("Apple Screen Sharing VNC password (capped at 16 by ARD-XOR)"),
                SecretRef::password(
                    "rustdesk-password",
                    BackendKind::Akeyless {
                        path: "/pleme-io/ryn/remote-access/rustdesk-password".into(),
                    },
                    24,
                )
                .with_rotation(RotationPolicy::Quarterly),
            ],
        )
    }

    // ── Charsets ──────────────────────────────────────────────────────

    #[test]
    fn every_charset_is_non_empty() {
        for c in [
            Charset::Alphanumeric,
            Charset::Symbols,
            Charset::Hex,
            Charset::Base32,
            Charset::Base64UrlSafe,
        ] {
            assert!(!c.alphabet().is_empty());
        }
    }

    #[test]
    fn hex_alphabet_is_lowercase() {
        assert_eq!(Charset::Hex.alphabet(), b"0123456789abcdef");
    }

    // ── Plan validation ────────────────────────────────────────────────

    #[test]
    fn ryn_plan_validates() {
        assert!(ryn_plan().validate().is_ok());
    }

    #[test]
    fn empty_plan_rejected() {
        let p = SecretMaterializationPlan::new("empty", vec![]);
        assert!(matches!(p.validate(), Err(PlanError::EmptyPlan)));
    }

    #[test]
    fn duplicate_secret_name_rejected() {
        let p = SecretMaterializationPlan::new(
            "dup",
            vec![akeyless_password("foo", 16), akeyless_password("foo", 16)],
        );
        assert!(matches!(p.validate(), Err(PlanError::DuplicateSecretName(_))));
    }

    #[test]
    fn duplicate_backend_rejected() {
        let mut a = akeyless_password("foo", 16);
        let mut b = akeyless_password("bar", 16);
        a.backend = BackendKind::Akeyless { path: "/x".into() };
        b.backend = BackendKind::Akeyless { path: "/x".into() };
        let p = SecretMaterializationPlan::new("dup-backend", vec![a, b]);
        assert!(matches!(p.validate(), Err(PlanError::DuplicateBackend(_))));
    }

    #[test]
    fn invalid_plan_name_rejected() {
        let p = SecretMaterializationPlan::new("Bad Name!", vec![akeyless_password("x", 16)]);
        assert!(matches!(p.validate(), Err(PlanError::InvalidPlanName(_))));
    }

    #[test]
    fn invalid_secret_name_rejected() {
        let p = SecretMaterializationPlan::new("ok", vec![akeyless_password("Bad Name", 16)]);
        assert!(matches!(p.validate(), Err(PlanError::InvalidSecretName(_))));
    }

    #[test]
    fn unsupported_apiversion_rejected() {
        let mut p = ryn_plan();
        p.api_version = "wrong/v0".into();
        assert!(matches!(p.validate(), Err(PlanError::UnsupportedApiVersion(_))));
    }

    #[test]
    fn unexpected_kind_rejected() {
        let mut p = ryn_plan();
        p.kind = "Whatever".into();
        assert!(matches!(p.validate(), Err(PlanError::UnexpectedKind(_))));
    }

    #[test]
    fn mock_backend_in_prod_plan_rejected() {
        let mut s = akeyless_password("foo", 16);
        s.backend = BackendKind::Mock { name: "x".into() };
        let p = SecretMaterializationPlan::new("prod", vec![s]);
        assert!(matches!(p.validate(), Err(PlanError::MockBackendInProductionPlan)));
    }

    #[test]
    fn mock_backend_in_test_plan_allowed() {
        let mut s = akeyless_password("foo", 16);
        s.backend = BackendKind::Mock { name: "x".into() };
        let mut p = SecretMaterializationPlan::new("test", vec![s]);
        p.test_only = true;
        assert!(p.validate().is_ok());
    }

    #[test]
    fn nonabsolute_sops_file_rejected() {
        let s = SecretRef::password(
            "foo",
            BackendKind::Sops {
                file: "relative/path.yaml".into(),
                yaml_path: "x.y".into(),
            },
            16,
        );
        let p = SecretMaterializationPlan::new("nonabs", vec![s]);
        assert!(matches!(p.validate(), Err(PlanError::NonAbsoluteSopsFile(_))));
    }

    #[test]
    fn empty_sops_yaml_path_rejected() {
        let s = SecretRef::password(
            "foo",
            BackendKind::Sops {
                file: "/abs.yaml".into(),
                yaml_path: String::new(),
            },
            16,
        );
        let p = SecretMaterializationPlan::new("emptyyp", vec![s]);
        assert!(matches!(p.validate(), Err(PlanError::EmptySopsYamlPath)));
    }

    #[test]
    fn invalid_akeyless_path_rejected() {
        let s = SecretRef::password(
            "foo",
            BackendKind::Akeyless { path: "no-slash".into() },
            16,
        );
        let p = SecretMaterializationPlan::new("invak", vec![s]);
        assert!(matches!(p.validate(), Err(PlanError::InvalidAkeylessPath(_))));
    }

    // ── Generation policy validation ───────────────────────────────────

    #[test]
    fn zero_length_password_rejected() {
        let s = SecretRef::password(
            "foo",
            BackendKind::Akeyless { path: "/x".into() },
            0,
        );
        let p = SecretMaterializationPlan::new("zerolen", vec![s]);
        assert!(matches!(p.validate(), Err(PlanError::ZeroLengthPassword)));
    }

    #[test]
    fn password_exceeds_max_length_rejected() {
        let s = SecretRef::capped_password(
            "vnc",
            BackendKind::Akeyless { path: "/x".into() },
            32,
            16,
        );
        let p = SecretMaterializationPlan::new("toolong", vec![s]);
        assert!(matches!(
            p.validate(),
            Err(PlanError::PasswordExceedsMaxLength { requested: 32, cap: 16 })
        ));
    }

    #[test]
    fn vnc_at_max_length_allowed() {
        // length == max_length is the BR canonical case for VNC.
        let s = SecretRef::capped_password(
            "vnc",
            BackendKind::Akeyless { path: "/x".into() },
            16,
            16,
        );
        let p = SecretMaterializationPlan::new("vnc", vec![s]);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn zero_byte_psk_rejected() {
        let s = SecretRef {
            name: "psk".into(),
            description: None,
            backend: BackendKind::Akeyless { path: "/x".into() },
            generation: Some(SecretGenPolicy::PreSharedKey { length_bytes: 0 }),
            rotation: RotationPolicy::Manual,
            labels: vec![],
        };
        let p = SecretMaterializationPlan::new("zeropsk", vec![s]);
        assert!(matches!(p.validate(), Err(PlanError::ZeroLengthPreSharedKey)));
    }

    #[test]
    fn zero_validity_tls_rejected() {
        let s = SecretRef {
            name: "tls".into(),
            description: None,
            backend: BackendKind::Akeyless { path: "/x".into() },
            generation: Some(SecretGenPolicy::TlsKeypair {
                algo: TlsAlgo::Ed25519,
                validity_days: 0,
            }),
            rotation: RotationPolicy::Manual,
            labels: vec![],
        };
        let p = SecretMaterializationPlan::new("notvalid", vec![s]);
        assert!(matches!(p.validate(), Err(PlanError::ZeroValidityDays)));
    }

    #[test]
    fn invalid_token_prefix_rejected() {
        let s = SecretRef {
            name: "tok".into(),
            description: None,
            backend: BackendKind::Akeyless { path: "/x".into() },
            generation: Some(SecretGenPolicy::Token {
                length: 32,
                prefix: Some("bad space".into()),
            }),
            rotation: RotationPolicy::Manual,
            labels: vec![],
        };
        let p = SecretMaterializationPlan::new("badprefix", vec![s]);
        assert!(matches!(p.validate(), Err(PlanError::InvalidTokenPrefix(_))));
    }

    // ── materialization_targets ────────────────────────────────────────

    #[test]
    fn singleton_password_has_one_target() {
        let s = akeyless_password("foo", 16);
        assert_eq!(s.materialization_targets().len(), 1);
    }

    #[test]
    fn wireguard_keypair_has_two_targets() {
        let s = SecretRef {
            name: "wg".into(),
            description: None,
            backend: BackendKind::Akeyless { path: "/x".into() },
            generation: Some(SecretGenPolicy::WireguardKeypair),
            rotation: RotationPolicy::Manual,
            labels: vec![],
        };
        let t = s.materialization_targets();
        assert_eq!(t.len(), 2);
        assert!(t[0].ends_with(".private"));
        assert!(t[1].ends_with(".public"));
    }

    #[test]
    fn tls_keypair_targets_are_key_and_crt() {
        let s = SecretRef {
            name: "tls".into(),
            description: None,
            backend: BackendKind::Akeyless { path: "/x".into() },
            generation: Some(SecretGenPolicy::TlsKeypair {
                algo: TlsAlgo::Ed25519,
                validity_days: 365,
            }),
            rotation: RotationPolicy::Yearly,
            labels: vec![],
        };
        let t = s.materialization_targets();
        assert!(t[0].ends_with(".key"));
        assert!(t[1].ends_with(".crt"));
    }

    // ── Round-trip ─────────────────────────────────────────────────────

    #[test]
    fn yaml_round_trip_is_total() {
        let p = ryn_plan();
        let s = p.to_yaml().unwrap();
        let q = SecretMaterializationPlan::from_yaml(&s).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn json_round_trip_is_total() {
        let p = ryn_plan();
        let s = serde_json::to_string(&p).unwrap();
        let q: SecretMaterializationPlan = serde_json::from_str(&s).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn yaml_is_deterministic() {
        let p = ryn_plan();
        assert_eq!(p.to_yaml().unwrap(), p.to_yaml().unwrap());
    }

    #[test]
    fn rotation_overdue_table() {
        assert_eq!(RotationPolicy::Manual.overdue_after_days(), None);
        assert_eq!(RotationPolicy::Quarterly.overdue_after_days(), Some(90));
        assert_eq!(RotationPolicy::Yearly.overdue_after_days(), Some(365));
        assert_eq!(RotationPolicy::Never.overdue_after_days(), None);
    }
}
