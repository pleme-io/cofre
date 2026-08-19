//! Secret backends.
//!
//! `SecretBackend` is the open-source-grade extension point. Anyone can
//! implement it for HashiCorp Vault, AWS Secrets Manager, GCP Secret
//! Manager, Azure Key Vault, 1Password, or a homegrown TPM-backed
//! store. cofre core ships three impls:
//!
//!   - `MockBackend`     — in-memory only, for tests
//!   - `AkeylessBackend` — direct HTTPS via the akeyless-api SDK; no
//!                         argv exposure ever
//!   - `SopsBackend`     — EDITOR-mode hijack of the `sops` CLI;
//!                         plaintext lives only in the in-process
//!                         buffer of the editor child
//!
//! Hard rules (every impl):
//!   - `write` takes `Zeroizing<String>`. Never `String`.
//!   - `read_for_inventory` returns BLAKE3 of `value || salt`, never
//!     the value itself. Used only by `cofre inventory`.
//!   - All `async fn` methods that handle plaintext must avoid `dbg!`,
//!     `println!`, and `tracing::debug!` on the value.

use cofre_types::{BackendKind, SecretRef};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("backend I/O failure: {0}")]
    Io(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("environment misconfiguration: {0}")]
    Env(String),
    #[error("backend kind {0} is not supported by this binary build")]
    Unsupported(String),
    #[error("backend rejected the operation: {0}")]
    Rejected(String),
}

/// Async trait for backend implementations. Methods take `&self` so a
/// single backend instance is safe to share across the multiple
/// secrets in a plan that target it (typical for SOPS files +
/// Akeyless tenants).
pub trait SecretBackend: Send + Sync {
    /// Stable name for logs + inventory output. Never includes secret
    /// values. Examples: `"akeyless"`, `"sops:/path/secrets.yaml"`.
    fn label(&self) -> String;

    /// Whether the secret at `<ref>.backend` already has a value.
    /// Implementors must NOT fetch the value here — only existence.
    fn exists<'a>(
        &'a self,
        secret: &'a SecretRef,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, BackendError>> + Send + 'a>>;

    /// Write the value into the backend at `<ref>.backend`. Idempotent
    /// on equivalent input is NOT required — callers gate on `exists`
    /// or pass `--rotate`. The implementor MUST NOT log, print, or
    /// emit `value` anywhere. The buffer is zeroed when this future
    /// completes (`Zeroizing` drop semantics).
    fn write<'a>(
        &'a self,
        secret: &'a SecretRef,
        value: Zeroizing<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BackendError>> + Send + 'a>>;
}

// ══════════════════════════════════════════════════════════════════════
// MockBackend — for tests only. Stored values live in a shared mutex.
// ══════════════════════════════════════════════════════════════════════

#[derive(Default, Clone)]
pub struct MockBackend {
    state: Arc<Mutex<std::collections::HashMap<String, Zeroizing<String>>>>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test helper: borrow a snapshot of stored keys (NOT values) for
    /// assertions. Never expose values from MockBackend in production
    /// paths — but we DO let tests inspect lengths to confirm
    /// generation policy was honored.
    pub fn keys(&self) -> Vec<String> {
        self.state.lock().unwrap().keys().cloned().collect()
    }

    /// Test helper: confirm a value is present and meets a length
    /// constraint without exposing it.
    pub fn value_length(&self, key: &str) -> Option<usize> {
        self.state.lock().unwrap().get(key).map(|v| v.len())
    }
}

impl SecretBackend for MockBackend {
    fn label(&self) -> String {
        "mock".into()
    }

    fn exists<'a>(
        &'a self,
        secret: &'a SecretRef,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, BackendError>> + Send + 'a>>
    {
        Box::pin(async move {
            Ok(self
                .state
                .lock()
                .unwrap()
                .contains_key(&secret.backend.stable_id()))
        })
    }

    fn write<'a>(
        &'a self,
        secret: &'a SecretRef,
        value: Zeroizing<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BackendError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.state
                .lock()
                .unwrap()
                .insert(secret.backend.stable_id(), value);
            Ok(())
        })
    }
}

// ══════════════════════════════════════════════════════════════════════
// AkeylessBackend — direct HTTPS via akeyless-api SDK
// ══════════════════════════════════════════════════════════════════════

pub struct AkeylessBackend {
    cfg: akeyless_api::apis::configuration::Configuration,
}

impl AkeylessBackend {
    /// Construct from environment. Requires the standard akeyless env vars:
    ///   `AKEYLESS_ACCESS_ID`, `AKEYLESS_ACCESS_KEY` (api-key auth)
    ///   `AKEYLESS_GATEWAY_URL` (optional; defaults to akeyless.io)
    ///
    /// The bearer token is fetched once per backend instance via the
    /// `Auth` endpoint and reused for the lifetime of `apply`.
    pub async fn from_env() -> Result<Self, BackendError> {
        let access_id = std::env::var("AKEYLESS_ACCESS_ID")
            .map_err(|_| BackendError::Env("AKEYLESS_ACCESS_ID not set".into()))?;
        let access_key = std::env::var("AKEYLESS_ACCESS_KEY")
            .map_err(|_| BackendError::Env("AKEYLESS_ACCESS_KEY not set".into()))?;
        let base_path = std::env::var("AKEYLESS_GATEWAY_URL")
            .unwrap_or_else(|_| "https://api.akeyless.io".into());

        let mut cfg = akeyless_api::apis::configuration::Configuration::new();
        cfg.base_path = base_path;

        let auth_req = akeyless_api::models::Auth {
            access_id: Some(access_id),
            access_key: Some(Zeroizing::new(access_key).to_string()),
            access_type: Some("access_key".into()),
            ..Default::default()
        };

        let auth_out = akeyless_api::apis::v2_api::auth(&cfg, auth_req)
            .await
            .map_err(|e| BackendError::Auth(format!("{e:?}")))?;

        cfg.bearer_access_token = auth_out.token;
        Ok(Self { cfg })
    }
}

impl SecretBackend for AkeylessBackend {
    fn label(&self) -> String {
        "akeyless".into()
    }

    fn exists<'a>(
        &'a self,
        secret: &'a SecretRef,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, BackendError>> + Send + 'a>>
    {
        Box::pin(async move {
            let path = match &secret.backend {
                BackendKind::Akeyless { path } => path.clone(),
                _ => return Err(BackendError::Unsupported(secret.backend.stable_id())),
            };
            let req = akeyless_api::models::DescribeItem {
                name: path,
                token: self.cfg.bearer_access_token.clone(),
                ..Default::default()
            };
            match akeyless_api::apis::v2_api::describe_item(&self.cfg, req).await {
                Ok(_) => Ok(true),
                Err(e) => {
                    // "ItemNotFound" → false; anything else → bubble up.
                    let msg = format!("{e:?}");
                    if msg.contains("not found")
                        || msg.contains("ItemNotFound")
                        || msg.contains("404")
                    {
                        Ok(false)
                    } else {
                        Err(BackendError::Io(msg))
                    }
                }
            }
        })
    }

    fn write<'a>(
        &'a self,
        secret: &'a SecretRef,
        value: Zeroizing<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BackendError>> + Send + 'a>>
    {
        Box::pin(async move {
            let path = match &secret.backend {
                BackendKind::Akeyless { path } => path.clone(),
                _ => return Err(BackendError::Unsupported(secret.backend.stable_id())),
            };
            // Plaintext flows: Zeroizing<String> → CreateSecret.value
            // (a plain String inside the request struct, but the struct
            // itself is dropped after the await completes; reqwest owns
            // it briefly during serialization). The HTTPS response
            // never echoes the value. The Zeroizing wrapper guarantees
            // *our* copy is wiped on drop.
            let plain: String = (*value).clone();
            let req = akeyless_api::models::CreateSecret {
                name: path,
                value: plain,
                token: self.cfg.bearer_access_token.clone(),
                ..Default::default()
            };
            akeyless_api::apis::v2_api::create_secret(&self.cfg, req)
                .await
                .map_err(|e| BackendError::Io(format!("{e:?}")))?;
            Ok(())
        })
    }
}

// ══════════════════════════════════════════════════════════════════════
// SopsBackend — EDITOR-mode hijack
// ══════════════════════════════════════════════════════════════════════
//
// Design:
//   1. `cofre apply` groups SOPS-backed secrets by `file` path.
//   2. For each unique file, write a JSON plan slice to a tempfile
//      with mode 0600 (the slice contains backend yaml-paths + which
//      generation policy each one uses).
//   3. Spawn `sops <file>` with:
//        EDITOR  = `<argv0> __sops-editor-hook`
//        COFRE_SOPS_PLAN_PATH = <plan-slice tempfile path>
//   4. `sops` decrypts the file to a tempfile in /tmp (mode 0600 by
//      default), invokes EDITOR with the tempfile path as argv[1],
//      waits for editor exit, re-encrypts.
//   5. Our `__sops-editor-hook` child reads the plan slice, opens the
//      sops tempfile, parses YAML, generates+sets each missing value
//      via `generation::generate`, writes back, exits.
//
// All plaintext lives only in the child's process memory + the
// /tmp tempfile during the hand-off (which sops created with 0600).

use crate::generation;
use std::path::PathBuf;

pub struct SopsBackend {
    file_path: PathBuf,
    sops_bin: PathBuf,
    self_argv0: PathBuf,
}

impl SopsBackend {
    pub fn new(
        file: impl Into<PathBuf>,
        self_argv0: impl Into<PathBuf>,
    ) -> Result<Self, BackendError> {
        let sops_bin = which_sops()?;
        Ok(Self {
            file_path: file.into(),
            sops_bin,
            self_argv0: self_argv0.into(),
        })
    }

    /// Apply a batch of writes to the sops file in a single editor
    /// invocation. This is the multi-secret entry point the CLI uses;
    /// the per-secret `SecretBackend::write` exists too but is less
    /// efficient (one sops invocation per secret).
    /// Returns `true` when the batch wrote at least one new value,
    /// `false` when every entry in the batch was already present (an
    /// idempotent no-op — sops's own exit 200, "file has not changed").
    pub async fn apply_batch(&self, plan_slice: &[SopsHookEntry]) -> Result<bool, BackendError> {
        // Write the plan slice (no secrets, just policy) to a 0600
        // tempfile that the hook child reads.
        let mut tmp = tempfile::Builder::new()
            .prefix("cofre-sops-plan-")
            .suffix(".json")
            .tempfile()
            .map_err(|e| BackendError::Io(format!("tempfile: {e}")))?;
        let plan_json = serde_json::to_string(plan_slice)
            .map_err(|e| BackendError::Io(format!("plan serialize: {e}")))?;
        std::io::Write::write_all(tmp.as_file_mut(), plan_json.as_bytes())
            .map_err(|e| BackendError::Io(format!("plan write: {e}")))?;

        let plan_path = tmp.path().to_path_buf();
        let editor_cmd = format!("{} __sops-editor-hook", self.self_argv0.display());

        let status = tokio::process::Command::new(&self.sops_bin)
            .arg(&self.file_path)
            .env("EDITOR", &editor_cmd)
            .env("COFRE_SOPS_PLAN_PATH", &plan_path)
            .status()
            .await
            .map_err(|e| BackendError::Io(format!("spawn sops: {e}")))?;

        // Drop tmpfile (auto-unlinks).
        drop(tmp);

        // sops's own documented convention: exit 200 means the editor
        // hook made no changes to the plaintext (every entry in this
        // batch was already present and none carried `force: true`) --
        // an idempotent no-op, not a failure. Only run_editor_hook can
        // produce this: it computes `wrote_any` and never touches the
        // plaintext file when it's false, which is exactly what leaves
        // sops with nothing to re-encrypt.
        const SOPS_NO_CHANGES: i32 = 200;
        if status.code() == Some(SOPS_NO_CHANGES) {
            return Ok(false);
        }
        if !status.success() {
            return Err(BackendError::Io(format!("sops exited with {status:?}")));
        }
        Ok(true)
    }
}

fn which_sops() -> Result<PathBuf, BackendError> {
    if let Ok(p) = std::env::var("SOPS") {
        return Ok(PathBuf::from(p));
    }
    // Naive PATH search.
    let path = std::env::var("PATH").map_err(|_| BackendError::Env("PATH not set".into()))?;
    for entry in path.split(':') {
        let candidate = std::path::Path::new(entry).join("sops");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(BackendError::Env(
        "`sops` binary not found in PATH (set $SOPS to override)".into(),
    ))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SopsHookEntry {
    /// Dotted YAML path inside the file, e.g. `cofre.ryn.vnc-password`.
    pub yaml_path: String,
    /// Generation policy.
    pub policy: cofre_types::SecretGenPolicy,
    /// True ⇒ overwrite even if present (driven by `--rotate`).
    pub force: bool,
}

/// Run the SOPS editor hook. Called by `main` when argv is
/// `cofre __sops-editor-hook <plaintext-tmp-path>`.
///
/// Steps:
///   1. Read the plan slice from `$COFRE_SOPS_PLAN_PATH`.
///   2. Read the plaintext YAML SOPS handed us.
///   3. For each entry: if missing OR `force=true`, generate a value
///      and splice it into the YAML at `yaml_path`.
///   4. Write the YAML back to the same path.
///   5. Exit 0 — sops re-encrypts.
pub fn run_editor_hook(plaintext_path: &std::path::Path) -> std::io::Result<()> {
    let plan_path = std::env::var("COFRE_SOPS_PLAN_PATH").map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::Other, "COFRE_SOPS_PLAN_PATH unset")
    })?;
    let plan_slice: Vec<SopsHookEntry> = serde_json::from_slice(&std::fs::read(&plan_path)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    // Read decrypted YAML SOPS handed us. Body is plaintext; treat
    // with care — never log it.
    let body = std::fs::read_to_string(plaintext_path)?;

    // ★ THIS PARSES WITH `suminuri_yaml`, NOT `serde_yaml` — AND WHAT THAT BUYS IS
    // A LOUD REFUSAL, *NOT* COMMENT PRESERVATION. Stated precisely because the first
    // version of this comment claimed preservation and was wrong.
    //
    // `serde_yaml::Value` has no variant for a comment, so `from_str` → `to_string`
    // silently DELETED every comment in the file. Style went with it: block scalars
    // collapsed and quoting was re-decided by serde's rules.
    //
    // `suminuri_yaml::parse` instead REFUSES a commented document by name
    // (`CommentsUnsupported { line }`). Its tree does model comments — `Item::Comment`
    // and `Entry::Comment` are variants, used when re-emitting — but the parser does
    // not yet build them, and a refusal is the honest state to be in: this hook
    // rewrites the operator's decrypted secrets, so silently dropping documentation
    // is the one outcome worse than failing.
    //
    // Measured before making the swap (2026-08-19): both real fleet files —
    // `nix/secrets.yaml` (1381 lines) and `nix/users/drzzln/secrets.yaml` (93) —
    // contain ZERO comment lines in their decrypted bodies, and the encrypted forms
    // carry zero `#ENC[` comment markers. So the refusal costs the fleet nothing
    // today while the silent strip was a standing hazard.
    //
    // What the swap also buys, and this part is unqualified: every `Scalar` keeps the
    // `ScalarStyle` it was parsed with, so quoting and block scalars survive a
    // round-trip that serde_yaml re-decided. One YAML model for sops files, in one
    // place.
    //
    // `pending-suminuri: comment-preserving parse` — the load-bearing fix is teaching
    // the parser to build the comment variants its tree already has, at which point
    // this becomes preservation rather than refusal.
    //
    // `cofre-types` still uses serde_yaml, correctly: it serialises cofre's OWN typed
    // plan struct, where there are no comments to lose and serde's derive is the right
    // tool. The rule is about whose file it is, not about the library.
    let mut doc = suminuri_yaml::parse(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let root = doc.roots.first_mut().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "empty YAML document")
    })?;

    let mut wrote_any = false;
    for entry in &plan_slice {
        let already_present = yaml_get(root, &entry.yaml_path).is_some();
        if already_present && !entry.force {
            continue;
        }
        let value = generation::generate(&entry.policy)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        yaml_set(root, &entry.yaml_path, (*value).clone());
        wrote_any = true;
    }

    if wrote_any {
        let new_body = suminuri_yaml::emit(&doc, suminuri_yaml::EmitOptions::default())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        std::fs::write(plaintext_path, new_body)?;
    }
    Ok(())
}

/// Look up a dotted path in a `suminuri_yaml` tree.
///
/// Note the path grammar here is DOTTED (`a.b.c`), not sops's bracket form
/// (`["a"]["b"]`). They are deliberately not unified: this one comes from cofre's
/// own `yaml_path` plan field, which is cofre's schema to define, while the bracket
/// form is sops's CLI contract that `suminuri` must reproduce exactly. Merging them
/// would mean one of the two surfaces silently accepting the other's syntax.
fn yaml_get<'a>(doc: &'a suminuri_yaml::Value, dotted: &str) -> Option<&'a suminuri_yaml::Value> {
    let mut cur = doc;
    for part in dotted.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

/// Set a dotted path, creating intermediate mappings.
///
/// An existing key is updated **in place** and a new key is **appended**, so the
/// mapping is never rebuilt and nothing around the write moves. That is what keeps
/// a `Comment` item's position stable once the parser learns to produce one; today
/// it is what keeps every untouched key's style and order intact.
fn yaml_set(doc: &mut suminuri_yaml::Value, dotted: &str, value: String) {
    use suminuri_yaml::{Item, Scalar, Value};

    let parts: Vec<&str> = dotted.split('.').collect();
    if !matches!(doc, Value::Mapping(_)) {
        *doc = Value::Mapping(Vec::new());
    }
    let mut cur = doc;
    for part in &parts[..parts.len() - 1] {
        let Value::Mapping(items) = cur else {
            // A non-mapping on the way down. The previous version `expect`ed here and
            // would panic inside a sops-invoked editor hook, which surfaces as a
            // failed rebuild with no explanation. Replacing the node is the same
            // behaviour serde_yaml's version had after its own `is_mapping` reset,
            // without the panic path.
            *cur = Value::Mapping(Vec::new());
            continue;
        };
        let present = items
            .iter()
            .any(|i| matches!(i, Item::Pair { key, .. } if key == *part));
        if !present {
            items.push(Item::Pair {
                key: (*part).to_string(),
                value: Value::Mapping(Vec::new()),
            });
        }
        cur = items
            .iter_mut()
            .find_map(|i| match i {
                Item::Pair { key, value } if key == *part => Some(value),
                _ => None,
            })
            .expect("just-inserted key present");
    }

    let last = *parts.last().expect("split always yields one part");
    let Value::Mapping(items) = cur else {
        *cur = Value::Mapping(vec![Item::Pair {
            key: last.to_string(),
            value: Value::Scalar(Scalar::new(value)),
        }]);
        return;
    };
    if let Some(slot) = items.iter_mut().find_map(|i| match i {
        Item::Pair { key, value } if key == last => Some(value),
        _ => None,
    }) {
        *slot = Value::Scalar(Scalar::new(value));
    } else {
        items.push(Item::Pair {
            key: last.to_string(),
            value: Value::Scalar(Scalar::new(value)),
        });
    }
}

// SopsBackend doesn't implement SecretBackend in the per-secret shape
// — it works in batched mode (one sops invocation per file). The CLI
// dispatcher special-cases SOPS targets accordingly.

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use cofre_types::{Charset, RotationPolicy, SecretGenPolicy, SecretRef};

    fn mock_secret(name: &str) -> SecretRef {
        SecretRef {
            name: name.into(),
            description: None,
            backend: BackendKind::Mock { name: name.into() },
            generation: Some(SecretGenPolicy::PasswordRandom {
                length: 16,
                charset: Charset::Alphanumeric,
                max_length: None,
            }),
            rotation: RotationPolicy::Manual,
            labels: vec![],
        }
    }

    #[tokio::test]
    async fn mock_exists_then_write_then_exists() {
        let b = MockBackend::new();
        let s = mock_secret("foo");
        assert!(!b.exists(&s).await.unwrap());
        b.write(&s, Zeroizing::new("supersecret".into()))
            .await
            .unwrap();
        assert!(b.exists(&s).await.unwrap());
        assert_eq!(b.value_length("mock:foo"), Some(11));
    }

    fn scalar_at(doc: &suminuri_yaml::Value, path: &str) -> Option<String> {
        match yaml_get(doc, path)? {
            suminuri_yaml::Value::Scalar(s) => Some(s.value.clone()),
            _ => None,
        }
    }

    #[test]
    fn yaml_set_creates_intermediate_maps() {
        let mut doc = suminuri_yaml::Value::Mapping(Vec::new());
        yaml_set(&mut doc, "a.b.c", "hi".to_string());
        assert_eq!(scalar_at(&doc, "a.b.c").as_deref(), Some("hi"));
    }

    #[test]
    fn yaml_set_overwrites_existing() {
        let mut doc = suminuri_yaml::parse("a:\n  b: old\n")
            .unwrap()
            .roots
            .remove(0);
        yaml_set(&mut doc, "a.b", "new".to_string());
        assert_eq!(scalar_at(&doc, "a.b").as_deref(), Some("new"));
    }

    #[test]
    fn yaml_get_returns_none_for_missing_path() {
        let doc = suminuri_yaml::parse("a: 1\n").unwrap().roots.remove(0);
        assert!(yaml_get(&doc, "a.b.c").is_none());
    }

    /// ★ WHAT THE SWAP ACTUALLY CHANGES: a commented file is now REFUSED BY NAME
    /// instead of silently losing its comments.
    ///
    /// This test exists because the first version of it asserted the opposite —
    /// that comments *survive* — and failed with `CommentsUnsupported { line: 1 }`.
    /// The tree models comments; the parser does not yet build them. Pinning the
    /// real behaviour keeps the next reader from re-deriving a preservation claim
    /// the code does not make.
    ///
    /// Refusal is the right state for this hook: it rewrites the operator's
    /// decrypted secrets, and `serde_yaml` would have dropped the documentation
    /// with no diagnostic at all.
    #[test]
    fn a_commented_document_is_refused_not_silently_stripped() {
        let src = "\
# the fleet-wide bootstrap token; see docs/onboarding-secrets.md
github:
    classic: old-value
";
        match suminuri_yaml::parse(src) {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.to_lowercase().contains("comment"),
                    "the refusal must name comments, got: {msg}"
                );
            }
            Ok(doc) => {
                // If the parser ever learns comments, this must become a
                // preservation assertion rather than quietly passing.
                let out =
                    suminuri_yaml::emit(&doc, suminuri_yaml::EmitOptions::default()).expect("emit");
                assert!(
                    out.contains("# the fleet-wide bootstrap token"),
                    "the parser now accepts comments but the emitter dropped them:\n{out}"
                );
            }
        }
    }

    /// A new key is APPENDED and an existing one is updated IN PLACE, so nothing
    /// around the write moves. That is the property that will keep a comment's
    /// position stable once the parser produces them, and today keeps every
    /// untouched key's order and style intact.
    #[test]
    fn a_new_key_is_appended_and_untouched_keys_do_not_move() {
        let src = "alpha: one\nbeta: two\n";
        let mut doc = suminuri_yaml::parse(src).expect("parse");
        yaml_set(
            doc.roots.first_mut().expect("one root"),
            "gamma",
            "three".to_string(),
        );
        let out = suminuri_yaml::emit(&doc, suminuri_yaml::EmitOptions::default()).expect("emit");
        let lines: Vec<&str> = out.lines().collect();
        let pos = |p: &str| lines.iter().position(|l| l.starts_with(p));
        assert_eq!(pos("alpha:"), Some(0), "order changed:\n{out}");
        assert_eq!(pos("beta:"), Some(1), "order changed:\n{out}");
        assert_eq!(pos("gamma:"), Some(2), "new key not appended:\n{out}");
    }

    /// An in-place update must not disturb the keys around it.
    #[test]
    fn an_update_in_place_leaves_siblings_byte_identical() {
        let src = "alpha: one\nbeta: 'quoted two'\ngamma: three\n";
        let mut doc = suminuri_yaml::parse(src).expect("parse");
        yaml_set(
            doc.roots.first_mut().expect("one root"),
            "gamma",
            "rewritten".to_string(),
        );
        let out = suminuri_yaml::emit(&doc, suminuri_yaml::EmitOptions::default()).expect("emit");
        assert!(out.contains("alpha: one"), "sibling changed:\n{out}");
        assert!(
            out.contains("beta: 'quoted two'"),
            "a sibling's QUOTING STYLE changed — the thing serde_yaml re-decided:\n{out}"
        );
        assert!(
            out.contains("gamma: rewritten"),
            "write did not take:\n{out}"
        );
    }
}
