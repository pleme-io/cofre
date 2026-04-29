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
                    if msg.contains("not found") || msg.contains("ItemNotFound") || msg.contains("404") {
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
    pub fn new(file: impl Into<PathBuf>, self_argv0: impl Into<PathBuf>) -> Result<Self, BackendError> {
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
    pub async fn apply_batch(
        &self,
        plan_slice: &[SopsHookEntry],
    ) -> Result<(), BackendError> {
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
        let editor_cmd = format!(
            "{} __sops-editor-hook",
            self.self_argv0.display()
        );

        let status = tokio::process::Command::new(&self.sops_bin)
            .arg(&self.file_path)
            .env("EDITOR", &editor_cmd)
            .env("COFRE_SOPS_PLAN_PATH", &plan_path)
            .status()
            .await
            .map_err(|e| BackendError::Io(format!("spawn sops: {e}")))?;

        // Drop tmpfile (auto-unlinks).
        drop(tmp);

        if !status.success() {
            return Err(BackendError::Io(format!(
                "sops exited with {status:?}"
            )));
        }
        Ok(())
    }
}

fn which_sops() -> Result<PathBuf, BackendError> {
    if let Ok(p) = std::env::var("SOPS") {
        return Ok(PathBuf::from(p));
    }
    // Naive PATH search.
    let path = std::env::var("PATH")
        .map_err(|_| BackendError::Env("PATH not set".into()))?;
    for entry in path.split(':') {
        let candidate = std::path::Path::new(entry).join("sops");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(BackendError::Env("`sops` binary not found in PATH (set $SOPS to override)".into()))
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
    let plan_path = std::env::var("COFRE_SOPS_PLAN_PATH")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "COFRE_SOPS_PLAN_PATH unset"))?;
    let plan_slice: Vec<SopsHookEntry> = serde_json::from_slice(&std::fs::read(&plan_path)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    // Read decrypted YAML SOPS handed us. Body is plaintext; treat
    // with care — never log it.
    let body = std::fs::read_to_string(plaintext_path)?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut wrote_any = false;
    for entry in &plan_slice {
        let already_present = yaml_get(&doc, &entry.yaml_path).is_some();
        if already_present && !entry.force {
            continue;
        }
        let value = generation::generate(&entry.policy)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        yaml_set(&mut doc, &entry.yaml_path, serde_yaml::Value::String((*value).clone()));
        wrote_any = true;
    }

    if wrote_any {
        let new_body = serde_yaml::to_string(&doc)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        std::fs::write(plaintext_path, new_body)?;
    }
    Ok(())
}

fn yaml_get<'a>(doc: &'a serde_yaml::Value, dotted: &str) -> Option<&'a serde_yaml::Value> {
    let mut cur = doc;
    for part in dotted.split('.') {
        let m = cur.as_mapping()?;
        cur = m.get(serde_yaml::Value::String(part.into()))?;
    }
    Some(cur)
}

fn yaml_set(doc: &mut serde_yaml::Value, dotted: &str, value: serde_yaml::Value) {
    let parts: Vec<&str> = dotted.split('.').collect();
    if !doc.is_mapping() {
        *doc = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let mut cur = doc;
    for part in &parts[..parts.len() - 1] {
        let key = serde_yaml::Value::String((*part).into());
        let map = cur.as_mapping_mut().expect("yaml_set traversal expected mapping");
        if !map.contains_key(&key) {
            map.insert(key.clone(), serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
        }
        cur = map.get_mut(&key).expect("just-inserted key present");
    }
    let last_key = serde_yaml::Value::String((*parts.last().unwrap()).into());
    let map = cur.as_mapping_mut().expect("final yaml_set traversal expected mapping");
    map.insert(last_key, value);
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
        b.write(&s, Zeroizing::new("supersecret".into())).await.unwrap();
        assert!(b.exists(&s).await.unwrap());
        assert_eq!(b.value_length("mock:foo"), Some(11));
    }

    #[test]
    fn yaml_set_creates_intermediate_maps() {
        let mut doc = serde_yaml::Value::Null;
        yaml_set(&mut doc, "a.b.c", serde_yaml::Value::String("hi".into()));
        let v = yaml_get(&doc, "a.b.c").unwrap();
        assert_eq!(v.as_str(), Some("hi"));
    }

    #[test]
    fn yaml_set_overwrites_existing() {
        let mut doc: serde_yaml::Value =
            serde_yaml::from_str("a:\n  b: old").unwrap();
        yaml_set(&mut doc, "a.b", serde_yaml::Value::String("new".into()));
        assert_eq!(yaml_get(&doc, "a.b").unwrap().as_str(), Some("new"));
    }

    #[test]
    fn yaml_get_returns_none_for_missing_path() {
        let doc: serde_yaml::Value = serde_yaml::from_str("a: 1").unwrap();
        assert!(yaml_get(&doc, "a.b.c").is_none());
    }
}
