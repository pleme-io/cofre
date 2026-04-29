# Implementing a custom `SecretBackend`

cofre's `SecretBackend` trait is the open extension point. Implement it
for any secret store and your backend plugs into the existing
`plan` / `apply` / `verify` flow.

## The trait

```rust
pub trait SecretBackend: Send + Sync {
    fn label(&self) -> String;

    fn exists<'a>(&'a self, secret: &'a SecretRef)
        -> Pin<Box<dyn Future<Output = Result<bool, BackendError>> + Send + 'a>>;

    fn write<'a>(&'a self, secret: &'a SecretRef, value: Zeroizing<String>)
        -> Pin<Box<dyn Future<Output = Result<(), BackendError>> + Send + 'a>>;
}
```

Three methods. Everything else (validation, generation, rotation,
inventory) is the bin's concern.

## Hard rules for implementations

1. **Never log, print, or store the `value` parameter.** Your future
   should pass it directly to your backend's network/file/TPM layer.
2. **Never call `format!()` on a `Zeroizing<String>`.** The resulting
   `String` is not zeroized.
3. **`exists` must NOT fetch the value.** Existence and value retrieval
   are different operations; `exists` must return on a HEAD-equivalent
   request.
4. **`label()` must be stable.** It appears in inventory artifacts and
   in error messages. Don't include timestamps or per-instance state.
5. **Errors carry no plaintext.** Even truncated. `BackendError::Io`
   should describe the API call, not the value.

## Example — a Hashicorp Vault backend

```rust
use cofre_types::{BackendKind, SecretRef};
use cofre::backends::{SecretBackend, BackendError};
use std::pin::Pin;
use std::future::Future;
use zeroize::Zeroizing;

pub struct VaultBackend {
    addr: String,
    token: Zeroizing<String>,  // VAULT_TOKEN, zeroized on drop
    client: reqwest::Client,
}

impl VaultBackend {
    pub fn from_env() -> Result<Self, BackendError> {
        let addr = std::env::var("VAULT_ADDR")
            .map_err(|_| BackendError::Env("VAULT_ADDR unset".into()))?;
        let token = std::env::var("VAULT_TOKEN")
            .map_err(|_| BackendError::Env("VAULT_TOKEN unset".into()))?;
        Ok(Self {
            addr,
            token: Zeroizing::new(token),
            client: reqwest::Client::new(),
        })
    }

    fn vault_path(&self, secret: &SecretRef) -> Result<String, BackendError> {
        match &secret.backend {
            BackendKind::Mock { name } => Ok(format!("/test/{name}")),
            // For Vault we'd want a new BackendKind::Vault variant — see below.
            _ => Err(BackendError::Unsupported(secret.backend.stable_id())),
        }
    }
}

impl SecretBackend for VaultBackend {
    fn label(&self) -> String {
        format!("vault:{}", self.addr)
    }

    fn exists<'a>(&'a self, secret: &'a SecretRef)
        -> Pin<Box<dyn Future<Output = Result<bool, BackendError>> + Send + 'a>>
    {
        Box::pin(async move {
            let path = self.vault_path(secret)?;
            let url = format!("{}/v1{}", self.addr, path);
            let res = self.client.head(&url)
                .header("X-Vault-Token", &**self.token)  // zeroized borrow
                .send().await
                .map_err(|e| BackendError::Io(e.to_string()))?;
            Ok(res.status().is_success())
        })
    }

    fn write<'a>(&'a self, secret: &'a SecretRef, value: Zeroizing<String>)
        -> Pin<Box<dyn Future<Output = Result<(), BackendError>> + Send + 'a>>
    {
        Box::pin(async move {
            let path = self.vault_path(secret)?;
            let url = format!("{}/v1{}", self.addr, path);
            // Build JSON body with plaintext briefly. The body Vec<u8>
            // is dropped after send(); the Zeroizing original is wiped
            // by its own drop.
            let body = serde_json::json!({ "data": { "value": &**value } });
            self.client.post(&url)
                .header("X-Vault-Token", &**self.token)
                .json(&body)
                .send().await
                .map_err(|e| BackendError::Io(e.to_string()))?
                .error_for_status()
                .map_err(|e| BackendError::Io(e.to_string()))?;
            Ok(())
        })
    }
}
```

## Adding a new `BackendKind` variant

If your backend doesn't fit `Akeyless` / `Sops`, extend
`cofre_types::BackendKind`:

```rust
// In cofre-types/src/lib.rs
pub enum BackendKind {
    Sops { file: String, yaml_path: String },
    Akeyless { path: String },
    Mock { name: String },
    Vault { mount: String, path: String },  // new
}
```

Add a `stable_id` arm, a validator arm in `validate_backend`, and the
plan format auto-extends to:

```yaml
backend:
  kind: vault
  mount: secret
  path: data/example
```

PRs that add a typed variant + a default implementation pair are
strongly preferred over external-only extensions.

## Wiring into the bin

The CLI dispatcher (`cofre/src/main.rs`) currently special-cases
`Akeyless` and `Sops` because their constructors have different
signatures (one is `from_env`, the other takes a file path + argv0).
A future refactor will introduce a `BackendRegistry` that lazy-instantiates
each backend kind on first use; until then, adding your backend means
extending the dispatcher's `match &s.backend { ... }` arms.

## Testing

Use `MockBackend` in your tests of cofre logic. Use `VaultBackend`
behind a feature flag for integration tests against a local Vault
container.
