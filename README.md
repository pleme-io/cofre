# cofre

Typed secret materialization. Generate and seed secrets into your
backend without ever exposing plaintext to the operator.

```
                  ┌──────────────────────────────────┐
SecretRef         │                                  │
+ GenPolicy ────► │  cofre apply --manifest <plan>   │ ────► Akeyless / SOPS / ...
+ Backend         │  (CSPRNG → Zeroizing<String>)    │       (encrypted at rest)
                  └──────────────────────────────────┘
                              │
                              ▼
                   "wrote: 2 | skipped: 0 | errored: 0"
                   (operator never sees a single secret byte)
```

## What it is

cofre is two things:

1. **`cofre-types`** — a stable, open Rust library defining typed primitives
   for "where a secret lives", "how it's born", and "when it should be
   rotated." Use it from any tool that needs a typed secret model. No I/O,
   no randomness, no backend code — pure types. Stable serde schema for
   YAML/JSON round-trip.

2. **`cofre`** — a CLI binary that consumes a `SecretMaterializationPlan`
   (typically rendered by an upstream typescape) and materializes every
   declared secret into its target backend. Plaintext never leaves
   process memory except into an encrypted destination.

## Why

Most secret-management tooling either (a) hard-codes one backend, (b)
exposes plaintext to the operator at some point, or (c) has no notion of
"this kind of password is constrained to ≤16 characters by the consuming
protocol." cofre's typed pipeline solves all three. By the time
generation begins, the typescape has already proven (at compile time +
`cargo test`) that lengths are compatible, charsets are non-empty,
rotation policies are consistent, and target backends are valid.

## Hard rules

These are non-negotiable and audited per release:

| Rule | Enforcement |
|------|------------|
| Plaintext never hits stdout, stderr, argv, env, or any log line. | Code review + grep gate in CI. |
| Plaintext lives only in `Zeroizing<String>` (zeroed on drop). | Type system. |
| Generation uses `getrandom` (OS CSPRNG). | Direct dep, audited. |
| SOPS writes go via EDITOR-mode hijack (no manual decrypt). | `SopsBackend::apply_batch` is the only SOPS path. |
| Akeyless writes go via the `akeyless-api` Rust SDK. | We never shell out to `akeyless` CLI's `--value` flag (that puts plaintext in argv). |
| Validation runs **before** any backend is contacted. | `SecretMaterializationPlan::validate()`. |
| `cofre apply` is idempotent. Existing secrets are skipped unless `--rotate <name>`. | `SecretBackend::exists` gate. |

## Install

From source:

```bash
git clone https://github.com/pleme-io/cofre
cd cofre
cargo install --path crates/cofre
```

From Nix flake:

```nix
{
  inputs.cofre.url = "github:pleme-io/cofre";
  # ...
  packages.cofre = inputs.cofre.packages.${system}.default;
}
```

## Quick start

```bash
# 1. Author a SecretMaterializationPlan in YAML.
cat > my-plan.yaml <<'EOF'
apiVersion: pleme.io/v1
kind: SecretMaterializationPlan
metadata:
  name: example
secrets:
  - name: vnc-password
    backend:
      kind: akeyless
      path: /example/vnc-password
    generation:
      kind: password-random
      length: 16
      charset: alphanumeric
      max-length: 16
    rotation: quarterly
EOF

# 2. Plan-time inspection — no backends contacted.
cofre plan --manifest my-plan.yaml

# 3. Materialize.
export AKEYLESS_ACCESS_ID=p-xxxxxx
export AKEYLESS_ACCESS_KEY=...
cofre apply --manifest my-plan.yaml
# wrote: 1 | skipped: 0 | errored: 0

# 4. Verify (no plaintext touched).
cofre verify --manifest my-plan.yaml
#   ✓ vnc-password (present)
# present: 1 | missing: 0

# 5. Rotate.
cofre apply --manifest my-plan.yaml --rotate vnc-password
```

## Generation policies

| Policy | What it produces |
|--------|------------------|
| `PasswordRandom { length, charset, max_length? }` | Random string from charset; `max_length` enforces structural caps (e.g. macOS VNC at 16 chars). |
| `Token { length, prefix? }` | Optional prefix + alphanumeric body. |
| `PreSharedKey { length_bytes }` | Random bytes encoded as base64 url-safe. |
| `WireguardKeypair` | X25519 keypair → `<path>.private` + `<path>.public`. *(planned)* |
| `SshKeypair { algo }` | Ed25519 / RSA-4096 → OpenSSH PEM + `.pub`. *(planned)* |
| `TlsKeypair { algo, validity_days }` | Self-signed cert + key. *(planned)* |

## Backends

cofre ships three:

| Backend | Path | Notes |
|---------|------|-------|
| **MockBackend** | in-memory | Tests only. |
| **AkeylessBackend** | direct HTTPS via `akeyless-api` SDK | Auth via `AKEYLESS_ACCESS_ID` + `AKEYLESS_ACCESS_KEY` env vars (api-key auth). |
| **SopsBackend** | EDITOR-mode hijack | Speaks the SOPS file via `sops <file>` with `EDITOR=cofre __sops-editor-hook`. Plaintext lives only in our editor child's process memory. |

`SecretBackend` is a public extension trait — implement it for HashiCorp
Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault,
1Password, or your homegrown TPM-backed store. PRs welcome.

## Concepts

A **`SecretMaterializationPlan`** is a typed, serializable manifest of:
- N `SecretRef`s, each declaring its `backend`, `generation` policy, and
  `rotation` policy.
- Plan-level metadata (`name`, optional `description` and `source` —
  used as an attestation breadcrumb when an upstream typescape rendered
  the plan).

Plans are usually rendered by an upstream typescape and consumed by
`cofre apply`. Examples in the wild:

- `pleme-io/arch-synthesizer/src/cofre_bridge.rs` — emits one plan per
  remote-access host (the `RemoteAccessHostDecl` typescape).

## Documentation

- [`docs/design.md`](docs/design.md) — design rationale, the typescape pattern.
- [`docs/security-model.md`](docs/security-model.md) — threat model + hard rules audit.
- [`docs/backends.md`](docs/backends.md) — implementing a custom `SecretBackend`.
- [`docs/generation-policies.md`](docs/generation-policies.md) — every policy + its CSPRNG semantics.

## License

Dual-licensed under MIT or Apache-2.0. Pick whichever fits your project.
