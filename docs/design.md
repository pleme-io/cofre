# Design

## The pattern

Most secret-management tooling is shaped like this:

```
operator → (sees plaintext) → CLI → backend
```

cofre is shaped like this:

```
typescape (compile-time validated) → SecretMaterializationPlan (typed)
                                                                  │
                                                                  ▼
                                                cofre apply (in-process CSPRNG +
                                                              Zeroizing<String>)
                                                                  │
                                                                  ▼
                                                              backend
```

The operator sees: a count.

## The two-crate split

`cofre-types` (the lib) is **pure types** — `SecretGenPolicy`,
`RotationPolicy`, `Charset`, `BackendKind`, `SecretRef`,
`SecretMaterializationPlan`. No I/O, no randomness, no backend code.
Stable serde schema.

`cofre` (the bin) is the **materializer** — CSPRNG + backends + CLI.
Depends on the lib. Compiled separately.

The split matters because:

1. **Many consumers, one shape.** Any tool that wants to declare typed
   secrets uses `cofre-types`. The bin is only relevant if you want to
   actually materialize them.
2. **Versioning.** The serde schema (lib) versions independently of the
   bin's internal architecture. Backend implementations come and go;
   the wire format is stable.
3. **Open-source friendliness.** Third parties write their own
   materializers (e.g. a TPM-backed one) by depending on `cofre-types`
   without dragging in our HTTPS/SOPS dependencies.

## The typescape pattern

Upstream typescapes (in arch-synthesizer or anywhere else) walk their
own typed declarations and emit a `SecretMaterializationPlan`. Example:
`pleme-io/arch-synthesizer/src/cofre_bridge.rs` walks a
`RemoteAccessHostDecl` and emits one plan per host:

```rust
pub fn remote_access_to_plan(decl: &RemoteAccessHostDecl) -> SecretMaterializationPlan {
    // ... walks tier configs, emits SecretRefs ...
}
```

The plan is then YAML-serialized and committed alongside other
generated artifacts. `cofre apply --manifest <plan>` consumes it.

This is the same compounding shape as `repo-forge`, `iac-forge`,
`forge-gen` — typed declarations + a renderer that materializes them.
Compounds across every typescape that already has `SecretRef`s.

## Why `Plan::validate()` runs before any backend is contacted

Because backend operations are slow, side-effecting, and sometimes
expensive. Plan validation is fast, pure, and total. Catching
"PasswordRandom length 32 with max_length 16" at validate time means
we never leave a partial trail of materialized secrets when the 17th
secret in the plan was structurally invalid all along.

## Why generation is rejection-sampled

Naive random-string sampling does `bytes[i] % alphabet.len()`. For
non-power-of-2 alphabets (e.g. 62-char alphanumeric), this introduces
a small bias toward early letters. Rejection sampling rejects bytes ≥
the largest multiple of `alphabet.len()` that fits in 256, then mods.
The output distribution is exactly uniform.

For a 62-char alphabet with rejection threshold 248, ~3% of CSPRNG
bytes are rejected. Negligible cost; structural correctness.

## Why `Zeroizing<String>` everywhere

`String` and `Vec<u8>` are not zeroized on drop. If they end up in a
heap that gets paged out, swap, or a coredump, plaintext can leak.
`zeroize::Zeroizing<T>` wipes the buffer on drop. The discipline is
load-bearing because Rust's borrow checker cannot tell us "this string
is plaintext, treat it specially" — but the wrapper type can.

The cost: every conversion (e.g. `Zeroizing<String>` → backend request
body) requires one explicit clone, which we mark in the code.

## Why SOPS uses EDITOR-mode hijack

The `sops` CLI offers three ways to mutate a file:

1. `sops <file>` — opens `$EDITOR` on the decrypted plaintext, re-encrypts on close.
2. `sops --set '["key"] "value"' <file>` — value is in argv. NO.
3. `sops -d` then re-encrypt — operator sees plaintext. NO.

(1) is the only one where plaintext stays in process memory. cofre
re-invokes itself as `EDITOR`, mutates the YAML in-process via the
`__sops-editor-hook` subcommand. The decrypted temp file SOPS creates
is mode 0600 in /tmp and lives for the duration of the editor child.

## Why Akeyless uses the API SDK

The `akeyless` CLI takes the secret value via a `--value` argv flag.
That puts plaintext in `ps`, in shell history (if the operator copy-
pastes), in the kernel argv buffer, in any audit logs that record
process invocations. NO.

The SDK path: `Auth` endpoint to fetch a bearer token, then
`CreateSecret` with the value in the JSON request body. Plaintext lives
only in process memory + the TLS frame. The operator's auth tokens
(`AKEYLESS_ACCESS_ID`, `AKEYLESS_ACCESS_KEY`) come from environment
variables — typically rendered by sops-nix into the operator's shell.

## Future directions

- **Add-only-no-decrypt SOPS backend.** SOPS encryption is asymmetric
  with age — adding a new value to an existing file does not require
  the decryption key. We could spawn `rage`-encrypt of the new value
  and splice the ciphertext into the YAML directly. This removes the
  operator's age key from the per-apply loop entirely.
- **First-class rotation tracking.** The inventory artifact currently
  carries a structural-only entry (no value hashes). Adding
  `SecretBackend::read_for_inventory` (returning `BLAKE3(value || salt)`)
  enables tamper detection across rotations.
- **Keypair generators.** WireGuard / SSH / TLS keypair policies are
  declared but not yet implemented in `generation::generate`. Adding
  them is straightforward; the `materialization_targets()` already
  emits the dual-path shape.
- **More backends.** HashiCorp Vault, AWS Secrets Manager, GCP Secret
  Manager, Azure Key Vault, 1Password — all good candidates. PRs
  welcome.
