# Generation Policies

Every `SecretGenPolicy` variant. Pick the right one for the consumer.

## `PasswordRandom { length, charset, max_length? }`

A random string drawn from the chosen alphabet.

| Field | Meaning |
|-------|---------|
| `length` | The length to generate. Must be ≤ `max_length` if set. |
| `charset` | Alphabet — see Charset table below. |
| `max_length` | Structural cap from the consumer (e.g. `Some(16)` for macOS legacy VNC). When set, the validator rejects `length > max_length`. |

**When to use:**
- User passwords for service accounts (RustDesk, app-specific basic auth, ...)
- Database connection passwords
- Anything that ends up in a UI password field

**When NOT to use:**
- Cryptographic keys — use `PreSharedKey` or a keypair variant.
- Bearer tokens — use `Token` so you can prefix them.

### Charsets

| Charset | Alphabet | When |
|---------|----------|------|
| `Alphanumeric` | `[A-Za-z0-9]` (62 chars) | Default. Safe in shells, JSON, YAML, query strings. |
| `Symbols` | `[A-Za-z0-9~!@#$%^&*()-_=+[]{};:,.<>?/]` | Higher entropy; some consumers reject specific symbols — test before deploying. |
| `Hex` | `[0-9a-f]` (16 chars) | Fixed-width hex tokens. |
| `Base32` | `[A-Z2-7]` (32 chars) | RFC 4648 base32. Used by some legacy 2FA systems and by tools that produce TOTP secrets. |
| `Base64UrlSafe` | `[A-Za-z0-9-_]` (64 chars) | URL-safe; useful for tokens that go into query strings. |

### Examples

```rust
// Apple Screen Sharing VNC — 16-char ARD-XOR cap is structural.
SecretGenPolicy::PasswordRandom {
    length: 16,
    charset: Charset::Alphanumeric,
    max_length: Some(16),
}

// 24-char strong password, no cap.
SecretGenPolicy::PasswordRandom {
    length: 24,
    charset: Charset::Alphanumeric,
    max_length: None,
}
```

## `Token { length, prefix? }`

A random alphanumeric body, optionally prefixed with a stable string.

| Field | Meaning |
|-------|---------|
| `length` | The random portion's length (the prefix doesn't count). |
| `prefix` | Optional, slug-shaped (`[a-zA-Z0-9_-]*`). |

**When to use:**
- Bearer tokens (PAT-style)
- API keys
- Any value where you want operators to be able to identify the
  source by visual inspection (`pat_AbC...` vs `gh_AbC...`)

### Example

```rust
SecretGenPolicy::Token {
    length: 32,
    prefix: Some("pat_".into()),
}
// Produces: pat_aB3xK9mPq2RwT4uY7nL5vJ8hG6cD1eF0
```

## `PreSharedKey { length_bytes }`

Random bytes, encoded as RFC 4648 base64 url-safe (no padding).

| Field | Meaning |
|-------|---------|
| `length_bytes` | Raw byte length. The output string is ~4/3 longer. |

**When to use:**
- WireGuard PSKs (`length_bytes: 32`)
- HMAC keys
- Anything that's just "random bytes, encoded for transport"

### Example

```rust
SecretGenPolicy::PreSharedKey { length_bytes: 32 }
// Produces a 43-char base64-urlsafe string (32*4/3 = 42.67, rounded up).
```

## `WireguardKeypair` *(planned)*

X25519 keypair. Materializes TWO entries: `<path>.private` and
`<path>.public`, both base64 (32 bytes each).

**Status:** declared in cofre-types, not yet implemented in
`generation::generate`. PRs welcome.

## `SshKeypair { algo }` *(planned)*

OpenSSH keypair (Ed25519 or RSA-4096). Materializes `<path>.private`
(OpenSSH PEM) and `<path>.public` (`ssh-ed25519 AAAA... comment` line).

**Status:** declared in cofre-types, not yet implemented.

## `TlsKeypair { algo, validity_days }` *(planned)*

Self-signed TLS keypair (Ed25519, RSA-4096, or ECDSA-P256), valid
`validity_days` from generation. Materializes `<path>.key` (PEM) and
`<path>.crt` (PEM).

**Status:** declared in cofre-types, not yet implemented.

## CSPRNG

All policies use the OS CSPRNG via the `getrandom` crate. Random-string
sampling uses **rejection sampling** to guarantee a uniform output
distribution regardless of alphabet size:

```
threshold = (256 / alphabet.len()) * alphabet.len()
loop {
    byte = getrandom(1)
    if byte < threshold {
        out.push(alphabet[byte % alphabet.len()])
        break
    }
}
```

For a 62-char alphanumeric alphabet, threshold = 248, ~3% of bytes are
rejected. Negligible cost; structural correctness.

## Rotation

A `RotationPolicy` lives next to `SecretGenPolicy` on the same
`SecretRef`. cofre's `apply` does not auto-rotate — `--rotate <name>`
is the only path to overwrite. `cofre plan` flags secrets as "overdue"
when their `last_applied` timestamp (recorded in the inventory) is
older than the rotation window:

| Policy | Overdue after |
|--------|---------------|
| `Manual` | Never (cofre doesn't track) |
| `Quarterly` | 90 days |
| `Yearly` | 365 days |
| `Never` | Never; `--rotate` refuses |
