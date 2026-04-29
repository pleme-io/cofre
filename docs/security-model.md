# Security Model

## Threat model

cofre is designed against:

| Threat | Mitigation |
|--------|------------|
| Operator's terminal scrollback / shoulder-surf | Plaintext never reaches stdout/stderr. |
| Process listing (`ps`, `/proc`, `auditd`) | No plaintext in argv. Akeyless uses SDK; SOPS uses EDITOR-mode. |
| Shell history | No plaintext on the command line. Operator never types or pastes a value. |
| Heap / swap / coredump leakage | All plaintext lives in `Zeroizing<String>` (zeroed on drop). |
| Misuse via "test mode" leaking into prod | `BackendKind::Mock` is rejected at validate time unless `Plan.test_only=true`. |
| Wrong-length password silently truncating downstream | `PasswordRandom { max_length }` paired with the consumer's structural cap. Validator rejects mismatched pairings. |
| Idempotent re-runs accidentally rotating live credentials | `apply` skips existing secrets; `--rotate <name>` is the only path to overwrite, and `RotationPolicy::Never` rejects even that. |

cofre is NOT designed against:

| Out of scope | Why |
|--------------|-----|
| Compromised operator workstation | If the box is owned, the operator's age key + Akeyless creds are accessible — cofre can't help. |
| Backend compromise (Akeyless tenant breach, SOPS file leaked with key) | Backend security is the backend's problem. |
| Sidechannel attacks on the CSPRNG | We trust `getrandom` (OS CSPRNG) absolutely. |
| Coercion ("give us the secret") | Cryptography doesn't help here. |

## Hard rules audit

These are the non-negotiable invariants. Each release must verify them.

### Rule 1 — Plaintext never reaches stdout, stderr, argv, env, or any log line

**Audit method:**
```bash
# Should produce zero output that contains plaintext.
grep -rn 'println!\|eprintln!\|dbg!\|tracing::\|log::' crates/cofre/src/ | grep -i 'value\|secret\|plain'

# Should produce zero output. We never put a value in argv.
grep -rn '\.args(' crates/cofre/src/ | grep 'value'
```

The CLI prints exactly:
- Plan structure (names, backend stable-ids, generation policies, rotation)
- Apply counts (`wrote: N | skipped: N | errored: N`)
- Verify presence (`✓ name (present)` / `× name (missing)`)
- Inventory (BLAKE3 hashes only — never values)

### Rule 2 — Plaintext lives only in `Zeroizing<String>`

**Audit method:**
```bash
# Find any String/Vec<u8> handling values (excluding tests).
grep -rn 'fn .*-> String\b' crates/cofre/src/ | grep -v 'test\|^//'
```

The `generation::generate` return type is `Zeroizing<String>`. The
`SecretBackend::write` parameter is `Zeroizing<String>`. The
`SopsHookEntry::policy` carries the policy, not a value. The Akeyless
`CreateSecret.value: String` is the unfortunate exception — the SDK's
generated type is `String` — but we explicitly clone from `Zeroizing`
into it, build the request, await, and the request body is dropped
synchronously after the await completes. The `Zeroizing` original is
wiped by its own drop.

### Rule 3 — Generation uses `getrandom`

**Audit method:**
```bash
# Should reference only getrandom.
grep -rn 'rand::\|StdRng\|thread_rng\|SmallRng' crates/cofre/src/

# Should be the only entropy import.
grep -n '^use getrandom' crates/cofre/src/generation.rs
```

### Rule 4 — SOPS via EDITOR-mode hijack

**Audit method:**
```bash
# The only call to sops should be in apply_batch — and the args list
# must NOT contain --set or any value-bearing flag.
grep -A 3 'Command::new.*sops' crates/cofre/src/backends.rs
```

### Rule 5 — Akeyless via SDK

**Audit method:**
```bash
# Should produce zero matches.
grep -rn 'Command::new.*akeyless\b' crates/cofre/src/

# Should reference akeyless_api.
grep -n 'akeyless_api' crates/cofre/src/backends.rs
```

### Rule 6 — Validation runs before any backend is contacted

`load_plan` calls `Plan::validate()` before returning to the
dispatcher. All other code paths consume already-validated plans.

### Rule 7 — Idempotent

`apply_one_via_backend` calls `backend.exists()` first. Existing
secrets short-circuit unless `force` is true (driven by `--rotate
<name>`). The dispatcher pre-validates the rotate target against
`RotationPolicy::Never` before any backend work begins.

## Per-release smoke test

The full integration test that touches real backends is NOT in CI
(it requires external state). Run manually before each release:

```bash
# 1. Plan-time, no backends contacted.
cofre plan --manifest test-fixtures/full-plan.yaml

# 2. Mock apply — exercises the in-memory backend + generation.
cofre apply --manifest test-fixtures/full-plan.yaml --mock

# 3. SOPS apply — exercises the EDITOR hijack.
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
cofre apply --manifest test-fixtures/sops-plan.yaml
sops -d test-fixtures/sops-secrets.yaml > /dev/null  # confirms decryption works

# 4. Akeyless apply — exercises the SDK path.
export AKEYLESS_ACCESS_ID=p-xxxxxx
export AKEYLESS_ACCESS_KEY=...
cofre apply --manifest test-fixtures/akeyless-plan.yaml
cofre verify --manifest test-fixtures/akeyless-plan.yaml
# Manual verification: log into Akeyless console, confirm secrets present
# at the declared paths. Spot-check that lengths match the declared
# generation policies.

# 5. Rotation.
cofre apply --manifest test-fixtures/akeyless-plan.yaml --rotate <name>

# 6. Refusal of Never.
cofre apply --manifest test-fixtures/never-rotate-plan.yaml --rotate <name>
# Expected: exit 4, "RotationPolicy::Never" message.
```

## Reporting vulnerabilities

Email: security@pleme.io. PGP key fingerprint published in
`SECURITY.md` at the repo root (placeholder until org-IaC creates it).
