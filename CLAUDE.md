# cofre — Claude Orientation

> **★★★ CSE / Knowable Construction.** This repo operates under
> **Constructive Substrate Engineering** — canonical specification at
> [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md).
> The Compounding Directive (operational rules: solve once, load-bearing
> fixes only, idiom-first, models stay current, direction beats velocity)
> is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before
> non-trivial changes.

One-sentence purpose: typed secret materialization — `cofre` generates
secrets and seeds them into a backend (SOPS, Akeyless, ...) without
ever exposing plaintext to the operator.

## Classification

- **Archetype:** rust-workspace (lib + bin)
- **Workspace members:** `crates/cofre-types` (lib) + `crates/cofre` (bin)
- **Substrate flake:** `rust-workspace-release-flake.nix`
- **Repo visibility:** private at first; **open-source under MIT-OR-Apache-2.0** when promoted via the pleme-io-github-posture flow.

## Where to look

| Intent | File |
|--------|------|
| Typed primitives (SecretGenPolicy, RotationPolicy, BackendKind, SecretRef, Plan) | `crates/cofre-types/src/lib.rs` |
| `SecretBackend` trait + Mock/Akeyless/Sops impls | `crates/cofre/src/backends.rs` |
| CSPRNG + Zeroize discipline | `crates/cofre/src/generation.rs` |
| Inventory artifact shape | `crates/cofre/src/inventory.rs` |
| CLI dispatch + plan/apply/verify/inventory | `crates/cofre/src/main.rs` |
| Threat model + hard rules | `docs/security-model.md` |
| Add a backend | `docs/backends.md` |

## Three layers, mapped

```
       cofre-types  (lib)        — typed primitives + serde, no I/O, no randomness
            │
            ▼
       cofre        (bin)        — CSPRNG, backend impls, CLI
            │
            ▼
   upstream typescape            — emits a SecretMaterializationPlan via cofre-types
   (e.g. arch-synthesizer/src/cofre_bridge.rs)
```

## Hard rules (security-critical)

These are non-negotiable. Code reviews gate on them; CI greps for
violations:

1. **Plaintext NEVER hits stdout, stderr, argv, env, or any log line.**
   Not even at debug level. The CLI prints counts, names, backend
   stable-ids, and rotation policies — never values.
2. **Plaintext lives only in `Zeroizing<String>`** (or `Zeroizing<Vec<u8>>`).
   `String`/`Vec<u8>` are forbidden for plaintext values. The type
   system carries the discipline.
3. **Generation uses `getrandom`** (OS CSPRNG). No `rand::thread_rng()`,
   no fallback PRNG. Random-string sampling is rejection-sampled to
   guarantee uniform distribution.
4. **SOPS writes go via EDITOR-mode hijack.** The `SopsBackend::apply_batch`
   path re-invokes `cofre __sops-editor-hook` as `EDITOR`, mutates the
   YAML in-process, and exits. We never call `sops --set` directly (it
   takes the value via argv).
5. **Akeyless writes go via the `akeyless-api` Rust SDK.** We never shell
   out to the `akeyless` CLI's `--value` flag (argv leak).
6. **Validation runs before any backend is contacted.** Empty plans,
   duplicate names, capped passwords exceeding their cap, mock backends
   in production plans — all rejected at `Plan::validate()`.
7. **Idempotent.** Existing secrets are skipped unless `--rotate <name>`.
   `RotationPolicy::Never` secrets refuse to rotate.

## What NOT to do

- Don't add `println!` or `eprintln!` of any value, ever. `format!()`
  on a `Zeroizing` is also forbidden — the resulting `String` is not
  zeroized.
- Don't bypass `cofre-types::Plan::validate()`. If a constraint is
  missing, add it to the validator, don't paper over it at apply time.
- Don't shell out to `akeyless` or `sops` CLIs in any new path. The
  two backend impls already there are the only blessed shell-outs.
- Don't store auth tokens in cofre-types. Auth is the bin's concern;
  the typescape stays oblivious.
- Don't add a backend that requires the operator to type a secret on
  the command line. cofre's whole reason for existing is to make that
  unnecessary.

## Companion typescapes

- `pleme-io/arch-synthesizer/src/cofre_bridge.rs` — emits
  `SecretMaterializationPlan` from any typescape that carries
  `cofre_types::SecretRef`s. First user: `RemoteAccessHostDecl`.

## Tests

```
crates/cofre-types  →  28 tests (validators, round-trip, materialization targets)
crates/cofre        →  11 tests (generation, mock backend, YAML helpers)
                       39 tests total, all sandboxed (no network, no fs writes)
```

Backend-specific integration tests (real SOPS, real Akeyless) are NOT
in the test suite — they require external state and are documented in
`docs/security-model.md` as the per-release manual smoke test.
