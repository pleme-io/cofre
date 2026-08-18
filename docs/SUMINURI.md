# suminuri (墨塗り) — sops, naturalized

**墨塗り** — *sumi* (墨, ink) + *nuri* (塗り, painting over). The Japanese word for a
redacted document: the page stays readable, the values are blacked out in place.
That is what a sops file is, and it is the one thing that distinguishes the format
from encrypting a file as a blob — the keys, the shape and the diff all survive.

Three crates in the `cofre` workspace:

| crate | owns |
|---|---|
| `suminuri-wire` | the bytes on disk — the `ENC[]` envelope, 32-byte-nonce GCM, the AAD, the MAC, the metadata invariant. No I/O, no clock. |
| `suminuri-yaml` | an ordered tree and a go-yaml-v3-**byte-compatible** emitter |
| `suminuri` | the `Environment` seam, age keys, `.sops.yaml`, the walk, and a CLI aliasable as `sops` |

The measured format spec is [`WIRE-FORMAT.md`](./WIRE-FORMAT.md). This document is
about what was *built*, what it is *worth*, and what is honestly **not done**.

---

## Rebuilt, not wrapped

`cofre`'s existing `SopsBackend` drives the real `sops` binary through an
`EDITOR=<self>` hijack. That is a wrap — sops's implementation kept behind a typed
border. suminuri is the other thing: the capability re-derived as native substrate,
with sops's *implementation* gone and its *wire format* honoured exactly.

The wire is honoured on purpose, not conceded. It is the magma posture — speak the
wire, own the executor — and here it is also the **migration mechanism**: because
every other consumer still reads our bytes, each front can flip independently and
upstream stays one env var away as a rollback.

The one thing consumed rather than rebuilt is the `age` crate. age is a wire format
five tools must agree on byte-for-byte; re-deriving X25519 + HKDF +
ChaCha20-Poly1305 + bech32 + the armor framing would buy nothing and risk an
incompatibility that only shows up on someone else's file.

---

## What the substrate can now do that it could not

Four things, and none of them is "we have another sops":

1. **A YAML layer that preserves comments, order and scalar style.** The fleet had
   none — every Rust consumer reaches for `serde_yaml`, whose `Value` has seven
   variants and no way to hold a comment. This one is a byte-exact go-yaml emitter,
   usable by anything that needs to rewrite a YAML file without reflowing it.
2. **A live defect fixed.** `cofre/crates/cofre/src/backends.rs` round-trips through
   `serde_yaml::from_str → to_string → fs::write`, which **silently strips every
   comment** from any SOPS file `cofre apply` touches. suminuri-yaml is the fix.
3. **The EDITOR-hijack shape retired.** Three repos independently ported the same
   `EDITOR=<self> <hook>` trick — because `sops set` takes its value as argv with
   no stdin form — two of them dragging in `jq` or `yq` as a second foreign binary.
   Three independent derivations of one shape is the extract signal, and a native
   library call retires all three.
4. **A declared-vs-actual recipient gap that cannot be emitted.** See below.

---

## The illegal states that have no code path

Named first, then removed.

1. **A 12-byte nonce.** `Iv` is `[u8; 32]` and the only constructor for a write;
   there is no length-taking form.
2. **An AAD built by hand.** `Aad` has no `From<String>`; only `AadPath::aad()`,
   which always appends the trailing colon and has no index-taking push, so
   sequence indices structurally cannot enter the AAD.
3. **A tree used without a MAC check.** Decryption yields `Unverified<T>` whose
   only safe exit is `verify()`. A **zero-leaf** verification is refused as vacuous
   — the empty digest matches another empty digest, so a walker that silently
   stopped finding leaves would otherwise verify green while checking nothing.
4. **A non-constant-time MAC or plaintext comparison.** Both inner values are
   private and both `PartialEq` impls route through `subtle`.
5. **Declared recipients that disagree with the ciphertext.** `Metadata`'s key
   arrays are *derived* from the `WrappedKey` set, and a `WrappedKey` cannot exist
   without its wrapped bytes. This is not hypothetical: `nix/.sops.yaml` declared an
   admin-recovery co-recipient for `users/gabi/secrets.yaml` on 2026-07-24 that was
   never in the ciphertext, and it stayed wrong for two weeks. `rewrap` also refuses
   an empty set, because a file no one can decrypt is the one unrecoverable outcome.
6. **A silently-ignored flag.** Every flag and verb sops has is enumerated; the ones
   this build cannot honour exit non-zero **naming themselves, before the file is
   read**. A dropped `--shamir-secret-sharing-threshold` would write a file with the
   wrong protection and report success.
7. **A dropped recipient on a provider we cannot serve.** A KMS or PGP key
   round-trips intact even though we cannot unwrap it. Dropping it on write would
   silently remove someone's access.

---

## Evidence

Self-consistency proves nothing on its own. The load-bearing tests are the ones
that ask the *other* implementation.

| gate | what it compares | result |
|---|---|---|
| `byte_parity` | 7 fixtures **written by sops v3.12.1**, re-emitted by us | byte-identical; includes an anti-vacuity denominator and a test that `--indent` is load-bearing |
| `live_parity` | operator-named real files, re-emitted | 3 files, 601 lines, 324 leaves — byte-identical, one of them written by sops **3.13.3** |
| `sops_differential` | both binaries over a 8-file corpus, both directions | 9 tests: 24 byte-comparisons + rotate ×2, extract, selector, the EDITOR-hijack exit codes, the YAML-1.1-bool non-round-trip, and a refusal — green |
| `sops -d` on real fleet files | rendering parity | `secrets.yaml` 1381 lines and `users/drzzln/secrets.yaml` 93 lines — **byte-identical** |
| whole workspace | 288 tests (wire 64 · yaml 50 · suminuri 110 · cofre's own 64) | green, repeated full-parallel runs |

Counts measured 2026-08-18. They are stated because a suite that quietly loses
cases still reports "ok" — the same anti-vacuity reason every gate here carries its
own denominator.

Both differential tests print their own denominator and say **"this is a SKIP, not
a pass"** when no oracle is available; `SUMINURI_DIFFERENTIAL_REQUIRE=1` and
`SUMINURI_PARITY_REQUIRE=1` turn a skip into a failure.

### The gate's own red runs

A differential that has never been *seen to fail* is a claim about a test, not about
the code. Two **independent** subsystems were deliberately broken and the gate named
each precisely; both were reverted and neither was committed.

| break | went red | the report |
|---|---|---|
| `'g'` exponent threshold reverted to the digit count | `both_binaries_render_a_decrypt_identically`, `real_sops_ciphertext_is_readable_by_us` | `bigfloat: want client_id: 6.088634523481149e+11 / got 608863452348.1149` |
| libyaml's `PLAIN → SINGLE` rung demoted straight to double quotes | the same two | `want hash: 'has # hash' / got hash: "has # hash"`, and the same for `colon:` and `lead_space:` |

Two different subsystems matter: a gate sensitive to only one mechanism would pass a
regression in the other, which is exactly how the six bugs below survived every
synthetic fixture.

### Six bugs the evidence caught that no amount of reading would have

Recorded because each one was invisible until a *different* implementation
disagreed:

| bug | found by |
|---|---|
| a multi-line string must be a **literal block**, not a quoted scalar | a 420-char SSH key in the operator's own file |
| libyaml's ladder has a **`PLAIN → SINGLE`** rung; conflating type-resolution with structural safety skips it | a 3179-char bootstrap script, 8 lines and ~324 chars of escaping |
| a decrypted float renders with **`'g'`**, while the ciphertext holds `'f'` | one `client_id`, 17 characters against 21 |
| Go's `'g'` threshold is a **constant 6**, not the digit count | the same `client_id`, still wrong after the first fix |
| `y`/`yes`/`on` are **strings** in yaml.v3, not bools | the differential corpus; a plaintext `y` was becoming `true` |
| `--extract` of a scalar has **no trailing newline** | the differential |

Plus one caught by review rather than by a test: the IV stash was keyed on plaintext
*bytes*, where Go keys on the typed value — collapsing `1`/`"1"` and `true`/`"True"`
so two list elements could share a nonce.

---

## Tier ledger

Tiers are `selo`'s closed vocabulary. A row grading `only-mitigated` **names its
ceiling**, because that is exactly where "we replaced sops" gets rounded up from
"we compose some primitives".

<!-- tier-ledger -->

| sops capability | suminuri realization | tier |
|---|---|---|
| a 12-byte GCM nonce on write | NET-NEW: `Iv` is `[u8; 32]`; no length-taking constructor exists | truly-unrep |
| an AAD with sequence indices, or without the trailing colon | NET-NEW: `Aad` has no public ctor; `AadPath` has no index push | truly-unrep |
| using a decrypted tree whose MAC was never checked | NET-NEW: `Unverified<T>`, whose only safe exit is `verify()` | truly-unrep *for the accidental case*; `into_inner_ignoring_mac` is a named escape — only-mitigated (C1: Rust cannot forbid a caller choosing a named call) |
| a vacuous MAC verification over zero leaves | NET-NEW: `verify()` refuses; the denominator is carried in the value | truly-unrep |
| a non-constant-time MAC / plaintext compare | NET-NEW: private inner, `subtle`-backed `PartialEq` | truly-unrep |
| declared recipients that outrun the ciphertext | NET-NEW: metadata key arrays derived from `WrappedKey`s | truly-unrep *for an emitted file*; policing `.sops.yaml` against a file is a reconciler's job — only-mitigated (C2: needs external observation) |
| a rekey to an empty recipient set | NET-NEW: `rewrap` refuses | truly-unrep |
| a silently-ignored unsupported flag | NET-NEW: closed flag catalog, refusal before the file is read | parse-time-rejected |
| a dropped recipient for a provider we cannot unwrap | NET-NEW: opaque `WrappedKey` round-trip | parse-time-rejected |
| a YAML document whose comments would be silently stripped | NET-NEW: refused with its line number | parse-time-rejected |
| an invalid selector regex silently matching nothing | NET-NEW: compiled once, refused at load | parse-time-rejected |
| a self-defeating `encrypted_comment_regex` | NET-NEW: refused, as upstream does | parse-time-rejected |
| encrypting with no recipients at all | NET-NEW: refused | parse-time-rejected |
| the `ENC[]` envelope, MAC, AAD, selectors | NET-NEW typed border, differential-gated both directions | only-mitigated (C3: a differential over a finite corpus; no proof over all inputs) |
| go-yaml byte-exact emission | NET-NEW emitter, gated against sops-written fixtures + 3 real files | only-mitigated (C3: same ceiling — 10 files, not all YAML) |
| age wrap/unwrap | SHIPPED-composition: the `age` crate behind our own identity discovery | only-mitigated (C3: the wire is a third party's) |
| PGP / AWS KMS / GCP KMS / HuaweiCloud KMS / Azure KV / Vault transit | **NOT IMPLEMENTED** — named refusal; keys round-trip | only-mitigated (C6: a refusal, not a capability) |
| key groups + Shamir | **NOT IMPLEMENTED** — refused rather than rewritten without them | only-mitigated (C6) |
| `set` / `unset` / `groups` / `exec-env` / `exec-file` / `publish` / `keyservice` / `completion` | **NOT IMPLEMENTED** — refused by name | only-mitigated (C6) |
| json / dotenv / ini / binary stores | **NOT IMPLEMENTED** — YAML only | only-mitigated (C6) |
| comment round-trip | **NOT IMPLEMENTED** — refused, never silently dropped | only-mitigated (C6) |
| plaintext never touching a disk during `edit` | 0600 in a 0700 dir, removed after | only-mitigated (C4: darwin has no per-user tmpfs to prefer; plaintext does briefly reach a disk) |
| Front 1 — PATH-resolved `exec` (21 sites) | overlay + alias | **DESIGN** — not wired |
| Front 2 — store-path/token sites (9) | same overlay | **DESIGN** — not wired |
| Front 3 — `sops-install-secrets` (337 declarations × 18 nodes) | drop-in at sops-nix's existing `sops.package` seam | **DESIGN** — the seam is measured and plumbed; the replacement binary is not written |
| Front 4 — Flux `kustomize-controller` (9 Kustomizations, 7 clusters) | **no alias reaches it**; retirement is removing `decryption.provider: sops` | **NOT REACHABLE** — a fleet-architecture decision |

**"Replaced" today means: nothing.** The parity is proven and the binary works; no
fleet consumer has been pointed at it. That is the honest state, and the ledger says
so rather than implying a cutover that has not happened.

---

## The cutover, specified rather than performed

Every step below is reversible, and the order is chosen so the operator's own
secret plane can never be left without a working decryptor. A broken secrets path
means no rebuild, no private-flake-input auth, and no cluster access.

**Prerequisite, unconditional: upstream sops stays built and pinned forever, as
`pkgs.sops-upstream`.** It is the differential's denominator — the only independent
check on the parity claim — and deleting it would destroy the evidence, exactly as
keeping the zoekt shards preserved the evidence for that sunset. ★★ MODULARIZE,
DON'T DELETE applies to the *dependency*, not only to our own code.

| step | change | done-predicate | rollback |
|---|---|---|---|
| C0 | add `cofre` as a flake input; build `suminuri` | `nix build .#suminuri` green; `nix eval .#kataFleetGate` unchanged | drop the input |
| C1 | `pleme.suminuri.enable = false` module, declaring the overlay and the seam but flipping nothing | the module evaluates on every node with no store-path change | delete the import |
| C2 | flip **Front 1 only** — the overlay puts `suminuri` on PATH as `sops` | `sops --version` names suminuri; `nix run .#sops-edit` round-trips a real file; every one of the 21 sites still works | one field |
| C3 | flip **Front 3, HM plane only** — `sops.package` on the user agent | that plane's generation advances; its 62 secrets + 9 templates materialize; the *system* plane is untouched and still on upstream | one field |
| C4 | flip Front 3's system plane | both planes on suminuri; `/run/secrets.d` correct | one field per plane |
| C5 | Front 4 — migrate the 9 Kustomizations off `decryption.provider: sops` | `rg '^\s*provider:\s*sops' k8s/` == 0 | git revert |

Two prerequisites for C3 that are easy to miss, both measured: `sops.gnupg.sshKeyPaths`
defaults to importing an RSA→OpenPGP key and `sops.age.sshKeyPaths` to an
ed25519→age conversion, and **both run on every darwin activation by default** even
though no fleet file carries a PGP key group. Either they ship first, or the
operator sets `sops.gnupg.sshKeyPaths = []` — which deletes the hardest crypto
prerequisite from the critical path. And darwin's **two planes are independent**; a
gate should forbid more than one arm moving per generation, so a half-cutover is
visible rather than silent.

C2 is safe to take today. C3 is not yet buildable — the drop-in binary is design.

---

## Known scope, stated plainly

- **YAML only.** json / dotenv / ini / binary are refused by name.
- **age only.** Every other provider is a named refusal, and its keys survive a
  round-trip.
- **No comment round-trip.** A commented file is refused, never mangled. All three
  encrypted files in the operator's nix repo carry zero comments, so this costs
  nothing today — and `.sops.yaml`, which is *full* of comments, is read-only and
  therefore handled by stripping rather than by refusing.
- **Single-document files only.** A multi-document stream is refused with a count.
- **No anchors, aliases or explicit tags.** sops's own tree model cannot represent
  them either.
- **The differential is a finite corpus.** Ten files and eight cases is evidence,
  not proof. The honest tier for every parity row is `only-mitigated (C3)`.
