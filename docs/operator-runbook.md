# Operator Runbook

End-to-end: typescape change → committed → flake-locked → applied to a host.
Specialized for the canonical first use case (ryn's two remote-access
passwords); the same sequence applies to any future cofre-managed secret.

## Mental model

cofre splits cleanly into two halves with **independent commit cycles**:

```
─────────────── PHASE A: GENERATE ─────────────  ── PHASE B: CONSUME ──
                                                                       
typescape change → cofre plan/apply →  Akeyless    nix flake update
                  (no flake involved)              + nix run .#rebuild
                                                   (ryn reads from
                                                    akeyless-nix)
```

You can do A without B (secrets exist in Akeyless, ryn doesn't see them
yet), and you can do B without A (config-only changes; ryn sees old
secrets). Most onboardings do A → B in sequence.

## Repos involved (and what's in each)

| Repo | What changed | Visibility |
|------|--------------|------------|
| `pleme-io/cofre`              | New: lib + bin + flake | Public (open-source) |
| `pleme-io/arch-synthesizer`   | + cofre-types dep, `cofre_bridge.rs`, render bin emits `cofre.yaml` | Private |
| `pleme-io/blackmatter-remote-access` | Schema updated to BackendKind shape | Private |
| `pleme-io/nix`                | Flake input + ryn imports + rendered modules | Private (this operator only) |
| `pleme-io/blackmatter-pleme`  | New skill `cofre`, org-level CLAUDE.md `★ cofre` section | Private |

## Phase A — Generate the two secrets in Akeyless

This is the part you actually want to run **right now**. No flake update,
no commit, no push — just generate.

### 0. Confirm prerequisites

```bash
# Akeyless creds in env (rendered by sops-nix on the operator's box):
test -n "$AKEYLESS_ACCESS_ID" || \
  export AKEYLESS_ACCESS_ID=$(cat ~/.config/akeyless/access-id)
test -n "$AKEYLESS_ACCESS_KEY" || \
  export AKEYLESS_ACCESS_KEY=$(cat ~/.config/akeyless/access-key)

# Sanity:
echo "AKEYLESS_ACCESS_ID=$AKEYLESS_ACCESS_ID"   # safe — it's a public ID
echo "AKEYLESS_ACCESS_KEY=$(echo $AKEYLESS_ACCESS_KEY | head -c 4)..."  # truncated
```

### 1. Confirm the typescape is fresh

```bash
cd ~/code/github/pleme-io/arch-synthesizer
cargo test --lib remote_access:: cofre_bridge:: 2>&1 | grep "test result"
# expected: test result: ok. 31 passed; ...
#           test result: ok. 10 passed; ...
```

### 2. Render the manifest (idempotent, byte-stable)

```bash
cd ~/code/github/pleme-io/arch-synthesizer
cargo run --bin render_remote_access -- ryn \
  ~/code/github/pleme-io/nix/modules/remote-access
# wrote remote-access.yaml, default.nix, RUNBOOK.md, cofre.yaml
```

### 3. Plan-time inspection (no backends contacted)

```bash
cd ~/code/github/pleme-io/cofre
cargo run --bin cofre -- plan \
  --manifest ~/code/github/pleme-io/nix/modules/remote-access/ryn/cofre.yaml
```

Expected output: two secrets listed, one capped at 16 (VNC), one
unlimited 24 (RustDesk). No values printed.

### 4. Apply (materialize against Akeyless)

```bash
cargo run --bin cofre -- apply \
  --manifest ~/code/github/pleme-io/nix/modules/remote-access/ryn/cofre.yaml
# expected: "wrote: 2 | skipped: 0 | errored: 0"
```

The two secrets now exist in Akeyless at:
- `/pleme-io/ryn/remote-access/vnc-password`
- `/pleme-io/ryn/remote-access/rustdesk-password`

You did not see, nor will ever see, either value. By design.

### 5. Verify

```bash
cargo run --bin cofre -- verify \
  --manifest ~/code/github/pleme-io/nix/modules/remote-access/ryn/cofre.yaml
# expected:
#   ✓ ryn-vnc-password (present)
#   ✓ ryn-rustdesk-password (present)
#   present: 2 | missing: 0
```

Phase A done.

## Phase B — Wire ryn to consume them

This is what makes the two secrets actually flow into Apple Screen
Sharing + RustDesk on ryn at activation. It's a separate set of changes
that need to land in nix/ alongside what's already there.

### B1 — Declare the secrets to akeyless-nix on ryn

The rendered `nix/modules/remote-access/ryn/default.nix` references:

```nix
config.akeyless.secrets."pleme-io/ryn/remote-access/vnc-password".path
config.akeyless.secrets."pleme-io/ryn/remote-access/rustdesk-password".path
```

Those references resolve only if akeyless-nix is told to fetch them.
Add to `nix/nodes/ryn/default.nix` (or wherever ryn already declares
akeyless secrets):

```nix
blackmatter.components.secrets.secrets = {
  "pleme-io/ryn/remote-access/vnc-password" = {
    backend = "akeyless";
  };
  "pleme-io/ryn/remote-access/rustdesk-password" = {
    backend = "akeyless";
  };
};
```

(Exact attribute shape depends on whether ryn uses
`blackmatter.components.secrets` or raw `akeyless.secrets` — match
whichever pattern its existing secrets follow. Check
`nix/nodes/ryn/secrets.nix` if it exists, or grep for
`akeyless.secrets` in the ryn config tree.)

### B2a — Create the GitHub repos via IaC (NEVER `gh repo create`)

The pleme-io org has a single Terraform-managed catalog at
`pangea-architectures/workspaces/pleme-io-opensource/org.yaml`. Adding
a new repo means appending a YAML entry, planning, applying. The skill
[`pleme-io-github-posture`](../../blackmatter-pleme/skills/pleme-io-github-posture/SKILL.md)
is canonical.

The two new entries (`cofre` public, `blackmatter-remote-access` private)
are already appended in this PR. To realize them:

```bash
cd ~/code/github/pleme-io/pangea-architectures

# Dry run — confirms the two new github_repository resources will be
# created and that org.yaml parses cleanly.
nix run .#plan-pleme-io-opensource

# Actual creation — terraform apply against the pleme-io GitHub org.
# Creates: github.com/pleme-io/cofre (public, MIT, branch_protection: standard)
#         github.com/pleme-io/blackmatter-remote-access (private, NOASSERTION)
nix run .#deploy-pleme-io-opensource
```

If you also want the `repos.lisp` (filesystem) catalog to know about
cofre (already done in this PR; blackmatter-remote-access is skipped
since blackmatter-* repos commonly aren't in repos.lisp), no separate
deploy is needed — `repo-forge migrate` is the consumer and runs only
when you ask it to.

### B2b — Commit + push the code (per repo, in dependency order)

Once the empty repos exist on GitHub, push code in dependency order so
downstream `flake.lock` references resolve:

```bash
# 1. cofre (open-source — push first, it has no pleme-io deps except akeyless-api)
cd ~/code/github/pleme-io/cofre
git init -b main && git add -A
git -c commit.gpgsign=false commit -m "Initial commit: typed secret materialization (lib + bin)"
git remote add origin git@github.com:pleme-io/cofre.git
git push -u origin main

# 2. blackmatter-remote-access (private — schema-only, no path deps)
cd ~/code/github/pleme-io/blackmatter-remote-access
git init -b main && git add -A
git -c commit.gpgsign=false commit -m "Initial commit: three-tier remote-access posture (darwin + NixOS)"
git remote add origin git@github.com:pleme-io/blackmatter-remote-access.git
git push -u origin main

# 3. arch-synthesizer (already pushed; commits cofre-types adoption + cofre_bridge)
cd ~/code/github/pleme-io/arch-synthesizer
git add Cargo.toml src/remote_access.rs src/cofre_bridge.rs \
        src/bin/render_remote_access.rs src/lib.rs CLAUDE.md
git -c commit.gpgsign=false commit -m "remote_access: adopt cofre-types; add cofre_bridge morphism"
git push

# 4. blackmatter-pleme (skill + org doc)
cd ~/code/github/pleme-io/blackmatter-pleme
git add skills/cofre/SKILL.md docs/pleme-io-CLAUDE.md
git -c commit.gpgsign=false commit -m "skills: cofre — operational guide for typed secret materialization"
git push

# 5. nix (the operator's private fleet repo) — last, depends on flake.lock pointing at github
cd ~/code/github/pleme-io/nix
git add flake.nix nodes/ryn/default.nix modules/remote-access/
git -c commit.gpgsign=false commit -m "ryn: wire blackmatter-remote-access; render cofre + remote-access modules"
# git push deferred until B3 lands flake.lock updates.

# 6. repo-forge (catalog entry for cofre)
cd ~/code/github/pleme-io/repo-forge
git add repos.lisp
git -c commit.gpgsign=false commit -m "repos.lisp: register cofre (rust-workspace-tool, public)"
git push

# 7. pangea-architectures (org.yaml — but only after B2a deploy succeeded)
cd ~/code/github/pleme-io/pangea-architectures
git add workspaces/pleme-io-opensource/org.yaml
git -c commit.gpgsign=false commit -m "pleme-io-opensource: register cofre + blackmatter-remote-access"
git push
```

### B3 — Flip flake inputs from `path:` to `github:` (after B2)

Once `pleme-io/cofre` and `pleme-io/blackmatter-remote-access` exist on
GitHub, swap the `nix/flake.nix` input:

```diff
 blackmatter-remote-access = {
-  url = "path:/Users/luis.d/code/github/pleme-io/blackmatter-remote-access";
+  url = "github:pleme-io/blackmatter-remote-access";
   inputs.nixpkgs.follows = "nixpkgs";
 };
```

Then update the lock + apply:

```bash
cd ~/code/github/pleme-io/nix
nix flake update --update-input blackmatter-remote-access
nix run .#rebuild
```

For the operator running on ryn directly, `nix run .#rebuild` evaluates
the local flake, fetches the flake input commits, and applies. The
activation hooks then read from `config.akeyless.secrets.<name>.path`
and configure Apple Screen Sharing + RustDesk with the values cofre put
into Akeyless during Phase A.

### B4 — Confirm on ryn

```bash
# Apple Screen Sharing — connect from cid:
open vnc://ryn

# RustDesk — launch the client on cid, ID = ryn's tailnet IP, password
# from the operator's password manager (NOT from cofre — operator has
# never seen it; instead they read it from Akeyless on demand via:
akeyless get-secret-value -n /pleme-io/ryn/remote-access/rustdesk-password
# Output is a one-shot read into the operator's clipboard or terminal,
# bypassed only when needed for an interactive session.

# Tailscale SSH (always on as the floor):
tailscale ssh ryn
```

## Rotation cadence

Both ryn passwords are `RotationPolicy::Quarterly` (90-day window).
When `cofre plan` flags one as overdue:

```bash
cd ~/code/github/pleme-io/cofre
cargo run --bin cofre -- apply \
  --manifest ~/code/github/pleme-io/nix/modules/remote-access/ryn/cofre.yaml \
  --rotate ryn-vnc-password
cd ~/code/github/pleme-io/nix
nix run .#rebuild  # picks up new value at activation
```

The new value lives in Akeyless until the next rebuild reads it. Don't
skip the rebuild — Apple Screen Sharing keeps the old password active
until activation rewrites VNCSettings.txt.

## Failure modes

| Symptom | Likely cause |
|---------|--------------|
| `cofre apply` exits 5 with `akeyless auth: ...` | `AKEYLESS_ACCESS_ID` / `AKEYLESS_ACCESS_KEY` unset or invalid. |
| `cofre verify` shows `× ... (missing)` after a successful apply | Looking at the wrong tenant — confirm `AKEYLESS_GATEWAY_URL`. |
| Activation script complains about missing secret file | B1 not done — akeyless-nix isn't fetching the secret. |
| Apple Screen Sharing rejects the password | VNC 16-char cap was bypassed somehow — check the typed `max_length: Some(16)` is still on the policy. |
| `nix flake update` fails with "no such ref" | Repos not yet pushed; either push them or keep `path:` ref for solo operation. |

## Safety properties to remember

- The operator never sees plaintext. The runbook never asks them to type one.
- Re-running `cofre apply` is a no-op for present secrets (idempotent).
- `--rotate` is the only way to overwrite. `RotationPolicy::Never`
  refuses even that.
- If you uncertain whether a secret was successfully written, run
  `cofre verify` — it never touches the value.
