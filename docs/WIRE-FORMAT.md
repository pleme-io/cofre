# The sops wire format — measured, not recalled

Every claim here was read out of the sops v3 Go source, or measured by running a
binary. Nothing is described from memory. Where a fact was learned by a *failure*,
the failure is recorded next to it, because the failure is the reason the fact is
worth writing down.

**Sources.** The sops v3 tree and `go.yaml.in/yaml/v3` as vendored inside sops-nix's
`sops-install-secrets` go-modules derivation; `sops --help` from the installed
v3.12.1 binary; Go 1.25.10's `strconv` for the float formats; and three probes run
against the operator's own live files. Measured **2026-08-18**.

---

## 0. Why this document exists

The format is small and almost every rule in it is *invisible to a wrong
implementation*. A 32-byte nonce where everything else in the world uses 12; a
MAC that is a bare SHA-512 and not an HMAC; a float with two different spellings
depending on which side of the cipher it is on. Each of those compiles, runs, and
produces a file that either nothing can open or that differs from sops's by a
handful of bytes — and a handful of bytes is the whole game for a format whose
purpose is a reviewable git diff.

So this is a spec written against the failures, not against the happy path.

---

## 1. Proof that the spec is right

| probe | claim | result |
|---|---|---|
| pure-Rust decrypt | the envelope, the AAD, the MAC | `nix/secrets.yaml` **272 leaves, 0 failures, MAC MATCH**; `users/drzzln/secrets.yaml` **47 leaves, MAC MATCH**; `users/gabi/secrets.yaml` **correctly refused** (not a recipient) |
| emitter re-emit | go-yaml byte parity | all three real files **byte-identical** (601 lines, 324 encrypted leaves), including one written by sops **3.13.3** |
| `sops -d` differential | rendering parity | `secrets.yaml` (1381 lines) and `users/drzzln/secrets.yaml` (93 lines) decrypt **byte-identically** between the two binaries |
| in-tree differential | both directions | 8 cases × 3 comparisons, plus rotate/extract/selector/refusal, green |

The negative controls are what make the positives mean anything: the one file whose
data key is not ours is *refused*, and a file encrypted to a stranger is refused by
both binaries with no plaintext printed.

---

## 2. Leaf value encoding

```
ENC[AES256_GCM,data:<b64std>,iv:<b64std>,tag:<b64std>,type:<t>]
```

`aes/cipher.go`'s regex is anchored **only at the start**, so trailing bytes after
the `]` are ignored rather than rejected.

- **base64 is `StdEncoding`** — padded, `+/`, not URL-safe.
- **The nonce is 32 bytes.** `const nonceSize int = 32`, used via
  `cipher.NewGCMWithNonceSize(aescipher, 32)`. This is the single most dangerous
  detail in the format: every mainstream AES-GCM API defaults to 96 bits, so the
  wrong choice is a compile error nowhere and an opaque authentication failure
  everywhere. GCM with a non-96-bit nonce derives its counter block by GHASH-ing
  the nonce, a different code path in every implementation. **On decrypt sops uses
  `len(iv)`, not the constant** — so a file carrying some other length still opens,
  and that asymmetry is deliberate.
- **The tag is the trailing 16 bytes** of Go's `gcm.Seal` output (`cryptoaes.BlockSize`);
  `data` is everything before it.
- **Empty is a fixed point in both directions.** `isEmpty` short-circuits encrypt
  *and* decrypt, so an empty string stays the empty string rather than becoming a
  zero-length ciphertext.

### The `type:` tag, and the two spellings of a value

| tag | the `ENC[]` plaintext (also the MAC bytes) | the decrypted YAML |
|---|---|---|
| `str` | the raw UTF-8 bytes | plain / single / double / literal, by §6's ladder |
| `int` | `strconv.Itoa` | the same digits |
| `float` | `FormatFloat(v, 'f', -1, 64)` — **never** an exponent | `FormatFloat(v, 'g', -1, 64)` — **exponent when short** |
| `bool` | **`True` / `False`** (Python titlecase) | **`true` / `false`** (Go's bool) |
| `time` | `time.Time.MarshalText()` | the same text, unquoted |
| `comment` | the body **without** the leading `#` | a comment line |
| `bytes` | the raw bytes | — |

**Two rows have different spellings on the two sides, and that is not a bug.** sops
hashes and stores `True` because the original Python implementation did, then hands
Go a `bool`, which go-yaml writes as `true`. Likewise a float is stored positionally
and *rendered* with `'g'`. An implementation that uses one spelling for both
produces a file that either fails its own MAC or decrypts to the wrong text. Both
rows were found by decrypting the operator's real `secrets.yaml` with two binaries
and diffing — a `client_id` of `608863452348.1149` stores as those digits and
decrypts as `6.088634523481149e+11`.

`type:bytes` is **decrypt-only**: `Cipher.Encrypt` has no `[]byte` arm, so sops
itself never writes one. Only Python-era files carry it.

### `'g'` versus `'f'`, exactly

Go's `'g'` uses exponent form when the decimal exponent is **below −4 or at least
6**. Six is a literal constant, not a function of the value — `ftoa.go` sets
`eprec = 6` unconditionally when the precision is "shortest", with the comment
*"if precision was the shortest possible, use precision 6 for this decision"*.
Measured against Go 1.25.10:

```
999999            g:999999                f:999999                (exp 5)
1234567           g:1.234567e+06          f:1234567               (exp 6)
0.0001            g:0.0001                f:0.0001                (exp -4)
0.00001           g:1e-05                 f:0.00001               (exp -5)
608863452348.1149 g:6.088634523481149e+11 f:608863452348.1149     (exp 11)
1e21              g:1e+21                 f:1000000000000000000000
```

The exponent is always signed and at least two digits. Two traps in implementing
this: computing the mantissa as `v / 10^exp` is inexact and loses the last digit
(it produced `…481148e+11` for `…481149e+11`), and `log10(1e-5).floor()` is `-6`,
so deriving the exponent arithmetically flips the branch. Take both from a
shortest-round-trip scientific rendering instead.

### The AAD is a path, and its construction is exact

```go
pathString := strings.Join(path, ":") + ":"
```

- Components are the **string mapping keys only**, joined by `:`, with a
  **trailing `:`**. A leaf at `a.b.c` gets `"a:b:c:"`.
- **Sequence indices are not in the path.** `walkSlice` recurses with `path`
  unchanged, so every element of a list authenticates under its parent key. An
  implementation that helpfully appends `[i]` writes files sops cannot open, and
  the failure surfaces as an opaque GCM error.
- At depth 0 the AAD is a bare `":"` — Go's `Join` over an empty slice is `""`,
  plus the trailing colon. Not a degenerate case: a **top-level comment** has an
  empty path, because `walkBranch` passes `item.Key` to `walkValue` without
  pushing. A `push(c); push(':')` loop gets this wrong; a join-then-append does not.
- Keys are joined unescaped, so `{"a:b": {"c": v}}` and `{"a": {"b:c": v}}`
  collide. Upstream ambiguity, reproduced.

### IV reuse is deliberate, and its key includes the type

`Cipher` carries `stash: map[stashKey][]byte` keyed on
`stashKey{plaintext interface{}, additionalData string}`, written **only by
`Decrypt`**. On encrypt, a hit reproduces the previous ciphertext byte for byte —
which is what makes `sops edit` produce a small diff instead of rewriting every
line. Without it the format's entire reason for existing is gone.

**A Go map compares an `interface{}` by dynamic type *and* value**, so `int(1)` and
`string("1")` are distinct keys. Keying on the plaintext *bytes* instead collapses
`1`/`1.0`/`"1"` and `true`/`"True"`, and two such leaves in one list — which share
an AAD, since a sequence adds no component — would then be handed the same nonce.
The plaintexts are equal so this is not the catastrophic form of GCM misuse; the
consequence is a file whose bytes differ from sops's.

Consequence to accept knowingly: two genuinely identical typed values at one path
do share a nonce. That reveals only that they are equal, which any deterministic
encryption concedes.

Two more facts from the same source: on a **fresh** encrypt there is nothing
stashed, so two identical list elements get *different* nonces — verified by
running sops on `items: [same, same]`. And the `mac` field goes through the *same*
`Cipher`, so decrypting it populates the stash and a same-timestamp re-encrypt
reproduces the `mac:` line too.

---

## 3. The MAC

**A bare SHA-512, not an HMAC.** `sops.go` imports `crypto/sha512` and calls
`sha512.New()`; there is no key in the construction.

```
digest   = SHA512( [sha256("sops") if mac_only_encrypted] || ToBytes(leaf₀) || … )
sops.mac = ENC[…,type:str] of UPPERCASE_HEX(digest), AAD = RFC3339(lastmodified)
```

- Leaves are fed in **tree-walk order**, which is why key order is part of the
  file's integrity and why the tree model cannot round-trip through a hash map.
- **Comments never contribute** — `if !ok` guards the `hash.Write` in both walkers,
  even when the comment itself is encrypted.
- `mac_only_encrypted` pre-seeds with `sha256(b"sops")` =
  `8a3fd2ad54ce66527b1034f3d147be0b0b975b3bf44f72c6fdadec8176f27d69`, and only
  leaves that end up encrypted are hashed. The seed exists so the two policies can
  never produce the same digest.
- The concatenation is unseparated, so `["ab"]` and `["a","b"]` collide. Upstream;
  reproduced.
- Output is `fmt.Sprintf("%X", …)` — **128 uppercase hex chars**.
- The `sops:` key is never walked, which is what lets the MAC field live inside the
  structure it covers.

The integrity comes from the second step: only a holder of the data key can produce
a `mac` field that opens, and its AAD binds the file to its own `lastmodified` — so
hand-editing that timestamp invalidates the file. Verification is
`fileMac != computedMac`, a **plain Go string compare**; using a constant-time
comparison instead is a strict improvement with an identical verdict.

**Order matters when writing:** stamp `lastmodified` *then* seal the MAC against
it. Reversed, the MAC field cannot be opened.

---

## 4. Which leaves get encrypted

`shouldBeEncrypted` runs six stages in a fixed order, **each overwriting the last**
— not independent filters that could be `&&`-ed or reordered. Two of them
(`encrypted_suffix`, `encrypted_regex`) begin by resetting the verdict to `false`,
so a later stage can un-exempt what an earlier one exempted.

| # | field | effect |
|---|---|---|
| 1 | `unencrypted_suffix` | any **path component** ending with it → `false` |
| 2 | `encrypted_suffix` | reset to `false`, then any component ending with it → `true` |
| 3 | `unencrypted_regex` | any component matching → `false` |
| 4 | `encrypted_regex` | reset to `false`, then any component matching → `true` |
| 5 | `unencrypted_comment_regex` | any active comment matching → `false` |
| 6 | `encrypted_comment_regex` | reset to `false`, then any matching → `true`, **skipping the innermost comment set's last line when the leaf is itself a comment** |

- The tests run against **every component of the path**, so a parent named
  `foo_unencrypted` silently exempts its whole subtree.
- Regexes are **unanchored** Go RE2 via `regexp.Match`, so `encrypted_regex: "data"`
  matches `metadata`. Rust's `regex` crate is the same syntax family and the same
  semantics; a PCRE is not.
- The compile error is **discarded** (`matched, _ :=`), so upstream treats an
  invalid pattern as "never matches" — a silently wrong subset. Compiling up front
  and refusing is a strict improvement.
- Default when nothing is configured: `unencrypted_suffix = "_unencrypted"`, and
  sops writes it into the metadata **explicitly**.
- Encrypting a comment that would then match `unencrypted_comment_regex` is a hard
  refusal, because such a file could never be decrypted again.

---

## 5. The `sops:` block

`stores.Metadata`'s Go field order **is** the byte order in every sops file ever
written, because go-yaml marshals a struct in declaration order. Not alphabetical;
must not be sorted.

```
shamir_threshold  key_groups  kms  gcp_kms  hckms  azure_kv  hc_vault  age
lastmodified*  mac*  pgp
unencrypted_suffix  encrypted_suffix  unencrypted_regex  encrypted_regex
unencrypted_comment_regex  encrypted_comment_regex  mac_only_encrypted  version*
```

`*` = always emitted; everything else is `omitempty`. Inside a `key_groups` entry,
`hc_vault` and `age` are *not* `omitempty` — an upstream inconsistency that emits
them even when empty.

| provider | fields |
|---|---|
| `age` | `recipient`, `enc` |
| `pgp` | `created_at`, `enc`, `fp` |
| `kms` | `arn`, `role?`, `context?`, `created_at`, `enc`, `aws_profile` |
| `gcp_kms` | `resource_id`, `created_at`, `enc` |
| `hckms` | `key_id`, `created_at`, `enc` |
| `hc_vault` | `vault_address`, `engine_path`, `key_name`, `created_at`, `enc` |
| `azure_kv` | `vault_url`, `name`, `version`, `created_at`, `enc` |

`lastmodified` must be kept **verbatim** from the file, never reformatted: it is
the MAC field's AAD, so a `Z` normalised to `+00:00` makes a valid file unreadable.

### Data key and age wrapping

- The data key is **32 random bytes** (`GenerateDataKey`).
- **age**: `armor.NewWriter` around `age.Encrypt(recipient)` — the raw key becomes
  a fully armored age file, stored verbatim in `enc` as a YAML literal block.
- Identity sources, in order: `SOPS_AGE_KEY` · `SOPS_AGE_KEY_FILE` ·
  `SOPS_AGE_KEY_CMD` · `SOPS_AGE_SSH_PRIVATE_KEY_{FILE,CMD}` ·
  `<userConfigDir>/sops/age/keys.txt`. **sops deliberately honours
  `XDG_CONFIG_HOME` on macOS** even though Go's `os.UserConfigDir` does not —
  its own comment says so. A darwin-primary fleet that skips this looks in
  `~/Library/Application Support` while sops reads `~/.config`.
- Only a **current** recipient can re-wrap the data key. So adding a recipient to
  `.sops.yaml` does nothing until somebody with an existing key runs
  `sops updatekeys` — and nothing reports the gap. `nix/.sops.yaml` carried a
  declared admin-recovery recipient for `users/gabi/secrets.yaml` for two weeks
  that was never in the ciphertext.

---

## 6. The YAML layer

`stores/yaml/store.go` uses **`go.yaml.in/yaml/v3`** — not `gopkg.in/yaml.v3`, and
worth naming because the two can drift. `IndentDefault = 4`, overridable by
`--indent`; a negative indent is a hard error. sops sets **no style and no tag**,
calling `valueNode.Encode(in)`, so go-yaml's encoder and resolver own every
quoting decision.

### Line wrapping is off, and the reason is an initialisation order

```text
best_width starts at -1                                     (apic.go:111)
if best_width >= 0 && best_width <= best_indent*2 { = 80 }   // skipped: -1 < 0
if best_width < 0 { best_width = 1<<31 - 1 }                 // taken
```

Unless a caller invokes `SetWidth` — sops never does — the effective width is
`i32::MAX` and **nothing wraps**. The `= 80` line is a decoy that only fires for a
caller who asked for an absurdly small width. This is why a 400-character
ciphertext sits on one line.

### Block-sequence indentation: go-yaml forked libyaml here

```text
go-yaml v3 :         - recipient: age1q3tep…     dash at indent×depth, content right after "- "
libyaml    :     -   recipient: age1q3tep…       dash at parent indent, content padded to indent
```

Deliberate, and labelled as such in `emitterc.go`:

```go
} else if !indentless {
    // [Go] This was changed so that indentations are more regular.
    if states[len-1] == BLOCK_SEQUENCE_ITEM_STATE {
        // The first indent inside a sequence will just skip the "- " indicator.
        indent += 2
    } else {
        indent = best_indent * ((indent + best_indent) / best_indent)   // integer division
        if compact_seq { indent -= 2 }
    }
}
```

`compact_sequence_indent` is a `bool` left at its zero value unless a caller opts
in with `CompactSeqIndent()`, and sops does not — so `compact_seq` is always
`false`. Checked against the observed columns of the real `secrets.yaml`:

| node | before | rule | after | observed |
|---|---|---|---|---|
| `sops:` children | 0 | `4·((0+4)/4)` | 4 | 4 ✓ |
| `age:` sequence | 4 | `4·((4+4)/4)` | 8 | 8 (the dash) ✓ |
| item mapping | 8 | sequence item → `+2` | 10 | 10 (`recipient:`) ✓ |
| `enc:` block scalar | 10 | `4·((10+4)/4)` | 12 | 12 (the armor) ✓ |

The `10 → 12` row is what proves the rule is not `current + width`.

### The scalar style ladder

`encode.go`'s `stringv` requests a style; libyaml's
`yaml_emitter_select_scalar_style` may demote it:

```text
requested = LITERAL  if the text contains a newline
          = PLAIN    if canUsePlain
          = DOUBLE   otherwise

PLAIN   + !block_plain_allowed    -> SINGLE
SINGLE  + !single_quoted_allowed  -> DOUBLE
LITERAL + !block_allowed          -> DOUBLE
simple_key_context && multiline   -> DOUBLE          (keys cannot be blocks)
```

`canUsePlain = resolve("",s) == strTag && !isBase60Float(s) && !isOldBool(s)` — a
**type** question. Structural safety is libyaml's job, via the analysis flags:

| flag cleared | by |
|---|---|
| `block_plain_allowed` | leading/trailing space or break, `break_space`, `space_break`, tab, non-printable, any line break, a block indicator |
| `single_quoted_allowed` | `break_space`, `space_break`, tab, non-printable |
| `block_allowed` | trailing space, `space_break`, non-printable, or an empty value |

Conflating the type question with the structural one skips the `PLAIN → SINGLE`
rung and double-quotes everything containing `: ` — which cost ~324 characters of
escaping across eight lines of the operator's `secrets.yaml`.

The table, measured by running sops on a file containing exactly these values:

```
hash: 'has # hash'          structurally plain-unsafe -> SINGLE
colon: 'a: b'               structurally plain-unsafe -> SINGLE
dash: '- leading dash'      structurally plain-unsafe -> SINGLE
lead_space: ' leading'      leading space             -> SINGLE
trail_space: 'trailing '    trailing space            -> SINGLE
tabbed: "a\tb"              tab kills single quotes   -> DOUBLE
quoted_bool: "true"         resolves as a bool        -> DOUBLE
number_str: "42"            resolves as an int        -> DOUBLE
plainish: normal-value      safe and a string         -> PLAIN
```

Every `ENC[]` payload is **plain**, because its colons are not followed by
whitespace.

### The two bool lists, and why they are two

`resolveMap` — what actually resolves as a non-string, case-exact:

```
bool   true True TRUE   false False FALSE
null   (empty) ~ null Null NULL
float  .nan .NaN .NAN   .inf .Inf .INF   +.inf … -.inf …
merge  <<
```

**`y`, `Y`, `yes`, `on`, `n`, `no`, `off` are STRINGS.** yaml.v3 dropped YAML 1.1's
boolean set. They survive only in `isOldBool`, which *quotes* them on the way out
"so that the marshalled output [is] valid for YAML 1.1 parsing".

Two lists, two jobs. Feeding the 1.1 set to the *decode* resolver turns a
plaintext `value: y` into a `type:bool` leaf that comes back as `true` — a value
changed by a round-trip. Consequence worth knowing: **sops does not round-trip
`value: y`**; it returns `value: "y"`. Both implementations agree on that.

`isBase60Float` matches `^[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?$` and is
quoted defensively, since a YAML 1.1 parser reads `1:20` as the number 80.

### Comments are tree items, not formatting

sops turns each comment line into a `sops.Comment{Value: line[1:]}` **tree item**,
which is why `encrypted_comment_regex` can encrypt one. Any implementation that
treats comments as node decoration cannot express that, and any that drops them
changes both the text and the MAC.

---

## 7. Formats other than YAML

`--input-type` / `--output-type` ∈ `yaml` · `json` · `dotenv` · `ini` · `binary`,
otherwise inferred from the extension. `binary` wraps the whole file as a single
`data` key. All three encrypted files in the operator's nix repo are YAML, but
sops-nix's manifest can name any of the five.

---

## 8. CLI surface (v3.12.1)

Subcommands: `encrypt` `decrypt` `rotate` `edit` `set` `unset` `updatekeys`
`groups` `exec-env` `exec-file` `publish` `filestatus` `keyservice` `completion`
`help`. Legacy flag forms `-e` `-d` `-r`, and a bare `sops <file>` = `edit`.

**Flags must precede the filename** or they are silently ignored — sops's own help
says so, and reproducing the quirk is what keeps muscle memory working.

**Exit code 200 = "file has not changed"** after an edit. Part of the contract:
`cofre`'s own SOPS backend branches on that exact value.

`--extract` of a scalar emits the value's bytes with **no trailing newline**.

`SOPS_DISABLE_VERSION_CHECK` is not cosmetic — without it sops reaches out for a
release check and **blocks on the network**, which inside a nix build is a wedged
rebuild rather than a slow one.

---

## 9. What a CLI alias can and cannot reach

There are **four fronts**, and they are not equally reachable. Measured, not assumed.

| front | mechanism | reachable by an alias? |
|---|---|---|
| 1. PATH-resolved `exec` | 21 sites across ~14 files in 11 repos — `nix run .#sops-edit`, cofre's `SopsBackend`, kikai ×2, seibi ×2, kindling, tatara-lisp's `(sops-extract)`, shikumi ×2, Ruby backticks | **yes** |
| 2. store-path-pinned / bare token | 9 sites in 6 files, only 5 under `parts/` | **yes**, via an overlay |
| 3. `sops-install-secrets` | links sops as a **Go library**; `main.go:343` calls `decrypt.File` and the only `exec.Command`s are systemctl/getconf/hdiutil/newfs_hfs/mount | **no** — but it has a `sops.package` seam |
| 4. Flux's `kustomize-controller` | `go.mod` requires `getsops/sops/v3` directly and imports eight of its packages in-process | **no**, and there is no seam |

**Front 3 is a supported drop-in, not a fork.** sops-nix exposes
`sops.package` / `sops.validationPackage`, `blackmatter-secrets` already forwards
it (`module/backends/sops.nix:57`), and it is set **nowhere**. Two further facts
matter before flipping it: darwin runs **two independent planes** — a system
daemon and an HM user agent, each with its own manifest, mountpoint and generation
counter — so flipping one leaves the other half on the old binary; and cid's
launchd job scrubs `PATH` and execs an absolute store path, which is why a PATH
shim is doubly out of reach there.

**Front 4 has no honest alias story.** Forking the controller to shell out is a
wrap and violates NO SHELL; a `go.mod replace` shim would mean maintaining
sops-the-library in Go *and* this workspace in Rust, two implementations that must
then agree with each other and with upstream. The honest retirement is to stop
asking Flux to decrypt at all — migrate the `decryption.provider: sops`
Kustomizations to a rendered Secret or an ESO `ExternalSecret` — which is a
fleet-architecture decision, not a parity one.

Any claim that "sops is replaced" while front 4 stands is a round-up.

---

## Multi-document streams: ONE data key, ONE MAC

**Measured 2026-08-19. This is not what the file's shape suggests, and the obvious
reading is wrong.**

A multi-document sops file carries a *complete* `sops:` block per document — its own
`age:` list with its own armored `enc` blob, its own `lastmodified`, its own `mac:`
line. Every instinct says N independent encrypted files sharing a byte stream.

They are copies. On
`pleme-io/k8s/clusters/plo/infrastructure/business-intelligence/postgres-superset.yaml`
(5 documents, 4 `---` separators):

| observation | count |
|---|---|
| distinct `mac:` ciphertexts | **1** (all five byte-identical) |
| distinct `lastmodified` values | **1** |
| `sops:` blocks | 5 |

Identical GCM ciphertext is the proof, not a coincidence: it requires the same key,
the same IV **and** the same plaintext. And the `mac:` field's AAD is the verbatim
`lastmodified`, so identical ciphertext already forces identical timestamps.

The independent confirmation is upstream's own error when a document is extracted
from the middle of the stream and decrypted alone:

```
MAC mismatch. File has C516636B7988F430…, computed CF83E1357EEFB8BD…
```

`CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE…` is the SHA-512
of the **empty string** — that document is two comments and an empty mapping, so on
its own it MACs to nothing, while the file's recorded MAC covers the whole stream.

### Consequences

1. **The MAC covers every document's leaves, in document order**, with one
   accumulator. `SopsFile::decrypt_stream` does exactly that.
2. **A document cannot be verified alone.** Splitting a stream on `---` and
   decrypting a piece fails in BOTH implementations. That is not a suminuri bug, and
   chasing it as one cost a diagnosis cycle — if you find yourself splitting a stream
   to isolate a MAC failure, stop.
3. **The data key comes from the first document's metadata**, because every block
   holds the same one. A per-document key would be a different file format.
4. **An empty document in a stream is legitimate.** It has no MAC-eligible leaf, so
   the walk feeds nothing — which must not be reported as a MAC mismatch. See
   `WireError::NothingToVerify`.

## Comments

**Comments do NOT contribute to the MAC, in either direction.** sops guards its
`hash.Write` with `if !ok` in both walkers. Verified from the outside: alter one
character of a comment in a real encrypted file, leave every byte of ciphertext
intact, and upstream still decrypts it.

An encrypted comment is a leaf like any other, rendered as a `#`-prefixed envelope
with `type:comment`:

```
    #ENC[AES256_GCM,data:...,iv:...,tag:...,type:comment]
```

Its AAD is the enclosing mapping's path — which is why a comment must be attached to
the right collection. Hoisting one to the root changes its AAD, the GCM tag then
fails, and because the decrypt path is deliberately forgiving ("assume it was not
encrypted in the first place") the failure surfaces as **raw ciphertext in the
output**, not as an error.

**On DECRYPT the file is the authority, not the selector.** A `type:comment` leaf is a
record of what was done; a policy that has since changed cannot un-encrypt bytes
already on disk. Gating decrypt on the selector makes any file whose
`encrypted_regex` later moved permanently unreadable while upstream reads it fine.

## Emitter facts that only a byte comparison finds

| fact | why it is not guessable |
|---|---|
| non-BMP characters are escaped `\UXXXXXXXX` in double quotes; BMP ones are not | libyaml's `IS_PRINTABLE` enumerates first bytes `0x20..=0x7E` and `0xC2..=0xEF`, omitting `0xF0..=0xF4`. One real file holds both a BMP check mark (literal) and a non-BMP wrench (escaped) |
| `-`, `?`, `:` are indicators only when followed by whitespace | `-U` is a valid plain scalar; over-quoting yields `- "-U"` where go-yaml writes `- -U` |
| a block scalar inside a `- ` item indents at `dash + 2` | go-yaml's `increase_indent_compact` takes the sequence branch, not `best * ((cur + best) / best)` — 30 vs 32 at dash-28 |
| a mapping holding only comments still emits `{}` | comments do not give a block mapping a key, so it is still the empty mapping |
| a YAML `null` is not a leaf at all | sops's `walkValue` has `case nil: return nil, nil`, returning before `onLeaves` where both cipher and MAC live. A quoted `"null"` IS a leaf — style is part of the test |
| a block scalar can open as a bare sequence entry (`- \|`) | a comment scanner that only looks after a `:` misses it and duplicates every `#` line of the body |

**Every row above was a byte difference against a real fleet file, and none was
reachable from a hand-written fixture.** The gate is
`crates/suminuri/tests/corpus_differential.rs`; run it before changing anything here.
