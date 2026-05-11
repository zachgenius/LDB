# Pack Signing

**Status:** design only, on branch `feat/pack-signing`. No code yet.

`.ldbpack` archives travel between operators and across networks. Today
they carry no authenticator: the producer's outer-bytes sha256 is
computed (`src/store/pack.cpp:807`, `:850`) and returned in
`PackResult.sha256` (`src/store/pack.h:75`), but the hash is never
written into the pack and `unpack()` never recomputes it
(`src/store/pack.cpp:862-864`). A pack received "from operator A" is
indistinguishable from one substituted mid-transit. This doc specifies
ed25519 detached signing as a backward-compatible additive layer.

## Threat Model

Two scenarios are in scope.

1. **Operator handoff.** A produces a pack on machine X, ships it to B
   over an arbitrary channel (email attachment, scp, USB, a chat client
   that re-encodes attachments). B wants to confirm both *A's identity*
   (the signer is the person they think) and *byte integrity* (no
   middlebox edited or truncated the file).
2. **Mid-transit substitution.** An attacker on the channel replaces the
   pack with a crafted one (e.g. an investigation transcript with
   fabricated symbol resolutions, or an artifact blob with a planted
   binary). B must reject any pack not signed by a trusted key.

Out of scope:

- **Confidentiality.** Packs are not encrypted. Operators wanting secrecy
  layer TLS, `age`, or `ssh -e` separately.
- **Revocation.** No CRL, OCSP, or expiry. A compromised key is removed
  from each operator's trust root by hand.
- **Hardware tokens.** No `ssh-agent`, no PKCS#11, no Secure Enclave.
  Signing reads a key file off disk.
- **Multi-signer / threshold.** One signer per pack.
- **Anti-replay.** The signature attests to bytes, not to freshness.

## Wire Format

**Chosen: option (a) — embedded sidecar tar entries.** Rejected:
option (b), an external `.ldbpack.sig` file alongside.

Reasons to reject (b): loses with one-file transports (chat
attachments, single-blob uploads — the whole appeal of `.ldbpack` is
"one file"); doubles the failure modes on import ("sig missing,"
"filenames disagree," "user renamed pack but not sig"); forces every
consumer to grow filesystem conventions before they can speak the
protocol. Embedded wins because the unit on the wire stays one file,
the verifier reuses existing gzip+tar code paths, and the manifest can
advertise signedness so old clients can opt to reject.

### Layout

Signed packs insert two new entries immediately after `manifest.json`
(which is itself at tar index 0; see `src/store/pack.cpp:797`,
`:841`).

```
tar index 0   manifest.json          (existing)
tar index 1   signature.json         (new, signed packs only)
tar index 2   signature.sig          (new, signed packs only — 64 raw bytes)
tar index 3+  sessions/... artifacts/...
```

`manifest["format"]` is bumped from `"ldbpack/1"` to `"ldbpack/1+sig"`
when, and only when, the two sidecar entries are present. Old
unsigned packs keep `"ldbpack/1"` and continue to load unchanged.
This is the single bit a client uses to decide "is signing claimed."

### `signature.json` schema

```json
{
  "algorithm": "ed25519",
  "key_id": "SHA256:<base64 of sha256(public_key_raw_32)>",
  "signer": "alice@example.com",
  "created_at": 1715472000,
  "covered": {
    "scheme": "ldbpack-sig/1",
    "manifest_sha256": "<hex>",
    "entries": [
      { "name": "sessions/<uuid>.db",         "sha256": "<hex>" },
      { "name": "sessions/<uuid>.meta.json",  "sha256": "<hex>" },
      { "name": "artifacts/<bid>/<name>",     "sha256": "<hex>" },
      ...
    ]
  }
}
```

`key_id` is the same string format `ssh-keygen -l -f key.pub` emits
(`SHA256:...`), so users can match the value against their keyring by
eye. `signer` is a free-form label the producer chose at sign time —
it carries no authority; only the key in the trust root does.

### Canonical signed bytes

The signature is over **`signature.json`'s UTF-8 bytes** with the
`signer` field set, the `algorithm` field set, and `covered` populated
as above. There is no separate "thing being signed" concept: the
producer fills `manifest_sha256` and the `entries` list, serializes
`signature.json`, hashes that JSON's bytes with sha256, and signs the
hash with ed25519. The verifier hashes the received `signature.json`,
ed25519-verifies it, then independently recomputes `manifest_sha256`
and each `entries[i].sha256` from the tar entries it just unpacked and
compares.

Why this and not "signature is over a concatenation of raw tar entry
bodies": tar is order-stable in our producer (`pack.cpp` builds the
vector then `tar.insert(tar.begin(), manifest)`), but a defender
checking by hand wants to read the JSON, see the hashes, and run
`sha256sum` against the extracted files. Putting the per-entry digests
in the JSON makes the contract auditable without a tool.

The producer **MUST** emit `entries` sorted by `name` (byte-wise
ascending). The verifier **MUST** confirm both that the sort holds and
that the set of names in `entries` equals the set of non-signature
tar entry names. A pack with an unsigned extra entry, or a missing
entry, fails verify.

Canonicalization: producer emits via `nlohmann::json::dump()` with
fixed key insertion order; verifier ed25519-checks the *received
bytes* literally and never re-serializes.

## Crypto Choice

**Chosen: libsodium (`crypto_sign_detached` / `crypto_sign_verify_detached`).**
Rejected: vendoring a single-file ed25519 reference (`ref10`, `ed25519-donna`).

| Concern             | libsodium                                              | Vendored ref10                            |
|---------------------|--------------------------------------------------------|-------------------------------------------|
| Build deps          | `apt install libsodium-dev`, `brew install libsodium`  | None; drop in `third_party/`              |
| Supply chain        | Distro-signed binaries, well-audited                   | We own one more crypto file forever       |
| Portability         | Linux x86-64, Linux arm64, macOS arm64 all packaged    | Same, but we maintain build flags         |
| Constant-time       | Yes, vetted                                            | ref10 is, but vendoring invites edits     |
| Code surface to us  | `~5` symbols (`sign`, `verify`, `keypair`, hex helpers) | Whole curve impl in tree                  |
| Tooling parity      | Matches `ssh-keygen`'s ed25519 wire format             | Same algorithm; less infra around it      |

`liblldb` already makes us tolerate distro-specific install paths; one
more is a smaller tax than maintaining curve arithmetic. The supply
chain argument runs both ways, and the audit weight of libsodium
beats anything we'd vendor.

CMake integration mirrors `Capstone` (`docs/12-capstone-disasm.md`):

- `pkg_check_modules(SODIUM REQUIRED libsodium)` first, then a manual
  `find_library(SODIUM sodium)` / `find_path(SODIUM sodium.h)` fallback.
- Linked into `ldbd` via `target_link_libraries(ldbd PRIVATE ${SODIUM_LIBRARIES})`
  in `src/CMakeLists.txt:40-47`.
- Not gated behind a `LDB_ENABLE_SIGNING` option: signing is *always*
  compiled in. The optional surface is the runtime `sign_key` /
  `trust_root` params, not the build.
- CI: Linux jobs gain `libsodium-dev` to the apt step
  (`docs/06-ci.md`); macOS jobs gain `libsodium` to the brew step.
  Linux arm64 validation leg picks libsodium from the same apt set as
  x86-64 — no special-case.

If a distro lacks libsodium (none on the supported matrix do), the
build fails loudly; we do not silently disable signing.

## Key Format and Storage

**Decision: accept OpenSSH-format ed25519 keys directly.** A user's
existing `~/.ssh/id_ed25519` works as a signing key, and
`~/.ssh/id_ed25519.pub` is a valid trust-root entry.

OpenSSH ed25519 private keys are the `-----BEGIN OPENSSH PRIVATE KEY-----`
PEM-ish wrapper around an internal binary structure that contains a raw
32-byte seed and the 32-byte public key. The parsing is short — under
200 lines for unencrypted keys — and well documented (PROTOCOL.key in
the OpenSSH source). We implement an in-process parser that:

1. Strips the PEM armour, base64-decodes the body.
2. Validates the `openssh-key-v1\0` magic.
3. Refuses anything that isn't `none` for cipher/kdf — encrypted keys
   are out of scope for v1; users decrypt to a temp file or use an
   unencrypted ops-only key. We emit a `kInvalidParams` with the
   exact reason ("encrypted OpenSSH keys not supported in v1; decrypt
   first").
4. Reads the public + private key blobs, asserts `ssh-ed25519` type.
5. Hands the 64-byte (seed || pub) buffer to
   `crypto_sign_detached(sig, NULL, m, mlen, sk)`.

Public-key files (`id_ed25519.pub`) are one line:
`ssh-ed25519 AAAA...base64... comment`. We base64-decode the middle
field, strip the 4-byte length-prefixed `ssh-ed25519` header, and the
remaining 32 bytes are the ed25519 public key. We never trust the
comment field for authentication; it only ends up as a default
`signer` label if the request didn't supply one.

Why not PEM PKCS#8 or raw `crypto_sign_keypair` output:

- A user pulling LDB into their workflow already has SSH ed25519
  keys. Asking them to mint a *second* key for one tool is friction.
- The signing surface is small enough that one parser, well tested,
  is fine.
- PEM PKCS#8 is portable but means the user has to convert
  (`ssh-keygen -e -m PKCS8 ...`), and most don't.

### Trust root

A **trust root** is a filesystem path. Two accepted forms:

- A directory containing one `.pub` file per allowed signer
  (`alice.pub`, `bob.pub`, ...). The dispatcher reads every `*.pub`
  entry in lexical order. Other filenames are ignored. This matches
  `/etc/ssh/sshd_config.d/`-style layout.
- A single file in `authorized_keys` format: one public key per line,
  blank lines and `#` comments skipped. Matches `~/.ssh/authorized_keys`.

Either form is accepted; we sniff by `is_directory()`. If the path
doesn't exist or is unreadable, the import fails with `kBadState`.

## API Surface

All new fields are optional. Existing clients see no behavior change.

### Export — `session.export`, `artifact.export`

Request (additions, both endpoints):

| Field      | Type   | Meaning                                                                 |
|------------|--------|-------------------------------------------------------------------------|
| `sign_key` | string | Filesystem path to an unencrypted OpenSSH-format ed25519 private key.   |
| `signer`   | string | Optional human label baked into `signature.json`. Default: key comment. |

Response (additions when `sign_key` was given):

```json
{
  "path": "...",
  "byte_size": 12345,
  "sha256": "...",
  "manifest": { ..., "format": "ldbpack/1+sig" },
  "signature": {
    "key_id":    "SHA256:abc...",
    "algorithm": "ed25519"
  }
}
```

If `sign_key` is omitted, output is bit-identical to today.

### Import — `session.import`, `artifact.import`

Request (additions, both endpoints; parsed by `parse_import_args` at
`src/daemon/dispatcher.cpp:4412`):

| Field            | Type   | Default | Meaning                                                        |
|------------------|--------|---------|----------------------------------------------------------------|
| `trust_root`     | string | none    | Path to trust-root directory or `authorized_keys` file.        |
| `require_signed` | bool   | `false` | If `true`, an unsigned pack is rejected with `kBadState`.      |

Response (additions when the pack is signed):

```json
{
  "imported": [...],
  "skipped":  [...],
  "policy":   "error",
  "signature": {
    "key_id":  "SHA256:abc...",
    "verified": true,
    "signer":   "alice@example.com"
  }
}
```

When the pack is signed and the import succeeded but `trust_root` was
not provided, `verified` is `false` and the import still completes —
the caller learns the bytes are internally consistent but the signer
is unauthenticated. The dispatcher does not invent trust.

### Error mapping

Confirmed against `src/protocol/jsonrpc.h:26-27`:

| Condition                                                       | Code   |
|-----------------------------------------------------------------|--------|
| `require_signed=true`, pack carries no signature                | -32002 |
| `require_signed=true`, `trust_root` missing or unreadable       | -32002 |
| Signature verify fails (ed25519 returns nonzero)                | -32003 |
| Per-entry sha256 in `signature.json` disagrees with tar bytes   | -32003 |
| `entries` set mismatches tar entry set                          | -32003 |
| Signing key in pack is not present in `trust_root`              | -32003 |
| `sign_key` path missing on export                               | -32602 |
| `sign_key` is an encrypted OpenSSH key                          | -32602 |
| Malformed OpenSSH key (bad magic, wrong type, truncated)        | -32602 |

`kBadState` is "the environment isn't right for this operation"
(missing config). `kForbidden` is "the operation is well-formed but
not permitted" (verify failed, signer not trusted). The split matches
existing usage at `dispatcher.cpp:6016` (allowlist not configured ⇒
`kBadState`) and `:6092` (allowlist configured but call rejected ⇒
`kForbidden`).

## Failure Semantics Matrix

| pack signed? | `require_signed`? | `trust_root` given? | sig verifies? | outcome                                                                   |
|:---:|:---:|:---:|:---:|---|
| no  | false | n/a | n/a | import succeeds; response has no `signature` field                          |
| no  | true  | n/a | n/a | reject `-32002` ("unsigned pack but require_signed=true")                   |
| yes | false | no  | n/a | import succeeds; response `signature.verified=false`                        |
| yes | true  | no  | n/a | reject `-32002` ("require_signed=true but no trust_root provided")          |
| yes | false | yes | yes | import succeeds; response `signature.verified=true`                         |
| yes | true  | yes | yes | import succeeds; response `signature.verified=true`                         |
| yes | false | yes | no  | reject `-32003` ("signature did not verify" or "signer not in trust_root")  |
| yes | true  | yes | no  | reject `-32003` (same)                                                      |

"sig verifies" collapses three sub-checks: ed25519 OK, `entries` set
matches tar, signer key in trust root. Any one failing maps to
`-32003`. The error `message` reports which check tripped, the
`data` object carries the `key_id` so the operator can identify what
they were sent.

## Test Plan

Tests to write *before* implementation, in the order they should turn
green:

**Unit (`tests/unit/test_pack.cpp` and new `tests/unit/test_pack_signing.cpp`):**

1. libsodium glue: round-trip `sign_buffer` / `verify_buffer` on a
   fixed `(seed, message)` pair, compare against a hand-computed
   ed25519 test vector from RFC 8032.
2. OpenSSH key parse: parse a fixture `id_ed25519` (unencrypted),
   assert the 32-byte public key matches a `ssh-keygen -y` value baked
   into the test.
3. Encrypted OpenSSH key rejected with the specific error message.
4. `.pub` parse: parse a fixture `id_ed25519.pub`, assert the same
   32-byte public key.
5. Round-trip pack sign + verify: build a 2-session, 3-artifact pack
   with `sign_key=fixture`, re-read, verify, assert
   `signature.verified=true` and `manifest.format=="ldbpack/1+sig"`.
6. Tampered pack fails verify: same producer, then flip one byte
   inside `sessions/<uuid>.db` post-tar / pre-gzip; reimport asserts
   `-32003` with message naming the entry whose sha256 mismatched.
7. Missing-signature pack rejected when `require_signed=true`:
   produce an unsigned pack (existing producer), import with
   `require_signed=true`, expect `-32002`.
8. Signed pack with key not in trust root rejected: trust root is a
   directory containing only `bob.pub`; pack signed by Alice;
   `-32003` with message naming the unknown `key_id`.
9. Signed pack with key in trust root accepted; assert all response
   fields, assert `manifest["format"] == "ldbpack/1+sig"`.
10. `entries` mismatch fails verify: forge a `signature.json` with one
    extra entry name; expect `-32003`.

**Smoke (`tests/smoke/test_ldbpack.py`):**

11. Two-daemon flow: daemon A exports a session with
    `sign_key=$TMPDIR/alice_key`, daemon B is launched with a working
    dir whose trust root contains `alice.pub`, imports the pack with
    `trust_root=$TMPDIR/trust` and `require_signed=true`, asserts a
    successful import and `signature.verified=true`.
12. Negative smoke: same setup but daemon B's trust root has only
    `bob.pub`; expect `-32003` and zero imported entries.

Each test starts as a failing assertion against the unmodified tree,
per CLAUDE.md TDD rules.

## Open Questions

- **Detached vs embedded signature bytes.** Current design puts the
  64-byte signature in its own tar entry (`signature.sig`). Alternative:
  inline `"sig_b64": "..."` inside `signature.json` and drop the second
  entry. The split makes the JSON readable by `tar -xOf pack.ldbpack
  signature.json | jq`. Decide before implementation.
- **`describe.endpoints` capability advertisement.** Should `hello`
  grow a `capabilities.pack_signing: true` like `disasm_backend` does
  in `docs/12-capstone-disasm.md`? Probably yes, so clients can choose
  to require signing without a round trip. Defer until the implementation
  PR.
- **Default `sign_key` from environment.** Should `LDBD_SIGN_KEY` env
  var act as a default for `sign_key`? Convenient for CI signing
  pipelines; risks accidentally signing every export. Lean: no, keep
  it explicit, revisit if operators ask.
- **Default `trust_root` from environment.** Same question for
  `LDBD_TRUST_ROOT` plus `~/.config/ldb/trust/`. Same default lean: no.
- **Key comment as `signer`.** OpenSSH stores a comment on each key.
  Using it as the default `signer` label is convenient but means a
  `~/.ssh/id_ed25519` whose comment is `zach@laptop` ends up on
  every signed pack. Acceptable, but flag in the export response so
  the operator notices.
- **Re-signing on import.** Should an imported pack be re-signed by
  the receiving operator before re-export? Out of scope for v1, but
  the manifest could carry a `signatures: []` array later. The current
  schema has room for that without a wire break.
- **Cross-version compatibility.** A daemon predating this design
  reads a `"ldbpack/1+sig"` manifest as an unknown format. Should the
  old behavior be "ignore the format string and import anyway" (today)
  or hard-fail? Today's `unpack` doesn't check the format field at
  all — it walks the manifest by key. So old daemons import signed
  packs successfully but silently ignore the signature. Acceptable.
- **Hash of `manifest.json` vs hash of the canonical JSON object.**
  We hash the *bytes that appear in the tar entry*. If a future
  re-serializer ever rewrites `manifest.json` (it shouldn't) the hash
  breaks. Document this as a producer-side invariant.
