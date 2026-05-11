// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "store/pack.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// `.ldbpack` ed25519 detached signing — see `docs/14-pack-signing.md` for
// the wire format, threat model, and key-handling rationale. This header
// declares the small surface the dispatcher needs:
//
//   * OpenSSH key parsers (private + public), so users can sign with their
//     existing `~/.ssh/id_ed25519` and add `~/.ssh/id_*.pub` files to a
//     trust root without minting a second key.
//   * Trivial libsodium glue (`sign_buffer` / `verify_buffer`) — separate
//     wrappers exist so the producer-side and verifier-side code can
//     unit-test against the same primitives the dispatcher uses.
//   * `compute_key_id` — the `SHA256:<base64>` string that `ssh-keygen
//     -l` would print, used in `signature.json["key_id"]` and as the
//     trust-root lookup key.
//
// All functions throw `backend::Error` on parsing / crypto failure; the
// dispatcher maps that to the appropriate JSON-RPC error code per
// `docs/14-pack-signing.md` §"Error mapping". `sign_buffer` /
// `verify_buffer` are noexcept on the libsodium contract — sodium_init()
// is called once on first use.

namespace ldb::store {

struct Ed25519KeyPair {
  std::array<std::uint8_t, 32> public_key{};
  // libsodium-format secret key: 32-byte seed followed by 32-byte public
  // key (see `crypto_sign_SECRETKEYBYTES`).
  std::array<std::uint8_t, 64> secret_key{};
};

struct Ed25519PublicKey {
  std::array<std::uint8_t, 32> bytes{};
  // "SHA256:<base64>" form, matching `ssh-keygen -l -f key.pub`.
  std::string key_id;
  // Free-form comment from the `.pub` line (e.g. "alice@laptop"). Empty
  // when parsed from a private key. The dispatcher uses this as the
  // default `signer` label when one isn't provided in the request.
  std::string comment;
};

// Parse an OpenSSH `-----BEGIN OPENSSH PRIVATE KEY-----` ed25519 key.
// Throws `backend::Error` on:
//   * bad PEM armour or base64 decode failure
//   * missing `openssh-key-v1\0` magic
//   * non-`none` cipher or kdfname (encrypted keys are v1-out-of-scope —
//     the message says "encrypted OpenSSH keys not supported in v1;
//     decrypt first" so the dispatcher can surface it verbatim)
//   * key type != `ssh-ed25519`
//   * truncated / malformed blobs
Ed25519KeyPair parse_openssh_secret_key(const std::vector<std::uint8_t>& pem_bytes);

// Parse a single line in `~/.ssh/authorized_keys` / `id_ed25519.pub`
// format: `ssh-ed25519 <base64> [comment]`. Throws on bad type prefix,
// bad base64, or wrong key length. The comment field is preserved.
Ed25519PublicKey parse_openssh_public_key(const std::string& line);

// Detached ed25519 signature. `key` provides the libsodium-format
// 64-byte secret. The 64-byte signature is returned by value; libsodium
// is initialised lazily on first call.
std::array<std::uint8_t, 64>
sign_buffer(const std::vector<std::uint8_t>& msg, const Ed25519KeyPair& key);

// Detached ed25519 verify. Returns `true` iff `sig` is a valid
// signature of `msg` under `public_key`. Constant-time on the libsodium
// contract.
bool verify_buffer(const std::vector<std::uint8_t>& msg,
                   const std::array<std::uint8_t, 64>& sig,
                   const std::array<std::uint8_t, 32>& public_key);

// `SHA256:<base64>` for a raw 32-byte ed25519 public key — the same
// canonical form `ssh-keygen -l -f key.pub` prints. Used as the
// `key_id` field in `signature.json` and as the lookup key when
// scanning a trust root.
std::string compute_key_id(const std::array<std::uint8_t, 32>& public_key);

// -------------------------------------------------------------------------
// Pack producer / verifier surface — declared here so the unit tests in
// `tests/unit/test_pack_signing.cpp` can pin the contract before the
// implementation lands. The implementations currently throw
// `backend::Error("pack_signing: not implemented")`; the dispatcher /
// pack-producer integration work in the next task fills them in.

// `ArtifactStore` / `SessionStore` come in through `store/pack.h` above.

// Mirror of `PackResult` plus the optional signature summary that the
// dispatcher returns when `sign_key` was provided on export.
struct SignedPackResult {
  PackResult result;
  // Empty when `sign_key` was not provided. Populated otherwise; the
  // string contents match `signature.json` exactly so callers can
  // re-emit them on the wire without re-serializing.
  std::optional<std::string>   signature_json;
  std::array<std::uint8_t, 64> signature_bytes{};
};

// Sign-aware producer wrappers — bit-identical to `pack_session` /
// `pack_artifacts` when `key` is `std::nullopt`; otherwise emits the
// `signature.json` + `signature.sig` sidecar entries described in
// docs/14-pack-signing.md §"Wire Format" and bumps `manifest["format"]`
// to `"ldbpack/1+sig"`.
SignedPackResult
pack_session_signed(SessionStore& sessions,
                    ArtifactStore& artifacts,
                    std::string_view session_id,
                    const std::filesystem::path& output_path,
                    std::optional<Ed25519KeyPair> key,
                    std::optional<std::string> signer_label);

SignedPackResult
pack_artifacts_signed(ArtifactStore& artifacts,
                      std::optional<std::string> build_id,
                      std::optional<std::vector<std::string>> names,
                      const std::filesystem::path& output_path,
                      std::optional<Ed25519KeyPair> key,
                      std::optional<std::string> signer_label);

// Verification report. `verified == true` only when the pack was signed
// AND ed25519 verify succeeded AND the per-entry sha256s match AND, if a
// trust root was provided, the signing key is present in it.
struct PackVerifyReport {
  bool        is_signed = false;   // pack carried signature.json + .sig
  bool        verified  = false;
  std::string key_id;              // empty when !is_signed
  std::string signer;               // free-form label from signature.json
  std::string error_message;       // when is_signed && !verified
};

// Verify a `.ldbpack` against an optional trust root. The trust root is
// either a directory of `*.pub` files (one per allowed signer) or a
// single `authorized_keys`-format file. When `trust_root` is empty the
// signature is checked for internal consistency only; `verified` is
// `false` (the signer is unauthenticated). Throws `backend::Error` on
// malformed signature blobs, sha256 mismatch, or `entries` set
// mismatch.
PackVerifyReport
verify_pack(const std::filesystem::path& input_path,
            const std::optional<std::filesystem::path>& trust_root);

}  // namespace ldb::store
