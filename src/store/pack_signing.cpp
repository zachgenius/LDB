// SPDX-License-Identifier: Apache-2.0
// pack_signing: real libsodium glue + real OpenSSH key parsers.
//
// Per the docs/14-pack-signing.md test plan, unit tests #1–#4 (RFC 8032
// vector, secret-key parse, encrypted-key rejection, public-key parse)
// exercise just this TU and should pass on this commit. Tests #5–#10
// exercise the pack producer/verifier integration, which doesn't exist
// yet — they are the WIP that the next task delivers.

#include "store/pack_signing.h"

#include "backend/debugger_backend.h"
#include "store/pack.h"
#include "util/base64.h"
#include "util/sha256.h"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace ldb::store {

namespace {

void ensure_sodium_init() {
  static std::once_flag once;
  std::call_once(once, []() {
    if (sodium_init() < 0) {
      throw backend::Error("pack_signing: sodium_init failed");
    }
  });
}

// ---- base64 wrappers ------------------------------------------------
//
// pack_signing historically owned its own copy; the shared
// implementation now lives in util/base64.{h,cpp} so other call sites
// (predicate.compile in #25 phase-2) don't duplicate the table. Local
// aliases preserve the original call shape inside this file.

using ldb::util::base64_encode;
using ldb::util::base64_decode;

// ---- OpenSSH-blob reader -------------------------------------------------
//
// The OpenSSH internal format for ed25519 keys is the wire format
// described in PROTOCOL.key in the upstream tree: a sequence of
// length-prefixed strings (uint32 big-endian length, then bytes). We
// only need a one-pass reader; the writer side isn't built.

class BlobReader {
 public:
  BlobReader(const std::uint8_t* data, std::size_t len)
      : data_(data), len_(len), off_(0) {}

  std::vector<std::uint8_t> read_bytes(std::size_t n) {
    if (off_ + n > len_) {
      throw backend::Error("pack_signing: openssh blob truncated");
    }
    std::vector<std::uint8_t> out(data_ + off_, data_ + off_ + n);
    off_ += n;
    return out;
  }

  std::uint32_t read_u32() {
    auto b = read_bytes(4);
    return (static_cast<std::uint32_t>(b[0]) << 24) |
           (static_cast<std::uint32_t>(b[1]) << 16) |
           (static_cast<std::uint32_t>(b[2]) << 8) |
            static_cast<std::uint32_t>(b[3]);
  }

  std::vector<std::uint8_t> read_string() {
    std::uint32_t n = read_u32();
    return read_bytes(n);
  }

  std::size_t remaining() const { return len_ - off_; }

 private:
  const std::uint8_t* data_;
  std::size_t         len_;
  std::size_t         off_;
};

constexpr std::string_view kSshOpensshMagic = "openssh-key-v1";  // + NUL

// Strip the PEM armour and base64-decode the body of an OpenSSH private
// key file. Returns the raw `openssh-key-v1\0...` byte string.
std::vector<std::uint8_t>
strip_openssh_armour(const std::vector<std::uint8_t>& pem_bytes) {
  std::string_view text(reinterpret_cast<const char*>(pem_bytes.data()),
                        pem_bytes.size());
  constexpr std::string_view kBegin = "-----BEGIN OPENSSH PRIVATE KEY-----";
  constexpr std::string_view kEnd   = "-----END OPENSSH PRIVATE KEY-----";
  auto bpos = text.find(kBegin);
  if (bpos == std::string_view::npos) {
    throw backend::Error(
        "pack_signing: not an OpenSSH PRIVATE KEY (missing BEGIN marker)");
  }
  bpos += kBegin.size();
  auto epos = text.find(kEnd, bpos);
  if (epos == std::string_view::npos) {
    throw backend::Error(
        "pack_signing: not an OpenSSH PRIVATE KEY (missing END marker)");
  }
  std::string b64;
  b64.reserve(epos - bpos);
  for (auto p = bpos; p < epos; ++p) {
    char c = text[p];
    if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
    b64.push_back(c);
  }
  return base64_decode(b64);
}

}  // namespace

// -------------------------------------------------------------------------
// Public API

Ed25519KeyPair parse_openssh_secret_key(
    const std::vector<std::uint8_t>& pem_bytes) {
  auto blob = strip_openssh_armour(pem_bytes);

  // 1) magic
  if (blob.size() < kSshOpensshMagic.size() + 1u) {
    throw backend::Error("pack_signing: openssh blob too short");
  }
  if (std::memcmp(blob.data(), kSshOpensshMagic.data(),
                  kSshOpensshMagic.size()) != 0 ||
      blob[kSshOpensshMagic.size()] != 0u) {
    throw backend::Error("pack_signing: bad openssh-key-v1 magic");
  }

  BlobReader r(blob.data() + kSshOpensshMagic.size() + 1u,
               blob.size() - kSshOpensshMagic.size() - 1u);

  // 2) cipher / kdf
  auto cipher = r.read_string();
  auto kdfname = r.read_string();
  (void)r.read_string();  // kdfoptions
  std::string_view cipher_sv(reinterpret_cast<const char*>(cipher.data()),
                              cipher.size());
  std::string_view kdf_sv(reinterpret_cast<const char*>(kdfname.data()),
                           kdfname.size());
  if (cipher_sv != "none" || kdf_sv != "none") {
    throw backend::Error(
        "encrypted OpenSSH keys not supported in v1; decrypt first");
  }

  // 3) numkeys (must be 1)
  std::uint32_t nkeys = r.read_u32();
  if (nkeys != 1) {
    throw backend::Error(
        "pack_signing: openssh key file has unexpected numkeys");
  }

  // 4) public key blob (length-prefixed) — contains its own type string
  //    followed by the 32-byte ed25519 public key.
  auto pub_section = r.read_string();
  {
    BlobReader pr(pub_section.data(), pub_section.size());
    auto type = pr.read_string();
    std::string_view type_sv(reinterpret_cast<const char*>(type.data()),
                              type.size());
    if (type_sv != "ssh-ed25519") {
      throw backend::Error(
          "pack_signing: unsupported public-key type (expected ssh-ed25519)");
    }
    auto pubkey = pr.read_string();
    if (pubkey.size() != 32) {
      throw backend::Error(
          "pack_signing: ssh-ed25519 public key wrong length");
    }
  }

  // 5) private-section: length-prefixed wrapping the unencrypted private
  //    blob. Layout: checkint, checkint, then per-key items.
  auto priv_section = r.read_string();
  BlobReader pr(priv_section.data(), priv_section.size());
  std::uint32_t ci1 = pr.read_u32();
  std::uint32_t ci2 = pr.read_u32();
  if (ci1 != ci2) {
    // OpenSSH uses the matching pair as a "did the user type the right
    // passphrase" sentinel. For unencrypted keys both halves are written
    // identical; a mismatch here means the file was hand-corrupted.
    throw backend::Error("pack_signing: openssh checkint mismatch");
  }

  auto type = pr.read_string();
  std::string_view type_sv(reinterpret_cast<const char*>(type.data()),
                            type.size());
  if (type_sv != "ssh-ed25519") {
    throw backend::Error(
        "pack_signing: unsupported private-key type (expected ssh-ed25519)");
  }

  auto pub  = pr.read_string();
  auto priv = pr.read_string();
  if (pub.size() != 32) {
    throw backend::Error("pack_signing: ssh-ed25519 public key wrong length");
  }
  if (priv.size() != 64) {
    throw backend::Error(
        "pack_signing: ssh-ed25519 secret key wrong length "
        "(expected 64 = seed||pub)");
  }

  Ed25519KeyPair out;
  std::memcpy(out.public_key.data(), pub.data(), 32);
  std::memcpy(out.secret_key.data(), priv.data(), 64);
  return out;
}

Ed25519PublicKey parse_openssh_public_key(const std::string& line) {
  // ssh-ed25519 <base64> [comment]
  std::size_t pos = 0;
  auto skip_ws = [&]() {
    while (pos < line.size() &&
           (line[pos] == ' ' || line[pos] == '\t')) {
      ++pos;
    }
  };
  auto read_field = [&]() {
    std::size_t s = pos;
    while (pos < line.size() &&
           line[pos] != ' ' && line[pos] != '\t' &&
           line[pos] != '\r' && line[pos] != '\n') {
      ++pos;
    }
    return line.substr(s, pos - s);
  };

  skip_ws();
  std::string type = read_field();
  if (type != "ssh-ed25519") {
    throw backend::Error(
        "pack_signing: unsupported public-key type (expected ssh-ed25519)");
  }
  skip_ws();
  std::string b64 = read_field();
  if (b64.empty()) {
    throw backend::Error("pack_signing: empty public-key blob");
  }
  skip_ws();
  // Remainder is the comment (allowed to contain internal spaces). Strip
  // a trailing newline if present.
  std::string comment;
  if (pos < line.size()) {
    comment = line.substr(pos);
    while (!comment.empty() &&
           (comment.back() == '\n' || comment.back() == '\r')) {
      comment.pop_back();
    }
  }

  auto blob = base64_decode(b64);
  BlobReader r(blob.data(), blob.size());
  auto bt = r.read_string();
  std::string_view bt_sv(reinterpret_cast<const char*>(bt.data()), bt.size());
  if (bt_sv != "ssh-ed25519") {
    throw backend::Error(
        "pack_signing: public-key blob type mismatch (not ssh-ed25519)");
  }
  auto pub = r.read_string();
  if (pub.size() != 32) {
    throw backend::Error("pack_signing: ssh-ed25519 public key wrong length");
  }

  Ed25519PublicKey out;
  std::memcpy(out.bytes.data(), pub.data(), 32);
  out.comment = std::move(comment);
  out.key_id  = compute_key_id(out.bytes);
  return out;
}

std::array<std::uint8_t, 64>
sign_buffer(const std::vector<std::uint8_t>& msg,
            const Ed25519KeyPair& key) {
  ensure_sodium_init();
  std::array<std::uint8_t, 64> sig{};
  unsigned long long siglen = 0;
  if (crypto_sign_detached(sig.data(), &siglen,
                           msg.empty() ? nullptr : msg.data(),
                           msg.size(),
                           key.secret_key.data()) != 0) {
    throw backend::Error("pack_signing: crypto_sign_detached failed");
  }
  // Static assertion-equivalent: libsodium ed25519 signatures are 64B.
  if (siglen != 64) {
    throw backend::Error("pack_signing: unexpected signature length");
  }
  return sig;
}

bool verify_buffer(const std::vector<std::uint8_t>& msg,
                   const std::array<std::uint8_t, 64>& sig,
                   const std::array<std::uint8_t, 32>& public_key) {
  ensure_sodium_init();
  return crypto_sign_verify_detached(
             sig.data(),
             msg.empty() ? nullptr : msg.data(),
             msg.size(),
             public_key.data()) == 0;
}

// ---- Producer / verifier surface ----------------------------------------
//
// Wire format (docs/14-pack-signing.md §"Wire Format"):
//
//   tar index 0  manifest.json   (manifest["format"] bumped to "ldbpack/1+sig")
//   tar index 1  signature.json  (covered.{manifest_sha256, entries[]})
//   tar index 2  signature.sig   (64 raw bytes — ed25519 detached signature
//                                  over sha256(signature.json bytes))
//   tar index 3+ sessions/...    artifacts/...                (as before)
//
// `covered.entries[]` is sorted byte-wise ascending by `name`. The
// signature is over the sha256 of `signature.json`'s serialized bytes —
// the verifier ed25519-checks the *received* signature.json verbatim
// (never re-serializes) and then independently recomputes the per-entry
// sha256s from the tar bytes it just unpacked. Each verify failure
// surfaces with a message naming which check tripped (see the
// `PackVerifyReport.error_message` formats below).

namespace {

constexpr std::string_view kSignedFormat = "ldbpack/1+sig";
constexpr std::string_view kSigJsonName  = "signature.json";
constexpr std::string_view kSigBlobName  = "signature.sig";

std::int64_t epoch_seconds_now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string sha256_hex_of(const std::vector<std::uint8_t>& bytes) {
  return ldb::util::sha256_hex(bytes);
}

// Given the canonical signature.json text, compute sha256 of those bytes
// and ed25519-sign with [key]. Returns the raw 64-byte signature.
std::array<std::uint8_t, 64>
sign_signature_json(const std::string& signature_json_text,
                    const Ed25519KeyPair& key) {
  ldb::util::Sha256 h;
  h.update(reinterpret_cast<const std::uint8_t*>(signature_json_text.data()),
           signature_json_text.size());
  auto digest = h.finalize();
  std::vector<std::uint8_t> msg(digest.begin(), digest.end());
  return sign_buffer(msg, key);
}

// Build the {signature.json, sig} pair for [tar_body] (everything BUT the
// manifest + signature entries — i.e. the entries the producer just
// emitted via build_*_pack_body), with `manifest_bytes` being the bytes
// of the manifest.json entry as it will appear on the wire.
//
// Returns the serialized signature.json text plus the raw signature.
struct SignaturePair {
  std::string                  signature_json_text;
  std::array<std::uint8_t, 64> signature_bytes;
};

SignaturePair
build_pack_signature(const std::vector<TarEntry>& body_entries,
                     const std::vector<std::uint8_t>& manifest_bytes,
                     const Ed25519KeyPair& key,
                     const std::string& signer_label) {
  // 1) Compute per-entry sha256s, sorted byte-wise ascending by name.
  struct EntryDigest { std::string name; std::string sha256; };
  std::vector<EntryDigest> digests;
  digests.reserve(body_entries.size());
  for (const auto& e : body_entries) {
    if (e.name == kSigJsonName || e.name == kSigBlobName) continue;
    EntryDigest d;
    d.name   = e.name;
    d.sha256 = sha256_hex_of(e.data);
    digests.push_back(std::move(d));
  }
  std::sort(digests.begin(), digests.end(),
            [](const EntryDigest& a, const EntryDigest& b) {
              return a.name < b.name;
            });

  // 2) Assemble signature.json. Field insertion order is fixed so the
  //    serialized form is deterministic across producers — the verifier
  //    never re-serializes, but matching producer output across rebuilds
  //    keeps round-trip tests stable.
  nlohmann::json sig_j;
  sig_j["algorithm"]  = "ed25519";
  sig_j["key_id"]     = compute_key_id(key.public_key);
  sig_j["signer"]     = signer_label;
  sig_j["created_at"] = epoch_seconds_now();
  nlohmann::json covered;
  covered["scheme"]          = "ldbpack-sig/1";
  covered["manifest_sha256"] = sha256_hex_of(manifest_bytes);
  nlohmann::json entries_arr = nlohmann::json::array();
  for (const auto& d : digests) {
    nlohmann::json e;
    e["name"]   = d.name;
    e["sha256"] = d.sha256;
    entries_arr.push_back(std::move(e));
  }
  covered["entries"] = std::move(entries_arr);
  sig_j["covered"]   = std::move(covered);

  SignaturePair out;
  out.signature_json_text = sig_j.dump();
  out.signature_bytes     = sign_signature_json(out.signature_json_text, key);
  return out;
}

// Common finalize: insert the manifest + (optionally) the signature
// entries at the front of [body_entries], tar+gzip, write the result,
// and fill a SignedPackResult.
SignedPackResult
finalize_signed_pack(std::vector<TarEntry> body_entries,
                     nlohmann::json manifest,
                     const std::filesystem::path& output_path,
                     const std::optional<Ed25519KeyPair>& key,
                     const std::optional<std::string>& signer_label) {
  std::uint64_t mtime = static_cast<std::uint64_t>(epoch_seconds_now());

  if (key.has_value()) {
    manifest["format"] = std::string(kSignedFormat);
  }
  auto manifest_entry = make_manifest_entry(manifest, mtime);
  std::vector<std::uint8_t> manifest_bytes = manifest_entry.data;

  std::optional<std::string>   sig_json_text;
  std::array<std::uint8_t, 64> sig_bytes{};

  if (key.has_value()) {
    std::string signer = signer_label.value_or("");
    auto pair = build_pack_signature(body_entries, manifest_bytes,
                                     *key, signer);
    sig_json_text = pair.signature_json_text;
    sig_bytes     = pair.signature_bytes;

    TarEntry sig_json_entry;
    sig_json_entry.name  = std::string(kSigJsonName);
    sig_json_entry.data  = std::vector<std::uint8_t>(
        pair.signature_json_text.begin(), pair.signature_json_text.end());
    sig_json_entry.mtime = mtime;

    TarEntry sig_blob_entry;
    sig_blob_entry.name  = std::string(kSigBlobName);
    sig_blob_entry.data  = std::vector<std::uint8_t>(
        sig_bytes.begin(), sig_bytes.end());
    sig_blob_entry.mtime = mtime;

    // Insertion order (reverse, so each `insert` lands at index 0):
    //   index 0: manifest.json
    //   index 1: signature.json
    //   index 2: signature.sig
    //   index 3+: sessions/... artifacts/...
    body_entries.insert(body_entries.begin(), std::move(sig_blob_entry));
    body_entries.insert(body_entries.begin(), std::move(sig_json_entry));
  }
  body_entries.insert(body_entries.begin(), std::move(manifest_entry));

  auto raw  = tar_pack(body_entries);
  auto comp = gzip_compress(raw);

  // write to disk via the same helper pack.cpp uses (create_directories
  // + atomic-ish write). Inlining the few lines here avoids extending
  // pack.h with a public write helper just for this TU.
  {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::create_directories(output_path.parent_path(), ec);
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
      throw backend::Error("pack io: open out: " + output_path.string());
    }
    if (!comp.empty()) {
      out.write(reinterpret_cast<const char*>(comp.data()),
                static_cast<std::streamsize>(comp.size()));
    }
    out.flush();
    if (!out) {
      throw backend::Error("pack io: write: " + output_path.string());
    }
  }

  SignedPackResult sr;
  sr.result.path      = output_path;
  sr.result.byte_size = static_cast<std::uint64_t>(comp.size());
  sr.result.sha256    = sha256_hex_of(comp);
  sr.result.manifest  = std::move(manifest);
  sr.signature_json   = std::move(sig_json_text);
  sr.signature_bytes  = sig_bytes;
  return sr;
}

}  // namespace

SignedPackResult
pack_session_signed(SessionStore& sessions,
                    ArtifactStore& artifacts,
                    std::string_view session_id,
                    const std::filesystem::path& output_path,
                    std::optional<Ed25519KeyPair> key,
                    std::optional<std::string> signer_label) {
  auto built = build_session_pack_body(sessions, artifacts, session_id);
  return finalize_signed_pack(std::move(built.tar_body),
                              std::move(built.manifest),
                              output_path,
                              key, signer_label);
}

SignedPackResult
pack_artifacts_signed(ArtifactStore& artifacts,
                      std::optional<std::string> build_id,
                      std::optional<std::vector<std::string>> names,
                      const std::filesystem::path& output_path,
                      std::optional<Ed25519KeyPair> key,
                      std::optional<std::string> signer_label) {
  auto built = build_artifacts_pack_body(artifacts, build_id, names);
  return finalize_signed_pack(std::move(built.tar_body),
                              std::move(built.manifest),
                              output_path,
                              key, signer_label);
}

namespace {

// Read every byte of [p] into a vector. Throws backend::Error on I/O
// failure (matches the rest of the pack toolchain).
std::vector<std::uint8_t> read_file_all(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) {
    throw backend::Error("verify_pack: open: " + p.string());
  }
  in.seekg(0, std::ios::end);
  auto sz = in.tellg();
  if (sz < 0) {
    throw backend::Error("verify_pack: tellg: " + p.string());
  }
  in.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> out(static_cast<std::size_t>(sz));
  if (sz > 0) {
    in.read(reinterpret_cast<char*>(out.data()),
            static_cast<std::streamsize>(out.size()));
    if (!in.good() && !in.eof()) {
      throw backend::Error("verify_pack: read: " + p.string());
    }
  }
  return out;
}

}  // namespace

PackVerifyReport
verify_pack(const std::filesystem::path& input_path,
            const std::optional<std::filesystem::path>& trust_root) {
  auto comp = read_file_all(input_path);
  auto raw  = gzip_decompress(comp);
  auto entries = tar_unpack(raw);

  const std::vector<std::uint8_t>* manifest_bytes = nullptr;
  const std::vector<std::uint8_t>* sig_json_bytes = nullptr;
  const std::vector<std::uint8_t>* sig_blob_bytes = nullptr;
  for (const auto& e : entries) {
    if      (e.name == "manifest.json")     manifest_bytes = &e.data;
    else if (e.name == kSigJsonName)        sig_json_bytes = &e.data;
    else if (e.name == kSigBlobName)        sig_blob_bytes = &e.data;
  }

  if (manifest_bytes == nullptr) {
    throw backend::Error("verify_pack: manifest.json missing");
  }

  PackVerifyReport rep;

  // Unsigned path: both sidecar entries absent. The manifest must NOT
  // claim "ldbpack/1+sig" — that would be an inconsistent producer.
  if (sig_json_bytes == nullptr && sig_blob_bytes == nullptr) {
    nlohmann::json mj;
    try {
      mj = nlohmann::json::parse(manifest_bytes->begin(),
                                 manifest_bytes->end());
    } catch (const std::exception& e) {
      throw backend::Error(std::string("verify_pack: manifest parse: ") +
                           e.what());
    }
    if (mj.contains("format") && mj["format"].is_string() &&
        mj["format"].get<std::string>() == kSignedFormat) {
      throw backend::Error(
          "verify_pack: manifest claims ldbpack/1+sig but signature "
          "sidecar entries are missing");
    }
    rep.is_signed = false;
    rep.verified  = false;
    return rep;
  }
  // Half-signed (one sidecar present, one missing) is malformed — the
  // producer always emits the pair atomically.
  if (sig_json_bytes == nullptr || sig_blob_bytes == nullptr) {
    throw backend::Error(
        "verify_pack: signature.json/.sig sidecar incomplete");
  }
  rep.is_signed = true;

  if (sig_blob_bytes->size() != 64) {
    rep.error_message =
        "verify_pack: signature.sig wrong length (expected 64 bytes)";
    return rep;
  }

  nlohmann::json sig_j;
  try {
    sig_j = nlohmann::json::parse(sig_json_bytes->begin(),
                                   sig_json_bytes->end());
  } catch (const std::exception& e) {
    rep.error_message = std::string("verify_pack: signature.json parse: ") +
                        e.what();
    return rep;
  }
  if (!sig_j.is_object()) {
    rep.error_message = "verify_pack: signature.json is not an object";
    return rep;
  }
  if (!sig_j.contains("algorithm") || !sig_j["algorithm"].is_string() ||
      sig_j["algorithm"].get<std::string>() != "ed25519") {
    rep.error_message = "verify_pack: signature.algorithm must be ed25519";
    return rep;
  }
  if (!sig_j.contains("key_id") || !sig_j["key_id"].is_string()) {
    rep.error_message = "verify_pack: signature.key_id missing";
    return rep;
  }
  rep.key_id = sig_j["key_id"].get<std::string>();
  if (sig_j.contains("signer") && sig_j["signer"].is_string()) {
    rep.signer = sig_j["signer"].get<std::string>();
  }
  if (!sig_j.contains("covered") || !sig_j["covered"].is_object()) {
    rep.error_message = "verify_pack: signature.covered missing";
    return rep;
  }
  const auto& covered = sig_j["covered"];
  if (!covered.contains("manifest_sha256") ||
      !covered["manifest_sha256"].is_string() ||
      !covered.contains("entries") ||
      !covered["entries"].is_array()) {
    rep.error_message = "verify_pack: signature.covered shape invalid";
    return rep;
  }

  // ed25519-verify the signature over the *received* signature.json
  // bytes (hashed). The verifier never re-serializes the JSON.
  std::array<std::uint8_t, 64> sig_arr{};
  std::memcpy(sig_arr.data(), sig_blob_bytes->data(), 64);
  {
    ldb::util::Sha256 h;
    h.update(reinterpret_cast<const std::uint8_t*>(sig_json_bytes->data()),
             sig_json_bytes->size());
    auto digest = h.finalize();
    std::vector<std::uint8_t> msg(digest.begin(), digest.end());

    // Pull the public key out of the signing key_id — we don't actually
    // have it on the wire; we need to look it up in the trust root.
    // BUT: ed25519 verify requires the public-key bytes. The verifier
    // approach: if no trust root, we can't verify (we don't trust the
    // signer anyway). If trust root is given, the matching key gives us
    // the public bytes to verify against; if no trust-root key matches
    // the in-pack key_id, that itself is a failure (signer not trusted).
    if (!trust_root.has_value()) {
      // Internal-consistency-only mode: we still want to flag tampering
      // detectable from the JSON contents (manifest hash, entry hashes).
      // Without the public key we cannot ed25519-verify, so callers in
      // this branch get `verified=false` (the signer is unauthenticated)
      // but the import proceeds — see docs/14 §"Failure Semantics".
      rep.verified = false;
      // Still recompute the manifest hash and per-entry hashes so we
      // can surface tampering as an error even when no trust root is
      // configured. Tests 6 + 10 don't exercise this branch (they all
      // pass a trust root), but the dispatcher's "no trust_root,
      // require_signed=false" path benefits.
    } else {
      // Resolve the public-key bytes via the trust root. We need a
      // map<key_id, public_bytes>; load_trust_root only returns the
      // set, so do a small inline load here. (Performance is fine — a
      // trust root is dozens of keys at most.)
      std::array<std::uint8_t, 32> pub_bytes{};
      bool found = false;
      namespace fs = std::filesystem;
      std::error_code ec;
      if (!fs::exists(*trust_root, ec)) {
        throw backend::Error("verify_pack: trust_root not found: " +
                             trust_root->string());
      }
      std::vector<std::string> lines;
      if (fs::is_directory(*trust_root, ec)) {
        std::vector<fs::path> pubs;
        for (auto& de : fs::directory_iterator(*trust_root, ec)) {
          if (ec) break;
          if (!de.is_regular_file(ec)) continue;
          if (de.path().extension() == ".pub") pubs.push_back(de.path());
        }
        std::sort(pubs.begin(), pubs.end());
        for (const auto& p : pubs) {
          std::ifstream in(p);
          if (!in) {
            throw backend::Error("verify_pack: trust_root: cannot read " +
                                 p.string());
          }
          std::stringstream ss; ss << in.rdbuf();
          lines.push_back(ss.str());
        }
      } else {
        std::ifstream in(*trust_root);
        if (!in) {
          throw backend::Error("verify_pack: trust_root: cannot read " +
                               trust_root->string());
        }
        std::string line;
        while (std::getline(in, line)) {
          while (!line.empty() &&
                 (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
          }
          std::size_t i = 0;
          while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
          if (i >= line.size() || line[i] == '#') continue;
          lines.push_back(line);
        }
      }
      for (const auto& ln : lines) {
        auto pk = parse_openssh_public_key(ln);
        if (pk.key_id == rep.key_id) {
          pub_bytes = pk.bytes;
          found = true;
          break;
        }
      }
      if (!found) {
        rep.verified = false;
        rep.error_message =
            "verify_pack: signer key_id " + rep.key_id +
            " not present in trust_root";
        return rep;
      }
      if (!verify_buffer(msg, sig_arr, pub_bytes)) {
        rep.verified = false;
        rep.error_message =
            "verify_pack: ed25519 signature did not verify "
            "over signature.json (signer " + rep.key_id + ")";
        return rep;
      }
    }
  }

  // Compare covered.manifest_sha256 against the bytes we just unpacked.
  std::string actual_mhash = sha256_hex_of(*manifest_bytes);
  if (covered["manifest_sha256"].get<std::string>() != actual_mhash) {
    rep.verified = false;
    rep.error_message =
        "verify_pack: manifest.json sha256 mismatch (covered says " +
        covered["manifest_sha256"].get<std::string>() +
        ", actual " + actual_mhash + ")";
    return rep;
  }

  // Recompute each entry's sha256 and verify the set matches the
  // non-signature tar entries.
  std::set<std::string> claimed_names;
  for (const auto& ce : covered["entries"]) {
    if (!ce.is_object() ||
        !ce.contains("name")   || !ce["name"].is_string() ||
        !ce.contains("sha256") || !ce["sha256"].is_string()) {
      rep.verified = false;
      rep.error_message =
          "verify_pack: covered.entries[] item shape invalid";
      return rep;
    }
    std::string name = ce["name"].get<std::string>();
    std::string want = ce["sha256"].get<std::string>();
    claimed_names.insert(name);
    const std::vector<std::uint8_t>* data = nullptr;
    for (const auto& e : entries) {
      if (e.name == name) { data = &e.data; break; }
    }
    if (data == nullptr) {
      rep.verified = false;
      rep.error_message =
          "verify_pack: covered entry '" + name +
          "' has no matching tar entry";
      return rep;
    }
    std::string got = sha256_hex_of(*data);
    if (got != want) {
      rep.verified = false;
      rep.error_message =
          "verify_pack: sha256 mismatch for '" + name +
          "' (expected " + want + ", got " + got + ")";
      return rep;
    }
  }
  // Extras: tar entries other than signature.json / signature.sig /
  // manifest.json must each appear in claimed_names.
  for (const auto& e : entries) {
    if (e.name == "manifest.json" || e.name == kSigJsonName ||
        e.name == kSigBlobName) continue;
    if (claimed_names.count(e.name) == 0) {
      rep.verified = false;
      rep.error_message =
          "verify_pack: tar entry '" + e.name +
          "' is not listed in covered.entries[]";
      return rep;
    }
  }

  // Reached here:
  //   * trust_root absent → verified stays false (signer unauthenticated)
  //   * trust_root present → all checks passed → verified = true
  if (trust_root.has_value()) {
    rep.verified = true;
  }
  return rep;
}

std::string compute_key_id(const std::array<std::uint8_t, 32>& public_key) {
  // ssh-keygen -l prints "<bits> SHA256:<base64-no-pad> <comment>". The
  // SHA256 is over the raw 32-byte ed25519 public key (matching the
  // wire-format `ssh-ed25519` body), and the base64 form drops trailing
  // `=` padding.
  ldb::util::Sha256 h;
  h.update(public_key.data(), public_key.size());
  auto digest = h.finalize();
  std::string b64 = base64_encode(digest.data(), digest.size(),
                                  /*pad=*/false);
  return "SHA256:" + b64;
}

}  // namespace ldb::store
