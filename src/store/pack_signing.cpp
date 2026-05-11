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
#include "util/sha256.h"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
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

// ---- base64 (standard alphabet, "+/", with "=" padding) -----------------
//
// OpenSSH `.pub` files use the standard alphabet, NOT URL-safe. The
// `key_id` form ("SHA256:<base64>") historically drops trailing `=`
// padding to match `ssh-keygen -l`'s output exactly — we do the same.

constexpr char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::uint8_t* data, std::size_t len,
                          bool pad) {
  std::string out;
  out.reserve(((len + 2u) / 3u) * 4u);
  std::size_t i = 0;
  while (i + 3u <= len) {
    std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                      (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                       static_cast<std::uint32_t>(data[i + 2]);
    out.push_back(kB64Alphabet[(v >> 18) & 0x3Fu]);
    out.push_back(kB64Alphabet[(v >> 12) & 0x3Fu]);
    out.push_back(kB64Alphabet[(v >> 6)  & 0x3Fu]);
    out.push_back(kB64Alphabet[ v        & 0x3Fu]);
    i += 3;
  }
  if (i < len) {
    std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
    if (i + 1u < len) v |= static_cast<std::uint32_t>(data[i + 1]) << 8;
    out.push_back(kB64Alphabet[(v >> 18) & 0x3Fu]);
    out.push_back(kB64Alphabet[(v >> 12) & 0x3Fu]);
    if (i + 1u < len) {
      out.push_back(kB64Alphabet[(v >> 6) & 0x3Fu]);
      if (pad) out.push_back('=');
    } else if (pad) {
      out.push_back('=');
      out.push_back('=');
    }
  }
  return out;
}

int b64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
  if (c >= '0' && c <= '9') return 52 + (c - '0');
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

std::vector<std::uint8_t> base64_decode(std::string_view s) {
  std::vector<std::uint8_t> out;
  out.reserve((s.size() / 4u) * 3u);
  std::uint32_t acc = 0;
  int bits = 0;
  for (char c : s) {
    if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
    if (c == '=') break;
    int v = b64_value(c);
    if (v < 0) {
      throw backend::Error("pack_signing: bad base64 character");
    }
    acc = (acc << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xFFu));
    }
  }
  return out;
}

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
// The bodies below are intentional stubs. The next task wires in the real
// implementation: emit `signature.json` + `signature.sig` tar entries
// after `manifest.json`, bump `manifest["format"]` to `"ldbpack/1+sig"`,
// and add an `unpack`-side path that recomputes per-entry sha256s and
// ed25519-verifies. Unit tests 5–10 in `tests/unit/test_pack_signing.cpp`
// will fail with "pack_signing: not implemented" until that lands —
// which is the expected failure-mode for this TDD checkpoint.

SignedPackResult
pack_session_signed(SessionStore& /*sessions*/,
                    ArtifactStore& /*artifacts*/,
                    std::string_view /*session_id*/,
                    const std::filesystem::path& /*output_path*/,
                    std::optional<Ed25519KeyPair> /*key*/,
                    std::optional<std::string> /*signer_label*/) {
  throw backend::Error("pack_signing: not implemented");
}

SignedPackResult
pack_artifacts_signed(ArtifactStore& /*artifacts*/,
                      std::optional<std::string> /*build_id*/,
                      std::optional<std::vector<std::string>> /*names*/,
                      const std::filesystem::path& /*output_path*/,
                      std::optional<Ed25519KeyPair> /*key*/,
                      std::optional<std::string> /*signer_label*/) {
  throw backend::Error("pack_signing: not implemented");
}

PackVerifyReport
verify_pack(const std::filesystem::path& /*input_path*/,
            const std::optional<std::filesystem::path>& /*trust_root*/) {
  throw backend::Error("pack_signing: not implemented");
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
