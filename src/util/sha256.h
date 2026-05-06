#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

// Public-domain reference SHA-256 — extracted out of store/artifact_store.cpp
// and store/pack.cpp so the same hand-rolled implementation backs every
// caller (artifacts, .ldbpack manifests, and the cores-only `_provenance`
// snapshot in M5 part 6). We intentionally don't pull in OpenSSL just for
// this — SHA-256 is small enough to keep in-tree and easy to audit.
//
// Verified against the NIST short-message vectors in
// `tests/unit/test_util_sha256.cpp`:
//   sha256("")    = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//   sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
//
// All hex output is lowercase, matching what the artifact store has been
// emitting since M3.

namespace ldb::util {

class Sha256 {
 public:
  Sha256() { reset(); }

  void update(const std::uint8_t* data, std::size_t len);
  void update(std::string_view sv) {
    update(reinterpret_cast<const std::uint8_t*>(sv.data()), sv.size());
  }

  // Produce the 32-byte digest. Resets the internal state — calling
  // finalize twice on the same instance returns sha256("") the second
  // time. (Defensive: the artifact-store call sites always discard the
  // hasher after one finalize.)
  std::array<std::uint8_t, 32> finalize();

 private:
  void reset();
  static std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
    return (x >> n) | (x << (32u - n));
  }
  void compress(const std::uint8_t* p);

  std::array<std::uint32_t, 8> h_{};
  std::uint8_t  buf_[64]{};
  std::size_t   buf_len_   = 0;
  std::uint64_t bit_count_ = 0;
};

// Convenience: hex-encode a 32-byte digest.
std::string sha256_hex(const std::array<std::uint8_t, 32>& digest);

// One-shot helpers — common case.
std::string sha256_hex(const std::vector<std::uint8_t>& bytes);
std::string sha256_hex(std::string_view bytes);

// Hash an on-disk file by streaming it through Sha256 in 64 KiB chunks.
// Throws std::runtime_error if the file cannot be opened or read. The
// path is resolved by the caller (no globbing, no relative-to-CWD
// surprises here).
std::string sha256_file_hex(const std::string& path);

}  // namespace ldb::util
