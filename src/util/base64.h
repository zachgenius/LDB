// SPDX-License-Identifier: Apache-2.0
#pragma once

// Standard-alphabet base64 (RFC 4648 §4 — "+/" alphabet, "=" padding).
//
// Two callers today:
//   * src/store/pack_signing.cpp — ssh key blob handling
//   * src/daemon/dispatcher.cpp predicate.compile — bytecode encoding
//     for agent expressions (post-V1 #25 phase-2)
//
// Decode tolerates whitespace (\r \n space tab) for line-broken input
// from text files. It throws backend::Error on non-base64 characters.

#include "backend/debugger_backend.h"   // backend::Error

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ldb::util {

// Encode `len` bytes from `data`. `pad` controls trailing `=` padding;
// pack_signing's SHA256:<b64> form drops padding to match
// `ssh-keygen -l`, so the flag exists.
std::string base64_encode(const std::uint8_t* data, std::size_t len,
                          bool pad = true);

inline std::string base64_encode(std::string_view bytes, bool pad = true) {
  return base64_encode(
      reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size(), pad);
}

inline std::string base64_encode(const std::vector<std::uint8_t>& v,
                                  bool pad = true) {
  return base64_encode(v.data(), v.size(), pad);
}

// Decode `s` into bytes. Tolerates whitespace; stops at `=`. Throws
// backend::Error on a non-base64 character.
std::vector<std::uint8_t> base64_decode(std::string_view s);

}  // namespace ldb::util
