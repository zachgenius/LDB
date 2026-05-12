// SPDX-License-Identifier: Apache-2.0
#include "util/base64.h"

namespace ldb::util {

namespace {

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
  if (c >= '0' && c <= '9') return 52 + (c - '0');
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

}  // namespace

std::string base64_encode(const std::uint8_t* data, std::size_t len,
                          bool pad) {
  std::string out;
  out.reserve(((len + 2u) / 3u) * 4u);
  std::size_t i = 0;
  while (i + 3u <= len) {
    std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16) |
                      (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                       static_cast<std::uint32_t>(data[i + 2]);
    out.push_back(kAlphabet[(v >> 18) & 0x3Fu]);
    out.push_back(kAlphabet[(v >> 12) & 0x3Fu]);
    out.push_back(kAlphabet[(v >> 6)  & 0x3Fu]);
    out.push_back(kAlphabet[ v        & 0x3Fu]);
    i += 3;
  }
  if (i < len) {
    std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
    if (i + 1u < len) v |= static_cast<std::uint32_t>(data[i + 1]) << 8;
    out.push_back(kAlphabet[(v >> 18) & 0x3Fu]);
    out.push_back(kAlphabet[(v >> 12) & 0x3Fu]);
    if (i + 1u < len) {
      out.push_back(kAlphabet[(v >> 6) & 0x3Fu]);
      if (pad) out.push_back('=');
    } else if (pad) {
      out.push_back('=');
      out.push_back('=');
    }
  }
  return out;
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
      throw backend::Error("base64: bad character");
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

}  // namespace ldb::util
