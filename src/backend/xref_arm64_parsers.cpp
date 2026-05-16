// SPDX-License-Identifier: Apache-2.0
#include "backend/xref_arm64_parsers.h"

#include <cctype>

namespace ldb::backend::xref_arm64 {

namespace {

// Accumulate digits at s[pos]; returns {ok, magnitude, end_pos}. ok is
// false when there's not a single digit to consume after the optional
// hex prefix. Hex prefix is `0x` or `0X`; decimal otherwise.
std::tuple<bool, std::uint64_t, std::size_t>
parse_magnitude(const std::string& s, std::size_t pos) {
  bool hex = false;
  if (pos + 1 < s.size() && s[pos] == '0' &&
      (s[pos + 1] == 'x' || s[pos + 1] == 'X')) {
    hex = true;
    pos += 2;
  }
  std::uint64_t value = 0;
  std::size_t   start = pos;
  while (pos < s.size()) {
    char c = s[pos];
    unsigned int d;
    if (c >= '0' && c <= '9')             d = static_cast<unsigned int>(c - '0');
    else if (hex && c >= 'a' && c <= 'f') d = static_cast<unsigned int>(c - 'a' + 10);
    else if (hex && c >= 'A' && c <= 'F') d = static_cast<unsigned int>(c - 'A' + 10);
    else break;
    value = (value * (hex ? 16ULL : 10ULL)) + d;
    ++pos;
  }
  if (pos == start) return {false, 0, pos};
  return {true, value, pos};
}

}  // namespace

std::tuple<bool, std::uint64_t, std::size_t>
parse_uint_at(const std::string& s, std::size_t pos) {
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
  if (pos < s.size() && s[pos] == '#') ++pos;
  if (pos >= s.size()) return {false, 0, pos};
  return parse_magnitude(s, pos);
}

std::tuple<bool, std::int64_t, std::size_t>
parse_int_at(const std::string& s, std::size_t pos) {
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
  if (pos < s.size() && s[pos] == '#') ++pos;
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
  bool negative = false;
  if (pos < s.size() && s[pos] == '-') {
    negative = true;
    ++pos;
  }
  if (pos >= s.size()) return {false, 0, pos};
  auto [ok, mag, end] = parse_magnitude(s, pos);
  if (!ok) return {false, 0, end};
  // Cast magnitude to signed; the wrap is intentional for INT64_MIN-
  // shaped immediates, but ADRP page counts are 21-bit signed so the
  // magnitude never approaches INT64_MAX in practice.
  std::int64_t signed_value = static_cast<std::int64_t>(mag);
  if (negative) signed_value = -signed_value;
  return {true, signed_value, end};
}

std::tuple<bool, std::string, std::size_t>
parse_reg_at(const std::string& s, std::size_t pos) {
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == ','))
    ++pos;
  std::size_t start = pos;
  while (pos < s.size()) {
    char c = s[pos];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
      ++pos;
    } else {
      break;
    }
  }
  if (pos == start) return {false, {}, pos};
  std::string tok = s.substr(start, pos - start);
  for (auto& ch : tok) ch = static_cast<char>(std::tolower(ch));
  if (!tok.empty() && tok[0] == 'w') tok[0] = 'x';
  return {true, std::move(tok), pos};
}

}  // namespace ldb::backend::xref_arm64
