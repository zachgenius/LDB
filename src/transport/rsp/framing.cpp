// SPDX-License-Identifier: Apache-2.0
#include "transport/rsp/framing.h"

#include <cctype>
#include <cstdint>

namespace ldb::transport::rsp {

namespace {

constexpr unsigned char kEscapeByte = 0x7d;   // '}'
constexpr unsigned char kPacketStart = 0x24;  // '$'
constexpr unsigned char kPacketEnd   = 0x23;  // '#'
constexpr unsigned char kRleByte     = 0x2a;  // '*'

char hex_lower(unsigned nibble) {
  return static_cast<char>(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));
}

bool from_hex(char c, unsigned* out) {
  if (c >= '0' && c <= '9') { *out = static_cast<unsigned>(c - '0'); return true; }
  if (c >= 'a' && c <= 'f') { *out = static_cast<unsigned>(c - 'a' + 10); return true; }
  if (c >= 'A' && c <= 'F') { *out = static_cast<unsigned>(c - 'A' + 10); return true; }
  return false;
}

// Reserved bytes that must be escaped INSIDE the payload (between $
// and #). The escape rule applies symmetrically on encode and decode.
bool is_reserved(unsigned char c) {
  return c == kPacketStart || c == kPacketEnd || c == kEscapeByte;
}

}  // namespace

std::string checksum8(std::string_view payload) {
  unsigned sum = 0;
  for (unsigned char c : payload) sum += c;
  sum &= 0xff;
  std::string out;
  out.push_back(hex_lower((sum >> 4) & 0xf));
  out.push_back(hex_lower(sum & 0xf));
  return out;
}

std::string encode_packet(std::string_view payload) {
  // Pre-size: $ + escaped payload (at most 2x) + # + 2 cs digits.
  std::string escaped;
  escaped.reserve(payload.size() * 2 + 4);
  for (unsigned char c : payload) {
    if (is_reserved(c)) {
      escaped.push_back(static_cast<char>(kEscapeByte));
      escaped.push_back(static_cast<char>(c ^ 0x20));
    } else {
      escaped.push_back(static_cast<char>(c));
    }
  }
  std::string out;
  out.reserve(escaped.size() + 4);
  out.push_back('$');
  out.append(escaped);
  out.push_back('#');
  out.append(checksum8(escaped));
  return out;
}

DecodeResult decode_packet(std::string_view input) {
  DecodeResult r;
  // 1. Skip leading +/− (gdb-remote ack/nack bytes the server may
  //    intersperse between real packets). Bail with kIncomplete if
  //    the buffer runs out before we find a $.
  std::size_t i = 0;
  while (i < input.size() && (input[i] == '+' || input[i] == '-')) ++i;
  if (i == input.size()) {
    // We consumed all the input but found no $ — treat as incomplete
    // so streaming callers wait for more bytes.
    r.error = DecodeError::kIncomplete;
    return r;
  }
  if (static_cast<unsigned char>(input[i]) != kPacketStart) {
    r.error = DecodeError::kBadStart;
    return r;
  }
  std::size_t payload_start = i + 1;

  // 2. Find the # terminator, copying-with-unescape-and-RLE-expand
  //    as we go. The wire-level checksum is computed over the
  //    *escaped* bytes (i.e. the wire bytes between $ and #), so we
  //    accumulate that in parallel with the decoded output.
  unsigned cs_running = 0;
  std::string decoded;
  decoded.reserve(64);
  unsigned char prev_decoded = 0;
  bool have_prev = false;

  std::size_t j = payload_start;
  while (j < input.size()) {
    unsigned char c = static_cast<unsigned char>(input[j]);
    if (c == kPacketEnd) break;

    // Track the wire checksum BEFORE consuming the byte's special
    // meaning (escape / RLE markers all contribute as their literal
    // value; this matches the gdb spec).
    cs_running = (cs_running + c) & 0xff;

    if (c == kEscapeByte) {
      // Escape: next byte XOR 0x20 is the decoded literal.
      if (j + 1 >= input.size()) {
        r.error = DecodeError::kIncomplete;
        return r;
      }
      unsigned char next = static_cast<unsigned char>(input[j + 1]);
      cs_running = (cs_running + next) & 0xff;
      unsigned char lit = next ^ 0x20;
      if (decoded.size() >= kMaxPayloadBytes) {
        r.error = DecodeError::kPayloadTooLarge;
        return r;
      }
      decoded.push_back(static_cast<char>(lit));
      prev_decoded = lit;
      have_prev = true;
      j += 2;
      continue;
    }

    if (c == kRleByte) {
      // RLE: '*' is followed by an ASCII byte N; repeat the previous
      // decoded byte (N - 29) additional times. (gdb spec: N is the
      // ASCII char; '+'=29 is illegal-as-count; ' '=32 means 3
      // additional copies; '~'=126 means 97 additional copies.)
      if (!have_prev) {
        // * with nothing to repeat — malformed.
        r.error = DecodeError::kBadRle;
        return r;
      }
      if (j + 1 >= input.size()) {
        r.error = DecodeError::kIncomplete;
        return r;
      }
      unsigned char n = static_cast<unsigned char>(input[j + 1]);
      cs_running = (cs_running + n) & 0xff;
      if (n < 29 || n > 126) {
        r.error = DecodeError::kBadRle;
        return r;
      }
      std::size_t extra = static_cast<std::size_t>(n) - 29;
      if (decoded.size() + extra > kMaxPayloadBytes) {
        r.error = DecodeError::kPayloadTooLarge;
        return r;
      }
      decoded.append(extra, static_cast<char>(prev_decoded));
      j += 2;
      continue;
    }

    // Plain literal byte.
    if (decoded.size() >= kMaxPayloadBytes) {
      r.error = DecodeError::kPayloadTooLarge;
      return r;
    }
    decoded.push_back(static_cast<char>(c));
    prev_decoded = c;
    have_prev = true;
    ++j;
  }

  if (j >= input.size()) {
    // No # found yet — wait for more bytes.
    r.error = DecodeError::kIncomplete;
    return r;
  }
  // 3. Two-digit checksum after #.
  if (j + 2 >= input.size()) {
    r.error = DecodeError::kIncomplete;
    return r;
  }
  unsigned hi = 0, lo = 0;
  if (!from_hex(input[j + 1], &hi) || !from_hex(input[j + 2], &lo)) {
    r.error = DecodeError::kBadChecksum;
    return r;
  }
  unsigned cs_wire = (hi << 4) | lo;
  if (cs_wire != cs_running) {
    r.error = DecodeError::kBadChecksum;
    return r;
  }

  r.error    = DecodeError::kOk;
  r.payload  = std::move(decoded);
  r.consumed = j + 3;  // include the #, hi, lo
  return r;
}

}  // namespace ldb::transport::rsp
