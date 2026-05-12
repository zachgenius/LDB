// SPDX-License-Identifier: Apache-2.0
// Unit tests for GDB RSP framing (post-V1 #17 phase-1).
//
// Coverage:
//   • Checksum is the lower 8 bits of the byte-sum, emitted as two
//     lower-case hex digits.
//   • encode_packet wraps payload in $...# + cs8 and escapes the
//     reserved bytes #, $, } via the } XOR 0x20 rule.
//   • decode_packet expects a $...# + cs8 envelope, unescapes the
//     reserved bytes, validates the checksum, and unrolls RLE
//     expansions (*N where N = count + 28 ASCII).
//   • Bad shape (missing $, missing #, short checksum, non-hex
//     checksum, checksum mismatch) → DecodeError with a sensible
//     code.
//   • The reader's stream interface tolerates packets arriving with
//     a stray + (ack) byte before the $ — gdb-remote servers send
//     these freely.
//
// Test vectors come straight from the gdb-remote spec
// (`docs/25-own-rsp-client.md` §2.3 + the GDB online manual).

#include <catch_amalgamated.hpp>

#include "transport/rsp/framing.h"

#include <sstream>
#include <string>
#include <vector>

using ldb::transport::rsp::DecodeError;
using ldb::transport::rsp::DecodeResult;
using ldb::transport::rsp::checksum8;
using ldb::transport::rsp::decode_packet;
using ldb::transport::rsp::encode_packet;

namespace {

// Helper: build a $...#cs string by hand to compare against the encoder.
std::string frame(std::string_view payload, std::string_view cs) {
  return std::string("$") + std::string(payload) + "#" + std::string(cs);
}

}  // namespace

TEST_CASE("rsp/framing: checksum8 is the byte-sum mod 256, lower-case hex",
          "[rsp][framing][checksum]") {
  // Empty payload sums to 0.
  CHECK(checksum8("") == "00");
  // gdb spec example: "qSupported".
  // 'q'+'S'+'u'+'p'+'p'+'o'+'r'+'t'+'e'+'d' = 113+83+117+112+112+111+114+116+101+100 = 1079
  // 1079 mod 256 = 55 = 0x37.
  CHECK(checksum8("qSupported") == "37");
  // Single byte "?" = 63 = 0x3f.
  CHECK(checksum8("?") == "3f");
  // Sum that ends in a lower-hex digit — verify case is lower.
  // "OK" = 79+75 = 154 = 0x9a.
  CHECK(checksum8("OK") == "9a");
}

TEST_CASE("rsp/framing: encode_packet wraps payload with $...# + cs8",
          "[rsp][framing][encode]") {
  CHECK(encode_packet("?") == frame("?", "3f"));
  CHECK(encode_packet("qSupported") == frame("qSupported", "37"));
  // Empty packet — used as the "unsupported" reply.
  CHECK(encode_packet("") == frame("", "00"));
}

TEST_CASE("rsp/framing: encode escapes $, #, } via the } XOR 0x20 rule",
          "[rsp][framing][encode][escape]") {
  // The reserved bytes must be escaped inside payload. The escape
  // byte is `}` and the escaped byte is original ^ 0x20.
  //   #  (0x23) → }(0x7d) + 0x03  = "}\x03"
  //   $  (0x24) → }(0x7d) + 0x04  = "}\x04"
  //   }  (0x7d) → }(0x7d) + 0x5d  = "}]"
  std::string in;
  in.push_back('#');
  in.push_back('$');
  in.push_back('}');
  auto out = encode_packet(in);
  // After escape, the payload between $ and # is: } 0x03 } 0x04 } ]
  // Its checksum: (0x7d + 0x03 + 0x7d + 0x04 + 0x7d + 0x5d) & 0xff
  //             = 475 & 0xff = 0xdb.
  std::string expected = "$";
  expected.push_back(0x7d); expected.push_back(0x03);
  expected.push_back(0x7d); expected.push_back(0x04);
  expected.push_back(0x7d); expected.push_back(0x5d);
  expected += "#db";
  CHECK(out == expected);
}

TEST_CASE("rsp/framing: decode_packet unwraps $...#cs and verifies cs",
          "[rsp][framing][decode]") {
  std::string raw = encode_packet("OK");
  auto r = decode_packet(raw);
  REQUIRE(r.error == DecodeError::kOk);
  CHECK(r.payload == "OK");
  CHECK(r.consumed == raw.size());
}

TEST_CASE("rsp/framing: decode unescapes the reserved-byte trio",
          "[rsp][framing][decode][escape]") {
  // Same payload as the encode-escape test, but feed bytes back in.
  std::string raw = "$";
  raw.push_back(0x7d); raw.push_back(0x03);   // -> '#'
  raw.push_back(0x7d); raw.push_back(0x04);   // -> '$'
  raw.push_back(0x7d); raw.push_back(0x5d);   // -> '}'
  raw += "#db";   // wire-cs of the 6 escaped bytes (see encode test)
  auto r = decode_packet(raw);
  REQUIRE(r.error == DecodeError::kOk);
  REQUIRE(r.payload.size() == 3);
  CHECK(static_cast<unsigned char>(r.payload[0]) == 0x23);
  CHECK(static_cast<unsigned char>(r.payload[1]) == 0x24);
  CHECK(static_cast<unsigned char>(r.payload[2]) == 0x7d);
}

TEST_CASE("rsp/framing: decode RLE expands *N (N = count + 28 ASCII)",
          "[rsp][framing][decode][rle]") {
  // "0* " is "0 repeated 3 times" — '*' followed by ' ' (0x20).
  // gdb RLE: the byte after * is (repeat_count + 28) in ASCII. Space
  // = 0x20 - 0x1c = 4 → meaning "repeat the previous byte 4 times"
  // for a total of 1 (original) + 3 (expanded) = 4 zeros.
  //
  // Actually the spec is: the repeat count is the ASCII char minus
  // 29 (i.e. ' ' = 4 means 4 additional copies). The previous-char
  // appears 1 + count times in the expanded output.
  //
  // Our encoder never produces RLE; our decoder must handle it.
  // Build a literal RLE-bearing packet and verify expansion.
  //
  // Payload "0* " expands to "0000" (1 + 3 copies).
  // Checksum of "0* " (the WIRE bytes) = '0'+'*'+' ' = 0x30+0x2a+0x20
  //   = 0x7a → "7a".
  std::string raw = "$0* #7a";
  auto r = decode_packet(raw);
  REQUIRE(r.error == DecodeError::kOk);
  CHECK(r.payload == "0000");
}

TEST_CASE("rsp/framing: decode rejects payload that doesn't start with $",
          "[rsp][framing][decode][error]") {
  auto r = decode_packet("OK#9a");
  CHECK(r.error == DecodeError::kBadStart);
}

TEST_CASE("rsp/framing: decode reports kIncomplete when payload truncates",
          "[rsp][framing][decode][error]") {
  // Missing the trailing #cs.
  auto r = decode_packet("$OK");
  CHECK(r.error == DecodeError::kIncomplete);
  // Missing one of the two cs digits.
  auto r2 = decode_packet("$OK#9");
  CHECK(r2.error == DecodeError::kIncomplete);
}

TEST_CASE("rsp/framing: decode rejects checksum mismatch with kBadChecksum",
          "[rsp][framing][decode][error]") {
  // Right shape, wrong cs.
  auto r = decode_packet("$OK#00");
  CHECK(r.error == DecodeError::kBadChecksum);
}

TEST_CASE("rsp/framing: decode rejects non-hex checksum",
          "[rsp][framing][decode][error]") {
  auto r = decode_packet("$OK#zz");
  CHECK(r.error == DecodeError::kBadChecksum);
}

TEST_CASE("rsp/framing: decode tolerates a leading + (ack)",
          "[rsp][framing][decode][ack]") {
  // gdb-remote servers freely send + (ack) bytes between packets;
  // the decoder should skip over leading +/− bytes and find the $.
  std::string raw = std::string("+") + encode_packet("OK");
  auto r = decode_packet(raw);
  REQUIRE(r.error == DecodeError::kOk);
  CHECK(r.payload == "OK");
  CHECK(r.consumed == raw.size());
}

TEST_CASE("rsp/framing: decode handles multiple packets — reports consumed",
          "[rsp][framing][decode][stream]") {
  // The decoder is used in a streaming loop. It must report exactly
  // how many bytes it consumed so the caller can advance the read
  // buffer.
  std::string raw = encode_packet("OK") + encode_packet("?");
  auto r = decode_packet(raw);
  REQUIRE(r.error == DecodeError::kOk);
  CHECK(r.payload == "OK");
  CHECK(r.consumed < raw.size());

  // Slice off the first packet, decode the rest.
  std::string rest = raw.substr(r.consumed);
  auto r2 = decode_packet(rest);
  REQUIRE(r2.error == DecodeError::kOk);
  CHECK(r2.payload == "?");
}

TEST_CASE("rsp/framing: RLE that would exceed kMaxPayloadBytes is rejected",
          "[rsp][framing][decode][rle][error]") {
  // A maliciously-large RLE expansion must be rejected rather than
  // allocating arbitrarily. '~' (0x7e) = 126 → 97 additional copies
  // per *. kMaxPayloadBytes is 256 KiB; we need >2700 cycles of "*~"
  // to exceed it. Use 3000 for headroom.
  std::string payload = "0";
  for (int i = 0; i < 3000; ++i) {
    payload += "*~";  // each adds 97 copies → 97 * 3000 ≈ 291k chars
  }
  std::string raw = "$" + payload + "#" + std::string(checksum8(payload));
  auto r = decode_packet(raw);
  CHECK(r.error == DecodeError::kPayloadTooLarge);
}
