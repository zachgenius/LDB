// SPDX-License-Identifier: Apache-2.0
#pragma once

// GDB RSP packet framing (post-V1 plan #17, docs/25-own-rsp-client.md
// §2.3). This module is intentionally narrow: it knows the wire shape
// of a single packet ($payload#cs8 with escape + RLE) and nothing
// about the packet vocabulary (`?`, `qSupported`, `m`, ...). The
// channel layer composes framing + I/O; the packets layer composes
// framing + typed builders/parsers.
//
// All functions are stateless and exception-free — callers consume
// the typed error code in DecodeResult.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace ldb::transport::rsp {

// Hard cap on a decoded payload's size. The RSP spec allows servers
// to negotiate larger packets via qSupported's `PacketSize=`, but
// the cap defends against a malicious or buggy peer using RLE to
// balloon a small wire-buffer into gigabytes of allocation.
inline constexpr std::size_t kMaxPayloadBytes = 256 * 1024;

// Lower 8 bits of the byte-sum of `payload`, formatted as two
// lower-case hex digits. Pure; no allocations beyond the 2-char
// return string.
std::string checksum8(std::string_view payload);

// Wrap `payload` as a complete RSP packet on the wire:
//   $<escaped payload>#<cs8>
// where #, $, and } in the payload are escaped via the
// "} XOR 0x20" rule. The encoder never produces RLE — it's a
// space-saving optimisation we don't need on send.
std::string encode_packet(std::string_view payload);

// Decode error codes. kOk + a populated `payload` is the only
// success path; every other code leaves `payload` empty.
enum class DecodeError {
  kOk = 0,
  kBadStart,         // input doesn't start with $ (after stripping +/-)
  kIncomplete,       // input ended before the # or before both cs digits
  kBadChecksum,      // checksum mismatch or non-hex digits
  kBadEscape,        // a } that wasn't followed by a valid escaped byte
  kBadRle,           // a * that wasn't followed by a printable repeat
  kPayloadTooLarge,  // expansion (post-RLE) exceeds kMaxPayloadBytes
};

struct DecodeResult {
  DecodeError  error    = DecodeError::kIncomplete;
  std::string  payload;
  // How many bytes of the input were consumed. On error == kOk, the
  // caller can advance its read buffer by this much and call decode
  // again to peel off the next packet. On error != kOk, undefined.
  std::size_t  consumed = 0;
};

// Try to decode one packet from the front of `input`. Leading +/−
// (ack/nack) bytes are skipped — gdb-remote servers send them
// freely. RLE is expanded; escape is unescaped; checksum is verified.
// Streaming-friendly: returns kIncomplete when the buffer doesn't
// hold a full packet so the caller can wait for more bytes.
DecodeResult decode_packet(std::string_view input);

}  // namespace ldb::transport::rsp
