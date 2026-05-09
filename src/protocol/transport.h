// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nlohmann/json.hpp>

#include <iosfwd>
#include <optional>
#include <stdexcept>
#include <string>

// Wire-format transport for ldbd's stdio channel.
//
// Two formats are supported:
//   * kJson: line-delimited (`\n`) UTF-8 JSON, one message per line. M0
//     default. Line buffering means one `getline` per call, but write_message
//     still flushes after every frame so a peer reading line-by-line never
//     stalls behind output buffering.
//   * kCbor: length-prefixed binary CBOR (RFC 8949). Frame layout is
//     `[4-byte big-endian uint32 length][N bytes of CBOR encoded value]`.
//     M5 part 3 — selected at startup via --format=cbor.
//
// Per-session format negotiation via `hello` is intentionally deferred —
// it requires recognizing the wire format of an incoming message before
// parsing it, which adds parser surface for negligible benefit when every
// known client knows what it speaks ahead of time. Document and revisit
// post-MVP.

namespace ldb::protocol {

using json = nlohmann::json;

enum class WireFormat {
  kJson,
  kCbor,
};

// Thrown for framing-level malfunctions (short read, truncated body,
// undecodable bytes). Distinct from std::ios_base::failure / nlohmann
// json exceptions so callers can give a clear "this client speaks the
// wrong protocol" diagnostic without confusing it with EOF.
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Read one message from `in` according to `fmt`.
//   - JSON: reads up to and consuming `\n`. Skips empty lines.
//   - CBOR: reads the 4-byte length prefix, then exactly that many bytes,
//     then decodes them as a single CBOR value with strict trailing-byte
//     check (no leftover bytes allowed inside the frame).
//
// Returns nullopt only on clean EOF (no partial frame in flight). Throws
// `Error` on framing or decode failure. Stream failbits other than EOF
// are not consumed silently — they bubble up as `Error`.
std::optional<json> read_message(std::istream& in, WireFormat fmt);

// Write one message to `out` according to `fmt`. Always flushes before
// returning so the peer sees the frame promptly.
//   - JSON: writes `j.dump()` followed by `\n`.
//   - CBOR: writes the 4-byte big-endian length prefix, then the CBOR
//     encoding of `j`.
//
// Throws `Error` if the encoded frame would exceed UINT32_MAX bytes
// (length prefix would overflow) — that's a design lever, not an
// expected runtime case for any reasonable RPC payload.
void write_message(std::ostream& out, const json& j, WireFormat fmt);

}  // namespace ldb::protocol
