// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nlohmann/json.hpp>

#include <iosfwd>
#include <optional>
#include <stdexcept>
#include <string>

// Wire-format transport for the Debug Adapter Protocol (DAP) shim.
//
// DAP framing is fundamentally different from the daemon's JSON-RPC
// stdio framings. Where ldbd's JSON mode is line-delimited and CBOR is
// big-endian length-prefix binary, DAP frames each JSON message with
// HTTP-style headers:
//
//   Content-Length: <NNN>\r\n
//   \r\n
//   <NNN bytes of UTF-8 JSON>
//
// Optional Content-Type header is permitted (and ignored). The two
// CRLFs after the headers separate the header block from the JSON body.
// See <https://microsoft.github.io/debug-adapter-protocol/specification>
// "Base Protocol".
//
// Implementation notes:
//   * Headers are case-insensitive per the spec; we accept any case for
//     "Content-Length" but emit canonical case on write.
//   * Bodies must be exactly N bytes. Short reads throw `dap::Error`
//     so the shim can log and exit rather than block forever.
//   * Header parsing tolerates bare \n line terminators in addition to
//     \r\n on read — some clients are sloppy. Writes always use \r\n.

namespace ldb::dap {

using json = nlohmann::json;

// Thrown for framing-level malfunctions (malformed Content-Length,
// missing CRLF, short body read). Distinct from std::ios_base::failure /
// nlohmann json exceptions so callers can give a clear diagnostic.
class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Read one DAP message from `in`. Returns nullopt on clean EOF (no
// bytes pending in a partial frame). Throws `Error` on framing or
// decode failure.
std::optional<json> read_dap_message(std::istream& in);

// Write one DAP message to `out`: emit `Content-Length: N\r\n\r\n`
// followed by the UTF-8 JSON body. Always flushes before returning so
// the peer sees the frame promptly.
void write_dap_message(std::ostream& out, const json& body);

}  // namespace ldb::dap
