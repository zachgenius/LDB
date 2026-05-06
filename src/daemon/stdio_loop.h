#pragma once

#include "daemon/dispatcher.h"
#include "protocol/transport.h"

namespace ldb::daemon {

// Reads framed JSON-RPC requests from stdin, writes framed responses to
// stdout. Wire format is selected by `fmt`:
//   * kJson — line-delimited (`\n`) JSON, one message per line. M0 default.
//   * kCbor — length-prefixed binary CBOR (RFC 8949). M5 part 3.
// Blocks until EOF on stdin. Returns 0 on clean exit.
int run_stdio_loop(Dispatcher& dispatcher,
                   protocol::WireFormat fmt = protocol::WireFormat::kJson);

}  // namespace ldb::daemon
