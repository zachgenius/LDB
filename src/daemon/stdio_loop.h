// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "daemon/dispatcher.h"
#include "protocol/output_channel.h"
#include "protocol/transport.h"

#include <functional>
#include <iosfwd>

namespace ldb::daemon {

// Reads framed JSON-RPC requests from stdin, writes framed responses
// via `out`. `out` is the daemon's single stdout writer; the
// listener thread (post-V1 #21 phase-2, docs/27) uses the same
// OutputChannel to publish thread.event notifications, so the two
// writers byte-interleave safely. Wire format on input is selected
// by `fmt` (kJson default, kCbor for the M5 binary frame mode);
// `out` already knows its own format and replies in it.
// Blocks until EOF on stdin. Returns 0 on clean exit.
int run_stdio_loop(Dispatcher& dispatcher,
                   protocol::OutputChannel& out,
                   protocol::WireFormat fmt = protocol::WireFormat::kJson);

// Pump one connection: read framed JSON-RPC from `in`, dispatch
// through `dispatcher`, write framed responses to `out`. Returns 0 on
// clean EOF from the peer, 1 on an unrecoverable framing desync (CBOR
// only) or a write failure. Designed to be called once per accept()
// in the `--listen` socket loop AND once for the lifetime of stdin
// in the `--stdio` loop — both modes share this body so dispatch
// semantics stay identical regardless of transport. `in` and `out`
// may refer to different fds (a TCP/unix socket pair) or to
// stdin/stdout.
//
// `is_shutdown` (post-review I2): optional predicate the worker
// checks between read and dispatch. If it returns true, the worker
// synthesises a kBadState error response ("daemon shutting down")
// and breaks out of the loop instead of dispatching the RPC. The
// socket-listen mode passes a closure over the file-scope
// `g_shutdown` flag; stdio mode leaves it unset (an empty
// std::function evaluates as false). Without this gate, a connected
// peer could keep sending RPCs after `daemon.shutdown` and the
// daemon would service them — directly contradicting the
// "shutdown stops accepting new RPCs immediately" guarantee in §2
// phase-2 docs.
int serve_one_connection(Dispatcher& dispatcher,
                         protocol::OutputChannel& out,
                         std::istream& in,
                         protocol::WireFormat fmt,
                         const std::function<bool()>& is_shutdown = {});

}  // namespace ldb::daemon
