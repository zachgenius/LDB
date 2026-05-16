// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "daemon/dispatcher.h"
#include "protocol/transport.h"

#include <string>

namespace ldb::daemon {

// Run `ldbd --listen unix:PATH` (single-client persistent socket; see
// docs/35-field-report-followups.md §2 phase 1).
//
// Lifecycle:
//   1. Acquire LOCK_EX|LOCK_NB on `${sock_path}.lock`. If another
//      daemon already holds it, return 1 after writing a stderr line
//      that names the holding pid when possible. The lock file is
//      created if absent (mode 0600) and remains across daemon
//      restarts — flock semantics make stale locks self-clearing.
//   2. If `sock_path`'s parent dir does not exist, create it 0700.
//      We do NOT chmod a pre-existing parent — its perms are the
//      operator's concern.
//   3. Bind the unix socket. Use a strict-umask trick so the inode
//      lands at 0600 atomically (POSIX bind() honours umask).
//   4. accept() loop. Each connection is dispatched to completion on
//      the calling thread — phase 1 is intentionally serial. The
//      dispatcher and its backend persist across connections, so
//      target_id from one client is visible to the next.
//   5. SIGTERM/SIGINT trigger a clean unbind + unlink of both the
//      socket and the lock file, then `return 0`.
//
// `fmt` is the wire format used over every connection — same JSON or
// length-prefixed CBOR framing as the stdio loop. We don't (yet)
// negotiate per-connection.
//
// Returns 0 on clean shutdown, 1 on bind/listen failure or lock
// collision.
int run_socket_listener(Dispatcher& dispatcher,
                        const std::string& sock_path,
                        protocol::WireFormat fmt);

}  // namespace ldb::daemon
