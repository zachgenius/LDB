#pragma once

#include "daemon/dispatcher.h"

namespace ldb::daemon {

// Reads line-delimited JSON-RPC requests from stdin, writes line-delimited
// responses to stdout. Blocks until EOF on stdin. Returns 0 on clean exit.
int run_stdio_loop(Dispatcher& dispatcher);

}  // namespace ldb::daemon
