// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "transport/ssh.h"  // ExecOptions, ExecResult — same shape

#include <string>
#include <vector>

// Local subprocess primitive (M4 part 3 prep).
//
// `local_exec(argv, opts) -> ExecResult` is the local-host counterpart to
// `ssh_exec`. Same `ExecOptions` / `ExecResult` shape so the typed
// observer endpoints (M4-3) can route their command through one or the
// other transport based on a `host?` parameter without rewriting the
// pump.
//
// Why a dedicated primitive (not popen / system / std::system):
//   • Stdout is reserved for ldbd's JSON-RPC channel. popen() inherits
//     the parent's fds in some implementations; we ALWAYS pipe so the
//     child can never write a stray byte to stdout.
//   • posix_spawnp avoids the fork+exec async-signal-safety footgun
//     and stays consistent with `ssh_exec`'s model.
//   • Same deadline-driven cancellation, stdout/stderr caps, truncation
//     bits — the observer endpoints rely on these for back-pressure.
//
// Errors: `local_exec` throws `ldb::backend::Error` only on spawn-side
// failure (executable not on PATH, posix_spawn failed, pipe creation
// failed). Subprocess non-zero exit / timeout / OOM-of-cap is reflected
// in the ExecResult.

namespace ldb::transport {

// Run `argv` as a local subprocess. argv[0] is searched on PATH the
// same way posix_spawnp resolves it. Throws ldb::backend::Error on
// spawn-side failure only.
ExecResult local_exec(const std::vector<std::string>& argv,
                      const ExecOptions&              opts = {});

}  // namespace ldb::transport
