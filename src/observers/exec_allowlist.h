// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "transport/ssh.h"

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// observer.exec — operator-allowlisted shell escape (M4 polish, plan §4.6).
//
// This is the §4.6 escape hatch the typed observers were designed to
// REPLACE. The plan keeps it because not every diagnostic an operator
// reaches for fits a typed schema (e.g. `systemctl status foo`,
// `lsmod`, an in-house health-check binary). The contract is:
//
//   • Off by default. The endpoint reports -32002 ("kBadState") if no
//     allowlist file is configured. The agent learns the endpoint
//     exists (it's listed in describe.endpoints) but learns nothing
//     about its policy from the wire — the operator is in charge.
//
//   • Allowlist file is plaintext, one line per allowed command. Lines
//     are POSIX `fnmatch` glob patterns matched against the WHOLE
//     space-joined argv. Patterns are anchored — a line must match the
//     full argv, not a substring. `#` introduces a line comment;
//     blank lines are ignored.
//
//     Example file:
//       # operator-approved commands for observer.exec
//       /usr/bin/uptime
//       /usr/bin/lsmod
//       /usr/bin/systemctl status *
//       ip addr show *
//
//   • argv[0] MUST be an absolute path OR appear on PATH (a bare
//     basename, no '/'). Relative paths like `./foo` or `../bar` are
//     -32602 — caller mistakes, not a policy decision. Documented
//     because the alternative (silently treat `./foo` as basename `foo`
//     and probe PATH) is a footgun at the agent boundary.
//
//   • Empty allowlist file → REJECT every command. Default-deny.
//
// The matcher is `fnmatch(pattern, argv_joined, FNM_PATHNAME)`. We
// deliberately do NOT pass FNM_LEADING_DIR — the line `/bin/sh` must
// not silently match `/bin/sh -c rm -rf /`. The `*` glob still spans
// arguments separated by single spaces in the joined string, so
// `/usr/bin/systemctl status *` matches `/usr/bin/systemctl status
// myunit` but not `/usr/bin/systemctl restart myunit`.
//
// Wire shape mirrors `observer.proc.*` for routing: `host?` absent ⇒
// `local_exec`, `host?` present ⇒ `ssh_exec`. stdin is bounded; outputs
// are size-capped with truncation flags so a misbehaving program can't
// inflate a single response into a multi-megabyte JSON-RPC line.

namespace ldb::observers {

class ExecAllowlist {
 public:
  // Returns nullopt iff the file does not exist or cannot be opened.
  // (An EMPTY file is a valid allowlist — it just denies everything.)
  static std::optional<ExecAllowlist> from_file(
      const std::filesystem::path& path);

  // True iff some pattern in the file matches `argv` (joined with
  // single spaces) under fnmatch(FNM_PATHNAME).
  bool allows(const std::vector<std::string>& argv) const;

  std::size_t pattern_count() const noexcept { return patterns_.size(); }

 private:
  std::vector<std::string> patterns_;
};

struct ExecRequest {
  std::vector<std::string>          argv;     // argv[0] is the program
  std::optional<transport::SshHost> remote;
  std::chrono::milliseconds         timeout = std::chrono::seconds(30);
  std::string                       stdin_data;
};

struct ExecResponse {
  std::string               stdout_data;
  std::string               stderr_data;
  int                       exit_code        = 0;
  std::chrono::milliseconds duration{0};
  bool                      stdout_truncated = false;
  bool                      stderr_truncated = false;
  bool                      timed_out        = false;
};

// Caller MUST have already verified `allowlist.allows(req.argv)` before
// invoking this — `run_observer_exec` is the bottom-half (transport +
// shape) and does NOT re-check the allowlist. The dispatcher does the
// allowlist check and the param validation.
//
// Throws backend::Error on transport failure (no exec on PATH, ssh
// spawn failure, pipe failure). A non-zero subprocess exit is reported
// in `exit_code`, NOT thrown.
ExecResponse run_observer_exec(const ExecAllowlist& allowlist,
                               const ExecRequest&   req);

}  // namespace ldb::observers
