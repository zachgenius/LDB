// SPDX-License-Identifier: Apache-2.0
#include "observers/exec_allowlist.h"

#include "backend/debugger_backend.h"  // backend::Error
#include "transport/local_exec.h"
#include "transport/ssh.h"

#include <fnmatch.h>

#include <cctype>
#include <fstream>
#include <string>
#include <utility>

namespace ldb::observers {

namespace {

// Trim leading/trailing whitespace (incl. CR for Windows line endings).
std::string trim(const std::string& s) {
  std::size_t a = 0;
  while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  std::size_t b = s.size();
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

std::string join_argv(const std::vector<std::string>& argv) {
  std::string out;
  for (std::size_t i = 0; i < argv.size(); ++i) {
    if (i) out.push_back(' ');
    out.append(argv[i]);
  }
  return out;
}

}  // namespace

std::optional<ExecAllowlist>
ExecAllowlist::from_file(const std::filesystem::path& path) {
  std::ifstream f(path);
  if (!f.is_open()) return std::nullopt;
  ExecAllowlist out;
  std::string line;
  while (std::getline(f, line)) {
    auto t = trim(line);
    if (t.empty()) continue;
    if (t.front() == '#') continue;
    out.patterns_.push_back(std::move(t));
  }
  return out;
}

bool ExecAllowlist::allows(const std::vector<std::string>& argv) const {
  if (argv.empty()) return false;
  const std::string joined = join_argv(argv);
  for (const auto& pat : patterns_) {
    // FNM_PATHNAME: '*' must not span '/' — the operator's intent is
    // pinned to whole path components. This also keeps `/bin/sh` from
    // silently matching `/bin/sh -c …` because there's no '/' before
    // the trailing args, and fnmatch is anchored end-to-end without
    // FNM_LEADING_DIR.
    if (::fnmatch(pat.c_str(), joined.c_str(), FNM_PATHNAME) == 0) {
      return true;
    }
  }
  return false;
}

ExecResponse run_observer_exec(const ExecAllowlist& /*allowlist*/,
                               const ExecRequest&    req) {
  if (req.argv.empty()) {
    throw backend::Error("observer.exec: empty argv");
  }
  transport::ExecOptions opts;
  opts.timeout    = req.timeout;
  opts.stdin_data = req.stdin_data;
  // Conservative caps: most diagnostic commands produce <1 MiB of
  // stdout; keep the SSH/local default of 4 MiB stdout, 1 MiB stderr.

  transport::ExecResult er;
  if (req.remote.has_value()) {
    er = transport::ssh_exec(*req.remote, req.argv, opts);
  } else {
    er = transport::local_exec(req.argv, opts);
  }

  ExecResponse out;
  out.stdout_data      = std::move(er.stdout_data);
  out.stderr_data      = std::move(er.stderr_data);
  out.exit_code        = er.exit_code;
  out.duration         = er.duration;
  out.stdout_truncated = er.stdout_truncated;
  out.stderr_truncated = er.stderr_truncated;
  out.timed_out        = er.timed_out;
  return out;
}

}  // namespace ldb::observers
