#include "observers/observers.h"

#include "backend/debugger_backend.h"  // backend::Error
#include "transport/local_exec.h"
#include "transport/ssh.h"

#include <cctype>
#include <cstdlib>
#include <sstream>
#include <string>

namespace ldb::observers {

namespace {

// Same routing helper as proc.cpp — kept private here to avoid a
// cross-TU dependency for one short function.
std::string run_collect(const std::optional<transport::SshHost>& remote,
                        const std::vector<std::string>&          argv,
                        std::chrono::milliseconds                timeout =
                            std::chrono::seconds(15)) {
  transport::ExecOptions opts;
  opts.timeout = timeout;
  transport::ExecResult er;
  if (remote.has_value()) {
    er = transport::ssh_exec(*remote, argv, opts);
  } else {
    er = transport::local_exec(argv, opts);
  }
  if (er.timed_out) {
    throw backend::Error("observer.net.sockets: ss timed out");
  }
  if (er.exit_code != 0) {
    std::string detail = "observer.net.sockets: ss failed (exit "
                         + std::to_string(er.exit_code) + ")";
    if (!er.stderr_data.empty()) {
      detail += ": ";
      detail += er.stderr_data.substr(0,
          std::min<std::size_t>(er.stderr_data.size(), 256));
    }
    throw backend::Error(detail);
  }
  return std::move(er.stdout_data);
}

bool is_ws(char c) {
  return c == ' ' || c == '\t';
}

std::string strip(const std::string& s) {
  std::size_t a = 0;
  while (a < s.size() && is_ws(s[a])) ++a;
  std::size_t b = s.size();
  while (b > a && is_ws(s[b - 1])) --b;
  return s.substr(a, b - a);
}

// Tokenize a header-or-data line on runs of whitespace. The
// `Process` column may contain whitespace inside `users:((...))`; we
// special-case that as a single-token suffix at parse time.
std::vector<std::string> split_ws(const std::string& s) {
  std::vector<std::string> out;
  std::size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && is_ws(s[i])) ++i;
    if (i >= s.size()) break;
    std::size_t b = i;
    while (i < s.size() && !is_ws(s[i])) ++i;
    out.push_back(s.substr(b, i - b));
  }
  return out;
}

// Parse `users:(("nc",pid=287663,fd=3),("ssh",pid=N,fd=M))` — first
// tuple wins. Some kernels render this as `users:(("name",pid=N,fd=M))`
// (single tuple). We extract the FIRST (name, pid, fd) and ignore the
// rest. Returns (comm?, pid?, fd?).
struct UsersInfo {
  std::optional<std::string>   comm;
  std::optional<std::int32_t>  pid;
  std::optional<std::int32_t>  fd;
};
UsersInfo parse_users_field(const std::string& s) {
  UsersInfo u;
  // Find the first inner `(` after `users:`.
  auto open = s.find("((");
  if (open == std::string::npos) return u;
  auto close = s.find(')', open);
  if (close == std::string::npos) return u;
  // Inside: "name",pid=NNN,fd=MMM
  std::string inner = s.substr(open + 2, close - (open + 2));
  // Comm: between the first pair of double quotes.
  auto q1 = inner.find('"');
  if (q1 != std::string::npos) {
    auto q2 = inner.find('"', q1 + 1);
    if (q2 != std::string::npos) {
      u.comm = inner.substr(q1 + 1, q2 - q1 - 1);
    }
  }
  // pid=NNN
  auto pid_pos = inner.find("pid=");
  if (pid_pos != std::string::npos) {
    char* end = nullptr;
    long long n = std::strtoll(inner.c_str() + pid_pos + 4, &end, 10);
    if (end != inner.c_str() + pid_pos + 4) {
      u.pid = static_cast<std::int32_t>(n);
    }
  }
  // fd=NNN
  auto fd_pos = inner.find("fd=");
  if (fd_pos != std::string::npos) {
    char* end = nullptr;
    long long n = std::strtoll(inner.c_str() + fd_pos + 3, &end, 10);
    if (end != inner.c_str() + fd_pos + 3) {
      u.fd = static_cast<std::int32_t>(n);
    }
  }
  return u;
}

}  // namespace

SocketsResult parse_ss_tunap(const std::string& ss_output) {
  SocketsResult out;
  std::istringstream is(ss_output);
  std::string line;
  bool first = true;
  while (std::getline(is, line)) {
    if (line.empty()) continue;
    if (first) {
      first = false;
      // Header line begins with "Netid". Skip it.
      auto stripped = strip(line);
      if (stripped.rfind("Netid", 0) == 0) continue;
      // Some hosts emit no header (rare); fall through to parse this row.
    }

    // Columns we expect (in order):
    //   Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port [Process...]
    // The Process column is optional; when present it begins with `users:((`.
    auto toks = split_ws(line);
    if (toks.size() < 6) continue;

    SocketEntry e;
    e.proto = toks[0];
    e.state = toks[1];
    // Recv-Q toks[2], Send-Q toks[3] — discarded.
    e.local = toks[4];
    e.peer  = toks[5];

    if (toks.size() >= 7) {
      // The remaining tokens may include process info. We rejoin them
      // (separator: space) and look for `users:((`.
      std::string rest;
      for (std::size_t i = 6; i < toks.size(); ++i) {
        if (!rest.empty()) rest += ' ';
        rest += toks[i];
      }
      auto u = parse_users_field(rest);
      e.comm = u.comm;
      e.pid  = u.pid;
      e.fd   = u.fd;
    }
    out.sockets.push_back(std::move(e));
  }
  out.total = out.sockets.size();
  return out;
}

SocketsResult fetch_net_sockets(const std::optional<transport::SshHost>& remote,
                                const std::string&                       filter) {
  // Hardcoded argv. `ss -tunap` = TCP + UDP + numeric + all states +
  // process info. No user-supplied tokens reach the shell.
  std::vector<std::string> argv = {"ss", "-tunap"};
  auto out = run_collect(remote, argv);
  auto parsed = parse_ss_tunap(out);
  if (filter.empty()) return parsed;

  // Substring filter against "<proto> <local> <peer> <state>".
  // Cheap, deterministic; we don't pass the filter to ss to avoid
  // any chance of the shell interpreting it.
  SocketsResult filtered;
  for (auto& s : parsed.sockets) {
    std::string flat = s.proto + ' ' + s.local + ' ' + s.peer + ' ' + s.state;
    if (flat.find(filter) != std::string::npos) {
      filtered.sockets.push_back(std::move(s));
    }
  }
  filtered.total = filtered.sockets.size();
  return filtered;
}

}  // namespace ldb::observers
