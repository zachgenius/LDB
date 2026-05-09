// SPDX-License-Identifier: Apache-2.0
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

// Run argv either locally or over ssh, depending on remote.has_value().
// Throws backend::Error on transport failure or non-zero exit. Returns
// captured stdout on success.
std::string run_collect(const std::optional<transport::SshHost>& remote,
                        const std::vector<std::string>&          argv,
                        std::chrono::milliseconds                timeout =
                            std::chrono::seconds(15)) {
  transport::ExecOptions opts;
  opts.timeout = timeout;
  // Caps tuned for /proc-sized data — proc/maps on a heavy process can
  // get into the megabytes; keep the SSH default.
  transport::ExecResult er;
  if (remote.has_value()) {
    er = transport::ssh_exec(*remote, argv, opts);
  } else {
    er = transport::local_exec(argv, opts);
  }
  if (er.timed_out) {
    throw backend::Error("observer: command timed out");
  }
  if (er.exit_code != 0) {
    std::string detail = "observer: command failed (exit "
                         + std::to_string(er.exit_code) + ")";
    if (!er.stderr_data.empty()) {
      detail += ": ";
      // Cap to avoid bloating the JSON-RPC reply.
      detail += er.stderr_data.substr(0,
          std::min<std::size_t>(er.stderr_data.size(), 256));
    }
    throw backend::Error(detail);
  }
  return std::move(er.stdout_data);
}

void require_positive_pid(std::int32_t pid) {
  if (pid <= 0) {
    throw backend::Error("observer: pid must be a positive integer");
  }
}

std::string fd_target_to_type(const std::string& target) {
  if (target.rfind("socket:", 0) == 0) return "socket";
  if (target.rfind("pipe:", 0) == 0)   return "pipe";
  if (target.rfind("anon_inode:", 0) == 0) return "anon";
  if (!target.empty() && target.front() == '/') return "file";
  return "other";
}

std::optional<std::uint64_t> parse_kb(const std::string& v) {
  // "    14072 kB" → 14072
  std::size_t i = 0;
  while (i < v.size() && std::isspace(static_cast<unsigned char>(v[i]))) ++i;
  if (i == v.size()) return std::nullopt;
  char* end = nullptr;
  unsigned long long n = std::strtoull(v.c_str() + i, &end, 10);
  if (end == v.c_str() + i) return std::nullopt;
  return static_cast<std::uint64_t>(n);
}

std::optional<std::uint32_t> parse_uint(const std::string& v) {
  std::size_t i = 0;
  while (i < v.size() && std::isspace(static_cast<unsigned char>(v[i]))) ++i;
  if (i == v.size()) return std::nullopt;
  char* end = nullptr;
  unsigned long long n = std::strtoull(v.c_str() + i, &end, 10);
  if (end == v.c_str() + i) return std::nullopt;
  return static_cast<std::uint32_t>(n);
}

std::optional<std::int32_t> parse_int(const std::string& v) {
  std::size_t i = 0;
  while (i < v.size() && std::isspace(static_cast<unsigned char>(v[i]))) ++i;
  if (i == v.size()) return std::nullopt;
  char* end = nullptr;
  long long n = std::strtoll(v.c_str() + i, &end, 10);
  if (end == v.c_str() + i) return std::nullopt;
  return static_cast<std::int32_t>(n);
}

std::string strip(const std::string& s) {
  std::size_t a = 0;
  while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  std::size_t b = s.size();
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

// /proc/PID/status uses "Name:\tvalue\n" with a TAB separator after the
// colon. The value may contain spaces; we copy verbatim minus the
// trailing newline.
std::pair<std::string, std::string> split_status_line(const std::string& line) {
  auto colon = line.find(':');
  if (colon == std::string::npos) return {"", ""};
  std::string key = line.substr(0, colon);
  std::string val = line.substr(colon + 1);
  // Strip a single leading TAB or spaces (the kernel prints '\t').
  std::size_t i = 0;
  while (i < val.size() && (val[i] == '\t' || val[i] == ' ')) ++i;
  if (!val.empty() && val.back() == '\n') val.pop_back();
  return {key, val.substr(i)};
}

}  // namespace

// ---- proc.fds ----------------------------------------------------------

FdsResult parse_proc_fds(const std::string& find_printf_output) {
  FdsResult out;
  std::istringstream is(find_printf_output);
  std::string line;
  while (std::getline(is, line)) {
    if (line.empty()) continue;
    auto sp = line.find(' ');
    if (sp == std::string::npos) continue;          // bad row, skip
    std::string fd_str    = line.substr(0, sp);
    std::string target    = line.substr(sp + 1);
    if (fd_str.empty() || target.empty()) continue;
    auto fd = parse_int(fd_str);
    if (!fd.has_value()) continue;
    if (*fd < 0) continue;
    FdEntry e;
    e.fd     = *fd;
    e.target = target;
    e.type   = fd_target_to_type(target);
    out.fds.push_back(std::move(e));
  }
  out.total = out.fds.size();
  return out;
}

FdsResult fetch_proc_fds(const std::optional<transport::SshHost>& remote,
                         std::int32_t                              pid) {
  require_positive_pid(pid);
  // `find ... -printf '%f %l\n'` gives us "<fd> <target>" per line atomically.
  // We pre-build the path so the caller never sees the pid as a shell token.
  std::string fd_dir = "/proc/" + std::to_string(pid) + "/fd";
  std::vector<std::string> argv = {
      "find", fd_dir, "-mindepth", "1", "-maxdepth", "1",
      "-printf", "%f %l\n"
  };
  auto stdout_data = run_collect(remote, argv);
  return parse_proc_fds(stdout_data);
}

// ---- proc.maps ---------------------------------------------------------

namespace {

bool parse_hex_u64(const std::string& s, std::uint64_t* out) {
  if (s.empty()) return false;
  char* end = nullptr;
  unsigned long long v = std::strtoull(s.c_str(), &end, 16);
  if (end == s.c_str()) return false;
  *out = static_cast<std::uint64_t>(v);
  return true;
}

}  // namespace

MapsResult parse_proc_maps(const std::string& maps_text) {
  MapsResult out;
  std::istringstream is(maps_text);
  std::string line;
  while (std::getline(is, line)) {
    if (line.empty()) continue;
    // Format:
    //   START-END PERM OFFSET DEV INODE [PATH]
    // Whitespace between columns is variable; the path may contain
    // spaces but it's the LAST column. We split the first 5 columns
    // greedily, then take the remainder as the path.
    MapsRegion r;

    auto skip_ws = [&line](std::size_t& i) {
      while (i < line.size() &&
             std::isspace(static_cast<unsigned char>(line[i]))) ++i;
    };
    auto next_token = [&line](std::size_t& i) -> std::string {
      while (i < line.size() &&
             std::isspace(static_cast<unsigned char>(line[i]))) ++i;
      std::size_t b = i;
      while (i < line.size() &&
             !std::isspace(static_cast<unsigned char>(line[i]))) ++i;
      return line.substr(b, i - b);
    };

    std::size_t i = 0;
    auto range = next_token(i);
    auto perm  = next_token(i);
    auto off   = next_token(i);
    auto dev   = next_token(i);
    auto inode = next_token(i);
    if (range.empty() || perm.empty() || off.empty() ||
        dev.empty()   || inode.empty()) continue;

    auto dash = range.find('-');
    if (dash == std::string::npos) continue;
    if (!parse_hex_u64(range.substr(0, dash), &r.start)) continue;
    if (!parse_hex_u64(range.substr(dash + 1),  &r.end))   continue;
    r.perm = perm;
    if (!parse_hex_u64(off, &r.offset)) continue;
    r.dev = dev;
    {
      char* end = nullptr;
      unsigned long long n = std::strtoull(inode.c_str(), &end, 10);
      if (end == inode.c_str()) continue;
      r.inode = static_cast<std::uint64_t>(n);
    }
    skip_ws(i);
    if (i < line.size()) {
      // The path is the remainder of the line. Trim trailing whitespace.
      std::string p = line.substr(i);
      while (!p.empty() &&
             std::isspace(static_cast<unsigned char>(p.back()))) p.pop_back();
      if (!p.empty()) r.path = std::move(p);
    }
    out.regions.push_back(std::move(r));
  }
  out.total = out.regions.size();
  return out;
}

MapsResult fetch_proc_maps(const std::optional<transport::SshHost>& remote,
                           std::int32_t                              pid) {
  require_positive_pid(pid);
  std::string path = "/proc/" + std::to_string(pid) + "/maps";
  std::vector<std::string> argv = {"cat", path};
  auto stdout_data = run_collect(remote, argv);
  return parse_proc_maps(stdout_data);
}

// ---- proc.status -------------------------------------------------------

ProcStatus parse_proc_status(const std::string& status_text) {
  ProcStatus out;
  std::istringstream is(status_text);
  std::string line;
  while (std::getline(is, line)) {
    if (line.empty()) continue;
    auto kv = split_status_line(line);
    if (kv.first.empty()) continue;
    out.raw_fields.emplace_back(kv);
    const std::string& k = kv.first;
    const std::string& v = kv.second;
    if (k == "Name")           out.name = v;
    else if (k == "Pid")       out.pid = parse_int(v);
    else if (k == "PPid")      out.ppid = parse_int(v);
    else if (k == "State")     out.state = strip(v);
    else if (k == "Uid")       {
      // "Uid:\t1000\t1000\t1000\t1000" — first column is real uid.
      auto t = strip(v);
      auto tab = t.find_first_of(" \t");
      if (tab == std::string::npos) tab = t.size();
      out.uid = parse_uint(t.substr(0, tab));
    }
    else if (k == "Gid")       {
      auto t = strip(v);
      auto tab = t.find_first_of(" \t");
      if (tab == std::string::npos) tab = t.size();
      out.gid = parse_uint(t.substr(0, tab));
    }
    else if (k == "Threads")   out.threads = parse_uint(v);
    else if (k == "VmRSS")     out.vm_rss_kb = parse_kb(v);
    else if (k == "VmSize")    out.vm_size_kb = parse_kb(v);
    else if (k == "VmPeak")    out.vm_peak_kb = parse_kb(v);
    else if (k == "FDSize")    out.fd_size = parse_kb(v);
  }
  return out;
}

ProcStatus fetch_proc_status(const std::optional<transport::SshHost>& remote,
                             std::int32_t                              pid) {
  require_positive_pid(pid);
  std::string path = "/proc/" + std::to_string(pid) + "/status";
  std::vector<std::string> argv = {"cat", path};
  auto stdout_data = run_collect(remote, argv);
  return parse_proc_status(stdout_data);
}

}  // namespace ldb::observers
