// observer.net.igmp — /proc/net/igmp + /proc/net/igmp6 typed observer
// (M4 §4.6 closeout).
//
// Two parsers, one fetcher. Local routing reads /proc/net/igmp{,6}
// directly via std::ifstream — they're static text files; no
// subprocess needed. Remote routing dispatches `cat /proc/net/igmp`
// (and the v6 path) over ssh_exec, mirroring the rest of observers.
//
// Byte order:
//   • V4 group hex column is in HOST byte order, which on Linux/x86
//     means little-endian. `010000E0` ⇒ 224.0.0.1. We always reverse
//     the four bytes regardless of build host — the kernel format is
//     stable across architectures by virtue of /proc emitting htohl(),
//     not byte-pun output.
//   • V6 address is 32 hex chars in network byte order; we render as
//     8 colon-separated groups of 4 lower-case hex chars (no zero-
//     compression — keep it deterministic for tests).

#include "observers/observers.h"

#include "backend/debugger_backend.h"  // backend::Error
#include "transport/local_exec.h"
#include "transport/ssh.h"

#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace ldb::observers {

namespace {

// Strip leading + trailing ASCII whitespace, returning a new string.
std::string strip_ws(const std::string& s) {
  std::size_t a = 0;
  while (a < s.size() &&
         std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  std::size_t b = s.size();
  while (b > a &&
         std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

// Whitespace-tokenize. Empty result if input is whitespace-only.
std::vector<std::string> tokenize_ws(const std::string& s) {
  std::vector<std::string> out;
  std::size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() &&
           std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    std::size_t b = i;
    while (i < s.size() &&
           !std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    if (i > b) out.push_back(s.substr(b, i - b));
  }
  return out;
}

bool starts_with_ws(const std::string& s) {
  return !s.empty() &&
         std::isspace(static_cast<unsigned char>(s[0]));
}

bool parse_hex_u32(const std::string& s, std::uint32_t* out) {
  if (s.empty()) return false;
  char* end = nullptr;
  unsigned long long v = std::strtoull(s.c_str(), &end, 16);
  if (end == s.c_str()) return false;
  if (v > 0xFFFFFFFFULL) return false;
  *out = static_cast<std::uint32_t>(v);
  return true;
}

bool parse_dec_u32(const std::string& s, std::uint32_t* out) {
  if (s.empty()) return false;
  char* end = nullptr;
  unsigned long long v = std::strtoull(s.c_str(), &end, 10);
  if (end == s.c_str()) return false;
  if (v > 0xFFFFFFFFULL) return false;
  *out = static_cast<std::uint32_t>(v);
  return true;
}

bool parse_hex_u64(const std::string& s, std::uint64_t* out) {
  if (s.empty()) return false;
  char* end = nullptr;
  unsigned long long v = std::strtoull(s.c_str(), &end, 16);
  if (end == s.c_str()) return false;
  *out = static_cast<std::uint64_t>(v);
  return true;
}

// Convert kernel little-endian 8-hex-char group ID to dotted-quad IPv4.
// `010000E0` ⇒ "224.0.0.1". Returns empty string on parse failure.
std::string hex_le_to_ipv4(const std::string& hex8) {
  if (hex8.size() != 8) return "";
  std::uint32_t v = 0;
  if (!parse_hex_u32(hex8, &v)) return "";
  // Bytes in `hex8` (big-endian text) are b3 b2 b1 b0 of the host
  // word, so the IPv4 octets in network order are:
  //   octet 0 = byte 0 (low)  = (v      ) & 0xFF
  //   octet 1 = byte 1        = (v >>  8) & 0xFF
  //   octet 2 = byte 2        = (v >> 16) & 0xFF
  //   octet 3 = byte 3 (high) = (v >> 24) & 0xFF
  unsigned o0 =  v        & 0xFFu;
  unsigned o1 = (v >>  8) & 0xFFu;
  unsigned o2 = (v >> 16) & 0xFFu;
  unsigned o3 = (v >> 24) & 0xFFu;
  std::ostringstream os;
  os << o0 << '.' << o1 << '.' << o2 << '.' << o3;
  return os.str();
}

// Convert 32-hex-char IPv6 representation to colon-separated 8 groups
// of 4 lowercase hex chars. Returns empty string on length mismatch.
std::string hex32_to_ipv6(const std::string& hex32) {
  if (hex32.size() != 32) return "";
  std::string out;
  out.reserve(39);
  for (std::size_t i = 0; i < 8; ++i) {
    if (i > 0) out += ':';
    for (std::size_t j = 0; j < 4; ++j) {
      char c = hex32[i * 4 + j];
      // lowercase
      if (c >= 'A' && c <= 'F') c = static_cast<char>(c + ('a' - 'A'));
      out += c;
    }
  }
  return out;
}

// Run argv either locally or over ssh; returns captured stdout. On
// non-zero exit OR transport failure, returns nullopt + sets *err to
// a human-readable detail. Used for the V6 path (where missing-file
// is non-fatal); the V4 path uses the throwing version below.
std::optional<std::string>
run_collect_optional(const std::optional<transport::SshHost>& remote,
                     const std::vector<std::string>&          argv,
                     std::string*                             err) {
  transport::ExecOptions opts;
  opts.timeout = std::chrono::seconds(10);
  transport::ExecResult er;
  if (remote.has_value()) {
    er = transport::ssh_exec(*remote, argv, opts);
  } else {
    er = transport::local_exec(argv, opts);
  }
  if (er.timed_out) {
    if (err) *err = "command timed out";
    return std::nullopt;
  }
  if (er.exit_code != 0) {
    if (err) *err = "exit " + std::to_string(er.exit_code) + ": "
                  + er.stderr_data.substr(0,
                      std::min<std::size_t>(er.stderr_data.size(), 256));
    return std::nullopt;
  }
  return std::move(er.stdout_data);
}

}  // namespace

// ---- pure parsers ------------------------------------------------------

IgmpEntry parse_proc_net_igmp(const std::string& v4_text) {
  IgmpEntry out;
  std::istringstream is(v4_text);
  std::string line;
  IgmpGroup* current = nullptr;  // points into out.groups; mutated as
                                 // we accumulate addresses for the
                                 // current header.

  while (std::getline(is, line)) {
    // Strip trailing CR (crlf-safe) but keep leading whitespace —
    // we use it to decide header-vs-continuation.
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
      line.pop_back();
    }
    if (strip_ws(line).empty()) continue;

    // The first non-blank line is the column header
    //   "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter"
    // We detect it by the literal prefix "Idx" (no leading whitespace,
    // contains "Device"). Skip silently.
    if (!starts_with_ws(line) &&
        line.rfind("Idx", 0) == 0 &&
        line.find("Device") != std::string::npos) {
      continue;
    }

    if (!starts_with_ws(line)) {
      // Header line: "<idx>\t<device>: <count> <querier>"
      auto colon = line.find(':');
      if (colon == std::string::npos) continue;
      std::string left  = line.substr(0, colon);
      std::string right = line.substr(colon + 1);

      auto left_tokens = tokenize_ws(left);
      if (left_tokens.size() < 2) continue;
      std::uint32_t idx = 0;
      if (!parse_dec_u32(left_tokens[0], &idx)) continue;
      // Some interface names contain no whitespace by kernel
      // contract; we always take token #1 as device.
      std::string device = left_tokens[1];

      auto right_tokens = tokenize_ws(right);
      // First token is "Count" (decimal), second is querier (V3/V2/V1).
      std::optional<std::uint32_t> count;
      std::optional<std::string>   querier;
      if (right_tokens.size() >= 1) {
        std::uint32_t c = 0;
        if (parse_dec_u32(right_tokens[0], &c)) count = c;
      }
      if (right_tokens.size() >= 2) {
        querier = right_tokens[1];
      }

      IgmpGroup g;
      g.idx     = idx;
      g.device  = std::move(device);
      g.count   = count;
      g.querier = std::move(querier);
      out.groups.push_back(std::move(g));
      current = &out.groups.back();
    } else {
      // Continuation address line under the most-recent header.
      if (current == nullptr) continue;
      auto tokens = tokenize_ws(line);
      // Format: "<hex8 group> <users> <timer-since-last:hex64> <reporter>"
      // The "reporter" field may be missing on some kernels; we
      // tolerate ≥3 tokens.
      if (tokens.size() < 3) continue;
      auto addr = hex_le_to_ipv4(tokens[0]);
      if (addr.empty()) continue;
      std::uint32_t users = 0;
      if (!parse_dec_u32(tokens[1], &users)) continue;
      // tokens[2] looks like "0:00000000" — colon-separated; we want
      // the right-of-colon hex value as the timer.
      std::uint64_t timer = 0;
      const std::string& t = tokens[2];
      auto col = t.find(':');
      std::string timer_str = (col == std::string::npos)
                                ? t
                                : t.substr(col + 1);
      parse_hex_u64(timer_str, &timer);

      IgmpAddress a;
      a.address = std::move(addr);
      a.users   = users;
      a.timer   = timer;
      current->addresses.push_back(std::move(a));
    }
  }

  out.total = out.groups.size();
  return out;
}

IgmpEntry parse_proc_net_igmp6(const std::string& v6_text) {
  IgmpEntry out;
  std::istringstream is(v6_text);
  std::string line;
  while (std::getline(is, line)) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
      line.pop_back();
    }
    if (strip_ws(line).empty()) continue;
    auto tokens = tokenize_ws(line);
    // Format:
    //   "<idx> <device> <addr-32hex> <users> <src:hex32> <timer-dec>"
    // We want: idx, device, addr, users, timer.
    if (tokens.size() < 5) continue;
    std::uint32_t idx = 0;
    if (!parse_dec_u32(tokens[0], &idx)) continue;
    std::string device = tokens[1];
    std::string addr_hex = tokens[2];
    if (addr_hex.size() != 32) continue;
    std::string addr = hex32_to_ipv6(addr_hex);
    if (addr.empty()) continue;
    std::uint32_t users = 0;
    if (!parse_dec_u32(tokens[3], &users)) continue;
    // tokens[4] is the source counter / timer-since-last (hex). On
    // every Linux kernel column ordering is stable; we take it as the
    // timer field. The plan's own example puts "00000004" here.
    std::uint64_t timer = 0;
    parse_hex_u64(tokens[4], &timer);

    IgmpGroup g;
    g.idx    = idx;
    g.device = std::move(device);
    // count + querier left absent — V6 has no per-interface header.
    IgmpAddress a;
    a.address = std::move(addr);
    a.users   = users;
    a.timer   = timer;
    g.addresses.push_back(std::move(a));

    out.groups.push_back(std::move(g));
  }
  out.total = out.groups.size();
  return out;
}

// ---- fetcher -----------------------------------------------------------

namespace {

// Read the whole contents of a path (or nullopt on failure).
std::optional<std::string> read_file_to_string(const std::string& path) {
  std::ifstream f(path);
  if (!f.is_open()) return std::nullopt;
  std::ostringstream os;
  os << f.rdbuf();
  return os.str();
}

}  // namespace

IgmpEntry list_igmp(const std::optional<transport::SshHost>& remote) {
  IgmpEntry out;

  // V4: required path. Local read → ifstream; remote → ssh_exec cat.
  std::string v4_text;
  if (remote.has_value()) {
    std::string err;
    auto t = run_collect_optional(remote, {"cat", "/proc/net/igmp"}, &err);
    if (!t.has_value()) {
      throw backend::Error("observer.net.igmp: read /proc/net/igmp failed: "
                           + err);
    }
    v4_text = std::move(*t);
  } else {
    auto t = read_file_to_string("/proc/net/igmp");
    if (!t.has_value()) {
      // No /proc/net/igmp on this host (off-Linux). Surface as an
      // empty result, NOT an error — same contract as other observers
      // when /proc is missing entirely. The dispatcher's smoke/live
      // tests gate on /proc existence anyway.
      return out;
    }
    v4_text = std::move(*t);
  }
  auto v4 = parse_proc_net_igmp(v4_text);
  for (auto& g : v4.groups) {
    out.groups.push_back(std::move(g));
  }

  // V6: optional. Missing file is silent.
  std::string v6_text;
  bool v6_ok = false;
  if (remote.has_value()) {
    std::string err;
    auto t = run_collect_optional(remote, {"cat", "/proc/net/igmp6"}, &err);
    if (t.has_value()) {
      v6_text = std::move(*t);
      v6_ok = true;
    }
  } else {
    auto t = read_file_to_string("/proc/net/igmp6");
    if (t.has_value()) {
      v6_text = std::move(*t);
      v6_ok = true;
    }
  }
  if (v6_ok) {
    auto v6 = parse_proc_net_igmp6(v6_text);
    for (auto& g : v6.groups) {
      out.groups.push_back(std::move(g));
    }
  }

  out.total = out.groups.size();
  return out;
}

}  // namespace ldb::observers
