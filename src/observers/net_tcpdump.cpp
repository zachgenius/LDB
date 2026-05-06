#include "observers/observers.h"

#include "backend/debugger_backend.h"  // backend::Error
#include "transport/streaming_exec.h"

#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <sstream>
#include <string>

// observer.net.tcpdump (M4 part 5, plan §4.6).
//
// Bounded one-shot live capture using `transport::StreamingExec`. We
// spawn `tcpdump -nn -tt -l -c <count> -i <iface> -s <snaplen> [bpf]`
// and pump stdout LINE-BY-LINE through the on_line callback into a
// PacketEntry vector. Once we hit `count`, we `terminate()` the
// child and return.
//
// Why StreamingExec (not local_exec/ssh_exec): tcpdump is a watch-and-
// stream tool. The blocking exec primitives wait for child exit
// before delivering bytes — but tcpdump only exits when SIGTERMed or
// when its own `-c` cap is hit. Either way we'd be paying for the
// full timeout window; with StreamingExec we get events as fast as
// they come and stop precisely when we have enough.
//
// Permission gating: a non-privileged tcpdump exits non-zero with
// "permission denied" / "Operation not permitted" on stderr. We
// surface that as a backend::Error so the dispatcher can map it to
// -32000 with the underlying stderr text.

namespace ldb::observers {

namespace {

bool is_ws(char c) {
  return c == ' ' || c == '\t' || c == '\r';
}

std::string strip(const std::string& s) {
  std::size_t a = 0;
  while (a < s.size() && is_ws(s[a])) ++a;
  std::size_t b = s.size();
  while (b > a && is_ws(s[b - 1])) --b;
  return s.substr(a, b - a);
}

// Try to extract `<sec>.<frac> ` from the start of a line. Returns
// nullopt if the leading token isn't a recognizable epoch timestamp.
std::optional<std::pair<double, std::size_t>> parse_leading_ts(
    const std::string& line) {
  std::size_t i = 0;
  while (i < line.size() && is_ws(line[i])) ++i;
  std::size_t start = i;
  while (i < line.size() &&
         (std::isdigit(static_cast<unsigned char>(line[i])) ||
          line[i] == '.')) {
    ++i;
  }
  if (i == start) return std::nullopt;
  if (i < line.size() && !is_ws(line[i])) return std::nullopt;
  // Must contain a decimal point — guards against parsing "IP" prefixes
  // when the timestamp was already stripped.
  std::string ts_str = line.substr(start, i - start);
  if (ts_str.find('.') == std::string::npos) return std::nullopt;
  char* end = nullptr;
  double v = std::strtod(ts_str.c_str(), &end);
  if (end != ts_str.c_str() + ts_str.size()) return std::nullopt;
  // Skip any trailing whitespace after the timestamp.
  while (i < line.size() && is_ws(line[i])) ++i;
  return std::make_pair(v, i);
}

// Best-effort split of an "IP A.B.C.D.PORT > E.F.G.H.PORT: ..." line.
// Populates p.proto / p.src / p.dst when we can match cleanly. This is
// strictly opportunistic — when in doubt we leave the optionals
// absent and the caller still has `summary` to fall back on.
void parse_proto_src_dst(const std::string& summary, PacketEntry& p) {
  if (summary.empty()) return;
  // Proto = first whitespace-separated token, with any trailing comma
  // stripped (ARP lines look like "ARP, Request who-has ...").
  std::size_t i = 0;
  while (i < summary.size() && !is_ws(summary[i]) &&
         summary[i] != ',') ++i;
  std::string proto = summary.substr(0, i);
  if (proto.empty()) return;
  p.proto = proto;

  // Look for "src > dst:" in the rest of the line; only present for
  // IP/IP6 (not ARP / IGMP / etc).
  if (proto != "IP" && proto != "IP6") return;
  while (i < summary.size() && (is_ws(summary[i]) ||
                                summary[i] == ',')) ++i;
  // src ends at the next whitespace.
  std::size_t s_start = i;
  while (i < summary.size() && !is_ws(summary[i])) ++i;
  if (i >= summary.size()) return;
  std::string src = summary.substr(s_start, i - s_start);
  while (i < summary.size() && is_ws(summary[i])) ++i;
  if (i >= summary.size() || summary[i] != '>') return;
  ++i;
  while (i < summary.size() && is_ws(summary[i])) ++i;
  // Read dst up to whitespace or ','; we cannot stop on ':' because
  // IPv6 endpoints contain colons natively (`::1.9001`). tcpdump
  // always terminates the dst with `: ` (colon + space), so by
  // stopping on whitespace we retain the trailing colon, then strip
  // exactly one before storing.
  std::size_t d_start = i;
  while (i < summary.size() && !is_ws(summary[i]) &&
         summary[i] != ',') ++i;
  if (i == d_start) return;
  std::string dst = summary.substr(d_start, i - d_start);
  if (!dst.empty() && dst.back() == ':') dst.pop_back();
  if (!src.empty()) p.src = src;
  if (!dst.empty()) p.dst = dst;
}

// Locate ", length N" anywhere in the summary and parse N.
std::optional<std::uint64_t> parse_length(const std::string& summary) {
  auto pos = summary.rfind("length ");
  if (pos == std::string::npos) return std::nullopt;
  // Walk forward over digits.
  std::size_t i = pos + 7;
  std::size_t b = i;
  while (i < summary.size() &&
         std::isdigit(static_cast<unsigned char>(summary[i]))) ++i;
  if (i == b) return std::nullopt;
  char* end = nullptr;
  unsigned long long n = std::strtoull(summary.c_str() + b, &end, 10);
  if (end == summary.c_str() + b) return std::nullopt;
  return static_cast<std::uint64_t>(n);
}

}  // namespace

std::optional<PacketEntry> parse_tcpdump_line(const std::string& raw) {
  std::string line = strip(raw);
  if (line.empty()) return std::nullopt;
  if (line[0] == '#') return std::nullopt;
  auto ts_split = parse_leading_ts(line);
  if (!ts_split.has_value()) return std::nullopt;
  PacketEntry p;
  p.ts_epoch = ts_split->first;
  p.summary  = line.substr(ts_split->second);
  if (p.summary.empty()) return std::nullopt;
  parse_proto_src_dst(p.summary, p);
  p.len = parse_length(p.summary);
  return p;
}

std::vector<PacketEntry> parse_tcpdump_lines(const std::string& text) {
  std::vector<PacketEntry> out;
  std::istringstream is(text);
  std::string line;
  while (std::getline(is, line)) {
    auto p = parse_tcpdump_line(line);
    if (p.has_value()) out.push_back(std::move(*p));
  }
  return out;
}

namespace {

// Spotting "no privilege" in tcpdump's stderr. We treat any of these
// case-insensitive substrings as a privilege failure so the dispatcher
// can map it to a single -32000 with the original message.
bool stderr_indicates_no_perm(const std::string& s) {
  // Lowercased copy for case-insensitive search.
  std::string lo(s.size(), '\0');
  for (std::size_t i = 0; i < s.size(); ++i) {
    lo[i] = static_cast<char>(std::tolower(
        static_cast<unsigned char>(s[i])));
  }
  return lo.find("permission") != std::string::npos
      || lo.find("operation not permitted") != std::string::npos
      || lo.find("eacces") != std::string::npos;
}

std::vector<std::string> build_argv(const TcpdumpRequest& req) {
  // -nn   : numeric addresses + ports.
  // -tt   : epoch timestamp ("<sec>.<usec>").
  // -l    : line-buffered stdout (DON'T omit — see CLAUDE.md/landmines).
  // -c N  : exit after N packets (defense in depth alongside our own bound).
  // -i I  : interface (validated non-empty by caller).
  // -s S  : snaplen (we cap at 65535 in the dispatcher).
  std::vector<std::string> argv = {"tcpdump", "-nn", "-tt", "-l"};
  argv.push_back("-c");
  argv.push_back(std::to_string(req.count));
  argv.push_back("-i");
  argv.push_back(req.iface);
  std::uint32_t snaplen = req.snaplen.value_or(256u);
  argv.push_back("-s");
  argv.push_back(std::to_string(snaplen));
  // Optional BPF filter — passed as a SINGLE argv element. tcpdump
  // accepts the entire filter expression as one tail arg.
  if (req.bpf.has_value() && !req.bpf->empty()) {
    argv.push_back(*req.bpf);
  }
  return argv;
}

}  // namespace

TcpdumpResult tcpdump(const TcpdumpRequest& req) {
  if (req.iface.empty()) {
    throw backend::Error("observer.net.tcpdump: empty iface");
  }
  if (req.count == 0 || req.count > 10000u) {
    throw backend::Error("observer.net.tcpdump: count out of range (1..10000)");
  }
  if (req.snaplen.has_value() &&
      (*req.snaplen == 0 || *req.snaplen > 65535u)) {
    throw backend::Error("observer.net.tcpdump: snaplen out of range (1..65535)");
  }

  TcpdumpResult result;

  // Coordinate the streaming reader with this thread. The reader
  // thread invokes `on_line` for every parsed line; we collect into
  // `result.packets` under `mu`. When we hit `count`, set `done` and
  // notify the wait below.
  std::mutex              mu;
  std::condition_variable cv;
  bool                    done = false;
  bool                    child_exited = false;

  auto on_line = [&](std::string_view line) {
    std::string s(line);
    auto p = parse_tcpdump_line(s);
    if (!p.has_value()) return;
    p->iface = req.iface;
    {
      std::lock_guard<std::mutex> lk(mu);
      if (result.packets.size() < req.count) {
        result.packets.push_back(std::move(*p));
        if (result.packets.size() >= req.count) {
          done = true;
          cv.notify_all();
        }
      }
    }
  };
  auto on_done = [&](int /*exit_code*/, bool /*timed_out*/) {
    std::lock_guard<std::mutex> lk(mu);
    child_exited = true;
    cv.notify_all();
  };

  std::unique_ptr<transport::StreamingExec> child;
  try {
    child = std::make_unique<transport::StreamingExec>(
        req.remote, build_argv(req), on_line, on_done);
  } catch (const backend::Error& e) {
    throw backend::Error(std::string("observer.net.tcpdump: ") + e.what());
  }

  // Wait for either the count to be hit, child to exit, or wall
  // clock to expire.
  auto deadline = std::chrono::steady_clock::now() + req.timeout;
  {
    std::unique_lock<std::mutex> lk(mu);
    cv.wait_until(lk, deadline, [&] {
      return done || child_exited;
    });
  }

  // Stop and reap the child (idempotent — also handles natural exit).
  child->terminate();

  // After terminate(), the reader thread is joined and on_done has
  // fired. Drain any captured stderr to inspect for privilege errors.
  std::string err = child->drain_stderr();

  bool collected_anything;
  {
    std::lock_guard<std::mutex> lk(mu);
    collected_anything = !result.packets.empty();
  }

  if (!collected_anything && stderr_indicates_no_perm(err)) {
    throw backend::Error(
        std::string("observer.net.tcpdump: permission denied: ")
        + strip(err));
  }
  if (!collected_anything && !err.empty() && !child_exited) {
    // Spawn started but the child died with diagnostic output and we
    // got nothing — surface as backend error with the first 256 bytes.
    throw backend::Error(
        std::string("observer.net.tcpdump: tcpdump failed: ")
        + err.substr(0, std::min<std::size_t>(err.size(), 256)));
  }
  if (!collected_anything && child_exited && !err.empty()) {
    // Child exited without producing parseable lines. The most likely
    // cause is an error reported on stderr (bad iface, bad bpf, etc.)
    // — surface it.
    if (err.find("syntax error") != std::string::npos
        || err.find("No such device") != std::string::npos
        || err.find("BIOCSETIF") != std::string::npos
        || err.find("usage:") != std::string::npos) {
      throw backend::Error(
          std::string("observer.net.tcpdump: ")
          + strip(err.substr(0, std::min<std::size_t>(err.size(), 256))));
    }
  }

  result.total     = static_cast<std::uint32_t>(result.packets.size());
  result.truncated = (result.total < req.count);
  return result;
}

}  // namespace ldb::observers
