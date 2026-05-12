// SPDX-License-Identifier: Apache-2.0
#include "perf/perf_parser.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace ldb::perf {

namespace {

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

std::string_view strip_left(std::string_view s) {
  std::size_t i = 0;
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  return s.substr(i);
}

std::string_view strip_right(std::string_view s) {
  std::size_t n = s.size();
  while (n > 0 && std::isspace(static_cast<unsigned char>(s[n - 1]))) --n;
  return s.substr(0, n);
}

std::string_view trim(std::string_view s) {
  return strip_right(strip_left(s));
}

// Try to parse "<sec>.<frac>" into nanoseconds. Returns false on
// malformed input. Accepts any number of fractional digits up to 9;
// pads with trailing zeros to make ns.
bool parse_timestamp_ns(std::string_view text, std::int64_t* out) {
  std::size_t dot = text.find('.');
  if (dot == std::string_view::npos) return false;
  // seconds
  std::string secs_s(text.substr(0, dot));
  std::string frac_s(text.substr(dot + 1));
  if (secs_s.empty() || frac_s.empty()) return false;
  for (char c : secs_s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
  }
  for (char c : frac_s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
  }
  // Cap fractional at 9 digits; pad with zeros if shorter.
  if (frac_s.size() > 9) frac_s.resize(9);
  while (frac_s.size() < 9) frac_s.push_back('0');

  char*    end  = nullptr;
  long long secs = std::strtoll(secs_s.c_str(), &end, 10);
  if (end == secs_s.c_str()) return false;
  long long frac = std::strtoll(frac_s.c_str(), &end, 10);
  if (end == frac_s.c_str()) return false;
  // ns = secs * 1e9 + frac
  *out = static_cast<std::int64_t>(secs) * 1000000000LL
       + static_cast<std::int64_t>(frac);
  return true;
}

// Parse a stack-frame line (leading whitespace then "IP SYM+OFFSET (DSO)").
// `body` is the trimmed line (no leading whitespace). Tolerant of:
//   - missing "(dso)" suffix
//   - "[unknown]" symbol
//   - symbol with no "+offset"
bool parse_frame_body(std::string_view body, Frame* out) {
  body = trim(body);
  if (body.empty()) return false;

  // First token: hex IP. (Some perf builds prefix with 0x; perf script's
  // default does NOT. Accept either.)
  std::size_t sp = body.find_first_of(" \t");
  if (sp == std::string_view::npos) return false;
  std::string ip_s(body.substr(0, sp));
  if (ip_s.empty()) return false;
  if (starts_with(ip_s, "0x") || starts_with(ip_s, "0X")) ip_s.erase(0, 2);
  // Strict hex.
  for (char c : ip_s) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
  }
  char*    end  = nullptr;
  unsigned long long ip = std::strtoull(ip_s.c_str(), &end, 16);
  if (end == ip_s.c_str()) return false;
  out->addr = static_cast<std::uint64_t>(ip);

  std::string_view rest = strip_left(body.substr(sp));
  // Strip trailing "(DSO)" if present.
  if (!rest.empty() && rest.back() == ')') {
    std::size_t open_paren = rest.rfind('(');
    if (open_paren != std::string_view::npos) {
      std::string_view dso = rest.substr(open_paren + 1,
                                          rest.size() - open_paren - 2);
      out->mod = std::string(trim(dso));
      rest = strip_right(rest.substr(0, open_paren));
    }
  }
  // What remains is "SYM" or "SYM+offset" or "[unknown]".
  if (!rest.empty()) {
    // Drop "+offset" suffix.
    std::size_t plus = rest.find('+');
    std::string_view sym = (plus == std::string_view::npos)
                               ? rest
                               : rest.substr(0, plus);
    out->sym = std::string(trim(sym));
  }
  return true;
}

// Try to parse an event-header line. Returns true on success and fills
// `sample`, plus an optional first frame inferred from the same line.
//
// Format (per --fields comm,pid,tid,cpu,time,event,ip,sym,dso):
//
//   COMM PID/TID [CPU] SEC.USEC: EVENT: PERIOD: IP SYM+OFFSET (DSO)
//
// Some fields may carry colons (event names like "cycles:u"), so we
// scan column-by-column rather than splitting on whitespace.
bool parse_event_header(std::string_view line,
                        Sample*          sample,
                        Frame*           first_frame,
                        bool*            have_first_frame) {
  *have_first_frame = false;
  line = trim(line);
  if (line.empty()) return false;

  // Tokenize on whitespace; we need at least: comm pid/tid [cpu] ts: event(:) period: ip sym (dso?)
  std::vector<std::string_view> toks;
  std::size_t i = 0;
  while (i < line.size()) {
    while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i])))
      ++i;
    std::size_t start = i;
    while (i < line.size() && !std::isspace(static_cast<unsigned char>(line[i])))
      ++i;
    if (start < i) toks.push_back(line.substr(start, i - start));
  }
  if (toks.size() < 6) return false;

  // tok[0] = comm. Note: comm may contain a hyphen or alphanumerics;
  // we forbid '/' inside comm because the next token uses '/' as a
  // separator. perf script doesn't emit comm with '/' (it would
  // collide with PID/TID parse).
  // tok[1] = "PID/TID"
  std::size_t slash = toks[1].find('/');
  if (slash == std::string_view::npos) return false;
  std::string pid_s(toks[1].substr(0, slash));
  std::string tid_s(toks[1].substr(slash + 1));
  if (pid_s.empty() || tid_s.empty()) return false;
  for (char c : pid_s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
  }
  for (char c : tid_s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
  }

  // tok[2] = "[CPU]" — defensively optional. We pass `--sample-cpu` to
  // perf record so every sample carries CPU info, but if the trace was
  // recorded without it (older perf, perf.data from an external tool)
  // tok[2] will be the timestamp instead and we fall back to cpu=-1.
  std::string cpu_s;
  std::size_t consumed = 3;  // tokens consumed by header so far (comm pid/tid cpu)
  if (toks[2].size() >= 3 && toks[2].front() == '[' && toks[2].back() == ']') {
    cpu_s.assign(toks[2].substr(1, toks[2].size() - 2));
    for (char c : cpu_s) {
      if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
  } else {
    // No [CPU] token — slide subsequent token indices back by one.
    consumed = 2;
  }

  // tok[consumed] = "SEC.USEC:" (trailing colon).
  if (consumed >= toks.size()) return false;
  std::string_view t3 = toks[consumed];
  if (t3.empty() || t3.back() != ':') return false;
  std::string_view ts_text = t3.substr(0, t3.size() - 1);
  std::int64_t ts_ns = 0;
  if (!parse_timestamp_ns(ts_text, &ts_ns)) return false;

  // EVENT (trailing colon; event name itself may carry additional
  // colons, but the perf script default trims to a single event-name
  // colon — accept verbatim minus the trailing ':').
  std::size_t event_idx = consumed + 1;
  if (event_idx >= toks.size()) return false;
  std::string_view t4 = toks[event_idx];
  if (t4.empty() || t4.back() != ':') return false;
  std::string event(t4.substr(0, t4.size() - 1));

  // <period>: — the sample period. We don't preserve it (callers care
  // about counts, not weights). Sanity-check the trailing colon since
  // some older perf builds drop it.
  std::size_t period_idx = consumed + 2;
  std::size_t frame_tok_idx = consumed + 3;
  if (period_idx < toks.size()
      && !toks[period_idx].empty()
      && toks[period_idx].back() == ':') {
    // OK — period is present and consumed.
  } else {
    // Older format: period missing. Frame starts where period would be.
    frame_tok_idx = period_idx;
  }

  sample->comm  = std::string(toks[0]);
  sample->pid   = std::strtoull(pid_s.c_str(), nullptr, 10);
  sample->tid   = std::strtoull(tid_s.c_str(), nullptr, 10);
  sample->cpu   = cpu_s.empty() ? -1 : std::atoi(cpu_s.c_str());
  sample->ts_ns = ts_ns;
  sample->event = std::move(event);

  // Reconstruct the rest as a frame body.
  if (frame_tok_idx < toks.size()) {
    // Find the offset of toks[frame_tok_idx] within `line` so we can
    // pass the verbatim suffix to parse_frame_body (which knows about
    // "(dso)" tail handling).
    const char* base = line.data();
    const char* fb   = toks[frame_tok_idx].data();
    std::size_t offset = static_cast<std::size_t>(fb - base);
    Frame f;
    if (parse_frame_body(line.substr(offset), &f)) {
      *first_frame      = std::move(f);
      *have_first_frame = true;
    }
  }
  return true;
}

// Pull "<key> : <value>" out of a `# key : value` header line.
//
// perf script's header looks like:
//   # ========
//   # captured on    : Mon May 11 12:00:00 2026
//   # hostname       : devbox
//   # os release     : 6.18.7-76061807-generic
//
// We grep for hostname / os release / arch and ignore the rest. Best-
// effort; missing fields are simply empty in the result.
void parse_header_line(std::string_view line, PerfParser::Result* r) {
  if (!starts_with(line, "#")) return;
  std::string body(trim(line.substr(1)));
  // "key : value"
  std::size_t colon = body.find(':');
  if (colon == std::string::npos) return;
  std::string key = std::string(trim(std::string_view(body).substr(0, colon)));
  std::string val = std::string(trim(std::string_view(body).substr(colon + 1)));
  if (key == "hostname")        r->hostname   = std::move(val);
  else if (key == "os release") r->os_release = std::move(val);
  else if (key == "arch")       r->arch       = std::move(val);
}

}  // namespace

PerfParser::Result PerfParser::parse(std::string_view text) {
  Result r;
  Sample current;
  bool   have_current = false;

  auto flush = [&] {
    if (have_current) {
      r.samples.push_back(std::move(current));
      current      = Sample{};
      have_current = false;
    }
  };

  // Iterate lines.
  std::size_t i = 0;
  while (i <= text.size()) {
    std::size_t nl = text.find('\n', i);
    std::string_view line = (nl == std::string_view::npos)
                                ? text.substr(i)
                                : text.substr(i, nl - i);
    // Strip a trailing '\r' if Windows line endings sneak in.
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);

    // Blank lines flush the in-flight sample.
    if (trim(line).empty()) {
      flush();
    } else if (starts_with(line, "#")) {
      parse_header_line(line, &r);
    } else if (!line.empty()
               && !std::isspace(static_cast<unsigned char>(line.front()))) {
      // New event-header line. Flush prior, start new.
      flush();
      Sample s;
      Frame  f;
      bool   have_f = false;
      if (parse_event_header(line, &s, &f, &have_f)) {
        current      = std::move(s);
        have_current = true;
        if (have_f) current.stack.push_back(std::move(f));
      } else {
        r.parse_errors.push_back("bad event header: "
                                  + std::string(line));
      }
    } else {
      // Indented line: stack frame.
      if (!have_current) {
        r.parse_errors.push_back("stack frame without event header: "
                                  + std::string(line));
      } else {
        Frame f;
        if (parse_frame_body(line, &f)) {
          current.stack.push_back(std::move(f));
        } else {
          r.parse_errors.push_back("bad stack frame: "
                                    + std::string(line));
        }
      }
    }

    if (nl == std::string_view::npos) break;
    i = nl + 1;
  }
  // Final flush (in case the buffer didn't end with a blank line).
  flush();
  return r;
}

nlohmann::json PerfParser::sample_to_json(const Sample& s) {
  nlohmann::json j;
  j["ts_ns"] = s.ts_ns;
  j["tid"]   = s.tid;
  j["pid"]   = s.pid;
  j["cpu"]   = s.cpu;
  j["comm"]  = s.comm;
  j["event"] = s.event;
  nlohmann::json arr = nlohmann::json::array();
  for (const auto& f : s.stack) {
    nlohmann::json fj;
    // addr as hex string for shape-alignment with probe events
    // (registers / pc are hex strings there too).
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(f.addr));
    fj["addr"] = buf;
    if (!f.sym.empty()) fj["sym"] = f.sym;
    if (!f.mod.empty()) fj["mod"] = f.mod;
    arr.push_back(std::move(fj));
  }
  j["stack"] = std::move(arr);
  return j;
}

}  // namespace ldb::perf
