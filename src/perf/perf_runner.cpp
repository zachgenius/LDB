// SPDX-License-Identifier: Apache-2.0
#include "perf/perf_runner.h"

#include "backend/debugger_backend.h"  // backend::Error
#include "transport/local_exec.h"

#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace ldb::perf {

namespace {

bool path_executable(const std::string& p) {
  if (p.empty()) return false;
  return ::access(p.c_str(), X_OK) == 0;
}

std::string which_via_path(const char* prog) {
  const char* path = std::getenv("PATH");
  if (!path || !*path) return {};
  std::string s = path;
  std::size_t i = 0;
  while (i <= s.size()) {
    std::size_t j = s.find(':', i);
    std::string dir = (j == std::string::npos)
                          ? s.substr(i)
                          : s.substr(i, j - i);
    if (!dir.empty()) {
      std::string cand = dir + "/" + prog;
      if (path_executable(cand)) return cand;
    }
    if (j == std::string::npos) break;
    i = j + 1;
  }
  return {};
}

// Last N bytes of stderr as a printable string; used for diagnostics.
// Bounded so it can't blow the JSON-RPC channel.
std::string tail(const std::string& s, std::size_t cap) {
  if (s.size() <= cap) return s;
  return s.substr(s.size() - cap);
}

std::string make_tempfile(std::string_view stem) {
  // Use std::filesystem::temp_directory_path + mkstemp pattern.
  std::filesystem::path dir = std::filesystem::temp_directory_path();
  std::string tmpl = (dir / (std::string(stem) + "-XXXXXX.data")).string();
  // mkstemps wants a writable C string; reserve space for the
  // 6 random chars + ".data" suffix.
  std::vector<char> buf(tmpl.begin(), tmpl.end());
  buf.push_back('\0');
  int fd = ::mkstemps(buf.data(), 5);
  if (fd < 0) {
    throw backend::Error(std::string("perf: mkstemps failed: ")
                         + std::strerror(errno));
  }
  ::close(fd);
  return std::string(buf.data());
}

std::uint64_t file_size(const std::string& path) {
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0) return 0;
  return static_cast<std::uint64_t>(st.st_size);
}

std::string join_events(const std::vector<std::string>& events) {
  if (events.empty()) return "cycles";
  std::string out;
  for (std::size_t i = 0; i < events.size(); ++i) {
    if (i) out.push_back(',');
    out += events[i];
  }
  return out;
}

}  // namespace

std::string PerfRunner::discover_perf() {
  if (const char* env = std::getenv("LDB_PERF"); env && *env) {
    if (path_executable(env)) return env;
  }
  // /usr/bin/perf is the canonical Ubuntu/Pop_OS install path. PATH
  // lookup falls back through that anyway, but skip the env scan when
  // the well-known location is present.
  static constexpr const char* kKnown[] = {
    "/usr/bin/perf",
    "/usr/local/bin/perf",
  };
  for (const char* p : kKnown) {
    if (path_executable(p)) return p;
  }
  return which_via_path("perf");
}

RecordResult PerfRunner::record(const RecordSpec& spec) {
  // Argument validation.
  const bool have_pid = spec.pid.has_value();
  const bool have_cmd = !spec.command.empty();
  if (have_pid == have_cmd) {
    throw backend::Error("perf: exactly one of pid|command must be set");
  }
  if (have_pid && spec.duration.count() <= 0) {
    throw backend::Error("perf: duration_ms must be > 0 when pid is set");
  }
  if (spec.duration.count() > RecordSpec::kMaxDurationMs) {
    throw backend::Error("perf: duration_ms exceeds "
                         + std::to_string(RecordSpec::kMaxDurationMs)
                         + " (5 min) cap");
  }
  if (spec.frequency_hz == 0) {
    throw backend::Error("perf: frequency_hz must be > 0");
  }

  std::string perf_bin = discover_perf();
  if (perf_bin.empty()) {
    throw backend::Error("perf: binary not found on PATH "
                         "(install linux-tools or set LDB_PERF)");
  }

  std::string out_path = make_tempfile("ldb-perf");

  // Build argv. Format:
  //   perf record -F <hz> -e <events> --call-graph <mode> -o <out>
  //               [-p <pid>] -- [sleep <secs> | <command...>]
  std::vector<std::string> argv;
  argv.emplace_back(perf_bin);
  argv.emplace_back("record");
  argv.emplace_back("-q");                          // quiet "[ perf record: ... ]"
  argv.emplace_back("-F");
  argv.emplace_back(std::to_string(spec.frequency_hz));
  argv.emplace_back("-e");
  argv.emplace_back(join_events(spec.events));
  argv.emplace_back("--call-graph");
  argv.emplace_back(spec.call_graph.empty() ? "fp" : spec.call_graph);
  argv.emplace_back("-o");
  argv.emplace_back(out_path);

  if (have_pid) {
    argv.emplace_back("-p");
    argv.emplace_back(std::to_string(*spec.pid));
    argv.emplace_back("--");
    argv.emplace_back("sleep");
    // perf -- sleep accepts a float number of seconds.
    char dur_buf[32];
    std::snprintf(dur_buf, sizeof(dur_buf), "%.3f",
                  static_cast<double>(spec.duration.count()) / 1000.0);
    argv.emplace_back(dur_buf);
  } else {
    argv.emplace_back("--");
    for (const auto& s : spec.command) argv.emplace_back(s);
  }

  // Generous timeout: the configured duration plus 30 s for spawn /
  // post-write flush. Hard cap from kMaxDurationMs already enforced.
  transport::ExecOptions opts;
  opts.timeout = spec.duration + std::chrono::seconds(30);

  auto t0 = std::chrono::steady_clock::now();
  transport::ExecResult er;
  try {
    er = transport::local_exec(argv, opts);
  } catch (const backend::Error& e) {
    ::unlink(out_path.c_str());
    throw;
  }
  auto t1 = std::chrono::steady_clock::now();

  if (er.timed_out) {
    ::unlink(out_path.c_str());
    throw backend::Error("perf record: timed out after "
                         + std::to_string(opts.timeout.count()) + "ms");
  }
  if (er.exit_code != 0) {
    std::string tail4k = tail(er.stderr_data, 4096);
    ::unlink(out_path.c_str());
    throw backend::Error("perf record: exited with rc="
                         + std::to_string(er.exit_code)
                         + ": " + tail4k);
  }
  std::uint64_t sz = file_size(out_path);
  if (sz == 0) {
    ::unlink(out_path.c_str());
    throw backend::Error("perf record: perf.data missing or empty "
                         "(perf rc=0; stderr: "
                         + tail(er.stderr_data, 4096) + ")");
  }

  // Reparse via perf script. We do this in-line so the runner returns
  // both the path AND the parsed samples in one call.
  ReportSpec rs;
  rs.perf_data_path = out_path;
  ReportResult rep = report(rs);

  RecordResult out;
  out.perf_data_path = std::move(out_path);
  out.perf_data_size = sz;
  out.perf_argv      = std::move(argv);
  out.parsed         = std::move(rep.parsed);
  out.wall_duration  = std::chrono::duration_cast<std::chrono::milliseconds>(
      t1 - t0);
  out.stderr_tail    = tail(er.stderr_data, 4096);
  return out;
}

ReportResult PerfRunner::report(const ReportSpec& spec) {
  if (spec.perf_data_path.empty()) {
    throw backend::Error("perf report: perf_data_path is empty");
  }
  if (::access(spec.perf_data_path.c_str(), R_OK) != 0) {
    throw backend::Error("perf report: cannot read perf.data at "
                         + spec.perf_data_path);
  }
  std::string perf_bin = discover_perf();
  if (perf_bin.empty()) {
    throw backend::Error("perf: binary not found on PATH "
                         "(install linux-tools or set LDB_PERF)");
  }

  std::vector<std::string> argv;
  argv.emplace_back(perf_bin);
  argv.emplace_back("script");
  argv.emplace_back("-i");
  argv.emplace_back(spec.perf_data_path);
  argv.emplace_back("--header");
  argv.emplace_back("--fields");
  argv.emplace_back("comm,pid,tid,cpu,time,event,ip,sym,dso");

  transport::ExecOptions opts;
  opts.timeout    = std::chrono::seconds(60);
  opts.stdout_cap = 64ULL * 1024 * 1024;  // perf script can be chatty
  transport::ExecResult er = transport::local_exec(argv, opts);
  if (er.timed_out) {
    throw backend::Error("perf script: timed out");
  }
  if (er.exit_code != 0) {
    throw backend::Error("perf script: rc="
                         + std::to_string(er.exit_code)
                         + ": " + tail(er.stderr_data, 4096));
  }

  ReportResult r;
  r.parsed = PerfParser::parse(er.stdout_data);
  if (spec.max_samples > 0
      && static_cast<std::int64_t>(r.parsed.samples.size())
             > spec.max_samples) {
    r.truncated = true;
    r.parsed.samples.resize(static_cast<std::size_t>(spec.max_samples));
  }
  if (spec.max_stack_depth > 0) {
    for (auto& s : r.parsed.samples) {
      if (static_cast<std::int64_t>(s.stack.size()) > spec.max_stack_depth) {
        s.stack.resize(static_cast<std::size_t>(spec.max_stack_depth));
      }
    }
  }
  return r;
}

}  // namespace ldb::perf
