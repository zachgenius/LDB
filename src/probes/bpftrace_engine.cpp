// SPDX-License-Identifier: Apache-2.0
#include "probes/bpftrace_engine.h"

#include "backend/debugger_backend.h"  // backend::Error
#include "util/log.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <sstream>
#include <string>
#include <thread>

namespace ldb::probes {

namespace {

bool is_supported_arg_name(std::string_view s) {
  // Allowed: arg0..arg9 (bpftrace exposes up to arg5; we accept up to
  // arg9 for forward compat). REJECT anything else — agents can't
  // smuggle arbitrary bpftrace expressions through this path.
  if (s.size() != 4) return false;
  if (s[0] != 'a' || s[1] != 'r' || s[2] != 'g') return false;
  return s[3] >= '0' && s[3] <= '9';
}

}  // namespace

std::string generate_bpftrace_program(const UprobeBpfSpec& s) {
  if (s.where_target.empty()) {
    throw std::invalid_argument(
        "bpftrace: where_target must be set");
  }
  for (const auto& a : s.captured_args) {
    if (!is_supported_arg_name(a)) {
      throw std::invalid_argument(
          "bpftrace: capture.args entries must be arg0..arg9, got: " + a);
    }
  }

  std::string head;
  switch (s.where_kind) {
    case UprobeBpfSpec::Kind::kUprobe:
      head = "uprobe:" + s.where_target;
      break;
    case UprobeBpfSpec::Kind::kTracepoint:
      head = "tracepoint:" + s.where_target;
      break;
    case UprobeBpfSpec::Kind::kKprobe:
      head = "kprobe:" + s.where_target;
      break;
  }

  std::string filter;
  if (s.filter_pid.has_value()) {
    filter = " /pid == " + std::to_string(*s.filter_pid) + "/";
  }

  // Build the printf format string and arg list.
  //
  // Output format example (newlines added for readability — the real
  // emission is one line per hit):
  //   {"ts_ns":<nsecs>,"tid":<tid>,"pid":<pid>,"args":["0x<arg0>","0x<arg1>"]}
  std::string fmt =
      "{\\\"ts_ns\\\":%lu,\\\"tid\\\":%d,\\\"pid\\\":%d,\\\"args\\\":[";
  std::string args_decl = "nsecs, tid, pid";
  for (std::size_t i = 0; i < s.captured_args.size(); ++i) {
    if (i) fmt += ",";
    fmt += "\\\"0x%lx\\\"";
    args_decl += ", ";
    args_decl += s.captured_args[i];
  }
  fmt += "]}\\n";

  std::ostringstream oss;
  oss << head << filter << " { printf(\"" << fmt << "\", "
      << args_decl << "); }";
  return oss.str();
}

std::optional<ProbeEvent> BpftraceParse::parse_line(std::string_view line) {
  // Trim leading whitespace.
  std::size_t i = 0;
  while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) ++i;
  if (i >= line.size() || line[i] != '{') return std::nullopt;

  nlohmann::json j;
  try {
    j = nlohmann::json::parse(line.substr(i));
  } catch (const std::exception&) {
    return std::nullopt;
  }
  if (!j.is_object()) return std::nullopt;

  ProbeEvent ev;
  if (auto it = j.find("ts_ns"); it != j.end() && it->is_number()) {
    ev.ts_ns = it->get<std::int64_t>();
  }
  if (auto it = j.find("tid"); it != j.end() && it->is_number()) {
    ev.tid = it->get<std::uint64_t>();
  }
  if (auto it = j.find("pc"); it != j.end()) {
    if (it->is_number_unsigned()) ev.pc = it->get<std::uint64_t>();
    else if (it->is_string()) {
      const auto& s = it->get_ref<const std::string&>();
      try { ev.pc = std::stoull(s, nullptr, 0); } catch (...) {}
    }
  }
  if (auto it = j.find("args"); it != j.end() && it->is_array()) {
    std::size_t idx = 0;
    for (const auto& a : *it) {
      std::uint64_t v = 0;
      if (a.is_string()) {
        const auto& s = a.get_ref<const std::string&>();
        try { v = std::stoull(s, nullptr, 0); } catch (...) {}
      } else if (a.is_number_unsigned()) {
        v = a.get<std::uint64_t>();
      } else if (a.is_number_integer()) {
        v = static_cast<std::uint64_t>(a.get<std::int64_t>());
      }
      ev.registers["arg" + std::to_string(idx)] = v;
      ++idx;
    }
  }
  return ev;
}

std::string discover_bpftrace() {
  if (const char* env = std::getenv("LDB_BPFTRACE"); env && *env) {
    if (std::filesystem::exists(env)) return env;
  }
  for (const char* candidate :
       {"/usr/bin/bpftrace", "/usr/local/bin/bpftrace"}) {
    if (std::filesystem::exists(candidate)) return candidate;
  }
  // PATH lookup via popen. We use `command -v` (POSIX) rather than
  // `which` which is shell-builtin-shadowed on some distros.
  FILE* fp = ::popen("command -v bpftrace 2>/dev/null", "r");
  if (!fp) return {};
  char buf[1024];
  std::string out;
  while (std::fgets(buf, sizeof(buf), fp) != nullptr) out += buf;
  ::pclose(fp);
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) {
    out.pop_back();
  }
  if (!out.empty() && out.front() == '/' && std::filesystem::exists(out)) {
    return out;
  }
  return {};
}

// ---------------------------------------------------------------------------
// BpftraceEngine
// ---------------------------------------------------------------------------

struct BpftraceEngine::Impl {
  UprobeBpfSpec                          spec;
  EventCallback                          on_event;
  ExitCallback                           on_exit;

  std::unique_ptr<transport::StreamingExec> sx;

  std::mutex                             mu;
  std::condition_variable                cv;
  bool                                   first_line_seen = false;
  bool                                   exited          = false;
  int                                    exit_code       = 0;
  bool                                   timed_out       = false;
  std::string                            stderr_text;

  std::atomic<bool>                      running{false};
};

BpftraceEngine::BpftraceEngine(UprobeBpfSpec spec,
                               EventCallback on_event,
                               ExitCallback  on_exit)
    : impl_(std::make_unique<Impl>()) {
  impl_->spec     = std::move(spec);
  impl_->on_event = std::move(on_event);
  impl_->on_exit  = std::move(on_exit);
}

BpftraceEngine::~BpftraceEngine() { stop(); }

void BpftraceEngine::start(std::chrono::milliseconds setup_timeout) {
  std::string bpf = discover_bpftrace();
  if (bpf.empty()) {
    throw backend::Error(
        "bpftrace not installed; install via your distro or grab a static "
        "binary from https://github.com/iovisor/bpftrace/releases. Or set "
        "LDB_BPFTRACE=/path/to/bpftrace.");
  }

  std::string program = generate_bpftrace_program(impl_->spec);

  // -B line forces line-buffered stdout — bpftrace defaults to block
  // buffering when its stdout is a pipe (which it always is for us),
  // and that buffering would defer events by tens of seconds under
  // light traffic. Documented landmine in CLAUDE.md / WORKLOG.
  std::vector<std::string> argv{
      bpf, "-B", "line", "-e", program};

  // Capture-by-impl raw pointer because the StreamingExec callbacks
  // outlive the invocation of start() but are owned by impl_.
  Impl* p = impl_.get();
  auto on_line = [p](std::string_view sv) {
    auto ev = BpftraceParse::parse_line(sv);
    if (!ev.has_value()) {
      // bpftrace prints status lines like "Attaching 1 probe..." which
      // we use as a startup signal.
      {
        std::lock_guard<std::mutex> lk(p->mu);
        p->first_line_seen = true;
      }
      p->cv.notify_all();
      return;
    }
    {
      std::lock_guard<std::mutex> lk(p->mu);
      p->first_line_seen = true;
    }
    p->cv.notify_all();
    if (p->on_event) p->on_event(*ev);
  };
  auto on_done = [p](int code, bool t) {
    {
      std::lock_guard<std::mutex> lk(p->mu);
      p->exited    = true;
      p->exit_code = code;
      p->timed_out = t;
    }
    p->cv.notify_all();
    p->running.store(false);
    if (p->on_exit) {
      // Snapshot stderr_text into a fresh string at fire time.
      std::string snap;
      if (p->sx) snap = p->sx->drain_stderr();
      p->on_exit(code, t, std::move(snap));
    }
  };

  impl_->sx = std::make_unique<transport::StreamingExec>(
      impl_->spec.remote, std::move(argv),
      std::move(on_line), std::move(on_done));

  impl_->running.store(true);

  // Wait for either: first stdout activity (success) OR child exit
  // (failure). We use the engine's own mutex/cv — set by the line and
  // done callbacks above.
  std::unique_lock<std::mutex> lk(impl_->mu);
  bool ok = impl_->cv.wait_for(lk, setup_timeout, [&] {
    return impl_->first_line_seen || impl_->exited;
  });
  if (!ok) {
    // Timed out without ANY output. bpftrace usually prints the
    // "Attaching N probes..." line immediately; absence means it's
    // wedged on probe attach (rare, usually CAP_BPF / privilege error).
    std::string err = impl_->sx ? impl_->sx->drain_stderr() : "";
    lk.unlock();
    stop();
    throw backend::Error("bpftrace startup timeout (" +
                         std::to_string(setup_timeout.count()) +
                         " ms); stderr: " + err);
  }
  if (impl_->exited) {
    int rc = impl_->exit_code;
    std::string err = impl_->sx ? impl_->sx->drain_stderr() : "";
    lk.unlock();
    stop();
    throw backend::Error(
        "bpftrace exited during startup (rc=" + std::to_string(rc) +
        "); stderr: " + err);
  }
}

void BpftraceEngine::stop() {
  if (impl_->sx) {
    impl_->sx->terminate();
    impl_->sx.reset();
  }
  impl_->running.store(false);
}

bool BpftraceEngine::running() const {
  return impl_->running.load();
}

std::string BpftraceEngine::drain_stderr() const {
  if (!impl_->sx) return {};
  return impl_->sx->drain_stderr();
}

}  // namespace ldb::probes
