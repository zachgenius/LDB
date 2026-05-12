// SPDX-License-Identifier: Apache-2.0
#include "probes/agent_engine.h"

#include "util/log.h"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <istream>
#include <ostream>
#include <streambuf>
#include <thread>
#include <vector>

extern char** environ;

namespace ldb::probes {

namespace pa = ldb::probe_agent;

namespace {

// Minimal fd-backed streambuf. The probe_agent protocol helpers take
// std::istream / std::ostream by reference, so we need *some* stream
// wrapping around our raw pipe fds. libstdc++'s __gnu_cxx::stdio_filebuf
// is exactly this but is libstdc++-only — Apple's libc++ doesn't ship
// it, breaking the macOS CI leg. Implementing the four overrides
// std::streambuf needs is ~30 lines and works across both stdlibs.
//
// Buffer sizes intentionally small: the protocol's read_frame /
// write_frame call sgetn / sputn in length-prefixed chunks (header,
// then body), so we don't get much from a fat buffer; we'd rather
// keep memory pressure minimal and force the kernel's pipe buffer
// (typically 64 KiB) to do its job. The class is non-owning of the
// fd — AgentEngine::Impl handles close() on the underlying.
class FdStreamBuf : public std::streambuf {
 public:
  explicit FdStreamBuf(int fd) : fd_(fd) {
    setg(in_buf_, in_buf_, in_buf_);  // empty get area; underflow fills.
    setp(out_buf_, out_buf_ + kOutBuf);
  }

  ~FdStreamBuf() override {
    // Best-effort flush; ignore errors at destruction.
    sync();
  }

 protected:
  // Reads more bytes from fd into the get area. Returns the next char,
  // or EOF on stream close / read failure (read returning 0 = EOF;
  // EINTR retries).
  int_type underflow() override {
    if (fd_ < 0) return traits_type::eof();
    for (;;) {
      ssize_t n = ::read(fd_, in_buf_, kInBuf);
      if (n > 0) {
        setg(in_buf_, in_buf_, in_buf_ + n);
        return traits_type::to_int_type(in_buf_[0]);
      }
      if (n == 0) return traits_type::eof();
      if (errno == EINTR) continue;
      return traits_type::eof();
    }
  }

  // Flush the put area when full, then write the overflow char.
  int_type overflow(int_type ch) override {
    if (sync() != 0) return traits_type::eof();
    if (ch != traits_type::eof()) {
      char c = static_cast<char>(ch);
      *pptr() = c;
      pbump(1);
    }
    return ch;
  }

  // Flush put area to fd in a single short loop. Returns 0 on success,
  // -1 on partial / failed write (caller treats as stream-fail; mirrors
  // stdio_filebuf semantics).
  int sync() override {
    if (fd_ < 0) return -1;
    char* base = pbase();
    std::ptrdiff_t pending = pptr() - base;
    while (pending > 0) {
      ssize_t n = ::write(fd_, base, static_cast<std::size_t>(pending));
      if (n > 0) {
        base    += n;
        pending -= n;
        continue;
      }
      if (n < 0 && errno == EINTR) continue;
      return -1;
    }
    setp(out_buf_, out_buf_ + kOutBuf);
    return 0;
  }

 private:
  static constexpr std::size_t kInBuf  = 4096;
  static constexpr std::size_t kOutBuf = 4096;
  int  fd_;
  char in_buf_[kInBuf];
  char out_buf_[kOutBuf];
};

}  // namespace

struct AgentEngine::Impl {
  pid_t pid       = -1;
  int   stdin_fd  = -1;
  int   stdout_fd = -1;

  // Portable fd-backed streambufs (avoid libstdc++'s stdio_filebuf so
  // the daemon builds on macOS / libc++). The streams hold the bufs by
  // raw pointer; we own the bufs and the fds independently.
  std::unique_ptr<FdStreamBuf>  in_buf;
  std::unique_ptr<FdStreamBuf>  out_buf;
  std::unique_ptr<std::ostream> stdin_stream;
  std::unique_ptr<std::istream> stdout_stream;
};

namespace {

[[nodiscard]] bool is_executable_file(const std::string& path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(path, ec)
      && ::access(path.c_str(), X_OK) == 0;
}

std::string sibling_of_self(const char* name) {
  // /proc/self/exe is Linux-specific; on a non-Linux build the binary
  // discovery is via PATH or $LDB_PROBE_AGENT. This helper is best-
  // effort, never throws.
  char buf[4096];
  ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return "";
  buf[n] = '\0';
  std::filesystem::path p(buf);
  auto candidate = p.parent_path() / name;
  return std::filesystem::weakly_canonical(candidate).string();
}

}  // namespace

std::string AgentEngine::discover_agent() {
  if (const char* env = std::getenv("LDB_PROBE_AGENT");
      env && *env && is_executable_file(env)) {
    return env;
  }
  // PATH search via filesystem (no shell).
  if (const char* path = std::getenv("PATH"); path && *path) {
    std::string p(path);
    std::size_t pos = 0;
    while (pos <= p.size()) {
      auto colon = p.find(':', pos);
      std::string dir = p.substr(pos, colon - pos);
      if (!dir.empty()) {
        std::string cand = dir + "/ldb-probe-agent";
        if (is_executable_file(cand)) return cand;
      }
      if (colon == std::string::npos) break;
      pos = colon + 1;
    }
  }
  // Co-located alongside ldbd in the build tree / install prefix.
  std::string sibling = sibling_of_self("ldb-probe-agent");
  if (is_executable_file(sibling)) return sibling;
  return "";
}

AgentEngine::AgentEngine(std::string agent_path)
    : impl_(std::make_unique<Impl>()) {
  if (agent_path.empty() || !is_executable_file(agent_path)) {
    throw backend::Error(
        "agent_engine: ldb-probe-agent not found "
        "(set $LDB_PROBE_AGENT, install on $PATH, or build alongside "
        "ldbd)");
  }

  int in_pipe[2]  = {-1, -1};
  int out_pipe[2] = {-1, -1};
  auto close_all = [&]() {
    for (int* p : {in_pipe, out_pipe}) {
      if (p[0] >= 0) ::close(p[0]);
      if (p[1] >= 0) ::close(p[1]);
    }
  };
  if (::pipe(in_pipe) < 0 || ::pipe(out_pipe) < 0) {
    int e = errno;
    close_all();
    throw backend::Error(std::string("agent_engine: pipe() failed: ")
                         + std::strerror(e));
  }

  posix_spawn_file_actions_t actions;
  ::posix_spawn_file_actions_init(&actions);
  ::posix_spawn_file_actions_adddup2(&actions, in_pipe[0],  STDIN_FILENO);
  ::posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
  ::posix_spawn_file_actions_addclose(&actions, in_pipe[0]);
  ::posix_spawn_file_actions_addclose(&actions, in_pipe[1]);
  ::posix_spawn_file_actions_addclose(&actions, out_pipe[0]);
  ::posix_spawn_file_actions_addclose(&actions, out_pipe[1]);

  std::vector<std::string> argv_storage = {agent_path};
  std::vector<char*> argv_ptrs;
  argv_ptrs.reserve(argv_storage.size() + 1);
  for (auto& s : argv_storage) argv_ptrs.push_back(s.data());
  argv_ptrs.push_back(nullptr);

  pid_t child = -1;
  int rc = ::posix_spawnp(&child, agent_path.c_str(), &actions, nullptr,
                          argv_ptrs.data(), environ);
  ::posix_spawn_file_actions_destroy(&actions);
  if (rc != 0) {
    close_all();
    throw backend::Error(std::string("agent_engine: posix_spawnp: ")
                         + std::strerror(rc));
  }
  // Close the child-side fds in the parent.
  ::close(in_pipe[0]);
  ::close(out_pipe[1]);

  impl_->pid       = child;
  impl_->stdin_fd  = in_pipe[1];
  impl_->stdout_fd = out_pipe[0];

  impl_->in_buf  = std::make_unique<FdStreamBuf>(impl_->stdin_fd);
  impl_->out_buf = std::make_unique<FdStreamBuf>(impl_->stdout_fd);
  impl_->stdin_stream  = std::make_unique<std::ostream>(impl_->in_buf.get());
  impl_->stdout_stream = std::make_unique<std::istream>(impl_->out_buf.get());
}

AgentEngine::~AgentEngine() {
  if (!impl_) return;
  if (impl_->stdin_stream) {
    // Send shutdown so the agent exits cleanly on its loop. Best effort
    // — if the agent already died, the write returns false and we
    // proceed to closing stdin which terminates the read side too.
    (void)pa::write_frame(*impl_->stdin_stream,
                          pa::make_shutdown_request().dump());
    impl_->stdin_stream->flush();
  }
  impl_->stdin_stream.reset();
  impl_->in_buf.reset();
  if (impl_->stdin_fd >= 0) ::close(impl_->stdin_fd);
  impl_->stdin_fd = -1;

  if (impl_->pid > 0) {
    // Short deadline: wait 500 ms for natural exit, then SIGKILL.
    int status = 0;
    pid_t got = 0;
    for (int i = 0; i < 50 && got == 0; ++i) {
      got = ::waitpid(impl_->pid, &status, WNOHANG);
      if (got == 0) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (got == 0) {
      ::kill(impl_->pid, SIGKILL);
      ::waitpid(impl_->pid, &status, 0);
    }
    impl_->pid = -1;
  }

  impl_->stdout_stream.reset();
  impl_->out_buf.reset();
  if (impl_->stdout_fd >= 0) ::close(impl_->stdout_fd);
  impl_->stdout_fd = -1;
}

nlohmann::json AgentEngine::round_trip(const nlohmann::json& request,
                                       std::string_view op) {
  if (!impl_ || !impl_->stdin_stream || !impl_->stdout_stream) {
    throw backend::Error("agent_engine: not initialized");
  }
  if (!pa::write_frame(*impl_->stdin_stream, request.dump())) {
    throw backend::Error(std::string("agent_engine: write_frame(")
                         + std::string(op) + ") failed");
  }
  impl_->stdin_stream->flush();

  std::string body;
  auto ferr = pa::read_frame(*impl_->stdout_stream, &body);
  if (ferr != pa::FrameError::kOk) {
    throw backend::Error(std::string("agent_engine: read_frame(")
                         + std::string(op) + ") failed (code="
                         + std::to_string(static_cast<int>(ferr)) + ")");
  }
  nlohmann::json resp;
  try {
    resp = nlohmann::json::parse(body);
  } catch (const std::exception& e) {
    throw backend::Error(std::string("agent_engine: ") + std::string(op)
                         + " response parse: " + e.what());
  }
  if (auto err = pa::parse_error(resp)) {
    throw backend::Error("agent_engine: " + std::string(op)
                         + ": agent error " + err->code
                         + ": " + err->message);
  }
  return resp;
}

pa::HelloOk AgentEngine::hello() {
  auto resp = round_trip(pa::make_hello_request(), "hello");
  auto ok = pa::parse_hello_ok(resp);
  if (!ok) {
    throw backend::Error("agent_engine: response is not a hello_ok shape: "
                         + resp.dump());
  }
  return *ok;
}

std::string AgentEngine::attach_uprobe(std::string_view program,
                                       std::string_view path,
                                       std::string_view symbol,
                                       std::optional<std::int64_t> pid) {
  auto resp = round_trip(
      pa::make_attach_uprobe_request(program, path, symbol, pid),
      "attach_uprobe");
  auto a = pa::parse_attached(resp);
  if (!a) {
    throw backend::Error("agent_engine: attach_uprobe: response is "
                         "not an attached shape: " + resp.dump());
  }
  return a->attach_id;
}

std::string AgentEngine::attach_kprobe(std::string_view program,
                                       std::string_view function) {
  auto resp = round_trip(
      pa::make_attach_kprobe_request(program, function), "attach_kprobe");
  auto a = pa::parse_attached(resp);
  if (!a) {
    throw backend::Error("agent_engine: attach_kprobe: response is "
                         "not an attached shape: " + resp.dump());
  }
  return a->attach_id;
}

std::string AgentEngine::attach_tracepoint(std::string_view program,
                                           std::string_view category,
                                           std::string_view name) {
  auto resp = round_trip(
      pa::make_attach_tracepoint_request(program, category, name),
      "attach_tracepoint");
  auto a = pa::parse_attached(resp);
  if (!a) {
    throw backend::Error("agent_engine: attach_tracepoint: response is "
                         "not an attached shape: " + resp.dump());
  }
  return a->attach_id;
}

pa::PollEvents AgentEngine::poll_events(std::string_view attach_id,
                                        std::uint32_t max) {
  auto resp = round_trip(
      pa::make_poll_events_request(attach_id, max), "poll_events");
  auto p = pa::parse_events(resp);
  if (!p) {
    throw backend::Error("agent_engine: poll_events: response is "
                         "not an events shape: " + resp.dump());
  }
  return *p;
}

void AgentEngine::detach(std::string_view attach_id) {
  // The agent's detached-ok response carries no payload of interest;
  // round_trip handles error envelopes. We discard the success body.
  (void)round_trip(pa::make_detach_request(attach_id), "detach");
}

}  // namespace ldb::probes
