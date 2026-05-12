// SPDX-License-Identifier: Apache-2.0
#include "probes/agent_engine.h"

#include "util/log.h"

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ext/stdio_filebuf.h>
#include <filesystem>
#include <iostream>
#include <istream>
#include <ostream>
#include <thread>
#include <vector>

extern char** environ;

namespace ldb::probes {

namespace pa = ldb::probe_agent;

struct AgentEngine::Impl {
  pid_t pid       = -1;
  int   stdin_fd  = -1;
  int   stdout_fd = -1;

  // stdio_filebuf so we can wrap the fds in std::iostream and reuse the
  // probe_agent::read_frame / write_frame helpers without copying.
  std::unique_ptr<__gnu_cxx::stdio_filebuf<char>> in_buf;
  std::unique_ptr<__gnu_cxx::stdio_filebuf<char>> out_buf;
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

  using filebuf = __gnu_cxx::stdio_filebuf<char>;
  impl_->in_buf  = std::make_unique<filebuf>(impl_->stdin_fd,
                                              std::ios::out | std::ios::binary);
  impl_->out_buf = std::make_unique<filebuf>(impl_->stdout_fd,
                                              std::ios::in | std::ios::binary);
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
