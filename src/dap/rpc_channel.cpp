// SPDX-License-Identifier: Apache-2.0
#include "dap/rpc_channel.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <istream>
#include <sstream>
#include <streambuf>
#include <string>
#include <utility>
#include <vector>

namespace ldb::dap {

namespace {

// fdstreambuf — a minimal std::streambuf wrapping a POSIX fd, so we can
// reuse iostream-based readline logic without a full stdio FILE*. Read
// path only (we write via raw ::write — the channel's write side is
// just `payload + '\n'`).
class FdStreambuf : public std::streambuf {
 public:
  explicit FdStreambuf(int fd, std::size_t buf_size = 4096)
      : fd_(fd), buf_(buf_size) {
    setg(buf_.data(), buf_.data(), buf_.data());
  }

 protected:
  int_type underflow() override {
    if (fd_ < 0) return traits_type::eof();
    while (true) {
      ssize_t n = ::read(fd_, buf_.data(), buf_.size());
      if (n > 0) {
        setg(buf_.data(), buf_.data(), buf_.data() + n);
        return traits_type::to_int_type(*gptr());
      }
      if (n == 0) return traits_type::eof();  // EOF
      if (errno == EINTR) continue;
      return traits_type::eof();
    }
  }

 private:
  int fd_;
  std::vector<char> buf_;
};

}  // namespace

struct SubprocessRpcChannel::Impl {
  pid_t pid = -1;
  int stdin_fd = -1;
  int stdout_fd = -1;
  std::unique_ptr<FdStreambuf> stdout_buf;
  std::unique_ptr<std::istream> stdout_stream;
};

SubprocessRpcChannel::SubprocessRpcChannel(
    const std::string& ldbd_path,
    std::vector<std::string> extra_args)
    : p_(std::make_unique<Impl>()) {
  int in_pipe[2] = {-1, -1};   // shim writes -> child stdin
  int out_pipe[2] = {-1, -1};  // child stdout -> shim reads
  if (::pipe(in_pipe) != 0 || ::pipe(out_pipe) != 0) {
    throw RpcError(std::string("pipe(): ") + std::strerror(errno));
  }

  pid_t pid = ::fork();
  if (pid < 0) {
    ::close(in_pipe[0]);  ::close(in_pipe[1]);
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    throw RpcError(std::string("fork(): ") + std::strerror(errno));
  }
  if (pid == 0) {
    // Child. Wire pipes to fd 0/1; leave stderr alone so the daemon's
    // log lines reach the shim's stderr (and thus the operator's
    // terminal). Then exec ldbd.
    ::dup2(in_pipe[0], 0);
    ::dup2(out_pipe[1], 1);
    ::close(in_pipe[0]);  ::close(in_pipe[1]);
    ::close(out_pipe[0]); ::close(out_pipe[1]);

    std::vector<std::string> argv_storage;
    argv_storage.push_back(ldbd_path);
    argv_storage.emplace_back("--stdio");
    argv_storage.emplace_back("--format");
    argv_storage.emplace_back("json");
    for (auto& a : extra_args) argv_storage.push_back(std::move(a));
    std::vector<char*> argv;
    argv.reserve(argv_storage.size() + 1);
    for (auto& s : argv_storage) argv.push_back(s.data());
    argv.push_back(nullptr);

    ::execvp(ldbd_path.c_str(), argv.data());
    // exec failed.
    std::fprintf(stderr, "ldb-dap: failed to exec %s: %s\n",
                 ldbd_path.c_str(), std::strerror(errno));
    _exit(127);
  }

  // Parent.
  ::close(in_pipe[0]);
  ::close(out_pipe[1]);
  p_->pid = pid;
  p_->stdin_fd = in_pipe[1];
  p_->stdout_fd = out_pipe[0];
  p_->stdout_buf = std::make_unique<FdStreambuf>(p_->stdout_fd);
  p_->stdout_stream = std::make_unique<std::istream>(p_->stdout_buf.get());
}

SubprocessRpcChannel::~SubprocessRpcChannel() {
  shutdown();
}

int SubprocessRpcChannel::shutdown() {
  if (!p_) return -1;
  if (p_->stdin_fd >= 0) { ::close(p_->stdin_fd); p_->stdin_fd = -1; }
  if (p_->pid > 0) {
    int status = 0;
    pid_t r = ::waitpid(p_->pid, &status, WNOHANG);
    if (r == 0) {
      // Still alive; ask politely, then forcefully.
      ::kill(p_->pid, SIGTERM);
      for (int i = 0; i < 50; ++i) {  // up to ~500ms
        r = ::waitpid(p_->pid, &status, WNOHANG);
        if (r != 0) break;
        ::usleep(10 * 1000);
      }
      if (r == 0) {
        ::kill(p_->pid, SIGKILL);
        ::waitpid(p_->pid, &status, 0);
      }
    }
    p_->pid = -1;
    if (p_->stdout_fd >= 0) { ::close(p_->stdout_fd); p_->stdout_fd = -1; }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  }
  return -1;
}

RpcResponse SubprocessRpcChannel::call(const std::string& method,
                                       const json& params) {
  if (!p_ || p_->stdin_fd < 0) {
    throw RpcError("RPC channel is closed");
  }
  std::uint64_t id = next_id_++;
  json req = {
      {"jsonrpc", "2.0"},
      {"id", id},
      {"method", method},
      {"params", params},
  };
  std::string line = req.dump() + "\n";
  std::size_t total = 0;
  while (total < line.size()) {
    ssize_t n = ::write(p_->stdin_fd, line.data() + total,
                        line.size() - total);
    if (n < 0) {
      if (errno == EINTR) continue;
      throw RpcError(std::string("write to ldbd stdin: ") +
                     std::strerror(errno));
    }
    total += static_cast<std::size_t>(n);
  }

  // Read response lines until we find one matching our id. Drop
  // unmatched frames (defensive — the daemon shouldn't emit any in
  // practice for synchronous JSON-RPC, but skipping is safer than
  // crashing if the protocol grows event frames).
  std::string in_line;
  while (std::getline(*p_->stdout_stream, in_line)) {
    if (in_line.empty()) continue;
    json resp;
    try {
      resp = json::parse(in_line);
    } catch (const json::parse_error& e) {
      throw RpcError(std::string("malformed daemon response: ") + e.what());
    }
    auto rid_it = resp.find("id");
    if (rid_it == resp.end()) continue;
    if (!rid_it->is_number_unsigned() && !rid_it->is_number_integer()) continue;
    std::uint64_t rid = rid_it->is_number_unsigned()
                            ? rid_it->get<std::uint64_t>()
                            : static_cast<std::uint64_t>(rid_it->get<std::int64_t>());
    if (rid != id) continue;

    RpcResponse out;
    if (auto it = resp.find("ok"); it != resp.end() && it->is_boolean()) {
      out.ok = it->get<bool>();
    }
    if (out.ok) {
      if (auto it = resp.find("data"); it != resp.end()) out.data = *it;
    } else {
      if (auto it = resp.find("error");
          it != resp.end() && it->is_object()) {
        if (auto c = it->find("code");
            c != it->end() && c->is_number_integer()) {
          out.error_code = c->get<int>();
        }
        if (auto m = it->find("message");
            m != it->end() && m->is_string()) {
          out.error_message = m->get<std::string>();
        }
        if (auto d = it->find("data"); d != it->end()) {
          out.error_data = *d;
        }
      }
    }
    return out;
  }
  throw RpcError("ldbd closed stdout before response");
}

}  // namespace ldb::dap
