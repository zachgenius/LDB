// SPDX-License-Identifier: Apache-2.0
// Tests for target.create_empty + target.attach + process.detach.
//
// Spawns the sleeper fixture as a separate process, parses the PID
// from its stdout, then attaches via the backend. The test process
// is the launcher of the inferior, so on macOS the signed Apple
// debugserver (auto-located via maybe_seed_apple_debugserver) handles
// the task_for_pid privileges without entitlement issues for our
// own child.
//
// On Linux the parent of a process is allowed to ptrace it under the
// default Yama setting. If a future Linux CI sets ptrace_scope=2 we'd
// have to skip these — leave that handling to when it bites.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "ptrace_probe.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;

namespace {

constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

struct SpawnedSleeper {
  pid_t pid = -1;
  int   stdout_fd = -1;
  ~SpawnedSleeper() {
    if (pid > 0) {
      ::kill(pid, SIGKILL);
      int status = 0;
      ::waitpid(pid, &status, 0);
    }
    if (stdout_fd >= 0) ::close(stdout_fd);
  }
};

std::unique_ptr<SpawnedSleeper> spawn_sleeper() {
  int pipefd[2];
  REQUIRE(::pipe(pipefd) == 0);

  pid_t child = ::fork();
  REQUIRE(child >= 0);

  if (child == 0) {
    ::dup2(pipefd[1], STDOUT_FILENO);
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    char* const argv[] = {const_cast<char*>(kSleeperPath), nullptr};
    ::execv(kSleeperPath, argv);
    _exit(127);
  }

  ::close(pipefd[1]);

  auto out = std::make_unique<SpawnedSleeper>();
  out->pid = child;
  out->stdout_fd = pipefd[0];

  // Wait for the READY line. Bounded — if it doesn't appear in 5s the
  // fixture is broken.
  std::string line;
  char buf[256];
  for (int tries = 0; tries < 50 && line.find('\n') == std::string::npos;
       ++tries) {
    ssize_t n = ::read(pipefd[0], buf, sizeof(buf));
    if (n > 0) line.append(buf, buf + n);
    else std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  REQUIRE(line.find("READY=") != std::string::npos);
  return out;
}

}  // namespace

TEST_CASE("target.create_empty: returns a usable target_id",
          "[backend][attach][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  CHECK(open.target_id != 0);
  // No modules yet on an empty target.
  auto mods = be->list_modules(open.target_id);
  CHECK(mods.empty());
}

TEST_CASE("target.attach: attaches by PID and reports kStopped",
          "[backend][attach][live]") {
  LDB_SKIP_WITHOUT_PTRACE();
  auto sleeper = spawn_sleeper();
  REQUIRE(sleeper->pid > 0);

  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  auto status = be->attach(open.target_id, sleeper->pid);
  CHECK(status.state == ProcessState::kStopped);
  CHECK(status.pid == sleeper->pid);

  // Detach so the child resumes; we still SIGKILL it via the dtor for
  // hygiene.
  auto detached = be->detach_process(open.target_id);
  CHECK((detached.state == ProcessState::kDetached ||
         detached.state == ProcessState::kNone));
}

TEST_CASE("target.attach: bogus pid throws backend::Error",
          "[backend][attach][live][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);
  // PID 0 is the kernel scheduler proc — never attachable from
  // userspace.
  CHECK_THROWS_AS(be->attach(open.target_id, /*pid=*/0),
                  ldb::backend::Error);
}

TEST_CASE("target.attach: invalid target_id throws backend::Error",
          "[backend][attach][live][error]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK_THROWS_AS(be->attach(/*tid=*/9999, /*pid=*/1),
                  ldb::backend::Error);
}

TEST_CASE("process.detach: with no process is idempotent",
          "[backend][attach][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);
  auto st = be->detach_process(open.target_id);
  CHECK(st.state == ProcessState::kNone);
}
