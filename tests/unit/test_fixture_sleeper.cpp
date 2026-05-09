// SPDX-License-Identifier: Apache-2.0
// Sanity test for the sleeper fixture. Spawns it, reads the
// PID=...READY=... line from its stdout, and kills it. This test exists
// to prove the fixture executes correctly before any attach / memory
// test depends on it; failures here mean the binary itself is broken,
// not the SBAPI code under test.

#include <catch_amalgamated.hpp>

#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

}

TEST_CASE("sleeper fixture: prints PID and READY marker, then sleeps",
          "[fixture][sleeper]") {
  int pipefd[2];
  REQUIRE(pipe(pipefd) == 0);

  pid_t child = fork();
  REQUIRE(child >= 0);

  if (child == 0) {
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);
    char* const argv[] = {const_cast<char*>(kSleeperPath), nullptr};
    execv(kSleeperPath, argv);
    _exit(127);
  }

  close(pipefd[1]);

  // Read the first line of the child's stdout. Bounded to avoid
  // blocking forever on a misbehaving fixture.
  std::string line;
  char buf[256];
  for (int tries = 0; tries < 50 && line.find('\n') == std::string::npos;
       ++tries) {
    ssize_t n = read(pipefd[0], buf, sizeof(buf));
    if (n <= 0) break;
    line.append(buf, buf + n);
  }
  close(pipefd[0]);

  CHECK(line.find("PID=") != std::string::npos);
  CHECK(line.find("READY=LDB_SLEEPER_MARKER_v1") != std::string::npos);

  // Cleanup. SIGKILL since the fixture pause()s; SIGTERM would also work.
  kill(child, SIGKILL);
  int status = 0;
  waitpid(child, &status, 0);
}
