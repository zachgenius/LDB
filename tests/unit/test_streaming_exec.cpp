// Unit tests for ldb::transport::StreamingExec — long-lived async
// line-streaming subprocess (M4-4 prep for the bpftrace engine).
//
// Test discipline:
//   • All cases here run LOCAL (remote == nullopt). The remote-routing
//     path is exercised indirectly via the bpftrace engine's smoke test
//     when ssh-to-localhost is available.
//   • We use /bin/sh as the test workhorse — every Linux box has it.
//   • Each case has a hard wall-clock budget (<5s) so a hung test fails
//     by missing the budget rather than by ctest timeout.

#include <catch_amalgamated.hpp>

#include "transport/streaming_exec.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

struct Collector {
  std::mutex                mu;
  std::condition_variable   cv;
  std::vector<std::string>  lines;
  bool                      done       = false;
  int                       exit_code  = -123;
  bool                      timed_out  = false;

  void on_line(std::string_view sv) {
    std::lock_guard<std::mutex> lk(mu);
    lines.emplace_back(sv);
    cv.notify_all();
  }
  void on_done(int code, bool timed) {
    std::lock_guard<std::mutex> lk(mu);
    done      = true;
    exit_code = code;
    timed_out = timed;
    cv.notify_all();
  }
  bool wait_done(std::chrono::milliseconds budget) {
    std::unique_lock<std::mutex> lk(mu);
    return cv.wait_for(lk, budget, [&] { return done; });
  }
  bool wait_lines(std::size_t n, std::chrono::milliseconds budget) {
    std::unique_lock<std::mutex> lk(mu);
    return cv.wait_for(lk, budget,
                       [&] { return lines.size() >= n; });
  }
};

}  // namespace

TEST_CASE("StreamingExec: spawns, streams lines, completes", "[transport][streaming]") {
  auto col = std::make_shared<Collector>();
  ldb::transport::StreamingExec se(
      std::nullopt,
      {"/bin/sh", "-c", "for i in 1 2 3; do echo line$i; done"},
      [col](std::string_view sv) { col->on_line(sv); },
      [col](int c, bool t)        { col->on_done(c, t); });

  REQUIRE(col->wait_done(2000ms));
  REQUIRE(col->done);
  REQUIRE(col->exit_code == 0);
  REQUIRE_FALSE(col->timed_out);
  REQUIRE(col->lines.size() == 3);
  REQUIRE(col->lines[0] == "line1");
  REQUIRE(col->lines[1] == "line2");
  REQUIRE(col->lines[2] == "line3");
}

TEST_CASE("StreamingExec: alive() flips false on natural exit", "[transport][streaming]") {
  auto col = std::make_shared<Collector>();
  ldb::transport::StreamingExec se(
      std::nullopt,
      {"/bin/sh", "-c", "echo hi; exit 7"},
      [col](std::string_view sv) { col->on_line(sv); },
      [col](int c, bool t)        { col->on_done(c, t); });

  REQUIRE(col->wait_done(2000ms));
  REQUIRE(col->exit_code == 7);
  REQUIRE_FALSE(se.alive());
}

TEST_CASE("StreamingExec: terminate() kills a long-running child", "[transport][streaming]") {
  auto col = std::make_shared<Collector>();
  // /bin/sleep 30 — terminate() must cut this short.
  ldb::transport::StreamingExec se(
      std::nullopt,
      {"/bin/sh", "-c", "sleep 30"},
      [col](std::string_view sv) { col->on_line(sv); },
      [col](int c, bool t)        { col->on_done(c, t); });

  REQUIRE(se.alive());
  std::this_thread::sleep_for(50ms);
  se.terminate();
  REQUIRE(col->wait_done(2000ms));
  REQUIRE(col->done);
  // 128 + SIGTERM(15) = 143; if SIGKILL kicked in (250ms grace
  // expired): 128 + 9 = 137. Either is acceptable for "we killed it".
  REQUIRE((col->exit_code == 143 || col->exit_code == 137 ||
           col->exit_code == -1));
  REQUIRE_FALSE(se.alive());
}

TEST_CASE("StreamingExec: dtor reaps the child cleanly", "[transport][streaming]") {
  auto col = std::make_shared<Collector>();
  {
    ldb::transport::StreamingExec se(
        std::nullopt,
        {"/bin/sh", "-c", "sleep 30"},
        [col](std::string_view sv) { col->on_line(sv); },
        [col](int c, bool t)        { col->on_done(c, t); });
    std::this_thread::sleep_for(50ms);
    // dtor runs here — must terminate, join, and call on_done.
  }
  REQUIRE(col->wait_done(2000ms));
  REQUIRE(col->done);
}

TEST_CASE("StreamingExec: long line truncation with marker", "[transport][streaming]") {
  // Generate a single 64 KiB line followed by a normal line. The cap is
  // 32 KiB; we expect (a) a truncated first delivery, (b) the next
  // line delivered intact, (c) on_done with exit_code 0.
  auto col = std::make_shared<Collector>();
  ldb::transport::StreamingExec se(
      std::nullopt,
      {"/bin/sh", "-c",
       "head -c 65536 /dev/zero | tr '\\0' 'A'; echo; echo short"},
      [col](std::string_view sv) { col->on_line(sv); },
      [col](int c, bool t)        { col->on_done(c, t); });

  REQUIRE(col->wait_done(3000ms));
  REQUIRE(col->done);
  REQUIRE(col->exit_code == 0);
  REQUIRE(col->lines.size() == 2);
  REQUIRE(col->lines[0].size() <=
          ldb::transport::StreamingExec::kMaxLineBytes + 64);  // cap + marker
  REQUIRE(col->lines[0].find("[truncated]") != std::string::npos);
  REQUIRE(col->lines[1] == "short");
}

TEST_CASE("StreamingExec: empty argv throws", "[transport][streaming][error]") {
  auto noop_line = [](std::string_view) {};
  auto noop_done = [](int, bool) {};
  REQUIRE_THROWS_AS(
      ldb::transport::StreamingExec(std::nullopt, {},
                                    noop_line, noop_done),
      ldb::backend::Error);
}

TEST_CASE("StreamingExec: nonexistent binary throws", "[transport][streaming][error]") {
  auto noop_line = [](std::string_view) {};
  auto noop_done = [](int, bool) {};
  REQUIRE_THROWS_AS(
      ldb::transport::StreamingExec(
          std::nullopt,
          {"/this/binary/does/not/exist/anywhere"},
          noop_line, noop_done),
      ldb::backend::Error);
}

TEST_CASE("StreamingExec: stderr captured to internal buffer",
          "[transport][streaming]") {
  auto col = std::make_shared<Collector>();
  ldb::transport::StreamingExec se(
      std::nullopt,
      {"/bin/sh", "-c", "echo on-stdout; echo on-stderr 1>&2"},
      [col](std::string_view sv) { col->on_line(sv); },
      [col](int c, bool t)        { col->on_done(c, t); });

  REQUIRE(col->wait_done(2000ms));
  REQUIRE(col->lines.size() == 1);
  REQUIRE(col->lines[0] == "on-stdout");
  std::string err = se.drain_stderr();
  REQUIRE(err.find("on-stderr") != std::string::npos);
}
