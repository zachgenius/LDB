// SPDX-License-Identifier: Apache-2.0
// Live rr round-trip for the backend reverse-execution methods.
//
// Pattern matches test_backend_connect_remote_rr.cpp: record /bin/true
// with rr, connect via rr://, then exercise reverse_continue and
// reverse_step_thread. SKIPs cleanly when rr is unavailable or when the
// host cannot record (perf_event_paranoid, ptrace_scope, unrecognised
// CPU microarch). Negative-path coverage that does not need rr lives in
// test_backend_reverse_exec.cpp.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "transport/rr.h"

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::ReverseStepKind;

namespace {

std::string find_rr_for_test() {
  return ldb::transport::find_rr_binary();
}

// Record /bin/true into trace_dir using rr. Returns true on success.
// rr record can fail for boring environmental reasons (paranoid sysctl,
// ptrace_scope, unknown CPU); the caller treats false as SKIP.
bool record_minimal_trace(const std::string& rr_bin,
                          const std::string& trace_root,
                          const std::string& trace_dir) {
  ::mkdir(trace_root.c_str(), 0700);
  ::setenv("_RR_TRACE_DIR", trace_root.c_str(), /*overwrite=*/1);
  std::string cmd = rr_bin + " record -o " + trace_dir +
                    " /bin/true >/dev/null 2>&1";
  return std::system(cmd.c_str()) == 0;
}

}  // namespace

TEST_CASE("reverse_continue: live rr round-trip succeeds",
          "[backend][reverse][rr][live][requires_rr]") {
  auto rr_bin = find_rr_for_test();
  if (rr_bin.empty()) {
    SKIP("rr not installed — live reverse-exec test cannot run");
  }
  std::string trace_root =
      std::filesystem::temp_directory_path().string() + "/ldb-rr-rev-" +
      std::to_string(::getpid());
  std::string trace_dir = trace_root + "/true-0";
  if (!record_minimal_trace(rr_bin, trace_root, trace_dir)) {
    SKIP("rr record /bin/true failed (perf_event_paranoid, ptrace_scope, "
         "or unsupported CPU microarch) — cannot exercise reverse-exec");
  }

  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  std::string url = "rr://" + trace_dir;
  ldb::backend::ProcessStatus status;
  try {
    status = be->connect_remote_target(open.target_id, url, "");
  } catch (const ldb::backend::Error& e) {
    FAIL("connect_remote rr:// failed: " << e.what());
  }
  REQUIRE(status.state == ProcessState::kStopped);

  // Now invoke reverse-continue. The trace is /bin/true → very short.
  // Either we land at a new PC (state=kStopped, possibly with a
  // different stop_reason), or we hit the beginning of the trace (which
  // rr surfaces as a stop with reason ~"signal SIGTRAP"). The contract
  // we pin is just "no throw and state is not kInvalid."
  ldb::backend::ProcessStatus after;
  try {
    after = be->reverse_continue(open.target_id);
  } catch (const ldb::backend::Error& e) {
    FAIL("reverse_continue threw: " << e.what());
  }
  CHECK(after.state != ProcessState::kInvalid);

  be->close_target(open.target_id);
  std::error_code ec;
  std::filesystem::remove_all(trace_root, ec);
  ::unsetenv("_RR_TRACE_DIR");
}

TEST_CASE("reverse_step_thread(kInsn): live rr round-trip succeeds",
          "[backend][reverse][rr][live][requires_rr]") {
  auto rr_bin = find_rr_for_test();
  if (rr_bin.empty()) {
    SKIP("rr not installed — live reverse-step test cannot run");
  }
  std::string trace_root =
      std::filesystem::temp_directory_path().string() + "/ldb-rr-revs-" +
      std::to_string(::getpid());
  std::string trace_dir = trace_root + "/true-0";
  if (!record_minimal_trace(rr_bin, trace_root, trace_dir)) {
    SKIP("rr record /bin/true failed — cannot exercise reverse-step");
  }

  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  std::string url = "rr://" + trace_dir;
  auto status = be->connect_remote_target(open.target_id, url, "");
  REQUIRE(status.state == ProcessState::kStopped);

  auto threads = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads.empty());
  auto tid = threads[0].tid;

  ldb::backend::ProcessStatus after;
  try {
    after = be->reverse_step_thread(open.target_id, tid, ReverseStepKind::kInsn);
  } catch (const ldb::backend::Error& e) {
    FAIL("reverse_step_thread threw: " << e.what());
  }
  CHECK(after.state != ProcessState::kInvalid);

  be->close_target(open.target_id);
  std::error_code ec;
  std::filesystem::remove_all(trace_root, ec);
  ::unsetenv("_RR_TRACE_DIR");
}
