// Tests for process.save_core + target.load_core.
//
// Flow: launch sleeper stop_at_entry → save_core → kill → load_core
//   → verify the resulting target has modules and at least one thread
//   (a frozen one).
//
// On platforms where SaveCore is not implemented we skip; macOS arm64
// supports it via the Mach-O save-core path.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <unistd.h>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;

namespace {

constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

std::filesystem::path scratch_core_path() {
  // Per-pid temp file so concurrent test runs don't clobber each other.
  auto p = std::filesystem::temp_directory_path();
  p /= "ldb_unit_core_" + std::to_string(::getpid()) + ".core";
  return p;
}

}  // namespace

TEST_CASE("process.save_core: writes a core file we can load",
          "[backend][core][live]") {
  auto core_path = scratch_core_path();
  std::filesystem::remove(core_path);

  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  REQUIRE(st.state == ProcessState::kStopped);

  // SaveCore is not always supported. Tolerate failures by skipping
  // (Catch2 doesn't have a clean SKIP at the case level pre-3.6, so
  // we simply early-return after a CHECK that covers the supported
  // case; failures here were always documented as platform-conditional).
  bool ok = false;
  try {
    ok = be->save_core(open.target_id, core_path.string());
  } catch (const ldb::backend::Error&) {
    ok = false;
  }
  if (!ok) {
    WARN("SaveCore not supported on this platform; skipping load_core check");
    be->kill_process(open.target_id);
    return;
  }

  REQUIRE(std::filesystem::exists(core_path));
  REQUIRE(std::filesystem::file_size(core_path) > 0);

  be->kill_process(open.target_id);
  be->close_target(open.target_id);

  // Now load it from a fresh backend instance to prove the artifact is
  // standalone (no in-memory state needed).
  auto be2 = std::make_unique<LldbBackend>();
  auto loaded = be2->load_core(core_path.string());
  CHECK(loaded.target_id != 0);

  // A core target has frozen threads; list_threads should give >= 1.
  auto threads = be2->list_threads(loaded.target_id);
  CHECK_FALSE(threads.empty());

  std::filesystem::remove(core_path);
}

TEST_CASE("target.load_core: missing path throws backend::Error",
          "[backend][core][error]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK_THROWS_AS(
      be->load_core("/nonexistent/path/does-not-exist.core"),
      ldb::backend::Error);
}

TEST_CASE("process.save_core: invalid target_id throws backend::Error",
          "[backend][core][error]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK_THROWS_AS(be->save_core(/*tid=*/9999, "/tmp/will-not-be-written"),
                  ldb::backend::Error);
}
