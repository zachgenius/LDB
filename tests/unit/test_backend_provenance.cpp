// Tests for LldbBackend::snapshot_for_target — the cores-only
// `_provenance.snapshot` source per plan §3.5 (M5 part 6).
//
// Cases:
//   * unknown target_id        → "none"
//   * target.open without proc → "none"
//   * live attached process    → "live"   ([live] gated)
//   * core-loaded target       → "core:<lowercase-hex-sha256>" matching
//                                the on-disk file's SHA-256 ([live]
//                                gated because we drive save_core to
//                                generate the file).

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "util/sha256.h"

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

}  // namespace

TEST_CASE("snapshot_for_target: unknown tid returns \"none\"",
          "[backend][provenance]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK(be->snapshot_for_target(/*tid=*/0)    == "none");
  CHECK(be->snapshot_for_target(/*tid=*/9999) == "none");
}

TEST_CASE("snapshot_for_target: target.open without process is \"none\"",
          "[backend][provenance][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);
  CHECK(be->snapshot_for_target(open.target_id) == "none");
}

TEST_CASE("snapshot_for_target: live attached process reports live:<gen>:<reg>:<layout>",
          "[backend][provenance][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  REQUIRE(st.state == ProcessState::kStopped);

  // v0.3 slice 1b: the bare "live" sentinel was replaced by the
  // detailed shape live:<gen>:<reg_digest>:<layout_digest>. The full
  // regex assertion lives in tests/unit/test_live_provenance.cpp; here
  // we just check the prefix and that the compose is non-empty.
  std::string snap = be->snapshot_for_target(open.target_id);
  CAPTURE(snap);
  CHECK(snap.rfind("live:", 0) == 0);
  CHECK(snap.size() > std::string("live:").size());

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
  // After close_target the cached state is gone — back to "none".
  CHECK(be->snapshot_for_target(open.target_id) == "none");
}

TEST_CASE("snapshot_for_target: core-loaded target carries SHA-256",
          "[backend][provenance][core][live]") {
  auto core_path = std::filesystem::temp_directory_path() /
                   ("ldb_provenance_core_" +
                    std::to_string(::getpid()) + ".core");
  std::filesystem::remove(core_path);

  // Generate a core via save_core. If the platform doesn't support it,
  // skip the rest cleanly — the live-attach case above already covers
  // the runtime contract.
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  REQUIRE(st.state == ProcessState::kStopped);

  bool ok = false;
  try {
    ok = be->save_core(open.target_id, core_path.string());
  } catch (const ldb::backend::Error&) {
    ok = false;
  }
  if (!ok) {
    WARN("save_core not supported here; skipping core snapshot check");
    be->kill_process(open.target_id);
    return;
  }
  REQUIRE(std::filesystem::exists(core_path));

  // Compute expected SHA-256 directly from the file the backend will
  // hash. The backend hashes the same path via the same util::sha256
  // helper, so a stream-vs-stream identity check is exactly what we
  // want.
  std::string expected = ldb::util::sha256_file_hex(core_path.string());
  REQUIRE(expected.size() == 64);

  be->kill_process(open.target_id);
  be->close_target(open.target_id);

  // Fresh backend so the load_core path is the only producer of the
  // cache entry.
  auto be2 = std::make_unique<LldbBackend>();
  auto loaded = be2->load_core(core_path.string());
  REQUIRE(loaded.target_id != 0);
  std::string snap = be2->snapshot_for_target(loaded.target_id);
  CHECK(snap == "core:" + expected);

  // After close_target the cached SHA is dropped.
  be2->close_target(loaded.target_id);
  CHECK(be2->snapshot_for_target(loaded.target_id) == "none");

  std::filesystem::remove(core_path);
}

TEST_CASE("snapshot_for_target: load_core with missing file does NOT cache",
          "[backend][provenance][error]") {
  auto be = std::make_unique<LldbBackend>();
  // Throws — but should not leave a half-populated entry around.
  CHECK_THROWS_AS(
      be->load_core("/nonexistent/almost-certainly-not-here.core"),
      ldb::backend::Error);
  // No targets were minted, so the next id stays at 1.
  CHECK(be->snapshot_for_target(/*tid=*/1) == "none");
}
