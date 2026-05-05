// Probe orchestrator unit tests (M3 part 3).
//
// Validates the lldb_breakpoint engine end-to-end against the structs
// fixture: probes fire, capture register/memory state, store
// artifacts, disable/enable round-trip, delete cleans up, paginated
// events.
//
// We launch the structs fixture; main() reaches point2_distance_sq
// before exiting, which is our reliable hit site.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "probes/probe_orchestrator.h"
#include "store/artifact_store.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <thread>

namespace fs = std::filesystem;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::probes::Action;
using ldb::probes::CaptureSpec;
using ldb::probes::ProbeOrchestrator;
using ldb::probes::ProbeSpec;
using ldb::store::ArtifactStore;

namespace {

constexpr const char* kStructsPath = LDB_FIXTURE_STRUCTS_PATH;

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_probe_orch_%016llx",
                  static_cast<unsigned long long>(gen()));
    root = fs::temp_directory_path() / buf;
    std::error_code ec;
    fs::remove_all(root, ec);
  }
  ~TmpStoreRoot() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

// Build a probe on point2_distance_sq with the given action.
ProbeSpec make_basic_spec(ldb::backend::TargetId tid, Action a) {
  ProbeSpec s;
  s.target_id      = tid;
  s.kind           = "lldb_breakpoint";
  s.where.function = "point2_distance_sq";
  s.action         = a;
  return s;
}

}  // namespace

TEST_CASE("orchestrator: probe fires on function and records event",
          "[probes][orchestrator][live]") {
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, /*artifacts=*/nullptr);
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  auto pid = orch.create(make_basic_spec(open.target_id,
                                         Action::kLogAndContinue));
  REQUIRE(!pid.empty());

  ldb::backend::LaunchOptions lo;
  lo.stop_at_entry = false;
  auto status = be->launch_process(open.target_id, lo);
  CHECK((status.state == ProcessState::kExited ||
         status.state == ProcessState::kStopped));

  // Bounded settle window — callback runs on LLDB's event thread.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  auto info = orch.info(pid);
  REQUIRE(info.has_value());
  CHECK(info->hit_count >= 1);
  CHECK(info->kind == "lldb_breakpoint");
  CHECK(info->where_expr == "point2_distance_sq");
  CHECK(info->enabled == true);

  auto evs = orch.events(pid, /*since=*/0, /*max=*/100);
  REQUIRE(!evs.empty());
  CHECK(evs[0].pc != 0);
  CHECK(evs[0].tid != 0);
  CHECK(evs[0].hit_seq == 1);
  CHECK(evs[0].ts_ns > 0);
  CHECK((evs[0].site.function == "point2_distance_sq" ||
         evs[0].site.function.find("point2_distance_sq") !=
             std::string::npos));
}

TEST_CASE("orchestrator: capture registers + memory",
          "[probes][orchestrator][live]") {
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, /*artifacts=*/nullptr);
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  // point2_distance_sq's first arg is `const struct point2 *a`; ABI-wise
  // that's rdi on x86-64 and x0 on arm64. Capturing 8 bytes from that
  // pointer should give us the struct's two int fields.
  ProbeSpec s = make_basic_spec(open.target_id, Action::kLogAndContinue);
#if defined(__x86_64__)
  s.capture.registers.push_back("rdi");
  CaptureSpec::MemSpec mm;
  mm.source   = CaptureSpec::MemSpec::Source::kRegister;
  mm.reg_name = "rdi";
  mm.len      = 8;
  mm.name     = "arg1_buf";
  s.capture.memory.push_back(mm);
#elif defined(__aarch64__) || defined(__arm64__)
  s.capture.registers.push_back("x0");
  CaptureSpec::MemSpec mm;
  mm.source   = CaptureSpec::MemSpec::Source::kRegister;
  mm.reg_name = "x0";
  mm.len      = 8;
  mm.name     = "arg1_buf";
  s.capture.memory.push_back(mm);
#endif

  auto pid = orch.create(s);
  ldb::backend::LaunchOptions lo;
  lo.stop_at_entry = false;
  be->launch_process(open.target_id, lo);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  auto evs = orch.events(pid, 0, 100);
  REQUIRE(!evs.empty());
  // At least one register snapshotted; the value is whatever the ABI
  // had at the call site — we just check the snapshot exists.
  CHECK(!evs[0].registers.empty());
  // memory[] may be empty if the read failed (e.g. the inferior's
  // pointer happened to be unreadable — shouldn't happen for arg1
  // here, which is &g_origin, a real address). Assert non-empty.
  CHECK(!evs[0].memory.empty());
  if (!evs[0].memory.empty()) {
    CHECK(evs[0].memory[0].name == "arg1_buf");
    CHECK(evs[0].memory[0].bytes.size() == 8);
  }
}

TEST_CASE("orchestrator: action=stop keeps process stopped",
          "[probes][orchestrator][live]") {
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, /*artifacts=*/nullptr);
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  auto pid = orch.create(make_basic_spec(open.target_id, Action::kStop));
  ldb::backend::LaunchOptions lo;
  lo.stop_at_entry = false;
  auto status = be->launch_process(open.target_id, lo);
  CHECK(status.state == ProcessState::kStopped);

  auto post = be->get_process_state(open.target_id);
  CHECK(post.state == ProcessState::kStopped);

  auto info = orch.info(pid);
  REQUIRE(info.has_value());
  CHECK(info->hit_count >= 1);

  // Clean up the running process.
  be->kill_process(open.target_id);
}

TEST_CASE("orchestrator: action=store_artifact creates artifact rows",
          "[probes][orchestrator][live]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto store = std::make_shared<ArtifactStore>(t.root);
  ProbeOrchestrator orch(be, store);
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  ProbeSpec s = make_basic_spec(open.target_id, Action::kStoreArtifact);
  s.build_id               = "build-test";
  s.artifact_name_template = "p2_dump_{hit}.bin";
#if defined(__x86_64__)
  CaptureSpec::MemSpec mm;
  mm.source   = CaptureSpec::MemSpec::Source::kRegister;
  mm.reg_name = "rdi";
  mm.len      = 8;
  mm.name     = "arg1";
  s.capture.memory.push_back(mm);
#elif defined(__aarch64__) || defined(__arm64__)
  CaptureSpec::MemSpec mm;
  mm.source   = CaptureSpec::MemSpec::Source::kRegister;
  mm.reg_name = "x0";
  mm.len      = 8;
  mm.name     = "arg1";
  s.capture.memory.push_back(mm);
#endif

  auto pid = orch.create(s);
  ldb::backend::LaunchOptions lo;
  lo.stop_at_entry = false;
  be->launch_process(open.target_id, lo);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  auto evs = orch.events(pid, 0, 100);
  REQUIRE(!evs.empty());
  REQUIRE(evs[0].artifact_id.has_value());
  REQUIRE(evs[0].artifact_name.has_value());

  // The store should have at least one row keyed by (build-test, name).
  auto rows = store->list(std::string("build-test"), std::nullopt);
  CHECK(!rows.empty());
  CHECK(rows[0].name == "p2_dump_1.bin");
}

TEST_CASE("orchestrator: disable suppresses fire, enable resumes",
          "[probes][orchestrator][live]") {
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, nullptr);
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  auto pid = orch.create(make_basic_spec(open.target_id,
                                         Action::kLogAndContinue));

  // Disable, run, expect 0 hits.
  orch.disable(pid);
  ldb::backend::LaunchOptions lo;
  lo.stop_at_entry = false;
  be->launch_process(open.target_id, lo);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  CHECK(orch.info(pid)->hit_count == 0);
  CHECK(orch.info(pid)->enabled == false);

  // Re-enable, run, expect ≥1 hit.
  orch.enable(pid);
  be->launch_process(open.target_id, lo);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  CHECK(orch.info(pid)->hit_count >= 1);
  CHECK(orch.info(pid)->enabled == true);
}

TEST_CASE("orchestrator: remove drops probe and entry",
          "[probes][orchestrator][live]") {
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, nullptr);
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  auto pid = orch.create(make_basic_spec(open.target_id,
                                         Action::kLogAndContinue));
  CHECK(orch.list().size() == 1);
  orch.remove(pid);
  CHECK(orch.list().empty());
  CHECK_FALSE(orch.info(pid).has_value());
  CHECK_THROWS_AS(orch.events(pid, 0, 10), ldb::backend::Error);
}

TEST_CASE("orchestrator: events paginate by since / max",
          "[probes][orchestrator]") {
  // Synthetic test — no live target. Construct an orchestrator on a
  // throwaway backend, manually push events through the public API
  // by creating a probe whose backend creation fails... actually we
  // can't shortcut that. Use a live target.
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, nullptr);
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  auto pid = orch.create(make_basic_spec(open.target_id,
                                         Action::kLogAndContinue));
  ldb::backend::LaunchOptions lo;
  lo.stop_at_entry = false;
  // Run twice to get 2 hits across two launches.
  be->launch_process(open.target_id, lo);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  be->launch_process(open.target_id, lo);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  auto info = orch.info(pid);
  REQUIRE(info.has_value());
  REQUIRE(info->hit_count >= 2);

  auto all = orch.events(pid, 0, 0);
  REQUIRE(all.size() >= 2);
  // since=hit_seq of first event → exclude it.
  auto rest = orch.events(pid, all[0].hit_seq, 0);
  CHECK(rest.size() == all.size() - 1);
  // max caps the result.
  auto first_only = orch.events(pid, 0, 1);
  CHECK(first_only.size() == 1);
  CHECK(first_only[0].hit_seq == all[0].hit_seq);
}

TEST_CASE("orchestrator: bad kind throws",
          "[probes][orchestrator][error]") {
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, nullptr);
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  ProbeSpec s;
  s.target_id      = open.target_id;
  s.kind           = "uprobe_bpf";  // M4
  s.where.function = "main";
  CHECK_THROWS_AS(orch.create(s), std::invalid_argument);
}

TEST_CASE("orchestrator: store_artifact without build_id throws",
          "[probes][orchestrator][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto store = std::make_shared<ArtifactStore>(t.root);
  ProbeOrchestrator orch(be, store);
  auto open = be->open_executable(kStructsPath);

  ProbeSpec s = make_basic_spec(open.target_id, Action::kStoreArtifact);
  s.artifact_name_template = "x_{hit}.bin";
  // build_id deliberately empty
  CHECK_THROWS_AS(orch.create(s), std::invalid_argument);
}

TEST_CASE("orchestrator: unknown probe_id on lifecycle ops throws",
          "[probes][orchestrator][error]") {
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, nullptr);
  CHECK_THROWS_AS(orch.disable("p999"), ldb::backend::Error);
  CHECK_THROWS_AS(orch.enable("p999"),  ldb::backend::Error);
  CHECK_THROWS_AS(orch.remove("p999"),  ldb::backend::Error);
  CHECK_THROWS_AS(orch.events("p999", 0, 0), ldb::backend::Error);
  CHECK_FALSE(orch.info("p999").has_value());
}
