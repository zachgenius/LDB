// Dispatcher-level tests for probe.create kind="uprobe_bpf" — pure
// param-validation paths that don't actually attach a BPF program.
// We rely on bpftrace being absent on this dev box to short-circuit
// to the documented -32000 "bpftrace not installed" path.

#include <catch_amalgamated.hpp>

#include "daemon/dispatcher.h"
#include "backend/lldb_backend.h"
#include "probes/bpftrace_engine.h"
#include "probes/probe_orchestrator.h"
#include "store/artifact_store.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <memory>

using json = nlohmann::json;

namespace {

ldb::protocol::Request make_req(const std::string& method, json params) {
  ldb::protocol::Request r;
  r.id     = "rid";
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("dispatcher: probe.create uprobe_bpf rejects malformed where",
          "[dispatcher][probes][uprobe_bpf]") {
  auto backend = std::make_shared<ldb::backend::LldbBackend>();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = std::make_shared<ldb::probes::ProbeOrchestrator>(backend, store);
  ldb::daemon::Dispatcher d(backend, store, nullptr, probes);

  auto req = make_req("probe.create", {
      {"target_id", 0},
      {"kind", "uprobe_bpf"},
      // Missing where → -32602
  });
  auto resp = d.dispatch(req);
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("dispatcher: probe.create uprobe_bpf reports missing bpftrace",
          "[dispatcher][probes][uprobe_bpf]") {
  // This test PASSES whether or not bpftrace is installed:
  //   - if absent, we get -32000 with "bpftrace not installed" or similar.
  //   - if present (and root/CAP_BPF available), the engine spawns and
  //     succeeds with a probe_id.
  // We use uprobe with a definitely-absent path so even on a privileged
  // box the BPF attach fails cleanly.
  auto backend = std::make_shared<ldb::backend::LldbBackend>();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = std::make_shared<ldb::probes::ProbeOrchestrator>(backend, store);
  ldb::daemon::Dispatcher d(backend, store, nullptr, probes);

  auto req = make_req("probe.create", {
      {"target_id", 0},
      {"kind", "uprobe_bpf"},
      {"where", {{"uprobe", "/no/such/binary:nonexistent_symbol"}}},
  });
  auto resp = d.dispatch(req);
  // If bpftrace is missing OR attach fails, we should see -32000
  // with a useful message. If somehow it succeeds (unlikely with
  // bogus path), the probe_id field is set.
  if (!resp.ok) {
    REQUIRE(static_cast<int>(resp.error_code) == -32000);
    REQUIRE_FALSE(resp.error_message.empty());
  } else {
    REQUIRE(resp.data.contains("probe_id"));
  }
}

TEST_CASE("dispatcher: probe.create rejects unknown kind",
          "[dispatcher][probes][uprobe_bpf]") {
  auto backend = std::make_shared<ldb::backend::LldbBackend>();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = std::make_shared<ldb::probes::ProbeOrchestrator>(backend, store);
  ldb::daemon::Dispatcher d(backend, store, nullptr, probes);

  auto req = make_req("probe.create", {
      {"target_id", 0},
      {"kind", "wireshark_capture"},
      {"where", {{"function", "main"}}},
  });
  auto resp = d.dispatch(req);
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
}
