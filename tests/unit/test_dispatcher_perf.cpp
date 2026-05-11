// SPDX-License-Identifier: Apache-2.0
// Dispatcher-level validation tests for perf.* endpoints (post-V1 #13).
// These cover input gates that fire before any subprocess is spawned, so
// the tests run regardless of whether `perf` is installed on the box.
//
//   • frequency_hz > 10000 Hz cap         → -32602 (kInvalidParams)
//   • empty event string                  → -32602 (kInvalidParams)
//   • command mode with no allowlist      → -32002 (kBadState)
//   • command mode with disallowed argv   → -32003 (kForbidden)
//
// The live happy path is covered by tests/smoke/test_perf_record.py
// (SKIPs when perf is missing).

#include <catch_amalgamated.hpp>

#include "daemon/dispatcher.h"
#include "backend/lldb_backend.h"
#include "observers/exec_allowlist.h"
#include "probes/probe_orchestrator.h"
#include "store/artifact_store.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
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

std::filesystem::path write_allowlist(const std::string& tag,
                                      const std::string& body) {
  auto p = std::filesystem::temp_directory_path()
           / ("ldb_disp_perf_" + tag + ".txt");
  std::filesystem::remove(p);
  std::ofstream f(p);
  REQUIRE(f.is_open());
  f << body;
  return p;
}

std::shared_ptr<ldb::backend::LldbBackend> make_backend() {
  return std::make_shared<ldb::backend::LldbBackend>();
}

std::shared_ptr<ldb::probes::ProbeOrchestrator>
make_probes(std::shared_ptr<ldb::backend::LldbBackend> backend,
            std::shared_ptr<ldb::store::ArtifactStore> store) {
  return std::make_shared<ldb::probes::ProbeOrchestrator>(backend, store);
}

}  // namespace

TEST_CASE("dispatcher: perf.record rejects frequency_hz over 10000 Hz cap",
          "[dispatcher][perf][validate]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_perf_freq");
  auto probes  = make_probes(backend, store);
  ldb::daemon::Dispatcher d(backend, store, nullptr, probes);

  auto resp = d.dispatch(make_req("perf.record",
      {{"pid", 1}, {"duration_ms", 100}, {"frequency_hz", 50000}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
  REQUIRE(resp.error_message.find("10000") != std::string::npos);
}

TEST_CASE("dispatcher: perf.record rejects empty event string",
          "[dispatcher][perf][validate]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_perf_event");
  auto probes  = make_probes(backend, store);
  ldb::daemon::Dispatcher d(backend, store, nullptr, probes);

  auto resp = d.dispatch(make_req("perf.record",
      {{"pid", 1},
       {"duration_ms", 100},
       {"events", json::array({"cycles", ""})}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
  REQUIRE(resp.error_message.find("non-empty") != std::string::npos);
}

TEST_CASE("dispatcher: perf.record command mode without allowlist → -32002",
          "[dispatcher][perf][allowlist]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_perf_cmd_no_al");
  auto probes  = make_probes(backend, store);
  // No allowlist passed — command mode is gated off.
  ldb::daemon::Dispatcher d(backend, store, nullptr, probes);

  auto resp = d.dispatch(make_req("perf.record",
      {{"command", json::array({"/bin/echo", "hello"})}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32002);
  REQUIRE(resp.error_message.find("allowlist") != std::string::npos);
}

TEST_CASE("dispatcher: perf.record command mode with disallowed argv → -32003",
          "[dispatcher][perf][allowlist]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_perf_cmd_forbid");
  auto probes  = make_probes(backend, store);

  auto p  = write_allowlist("forbidden", "/bin/echo hello\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());

  ldb::daemon::Dispatcher d(backend, store, nullptr, probes,
      std::make_shared<ldb::observers::ExecAllowlist>(*al));

  // /bin/cat is plausible-but-not-allowed; should hit the allowlist gate
  // before any subprocess is spawned (so this test never touches perf).
  auto resp = d.dispatch(make_req("perf.record",
      {{"command", json::array({"/bin/cat", "/etc/shadow"})}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32003);
  REQUIRE(resp.error_message.find("operator policy") != std::string::npos);
}
