// SPDX-License-Identifier: Apache-2.0
// Dispatcher ↔ ProbeOrchestrator integration test (M3 part 3).
//
// Validates the full-stack JSON-RPC surface for the probe.* endpoints:
//   • probe.create on a real target → probe_id returned
//   • process.launch fires the probe → probe.events returns ≥1 event
//   • probe.list reflects hit_count > 0
//   • probe.delete cleans up
//   • Error paths: bad target_id, missing where, unknown action

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "probes/probe_orchestrator.h"
#include "protocol/jsonrpc.h"
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
using ldb::daemon::Dispatcher;
using ldb::probes::ProbeOrchestrator;
using ldb::protocol::Request;
using ldb::store::ArtifactStore;
using nlohmann::json;

namespace {

constexpr const char* kStructsPath = LDB_FIXTURE_STRUCTS_PATH;

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_disp_probe_%016llx",
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

Request make_req(const char* method, json params = json::object(),
                 const char* id = "rX") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("dispatcher: probe.create + launch + events end-to-end",
          "[dispatcher][probe][live]") {
  auto be = std::make_shared<LldbBackend>();
  auto orch = std::make_shared<ProbeOrchestrator>(be, /*artifacts=*/nullptr);
  Dispatcher d(be, /*artifacts=*/nullptr, /*sessions=*/nullptr, orch);

  // Open the target.
  auto open = d.dispatch(make_req("target.open",
                                  json{{"path", kStructsPath}}));
  REQUIRE(open.ok);
  auto target_id = open.data["target_id"].get<std::uint64_t>();

  // Create a probe on point2_distance_sq (called from main).
  auto cr = d.dispatch(make_req(
      "probe.create",
      json{
          {"target_id", target_id},
          {"kind", "lldb_breakpoint"},
          {"where", json{{"function", "point2_distance_sq"}}},
          {"action", "log_and_continue"},
      }));
  REQUIRE(cr.ok);
  REQUIRE(cr.data.contains("probe_id"));
  std::string probe_id = cr.data["probe_id"].get<std::string>();
  REQUIRE(!probe_id.empty());

  // Launch the inferior — it'll run main, hit the bp (callback returns
  // false → auto-continue), and exit.
  auto lr = d.dispatch(make_req("process.launch",
                                json{{"target_id", target_id},
                                     {"stop_at_entry", false}}));
  REQUIRE(lr.ok);

  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // probe.events should report ≥1 event.
  auto er = d.dispatch(make_req("probe.events",
                                json{{"probe_id", probe_id}}));
  REQUIRE(er.ok);
  auto events = er.data["events"];
  REQUIRE(events.is_array());
  REQUIRE(events.size() >= 1);
  CHECK(events[0]["probe_id"] == probe_id);
  CHECK(events[0]["hit_seq"].get<std::int64_t>() == 1);
  CHECK(events[0]["pc"].is_string());  // hex string per plan §7.3
  CHECK(events[0]["tid"].get<std::uint64_t>() != 0);
  CHECK(events[0]["site"]["function"].is_string());

  // probe.list shows hit_count > 0.
  auto lst = d.dispatch(make_req("probe.list"));
  REQUIRE(lst.ok);
  auto probes = lst.data["probes"];
  REQUIRE(probes.size() == 1);
  CHECK(probes[0]["probe_id"] == probe_id);
  CHECK(probes[0]["hit_count"].get<std::int64_t>() >= 1);
  CHECK(probes[0]["enabled"] == true);

  // probe.delete; subsequent list is empty.
  auto del = d.dispatch(make_req("probe.delete",
                                 json{{"probe_id", probe_id}}));
  REQUIRE(del.ok);
  CHECK(del.data["deleted"] == true);

  auto lst2 = d.dispatch(make_req("probe.list"));
  REQUIRE(lst2.ok);
  CHECK(lst2.data["probes"].size() == 0);
}

TEST_CASE("dispatcher: probe.create with bad target_id returns -32000",
          "[dispatcher][probe][error]") {
  auto be = std::make_shared<LldbBackend>();
  auto orch = std::make_shared<ProbeOrchestrator>(be, nullptr);
  Dispatcher d(be, nullptr, nullptr, orch);

  auto resp = d.dispatch(make_req(
      "probe.create",
      json{{"target_id", 9999},
           {"kind", "lldb_breakpoint"},
           {"where", json{{"function", "main"}}}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32000);
}

TEST_CASE("dispatcher: probe.create without where returns -32602",
          "[dispatcher][probe][error]") {
  auto be = std::make_shared<LldbBackend>();
  auto orch = std::make_shared<ProbeOrchestrator>(be, nullptr);
  Dispatcher d(be, nullptr, nullptr, orch);

  auto open = d.dispatch(make_req("target.open",
                                  json{{"path", kStructsPath}}));
  REQUIRE(open.ok);
  auto target_id = open.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req(
      "probe.create",
      json{{"target_id", target_id}, {"kind", "lldb_breakpoint"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);

  // Empty where object also fails (no fields set).
  auto resp2 = d.dispatch(make_req(
      "probe.create",
      json{{"target_id", target_id},
           {"kind", "lldb_breakpoint"},
           {"where", json::object()}}));
  CHECK_FALSE(resp2.ok);
  CHECK(static_cast<int>(resp2.error_code) == -32602);
}

TEST_CASE("dispatcher: probe.create with unknown action returns -32602",
          "[dispatcher][probe][error]") {
  auto be = std::make_shared<LldbBackend>();
  auto orch = std::make_shared<ProbeOrchestrator>(be, nullptr);
  Dispatcher d(be, nullptr, nullptr, orch);

  auto open = d.dispatch(make_req("target.open",
                                  json{{"path", kStructsPath}}));
  REQUIRE(open.ok);
  auto target_id = open.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req(
      "probe.create",
      json{{"target_id", target_id},
           {"kind", "lldb_breakpoint"},
           {"where", json{{"function", "main"}}},
           {"action", "no_such_action"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("dispatcher: probe.* without orchestrator returns -32002",
          "[dispatcher][probe][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be, nullptr, nullptr, /*probes=*/nullptr);

  auto cr = d.dispatch(make_req(
      "probe.create",
      json{{"target_id", 1},
           {"kind", "lldb_breakpoint"},
           {"where", json{{"function", "main"}}}}));
  CHECK_FALSE(cr.ok);
  CHECK(static_cast<int>(cr.error_code) == -32002);

  auto lst = d.dispatch(make_req("probe.list"));
  CHECK_FALSE(lst.ok);
  CHECK(static_cast<int>(lst.error_code) == -32002);
}

TEST_CASE("dispatcher: probe.disable / enable round-trip via RPC",
          "[dispatcher][probe][live]") {
  auto be = std::make_shared<LldbBackend>();
  auto orch = std::make_shared<ProbeOrchestrator>(be, nullptr);
  Dispatcher d(be, nullptr, nullptr, orch);

  auto open = d.dispatch(make_req("target.open",
                                  json{{"path", kStructsPath}}));
  REQUIRE(open.ok);
  auto target_id = open.data["target_id"].get<std::uint64_t>();

  auto cr = d.dispatch(make_req(
      "probe.create",
      json{{"target_id", target_id},
           {"kind", "lldb_breakpoint"},
           {"where", json{{"function", "point2_distance_sq"}}}}));
  REQUIRE(cr.ok);
  std::string pid = cr.data["probe_id"].get<std::string>();

  auto dis = d.dispatch(make_req("probe.disable",
                                 json{{"probe_id", pid}}));
  REQUIRE(dis.ok);
  CHECK(dis.data["enabled"] == false);

  auto en = d.dispatch(make_req("probe.enable",
                                json{{"probe_id", pid}}));
  REQUIRE(en.ok);
  CHECK(en.data["enabled"] == true);
}
