// SPDX-License-Identifier: Apache-2.0
// Dispatcher-level tests for observer.net.tcpdump (M4 part 5, §4.6).
//
// Param-validation paths (no privilege required) AND the
// "no permission" path that runs locally. The live capture path is
// tested separately in test_observer_tcpdump_live.cpp; this file
// exercises the JSON-RPC framing, validation, and the documented
// -32000 mapping for the unprivileged tcpdump exec.

#include <catch_amalgamated.hpp>

#include "daemon/dispatcher.h"
#include "backend/lldb_backend.h"
#include "store/artifact_store.h"
#include "probes/probe_orchestrator.h"

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <unistd.h>

using json = nlohmann::json;

namespace {

ldb::protocol::Request make_req(const std::string& method, json params) {
  ldb::protocol::Request r;
  r.id     = "rid";
  r.method = method;
  r.params = std::move(params);
  return r;
}

ldb::daemon::Dispatcher make_dispatcher() {
  auto backend = std::make_shared<ldb::backend::LldbBackend>();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = std::make_shared<ldb::probes::ProbeOrchestrator>(backend, store);
  return ldb::daemon::Dispatcher(backend, store, nullptr, probes);
}

bool tcpdump_can_capture() {
  // Cheap probe: try `tcpdump --version` via system(); if it returns 0,
  // the binary exists. Privilege is detected separately by inspecting
  // stderr after a real capture attempt.
  int rc = std::system("tcpdump --version >/dev/null 2>&1");
  return rc == 0;
}

}  // namespace

TEST_CASE("dispatcher: observer.net.tcpdump rejects missing iface",
          "[dispatcher][observer][tcpdump]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_req("observer.net.tcpdump", {
      {"count", 3},
  }));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("dispatcher: observer.net.tcpdump rejects empty iface",
          "[dispatcher][observer][tcpdump]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_req("observer.net.tcpdump", {
      {"iface", ""},
      {"count", 3},
  }));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("dispatcher: observer.net.tcpdump rejects missing count",
          "[dispatcher][observer][tcpdump]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_req("observer.net.tcpdump", {
      {"iface", "lo"},
  }));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("dispatcher: observer.net.tcpdump rejects zero / negative count",
          "[dispatcher][observer][tcpdump]") {
  auto d = make_dispatcher();
  auto r0 = d.dispatch(make_req("observer.net.tcpdump", {
      {"iface", "lo"}, {"count", 0},
  }));
  REQUIRE_FALSE(r0.ok);
  REQUIRE(static_cast<int>(r0.error_code) == -32602);
  auto rn = d.dispatch(make_req("observer.net.tcpdump", {
      {"iface", "lo"}, {"count", -1},
  }));
  REQUIRE_FALSE(rn.ok);
  REQUIRE(static_cast<int>(rn.error_code) == -32602);
}

TEST_CASE("dispatcher: observer.net.tcpdump rejects out-of-range count",
          "[dispatcher][observer][tcpdump]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_req("observer.net.tcpdump", {
      {"iface", "lo"}, {"count", 100000},
  }));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("dispatcher: observer.net.tcpdump rejects out-of-range snaplen",
          "[dispatcher][observer][tcpdump]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_req("observer.net.tcpdump", {
      {"iface", "lo"}, {"count", 1}, {"snaplen", 65536},
  }));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("dispatcher: observer.net.tcpdump no-permission → -32000",
          "[dispatcher][observer][tcpdump]") {
  // This box has tcpdump but no CAP_NET_RAW for the test runner. The
  // dispatcher should map the permission error to -32000 with the
  // underlying stderr message in error_message. If the runner DOES have
  // capabilities (uncommon — root or setcap), tcpdump will succeed and
  // we don't assert (the live test covers that path).
  if (!tcpdump_can_capture()) {
    SKIP("tcpdump --version failed — binary not available");
  }
  if (::geteuid() == 0) {
    SKIP("running as root: capture would succeed (live test covers this)");
  }
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_req("observer.net.tcpdump", {
      {"iface", "lo"}, {"count", 1},
  }));
  // Either privilege-denied (-32000) or — extraordinarily — success.
  if (!resp.ok) {
    REQUIRE(static_cast<int>(resp.error_code) == -32000);
    REQUIRE_FALSE(resp.error_message.empty());
  } else {
    // Binary somehow had capabilities. Wire shape sanity-check.
    REQUIRE(resp.data.contains("packets"));
    REQUIRE(resp.data.contains("total"));
  }
}

TEST_CASE("dispatcher: observer.net.tcpdump in describe.endpoints",
          "[dispatcher][observer][tcpdump]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_req("describe.endpoints", json::object()));
  REQUIRE(resp.ok);
  bool found = false;
  for (const auto& e : resp.data["endpoints"]) {
    if (e["method"] == "observer.net.tcpdump") {
      found = true;
      REQUIRE(e.contains("summary"));
      // M5 part 2: schema shape (informal `params`/`returns` was dropped).
      REQUIRE(e.contains("params_schema"));
      REQUIRE(e.contains("returns_schema"));
      REQUIRE(e.contains("requires_stopped"));
      REQUIRE(e.contains("cost_hint"));
      break;
    }
  }
  REQUIRE(found);
}
