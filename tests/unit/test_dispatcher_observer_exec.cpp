// Dispatcher-level tests for the observer.exec endpoint (M4 polish,
// plan §4.6). Covers:
//
//   • not configured → -32002 (kBadState)
//   • disallowed argv → -32003 (kForbidden)
//   • allowed argv with local_exec → real stdout
//   • argv missing / empty / non-string → -32602 (kInvalidParams)
//   • argv[0] is a relative path (`./foo`) → -32602 (caller mistake)
//   • stdin payload over 64 KiB → -32602
//
// Allowlist file is built per-test in std::filesystem::temp_directory_path().

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
#include <string>

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
           / ("ldb_disp_exec_" + tag + ".txt");
  std::filesystem::remove(p);
  std::ofstream f(p);
  REQUIRE(f.is_open());
  f << body;
  f.close();
  return p;
}

std::shared_ptr<ldb::backend::LldbBackend> make_backend() {
  return std::make_shared<ldb::backend::LldbBackend>();
}

std::shared_ptr<ldb::probes::ProbeOrchestrator> make_probes(
    std::shared_ptr<ldb::backend::LldbBackend> backend,
    std::shared_ptr<ldb::store::ArtifactStore> store) {
  return std::make_shared<ldb::probes::ProbeOrchestrator>(backend, store);
}

}  // namespace

TEST_CASE("dispatcher: observer.exec with no allowlist configured → -32002",
          "[dispatcher][observers][exec]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = make_probes(backend, store);
  // No allowlist passed.
  ldb::daemon::Dispatcher d(backend, store, nullptr, probes);

  auto resp = d.dispatch(make_req("observer.exec",
      {{"argv", json::array({"/bin/echo", "hello"})}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32002);
  REQUIRE(resp.error_message.find("observer.exec disabled") != std::string::npos);
}

TEST_CASE("dispatcher: observer.exec with disallowed argv → -32003",
          "[dispatcher][observers][exec]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = make_probes(backend, store);

  auto p = write_allowlist("forbidden", "/bin/echo hello\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());

  ldb::daemon::Dispatcher d(backend, store, nullptr, probes,
                            std::make_shared<ldb::observers::ExecAllowlist>(*al));
  // /bin/cat /etc/shadow is plausible-but-not-allowed.
  auto resp = d.dispatch(make_req("observer.exec",
      {{"argv", json::array({"/bin/cat", "/etc/shadow"})}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32003);
}

TEST_CASE("dispatcher: observer.exec happy path local_exec",
          "[dispatcher][observers][exec]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = make_probes(backend, store);

  auto p = write_allowlist("happy", "/bin/echo hello\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());

  ldb::daemon::Dispatcher d(backend, store, nullptr, probes,
                            std::make_shared<ldb::observers::ExecAllowlist>(*al));
  auto resp = d.dispatch(make_req("observer.exec",
      {{"argv", json::array({"/bin/echo", "hello"})}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("stdout"));
  REQUIRE(resp.data.contains("exit_code"));
  REQUIRE(resp.data["exit_code"].get<int>() == 0);
  REQUIRE(resp.data["stdout"].get<std::string>() == "hello\n");
}

TEST_CASE("dispatcher: observer.exec rejects empty / missing argv",
          "[dispatcher][observers][exec]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = make_probes(backend, store);
  auto p  = write_allowlist("empty_argv", "/bin/echo hello\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());

  ldb::daemon::Dispatcher d(backend, store, nullptr, probes,
                            std::make_shared<ldb::observers::ExecAllowlist>(*al));

  // Missing argv.
  auto r1 = d.dispatch(make_req("observer.exec", json::object()));
  REQUIRE_FALSE(r1.ok);
  REQUIRE(static_cast<int>(r1.error_code) == -32602);

  // Empty argv array.
  auto r2 = d.dispatch(make_req("observer.exec",
      {{"argv", json::array()}}));
  REQUIRE_FALSE(r2.ok);
  REQUIRE(static_cast<int>(r2.error_code) == -32602);

  // argv contains non-string.
  auto r3 = d.dispatch(make_req("observer.exec",
      {{"argv", json::array({"/bin/echo", 42})}}));
  REQUIRE_FALSE(r3.ok);
  REQUIRE(static_cast<int>(r3.error_code) == -32602);
}

TEST_CASE("dispatcher: observer.exec rejects relative argv[0]",
          "[dispatcher][observers][exec]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = make_probes(backend, store);
  auto p  = write_allowlist("rel", "./bin/echo hello\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());

  ldb::daemon::Dispatcher d(backend, store, nullptr, probes,
                            std::make_shared<ldb::observers::ExecAllowlist>(*al));

  auto resp = d.dispatch(make_req("observer.exec",
      {{"argv", json::array({"./bin/echo", "hello"})}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
  REQUIRE(resp.error_message.find("argv[0]") != std::string::npos);
}

TEST_CASE("dispatcher: observer.exec rejects oversized stdin",
          "[dispatcher][observers][exec]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = make_probes(backend, store);
  auto p  = write_allowlist("bigstdin", "/bin/cat\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());

  ldb::daemon::Dispatcher d(backend, store, nullptr, probes,
                            std::make_shared<ldb::observers::ExecAllowlist>(*al));

  std::string big(64 * 1024 + 1, 'x');
  auto resp = d.dispatch(make_req("observer.exec",
      {{"argv", json::array({"/bin/cat"})},
       {"stdin", big}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("dispatcher: describe.endpoints lists observer.exec",
          "[dispatcher][observers][exec]") {
  auto backend = make_backend();
  auto store   = std::make_shared<ldb::store::ArtifactStore>(
      std::filesystem::temp_directory_path() / "ldb_test_store");
  auto probes  = make_probes(backend, store);
  ldb::daemon::Dispatcher d(backend, store, nullptr, probes);
  auto resp = d.dispatch(make_req("describe.endpoints", json::object()));
  REQUIRE(resp.ok);
  bool found = false;
  for (const auto& e : resp.data["endpoints"]) {
    if (e["method"] == "observer.exec") { found = true; break; }
  }
  REQUIRE(found);
}
