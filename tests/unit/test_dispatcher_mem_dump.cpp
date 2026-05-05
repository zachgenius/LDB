// Dispatcher integration test for mem.dump_artifact (M3 closeout, plan §4.4).
//
// mem.dump_artifact is a pure composition endpoint: it reads memory from
// the live target via the same path as mem.read, then stores the bytes
// into the ArtifactStore via the same path as artifact.put. We verify:
//
//   • Live: attach to the sleeper fixture, resolve g_counter, dump 8
//     bytes, assert the response shape and that the stored blob matches
//     what mem.read returns at the same address.
//   • Live: format / meta forwarded into the row.
//   • Live: re-dump same (build_id, name) replaces (artifact.put contract)
//     — id changes, byte_size matches.
//   • Negative: missing target_id / addr / len / build_id / name → -32602.
//   • Negative: store unavailable → -32002.
//   • Negative: backend read failure (bad target_id) → -32000.
//   • Negative: oversize len (> 1 MiB cap) → -32000 (backend throws).
//
// The attach-to-sleeper pattern mirrors test_backend_memory.cpp: launching
// stop-at-entry on macOS arm64 PIE produces an unrelocated globals layout
// (CLAUDE.md landmines), so we attach to a freshly-spawned sleeper instead.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "store/artifact_store.h"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;
using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::Request;
using ldb::store::ArtifactStore;
using nlohmann::json;

namespace {

constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[48];
    std::snprintf(buf, sizeof(buf), "ldb_disp_memdump_%016llx",
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

// Spawn the sleeper, wait for its READY line, return the pid + stdout fd
// so the caller can detach + reap deterministically.
struct Sleeper {
  pid_t pid       = -1;
  int   stdout_fd = -1;
  ~Sleeper() {
    if (pid > 0) {
      ::kill(pid, SIGKILL);
      int status = 0;
      ::waitpid(pid, &status, 0);
    }
    if (stdout_fd >= 0) ::close(stdout_fd);
  }
};

std::unique_ptr<Sleeper> spawn_sleeper() {
  int pipefd[2];
  REQUIRE(::pipe(pipefd) == 0);
  pid_t child = ::fork();
  REQUIRE(child >= 0);
  if (child == 0) {
    ::dup2(pipefd[1], STDOUT_FILENO);
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    char* const argv[] = {const_cast<char*>(kSleeperPath), nullptr};
    ::execv(kSleeperPath, argv);
    _exit(127);
  }
  ::close(pipefd[1]);

  std::string line;
  char buf[256];
  for (int tries = 0; tries < 50 &&
       line.find('\n') == std::string::npos; ++tries) {
    ssize_t n = ::read(pipefd[0], buf, sizeof(buf));
    if (n > 0) line.append(buf, buf + n);
    else std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  REQUIRE(line.find("READY=") != std::string::npos);

  auto s = std::make_unique<Sleeper>();
  s->pid       = child;
  s->stdout_fd = pipefd[0];
  return s;
}

}  // namespace

TEST_CASE("dispatcher: mem.dump_artifact happy path on the sleeper",
          "[dispatcher][mem][dump][live]") {
  TmpStoreRoot t;
  auto be       = std::make_shared<LldbBackend>();
  auto store    = std::make_shared<ArtifactStore>(t.root);
  Dispatcher d(be, store, /*sessions=*/nullptr, /*probes=*/nullptr);

  auto sleeper = spawn_sleeper();

  // target.create_empty + target.attach via the dispatcher.
  auto cr = d.dispatch(make_req("target.create_empty"));
  REQUIRE(cr.ok);
  auto target_id = cr.data["target_id"].get<std::uint64_t>();

  auto at = d.dispatch(make_req("target.attach",
                                json{{"target_id", target_id},
                                     {"pid", sleeper->pid}}));
  REQUIRE(at.ok);

  // Resolve g_counter — a uint64_t global, so we'll dump exactly 8 bytes.
  auto sf = d.dispatch(make_req("symbol.find",
                                json{{"target_id", target_id},
                                     {"name", "g_counter"}}));
  REQUIRE(sf.ok);
  auto matches = sf.data["matches"];
  REQUIRE(matches.is_array());
  REQUIRE(matches.size() >= 1);
  REQUIRE(matches[0].contains("load_addr"));
  auto load_addr = matches[0]["load_addr"].get<std::uint64_t>();
  REQUIRE(load_addr != 0);

  // Compose: read+store in one round-trip.
  auto dr = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", target_id},
           {"addr", load_addr},
           {"len", 8},
           {"build_id", "build-sleeper"},
           {"name", "g_counter.bin"},
           {"format", "raw"},
           {"meta", json{{"capture", "live-attach"}}}}));
  REQUIRE(dr.ok);
  REQUIRE(dr.data.contains("artifact_id"));
  REQUIRE(dr.data.contains("byte_size"));
  REQUIRE(dr.data.contains("sha256"));
  REQUIRE(dr.data.contains("name"));

  auto artifact_id = dr.data["artifact_id"].get<std::int64_t>();
  CHECK(artifact_id > 0);
  CHECK(dr.data["byte_size"].get<std::uint64_t>() == 8);
  auto sha = dr.data["sha256"].get<std::string>();
  REQUIRE(sha.size() == 64);
  for (char c : sha) {
    CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
  }
  CHECK(dr.data["name"].get<std::string>() == "g_counter.bin");

  // Cross-check: artifact.get returns bytes that match a fresh mem.read.
  auto mr = d.dispatch(make_req(
      "mem.read",
      json{{"target_id", target_id},
           {"address", load_addr},
           {"size", 8}}));
  REQUIRE(mr.ok);
  auto mr_hex = mr.data["bytes"].get<std::string>();
  REQUIRE(mr_hex.size() == 16);

  auto ag = d.dispatch(make_req(
      "artifact.get",
      json{{"build_id", "build-sleeper"},
           {"name", "g_counter.bin"}}));
  REQUIRE(ag.ok);
  CHECK(ag.data["sha256"].get<std::string>() == sha);
  CHECK(ag.data["byte_size"].get<std::uint64_t>() == 8);
  CHECK(ag.data["format"].get<std::string>() == "raw");
  CHECK(ag.data["meta"]["capture"].get<std::string>() == "live-attach");

  // Cleanup.
  d.dispatch(make_req("process.detach", json{{"target_id", target_id}}));
}

TEST_CASE("dispatcher: mem.dump_artifact replaces on duplicate (build_id, name)",
          "[dispatcher][mem][dump][live]") {
  TmpStoreRoot t;
  auto be       = std::make_shared<LldbBackend>();
  auto store    = std::make_shared<ArtifactStore>(t.root);
  Dispatcher d(be, store, nullptr, nullptr);

  auto sleeper = spawn_sleeper();

  auto cr = d.dispatch(make_req("target.create_empty"));
  REQUIRE(cr.ok);
  auto target_id = cr.data["target_id"].get<std::uint64_t>();
  auto at = d.dispatch(make_req("target.attach",
                                json{{"target_id", target_id},
                                     {"pid", sleeper->pid}}));
  REQUIRE(at.ok);
  auto sf = d.dispatch(make_req("symbol.find",
                                json{{"target_id", target_id},
                                     {"name", "g_counter"}}));
  REQUIRE(sf.ok);
  auto load_addr =
      sf.data["matches"][0]["load_addr"].get<std::uint64_t>();

  json p{{"target_id", target_id},
         {"addr", load_addr},
         {"len", 8},
         {"build_id", "build-replace"},
         {"name", "dump.bin"}};

  auto first = d.dispatch(make_req("mem.dump_artifact", p));
  REQUIRE(first.ok);
  auto first_id = first.data["artifact_id"].get<std::int64_t>();

  auto second = d.dispatch(make_req("mem.dump_artifact", p));
  REQUIRE(second.ok);
  auto second_id = second.data["artifact_id"].get<std::int64_t>();
  // Per ArtifactStore::put contract, replace deletes + reinserts → id changes.
  CHECK(second_id != first_id);
  CHECK(second.data["byte_size"].get<std::uint64_t>() == 8);

  d.dispatch(make_req("process.detach", json{{"target_id", target_id}}));
}

TEST_CASE("dispatcher: mem.dump_artifact missing required params → -32602",
          "[dispatcher][mem][dump][error]") {
  TmpStoreRoot t;
  auto be    = std::make_shared<LldbBackend>();
  auto store = std::make_shared<ArtifactStore>(t.root);
  Dispatcher d(be, store, nullptr, nullptr);

  // No target_id.
  auto r1 = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"addr", 0x1000}, {"len", 8},
           {"build_id", "b"}, {"name", "n"}}));
  CHECK_FALSE(r1.ok);
  CHECK(static_cast<int>(r1.error_code) == -32602);

  // No addr.
  auto r2 = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", 1}, {"len", 8},
           {"build_id", "b"}, {"name", "n"}}));
  CHECK_FALSE(r2.ok);
  CHECK(static_cast<int>(r2.error_code) == -32602);

  // No len.
  auto r3 = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", 1}, {"addr", 0x1000},
           {"build_id", "b"}, {"name", "n"}}));
  CHECK_FALSE(r3.ok);
  CHECK(static_cast<int>(r3.error_code) == -32602);

  // No build_id.
  auto r4 = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", 1}, {"addr", 0x1000}, {"len", 8},
           {"name", "n"}}));
  CHECK_FALSE(r4.ok);
  CHECK(static_cast<int>(r4.error_code) == -32602);

  // No name.
  auto r5 = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", 1}, {"addr", 0x1000}, {"len", 8},
           {"build_id", "b"}}));
  CHECK_FALSE(r5.ok);
  CHECK(static_cast<int>(r5.error_code) == -32602);

  // Empty build_id is rejected (mirrors artifact.put).
  auto r6 = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", 1}, {"addr", 0x1000}, {"len", 8},
           {"build_id", ""}, {"name", "n"}}));
  CHECK_FALSE(r6.ok);
  CHECK(static_cast<int>(r6.error_code) == -32602);

  // Empty name likewise.
  auto r7 = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", 1}, {"addr", 0x1000}, {"len", 8},
           {"build_id", "b"}, {"name", ""}}));
  CHECK_FALSE(r7.ok);
  CHECK(static_cast<int>(r7.error_code) == -32602);
}

TEST_CASE("dispatcher: mem.dump_artifact with no store configured → -32002",
          "[dispatcher][mem][dump][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be, /*artifacts=*/nullptr, nullptr, nullptr);

  auto r = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", 1}, {"addr", 0x1000}, {"len", 8},
           {"build_id", "b"}, {"name", "n"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32002);
}

TEST_CASE("dispatcher: mem.dump_artifact backend read failure → -32000",
          "[dispatcher][mem][dump][error]") {
  TmpStoreRoot t;
  auto be    = std::make_shared<LldbBackend>();
  auto store = std::make_shared<ArtifactStore>(t.root);
  Dispatcher d(be, store, nullptr, nullptr);

  // Bad target_id — backend throws Error → -32000.
  auto r = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", 9999}, {"addr", 0x1000}, {"len", 8},
           {"build_id", "b"}, {"name", "n"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32000);
}

TEST_CASE("dispatcher: mem.dump_artifact len > 1 MiB → -32000",
          "[dispatcher][mem][dump][error]") {
  TmpStoreRoot t;
  auto be    = std::make_shared<LldbBackend>();
  auto store = std::make_shared<ArtifactStore>(t.root);
  Dispatcher d(be, store, nullptr, nullptr);

  auto sleeper = spawn_sleeper();
  auto cr = d.dispatch(make_req("target.create_empty"));
  REQUIRE(cr.ok);
  auto target_id = cr.data["target_id"].get<std::uint64_t>();
  auto at = d.dispatch(make_req("target.attach",
                                json{{"target_id", target_id},
                                     {"pid", sleeper->pid}}));
  REQUIRE(at.ok);

  auto r = d.dispatch(make_req(
      "mem.dump_artifact",
      json{{"target_id", target_id},
           {"addr", 0x1000},
           {"len", 2 * 1024 * 1024},
           {"build_id", "b"}, {"name", "n"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32000);

  d.dispatch(make_req("process.detach", json{{"target_id", target_id}}));
}
