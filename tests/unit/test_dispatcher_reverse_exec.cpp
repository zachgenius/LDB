// SPDX-License-Identifier: Apache-2.0
// Tests for dispatcher routing of the reverse-execution endpoints:
//
//   * process.reverse_continue({target_id})
//   * process.reverse_step    ({target_id, tid, kind})
//   * thread.reverse_step     ({target_id, tid, kind})
//
// v0.3 scope: kind="insn" only. kind="in" / kind="over" are accepted
// strings but rejected with -32602 because their reverse semantics
// require client-side step-over emulation (decode current insn, set
// internal stops, send `bc` and watch). They are reserved so the wire
// shape doesn't change when v0.4 fills them in.
//
// Capability gating happens in the backend (per-target is_reverse_capable
// flag, set on rr:// connect). The dispatcher just routes — these tests
// use a CountingStub backend so they run without rr / a fixture.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <memory>
#include <optional>
#include <string>

using ldb::backend::DebuggerBackend;
using ldb::backend::ProcessState;
using ldb::backend::ProcessStatus;
using ldb::backend::ReverseStepKind;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::daemon::Dispatcher;
using ldb::protocol::ErrorCode;
using ldb::protocol::Request;
using ldb::protocol::Response;
using ldb::protocol::json;

namespace {

class CountingStub : public DebuggerBackend {
 public:
  using TID = TargetId;
  using ThrID = ThreadId;

  // Recording state.
  int reverse_continue_calls       = 0;
  int reverse_step_thread_calls    = 0;
  TID  last_rev_step_target        = 0;
  ThrID last_rev_step_tid          = 0;
  ReverseStepKind last_rev_step_kind = ReverseStepKind::kInsn;

  TID known_target = 1;

  ProcessStatus make_status() const {
    ProcessStatus s;
    s.state = ProcessState::kStopped;
    s.pid   = 42;
    return s;
  }

  ProcessStatus reverse_continue(TID t) override {
    if (t != known_target) throw ldb::backend::Error("unknown target_id");
    ++reverse_continue_calls;
    return make_status();
  }

  ProcessStatus
  reverse_step_thread(TID t, ThrID th, ReverseStepKind k) override {
    if (t != known_target) throw ldb::backend::Error("unknown target_id");
    ++reverse_step_thread_calls;
    last_rev_step_target = t;
    last_rev_step_tid    = th;
    last_rev_step_kind   = k;
    return make_status();
  }

  // The rest are unused stubs (mirror test_dispatcher_thread_continue).
  ldb::backend::OpenResult open_executable(const std::string&) override { return {}; }
  ldb::backend::OpenResult create_empty_target() override { return {}; }
  ldb::backend::OpenResult load_core(const std::string&) override { return {}; }
  std::vector<ldb::backend::Module> list_modules(TID) override { return {}; }
  std::optional<ldb::backend::TypeLayout>
      find_type_layout(TID, const std::string&) override { return std::nullopt; }
  std::vector<ldb::backend::SymbolMatch>
      find_symbols(TID, const ldb::backend::SymbolQuery&) override { return {}; }
  std::vector<ldb::backend::GlobalVarMatch>
      find_globals_of_type(TID, std::string_view, bool&) override { return {}; }
  std::vector<ldb::backend::StringMatch>
      find_strings(TID, const ldb::backend::StringQuery&) override { return {}; }
  std::vector<ldb::backend::DisasmInsn>
      disassemble_range(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::vector<ldb::backend::XrefMatch>
      xref_address(TID, std::uint64_t) override { return {}; }
  std::vector<ldb::backend::StringXrefResult>
      find_string_xrefs(TID, const std::string&) override { return {}; }
  ProcessStatus launch_process(TID, const ldb::backend::LaunchOptions&) override { return {}; }
  ProcessStatus get_process_state(TID) override { return {}; }
  ProcessStatus continue_process(TID) override { return {}; }
  ProcessStatus continue_thread(TID, ThrID) override { return {}; }
  ProcessStatus kill_process(TID) override { return {}; }
  ProcessStatus attach(TID, std::int32_t) override { return {}; }
  ProcessStatus detach_process(TID) override { return {}; }
  ProcessStatus
      connect_remote_target(TID, const std::string&, const std::string&) override {
    return {};
  }
  ldb::backend::ConnectRemoteSshResult
      connect_remote_target_ssh(TID,
          const ldb::backend::ConnectRemoteSshOptions&) override { return {}; }
  bool save_core(TID, const std::string&) override { return false; }
  std::vector<ldb::backend::ThreadInfo> list_threads(TID) override { return {}; }
  std::vector<ldb::backend::FrameInfo>
      list_frames(TID, ThrID, std::uint32_t) override { return {}; }
  ProcessStatus
      step_thread(TID, ThrID, ldb::backend::StepKind) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_locals(TID, ThrID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_args(TID, ThrID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_registers(TID, ThrID, std::uint32_t) override { return {}; }
  ldb::backend::EvalResult
      evaluate_expression(TID, ThrID, std::uint32_t,
                          const std::string&,
                          const ldb::backend::EvalOptions&) override { return {}; }
  ldb::backend::ReadResult
      read_value_path(TID, ThrID, std::uint32_t,
                      const std::string&) override { return {}; }
  std::vector<std::uint8_t>
      read_memory(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::string read_cstring(TID, std::uint64_t, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::MemoryRegion> list_regions(TID) override { return {}; }
  std::vector<ldb::backend::MemorySearchHit>
      search_memory(TID, std::uint64_t, std::uint64_t,
                    const std::vector<std::uint8_t>&,
                    std::uint32_t) override { return {}; }
  ldb::backend::BreakpointHandle
      create_breakpoint(TID, const ldb::backend::BreakpointSpec&) override { return {}; }
  void set_breakpoint_callback(TID, std::int32_t,
                               ldb::backend::BreakpointCallback,
                               void*) override {}
  void disable_breakpoint(TID, std::int32_t) override {}
  void enable_breakpoint(TID, std::int32_t) override {}
  void delete_breakpoint(TID, std::int32_t) override {}
  std::uint64_t read_register(TID, ThrID, std::uint32_t,
                              const std::string&) override { return 0; }
  void close_target(TID) override {}
  std::vector<ldb::backend::TargetInfo> list_targets() override {
    ldb::backend::TargetInfo i;
    i.target_id = known_target;
    i.triple = "stub";
    return {i};
  }
  void label_target(TID, std::string) override {}
  std::optional<std::string> get_target_label(TID) override { return std::nullopt; }
  std::string snapshot_for_target(TID) override { return "none"; }
  void attach_target_resource(TID,
      std::unique_ptr<DebuggerBackend::TargetResource>) override {}
};

Request make_req(const std::string& method, json params,
                 const std::string& id = "1") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

// ---- process.reverse_continue -------------------------------------------

TEST_CASE("process.reverse_continue: routes to backend.reverse_continue",
          "[dispatcher][process][reverse_continue]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.reverse_continue",
                                  json{{"target_id", 1}}));
  REQUIRE(resp.ok);
  CHECK(be->reverse_continue_calls == 1);
  CHECK(resp.data.contains("state"));
  CHECK(resp.data.contains("pid"));
}

TEST_CASE("process.reverse_continue: missing target_id → -32602",
          "[dispatcher][process][reverse_continue][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.reverse_continue", json::object()));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("process.reverse_continue: unknown target_id surfaces backend error",
          "[dispatcher][process][reverse_continue][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.reverse_continue",
                                  json{{"target_id", 9999}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kBackendError);
}

// ---- process.reverse_step ----------------------------------------------

TEST_CASE("process.reverse_step kind=insn routes to backend.reverse_step_thread",
          "[dispatcher][process][reverse_step]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.reverse_step",
      json{{"target_id", 1}, {"tid", 7777}, {"kind", "insn"}}));
  REQUIRE(resp.ok);
  CHECK(be->reverse_step_thread_calls == 1);
  CHECK(be->last_rev_step_target == 1);
  CHECK(be->last_rev_step_tid    == 7777u);
  CHECK(be->last_rev_step_kind   == ReverseStepKind::kInsn);
}

TEST_CASE("process.reverse_step accepts kind=in/over/out (v1.3 carve-out)",
          "[dispatcher][process][reverse_step]") {
  // v1.3 implemented client-side step-over emulation for the deferred
  // kinds. The dispatcher now forwards them to the backend instead of
  // rejecting with -32602. See docs/16-reverse-exec.md.
  for (const char* kind_str : {"in", "over", "out"}) {
    auto be = std::make_shared<CountingStub>();
    Dispatcher d(be);
    auto resp = d.dispatch(make_req("process.reverse_step",
        json{{"target_id", 1}, {"tid", 7}, {"kind", kind_str}}));
    REQUIRE(resp.ok);
    CHECK(be->reverse_step_thread_calls == 1);
  }
}

TEST_CASE("process.reverse_step routes the parsed kind verbatim",
          "[dispatcher][process][reverse_step]") {
  struct Case { const char* str; ReverseStepKind expected; };
  for (const Case& c : {Case{"in",   ReverseStepKind::kIn},
                        Case{"over", ReverseStepKind::kOver},
                        Case{"out",  ReverseStepKind::kOut},
                        Case{"insn", ReverseStepKind::kInsn}}) {
    auto be = std::make_shared<CountingStub>();
    Dispatcher d(be);
    auto resp = d.dispatch(make_req("process.reverse_step",
        json{{"target_id", 1}, {"tid", 7}, {"kind", c.str}}));
    REQUIRE(resp.ok);
    CHECK(be->last_rev_step_kind == c.expected);
  }
}

TEST_CASE("process.reverse_step rejects unknown kind with -32602",
          "[dispatcher][process][reverse_step][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.reverse_step",
      json{{"target_id", 1}, {"tid", 7}, {"kind", "sideways"}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
  CHECK(be->reverse_step_thread_calls == 0);
}

TEST_CASE("process.reverse_step missing tid → -32602",
          "[dispatcher][process][reverse_step][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.reverse_step",
      json{{"target_id", 1}, {"kind", "insn"}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

// ---- thread.reverse_step -----------------------------------------------

TEST_CASE("thread.reverse_step kind=insn routes to backend.reverse_step_thread",
          "[dispatcher][thread][reverse_step]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("thread.reverse_step",
      json{{"target_id", 1}, {"tid", 12345}, {"kind", "insn"}}));
  REQUIRE(resp.ok);
  CHECK(be->reverse_step_thread_calls == 1);
  CHECK(be->last_rev_step_target == 1);
  CHECK(be->last_rev_step_tid    == 12345u);
  CHECK(be->last_rev_step_kind   == ReverseStepKind::kInsn);
}

TEST_CASE("thread.reverse_step missing target_id → -32602",
          "[dispatcher][thread][reverse_step][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("thread.reverse_step",
      json{{"tid", 1}, {"kind", "insn"}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

// ---- describe.endpoints --------------------------------------------------

TEST_CASE("describe.endpoints: reverse-exec endpoints are registered",
          "[dispatcher][describe][reverse]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("describe.endpoints", json::object()));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("endpoints"));

  bool found_rc = false, found_prs = false, found_trs = false;
  for (const auto& e : resp.data["endpoints"]) {
    const auto m = e.value("method", "");
    if (m == "process.reverse_continue") {
      found_rc = true;
      const auto& ps = e["params_schema"];
      REQUIRE(ps.contains("required"));
      bool has_target_id = false;
      for (const auto& r : ps["required"]) {
        if (r == "target_id") has_target_id = true;
      }
      CHECK(has_target_id);
    }
    if (m == "process.reverse_step") {
      found_prs = true;
      const auto& ps = e["params_schema"];
      REQUIRE(ps.contains("required"));
      bool has_target_id = false, has_tid = false, has_kind = false;
      for (const auto& r : ps["required"]) {
        if (r == "target_id") has_target_id = true;
        if (r == "tid")       has_tid = true;
        if (r == "kind")      has_kind = true;
      }
      CHECK(has_target_id);
      CHECK(has_tid);
      CHECK(has_kind);
    }
    if (m == "thread.reverse_step") {
      found_trs = true;
    }
  }
  CHECK(found_rc);
  CHECK(found_prs);
  CHECK(found_trs);
}
