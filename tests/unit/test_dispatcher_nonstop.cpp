// SPDX-License-Identifier: Apache-2.0
// Dispatcher wire-up for the post-V1 #21 non-stop runtime phase-1
// (docs/26-nonstop-runtime.md). Covers:
//
//   * hello.capabilities.non_stop_runtime  is true
//   * thread.list_state            returns {stop_event_seq, threads:[...]}
//   * thread.continue              records nonstop_.set_running(...) so
//                                  a subsequent thread.list_state reflects
//                                  the resumed thread
//   * thread.suspend               forwards to backend.suspend_thread
//                                  for non-RSP targets (v1.6 #21 LLDB
//                                  completion). Errors map: typed
//                                  NotImplementedError → -32001,
//                                  generic Error → -32004.
//   * process.continue all_threads=false  → -32602 with hint
//   * process.continue all_threads=true   → forwards as before
//   * describe.endpoints           lists thread.list_state +
//                                  thread.suspend
//
// We reuse a minimal stub backend; the lower-layer assertions live in
// test_dispatcher_thread_continue.cpp and test_nonstop_runtime.cpp.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <memory>
#include <string>

using ldb::backend::DebuggerBackend;
using ldb::backend::ProcessState;
using ldb::backend::ProcessStatus;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::daemon::Dispatcher;
using ldb::protocol::ErrorCode;
using ldb::protocol::Request;
using ldb::protocol::Response;
using ldb::protocol::json;

namespace {

class NoOpBackend : public DebuggerBackend {
 public:
  using TID = TargetId;
  using ThrID = ThreadId;
  TID known = 1;

  ProcessStatus continue_process(TID t) override {
    if (t != known) throw ldb::backend::Error("unknown target_id");
    ProcessStatus s; s.state = ProcessState::kRunning; s.pid = 42; return s;
  }
  ProcessStatus continue_thread(TID t, ThrID) override {
    if (t != known) throw ldb::backend::Error("unknown target_id");
    ProcessStatus s; s.state = ProcessState::kRunning; s.pid = 42; return s;
  }
  ProcessStatus suspend_thread(TID t, ThrID) override {
    if (t != known) throw ldb::backend::Error("unknown target_id");
    // Stub returns kStopped: SBThread::Suspend doesn't change the
    // process state, so the post-suspend snapshot reflects whatever
    // the process was already in. The dispatcher test only cares the
    // call succeeds + returns a ProcessStatus shape.
    ProcessStatus s; s.state = ProcessState::kStopped; s.pid = 42; return s;
  }
  ldb::backend::OpenResult open_executable(const std::string&, const ldb::backend::OpenOptions& = {}) override { return {}; }
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
  DebuggerBackend::ModuleSymbols  iterate_symbols(TID, std::string_view) override { return {}; }
  DebuggerBackend::ModuleTypes    iterate_types(TID, std::string_view)   override { return {}; }
  DebuggerBackend::ModuleStrings  iterate_strings(TID, std::string_view) override { return {}; }
  std::vector<ldb::backend::DisasmInsn>
      disassemble_range(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::vector<ldb::backend::XrefMatch>
      xref_address(TID, std::uint64_t, ldb::backend::XrefProvenance*) override { return {}; }
  std::vector<ldb::backend::StringXrefResult>
      find_string_xrefs(TID, const std::string&, ldb::backend::XrefProvenance*) override { return {}; }
  ProcessStatus launch_process(TID, const ldb::backend::LaunchOptions&) override { return {}; }
  ProcessStatus get_process_state(TID) override { return {}; }
  ProcessStatus kill_process(TID) override { return {}; }
  ProcessStatus attach(TID, std::int32_t) override { return {}; }
  ProcessStatus detach_process(TID) override { return {}; }
  ProcessStatus connect_remote_target(TID, const std::string&, const std::string&) override { return {}; }
  ldb::backend::ConnectRemoteSshResult
      connect_remote_target_ssh(TID, const ldb::backend::ConnectRemoteSshOptions&) override { return {}; }
  bool save_core(TID, const std::string&) override { return false; }
  std::vector<ldb::backend::ThreadInfo> list_threads(TID) override { return {}; }
  std::vector<ldb::backend::FrameInfo>
      list_frames(TID, ThrID, std::uint32_t) override { return {}; }
  ProcessStatus step_thread(TID, ThrID, ldb::backend::StepKind) override { return {}; }
  ProcessStatus reverse_continue(TID) override { return {}; }
  ProcessStatus reverse_step_thread(TID, ThrID, ldb::backend::ReverseStepKind) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_locals(TID, ThrID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_args(TID, ThrID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_registers(TID, ThrID, std::uint32_t) override { return {}; }
  ldb::backend::EvalResult
      evaluate_expression(TID, ThrID, std::uint32_t, const std::string&,
                          const ldb::backend::EvalOptions&) override { return {}; }
  ldb::backend::ReadResult
      read_value_path(TID, ThrID, std::uint32_t, const std::string&) override { return {}; }
  std::vector<std::uint8_t>
      read_memory(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::string read_cstring(TID, std::uint64_t, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::MemoryRegion> list_regions(TID) override { return {}; }
  std::vector<ldb::backend::MemorySearchHit>
      search_memory(TID, std::uint64_t, std::uint64_t,
                    const std::vector<std::uint8_t>&, std::uint32_t) override { return {}; }
  ldb::backend::BreakpointHandle
      create_breakpoint(TID, const ldb::backend::BreakpointSpec&) override { return {}; }
  void set_breakpoint_callback(TID, std::int32_t,
                               ldb::backend::BreakpointCallback, void*) override {}
  void disable_breakpoint(TID, std::int32_t) override {}
  void enable_breakpoint(TID, std::int32_t) override {}
  void delete_breakpoint(TID, std::int32_t) override {}
  std::uint64_t read_register(TID, ThrID, std::uint32_t, const std::string&) override { return 0; }
  void close_target(TID) override {}
  std::vector<ldb::backend::TargetInfo> list_targets() override {
    ldb::backend::TargetInfo i; i.target_id = known; i.triple = "stub";
    return {i};
  }
  void label_target(TID, std::string) override {}
  std::optional<std::string> get_target_label(TID) override { return std::nullopt; }
  std::string snapshot_for_target(TID) override { return "none"; }
  void attach_target_resource(TID,
      std::unique_ptr<DebuggerBackend::TargetResource>) override {}
};

Request req(const std::string& method, json params, const std::string& id = "1") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("hello: capabilities.non_stop_runtime is true",
          "[dispatcher][hello][nonstop]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("hello", json::object()));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("capabilities"));
  CHECK(resp.data["capabilities"].value("non_stop_runtime", false) == true);
}

TEST_CASE("thread.list_state: empty when nothing has been resumed",
          "[dispatcher][thread][list_state]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("thread.list_state", json{{"target_id", 1}}));
  REQUIRE(resp.ok);
  CHECK(resp.data.value("stop_event_seq", -1) == 0);
  REQUIRE(resp.data.contains("threads"));
  CHECK(resp.data["threads"].is_array());
  CHECK(resp.data["threads"].empty());
}

TEST_CASE("thread.list_state: missing target_id → -32602",
          "[dispatcher][thread][list_state][error]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("thread.list_state", json::object()));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("thread.continue: records set_running so thread.list_state reflects it",
          "[dispatcher][thread][continue][nonstop]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto r1 = d.dispatch(req("thread.continue",
      json{{"target_id", 1}, {"tid", 4242}}));
  REQUIRE(r1.ok);

  auto r2 = d.dispatch(req("thread.list_state", json{{"target_id", 1}}));
  REQUIRE(r2.ok);
  // thread.continue alone doesn't bump stop_event_seq — continue is
  // not a stop event (set_stopped is). Only when phase-2's listener
  // delivers a stop reply does seq advance.
  CHECK(r2.data.value("stop_event_seq", -1) == 0);
  REQUIRE(r2.data["threads"].is_array());
  REQUIRE(r2.data["threads"].size() == 1);
  const auto& t = r2.data["threads"][0];
  CHECK(t.value("tid", 0) == 4242);
  CHECK(t.value("state", std::string{}) == "running");
}

// v1.6 #21 LLDB completion: thread.suspend now forwards to the backend
// for non-RSP targets. The original phase-1 contract returned -32001
// kNotImplemented; that stub disappears once a backend (LldbBackend or
// any stub that overrides suspend_thread) is wired in. RSP-backed
// targets still go through the vCont;t path — covered by
// test_dispatcher_vcont_rsp.cpp.
TEST_CASE("thread.suspend: forwards to backend.suspend_thread (non-RSP path)",
          "[dispatcher][thread][suspend]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("thread.suspend",
      json{{"target_id", 1}, {"tid", 1}}));
  REQUIRE(resp.ok);
  CHECK(resp.data.value("state", std::string{}) == "stopped");
}

TEST_CASE("thread.suspend: unknown target_id → -32004 kBackendError",
          "[dispatcher][thread][suspend][error]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("thread.suspend",
      json{{"target_id", 9999}, {"tid", 1}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kBackendError);
}

// v1.6 #21 follow-up: dispatcher discriminates the not-implemented
// path by EXCEPTION TYPE (backend::NotImplementedError), not by
// substring-matching what(). These two cases pin that contract.

// A backend that throws NotImplementedError surfaces as -32001
// kNotImplemented — even when its message doesn't contain the words
// "not implemented" anywhere.
namespace {
class SuspendNotImplementedBackend : public NoOpBackend {
 public:
  ProcessStatus suspend_thread(TID, ThrID) override {
    // Intentionally a message that does NOT contain "not implemented"
    // — we want to prove the dispatcher uses the exception TYPE, not
    // the string content.
    throw ldb::backend::NotImplementedError("backend lacks the primitive");
  }
};
}  // namespace

TEST_CASE("thread.suspend: NotImplementedError → -32001 by exception type",
          "[dispatcher][thread][suspend][not_implemented]") {
  auto be = std::make_shared<SuspendNotImplementedBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("thread.suspend",
      json{{"target_id", 1}, {"tid", 1}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kNotImplemented);
  // The pre-fix code matched the message; this message has no such
  // substring, so a regression would silently downgrade to -32004.
  CHECK(resp.error_message.find("not implemented") == std::string::npos);
  CHECK(resp.error_message.find("lacks the primitive") != std::string::npos);
}

// And the inverse: a generic backend::Error whose message HAPPENS to
// contain "not implemented" must still surface as -32004, not be
// promoted to -32001. This is the exact bug the typed subclass fixed.
namespace {
class SuspendErrorWithNotImplementedSubstrBackend : public NoOpBackend {
 public:
  ProcessStatus suspend_thread(TID, ThrID) override {
    // Real runtime failure whose human-readable message includes
    // "not implemented" as descriptive prose (e.g. "feature X is
    // not implemented on this kernel"). Pre-fix this would have been
    // promoted to -32001 by the substring match.
    throw ldb::backend::Error(
        "kernel feature not implemented on this host (real failure)");
  }
};
}  // namespace

TEST_CASE("thread.suspend: generic Error with 'not implemented' substring "
          "stays -32004 (no string-match promotion)",
          "[dispatcher][thread][suspend][regression]") {
  auto be = std::make_shared<SuspendErrorWithNotImplementedSubstrBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("thread.suspend",
      json{{"target_id", 1}, {"tid", 1}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kBackendError);
}

TEST_CASE("process.continue: all_threads=false → -32602 with hint",
          "[dispatcher][process][continue][nonstop]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("process.continue",
      json{{"target_id", 1}, {"all_threads", false}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
  // The hint should point at thread.continue; otherwise the agent
  // has no signpost to the new endpoint.
  CHECK(resp.error_message.find("thread.continue") != std::string::npos);
}

TEST_CASE("process.continue: all_threads=true is the existing behavior",
          "[dispatcher][process][continue][nonstop]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("process.continue",
      json{{"target_id", 1}, {"all_threads", true}}));
  REQUIRE(resp.ok);
  CHECK(resp.data.contains("state"));
}

TEST_CASE("process.continue: omitted all_threads defaults to true",
          "[dispatcher][process][continue][nonstop]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("process.continue", json{{"target_id", 1}}));
  REQUIRE(resp.ok);  // wire-compat — old clients keep working
}

TEST_CASE("describe.endpoints: thread.list_state + thread.suspend are listed",
          "[dispatcher][describe][nonstop]") {
  auto be = std::make_shared<NoOpBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(req("describe.endpoints", json::object()));
  REQUIRE(resp.ok);
  bool list_state = false, suspend = false;
  for (const auto& e : resp.data["endpoints"]) {
    const auto m = e.value("method", std::string{});
    if (m == "thread.list_state") list_state = true;
    if (m == "thread.suspend")    suspend    = true;
  }
  CHECK(list_state);
  CHECK(suspend);
}
