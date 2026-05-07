// Tests for src/dap/handlers — DAP request → LDB JSON-RPC translation.
//
// Each handler is exercised against a stub RpcChannel that records the
// (method, params) pairs the handler emits and returns canned responses.
// The tests assert two things per case:
//   1. the LDB-side `call(method, params)` invocations are exactly what
//      the DAP→LDB mapping calls for; and
//   2. the DAP response body matches the spec-required shape for that
//      DAP command.
//
// This pins the translation layer without spawning a real daemon. The
// concrete `SubprocessRpcChannel` is exercised separately in
// test_dap_rpc_channel.

#include <catch_amalgamated.hpp>

#include "dap/handlers.h"
#include "dap/rpc_channel.h"

#include <deque>
#include <functional>
#include <string>
#include <utility>
#include <vector>

using ldb::dap::DapResult;
using ldb::dap::json;
using ldb::dap::RpcChannel;
using ldb::dap::RpcResponse;
using ldb::dap::Session;

namespace {

// Records every call and returns canned responses. The canned response
// for each (method) is a deque so a test can stage a sequence of
// answers (e.g. process.state polled twice).
class StubChannel : public RpcChannel {
 public:
  struct Call {
    std::string method;
    json params;
  };
  std::vector<Call> calls;

  using Responder = std::function<RpcResponse(const json&)>;

  void on(const std::string& method, Responder fn) {
    handlers_[method].push_back(std::move(fn));
  }

  // Convenience: queue a fixed `ok=true, data=...` response.
  void on_ok(const std::string& method, json data) {
    on(method, [d = std::move(data)](const json&) {
      RpcResponse r;
      r.ok = true;
      r.data = d;
      return r;
    });
  }

  void on_err(const std::string& method, int code, std::string msg) {
    on(method, [code, m = std::move(msg)](const json&) {
      RpcResponse r;
      r.ok = false;
      r.error_code = code;
      r.error_message = m;
      return r;
    });
  }

  RpcResponse call(const std::string& method, const json& params) override {
    calls.push_back({method, params});
    auto it = handlers_.find(method);
    if (it == handlers_.end() || it->second.empty()) {
      RpcResponse r;
      r.ok = false;
      r.error_code = -32601;
      r.error_message = "stub: no handler for " + method;
      return r;
    }
    auto fn = std::move(it->second.front());
    it->second.pop_front();
    return fn(params);
  }

 private:
  std::unordered_map<std::string, std::deque<Responder>> handlers_;
};

}  // namespace

TEST_CASE("on_initialize: returns honest capabilities", "[dap][handlers]") {
  StubChannel ch;
  Session s(ch);
  auto r = s.on_initialize(json::object());
  REQUIRE(r.success);
  // Spec requires `supportsConfigurationDoneRequest` to be honestly set.
  REQUIRE(r.body.contains("supportsConfigurationDoneRequest"));
  REQUIRE(r.body["supportsConfigurationDoneRequest"] == true);
  // We don't support exception bps, restart, terminate, conditional
  // breakpoints, step-back. Be honest.
  REQUIRE(r.body["supportsConditionalBreakpoints"] == false);
  REQUIRE(r.body["supportsRestartRequest"] == false);
  REQUIRE(r.body["supportsTerminateRequest"] == false);
  REQUIRE(r.body["supportsStepBack"] == false);
  REQUIRE(r.body["supportsLoadedSourcesRequest"] == false);
  // No daemon calls during initialize.
  REQUIRE(ch.calls.empty());
  // Handler should request that an `initialized` event be emitted
  // AFTER the response (per DAP spec ordering).
  REQUIRE_FALSE(r.events.empty());
  REQUIRE(r.events.front()["event"] == "initialized");
}

TEST_CASE("on_launch: target.open + process.launch", "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.open",
           {{"target_id", 7}, {"triple", "x86_64-pc-linux"},
            {"modules", json::array()}});
  ch.on_ok("process.launch",
           {{"state", "stopped"}, {"pid", 12345}, {"stop_reason", "entry"}});

  Session s(ch);
  auto r = s.on_launch({{"program", "/bin/ls"}});
  REQUIRE(r.success);
  REQUIRE(s.target_id() == 7);

  // First call must be target.open with `path` from `program`.
  REQUIRE(ch.calls.size() >= 2);
  REQUIRE(ch.calls[0].method == "target.open");
  REQUIRE(ch.calls[0].params["path"] == "/bin/ls");

  // Second call: process.launch with the issued target_id.
  REQUIRE(ch.calls[1].method == "process.launch");
  REQUIRE(ch.calls[1].params["target_id"] == 7);
}

TEST_CASE("on_attach: target.create_empty + target.attach", "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 11}, {"triple", "x86_64-pc-linux"},
            {"modules", json::array()}});
  ch.on_ok("target.attach",
           {{"state", "stopped"}, {"pid", 4242}});

  Session s(ch);
  auto r = s.on_attach({{"processId", 4242}});
  REQUIRE(r.success);
  REQUIRE(s.target_id() == 11);

  REQUIRE(ch.calls.size() == 2);
  REQUIRE(ch.calls[0].method == "target.create_empty");
  REQUIRE(ch.calls[1].method == "target.attach");
  REQUIRE(ch.calls[1].params["target_id"] == 11);
  REQUIRE(ch.calls[1].params["pid"] == 4242);
}

TEST_CASE("on_threads: thread.list -> DAP threads array",
          "[dap][handlers]") {
  StubChannel ch;
  // First open the target so target_id is set.
  ch.on_ok("target.create_empty",
           {{"target_id", 1}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  ch.on_ok("thread.list",
           json{{"threads", json::array(
               {{{"tid", 100}, {"index", 0}, {"name", "main"},
                 {"state", "stopped"}, {"pc", 0x4000}, {"sp", 0x7fff0}},
                {{"tid", 101}, {"index", 1}, {"name", "worker"},
                 {"state", "stopped"}, {"pc", 0x4100}, {"sp", 0x7fff1}}})}});

  Session s(ch);
  s.on_attach({{"processId", 1}});
  ch.calls.clear();

  auto r = s.on_threads(json::object());
  REQUIRE(r.success);
  REQUIRE(r.body.contains("threads"));
  REQUIRE(r.body["threads"].size() == 2);
  // DAP requires {id, name} on every thread.
  REQUIRE(r.body["threads"][0]["id"] == 100);
  REQUIRE(r.body["threads"][0]["name"] == "main");
  REQUIRE(r.body["threads"][1]["id"] == 101);
  REQUIRE(r.body["threads"][1]["name"] == "worker");

  REQUIRE(ch.calls.size() == 1);
  REQUIRE(ch.calls[0].method == "thread.list");
  REQUIRE(ch.calls[0].params["target_id"] == 1);
}

TEST_CASE("on_stack_trace: thread.frames -> DAP stackFrames",
          "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 1}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  ch.on_ok("thread.frames",
           json{{"frames", json::array(
               {{{"index", 0}, {"pc", 0x4000}, {"function", "main"},
                 {"file", "main.c"}, {"line", 5}},
                {{"index", 1}, {"pc", 0x4100}, {"function", "outer"},
                 {"file", "x.c"}, {"line", 10}}})}});

  Session s(ch);
  s.on_attach({{"processId", 1}});
  ch.calls.clear();

  auto r = s.on_stack_trace({{"threadId", 100}});
  REQUIRE(r.success);
  REQUIRE(r.body.contains("stackFrames"));
  REQUIRE(r.body["stackFrames"].size() == 2);
  REQUIRE(r.body["stackFrames"][0]["name"] == "main");
  REQUIRE(r.body["stackFrames"][0]["line"] == 5);
  REQUIRE(r.body["stackFrames"][0]["source"]["path"] == "main.c");
  REQUIRE(r.body["totalFrames"] == 2);
  // Each stackFrame must have a non-zero `id` so subsequent `scopes`
  // requests can look up the frame.
  REQUIRE(r.body["stackFrames"][0]["id"].get<int>() > 0);
  REQUIRE(r.body["stackFrames"][1]["id"].get<int>() > 0);

  REQUIRE(ch.calls.size() == 1);
  REQUIRE(ch.calls[0].method == "thread.frames");
  REQUIRE(ch.calls[0].params["target_id"] == 1);
  REQUIRE(ch.calls[0].params["tid"] == 100);
}

TEST_CASE("on_scopes -> on_variables maps to frame.locals/args/registers",
          "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 2}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  ch.on_ok("thread.frames",
           json{{"frames", json::array(
               {{{"index", 0}, {"pc", 0x1000}, {"function", "f"},
                 {"file", "f.c"}, {"line", 3}}})}});

  Session s(ch);
  s.on_attach({{"processId", 1}});
  auto r_st = s.on_stack_trace({{"threadId", 200}});
  REQUIRE(r_st.success);
  int frame_id = r_st.body["stackFrames"][0]["id"].get<int>();
  ch.calls.clear();

  auto r_sc = s.on_scopes({{"frameId", frame_id}});
  REQUIRE(r_sc.success);
  REQUIRE(r_sc.body.contains("scopes"));
  REQUIRE(r_sc.body["scopes"].size() == 3);
  // Required scope names per spec usage.
  std::vector<std::string> got_names;
  for (const auto& sc : r_sc.body["scopes"]) {
    got_names.push_back(sc["name"].get<std::string>());
  }
  REQUIRE(got_names == std::vector<std::string>{"Locals", "Arguments",
                                                "Registers"});
  // Each scope must carry a non-zero variablesReference.
  std::vector<int> refs;
  for (const auto& sc : r_sc.body["scopes"]) {
    int ref = sc["variablesReference"].get<int>();
    REQUIRE(ref > 0);
    refs.push_back(ref);
  }

  // Now ask for variables on the Locals scope and verify it calls
  // frame.locals with the right (target_id, tid, frame_index).
  ch.on_ok("frame.locals",
           json{{"locals", json::array(
               {{{"name", "x"}, {"type", "int"}, {"value", "42"}}})}});
  auto r_v = s.on_variables({{"variablesReference", refs[0]}});
  REQUIRE(r_v.success);
  REQUIRE(r_v.body["variables"].size() == 1);
  REQUIRE(r_v.body["variables"][0]["name"] == "x");
  REQUIRE(r_v.body["variables"][0]["value"] == "42");
  REQUIRE(r_v.body["variables"][0]["type"] == "int");

  REQUIRE(ch.calls.back().method == "frame.locals");
  REQUIRE(ch.calls.back().params["target_id"] == 2);
  REQUIRE(ch.calls.back().params["tid"] == 200);
  REQUIRE(ch.calls.back().params["frame_index"] == 0);

  // Arguments scope -> frame.args.
  ch.on_ok("frame.args",
           json{{"args", json::array(
               {{{"name", "argc"}, {"type", "int"}, {"value", "1"}}})}});
  auto r_a = s.on_variables({{"variablesReference", refs[1]}});
  REQUIRE(r_a.success);
  REQUIRE(ch.calls.back().method == "frame.args");

  // Registers scope -> frame.registers.
  ch.on_ok("frame.registers",
           json{{"registers", json::array(
               {{{"name", "rip"}, {"value", "0x1000"}}})}});
  auto r_r = s.on_variables({{"variablesReference", refs[2]}});
  REQUIRE(r_r.success);
  REQUIRE(ch.calls.back().method == "frame.registers");
}

TEST_CASE("on_evaluate: value.eval with frameId context", "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 3}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  ch.on_ok("thread.frames",
           json{{"frames", json::array(
               {{{"index", 0}, {"pc", 0x1000}, {"function", "f"},
                 {"file", "f.c"}, {"line", 1}}})}});

  Session s(ch);
  s.on_attach({{"processId", 1}});
  auto r_st = s.on_stack_trace({{"threadId", 300}});
  int frame_id = r_st.body["stackFrames"][0]["id"].get<int>();
  ch.calls.clear();

  ch.on_ok("value.eval",
           json{{"value", json{{"name", "result"}, {"type", "int"},
                               {"value", "7"}}}});
  auto r_e = s.on_evaluate({{"expression", "1+6"}, {"frameId", frame_id}});
  REQUIRE(r_e.success);
  REQUIRE(r_e.body["result"] == "7");
  REQUIRE(r_e.body["type"] == "int");

  REQUIRE(ch.calls.back().method == "value.eval");
  REQUIRE(ch.calls.back().params["target_id"] == 3);
  REQUIRE(ch.calls.back().params["tid"] == 300);
  REQUIRE(ch.calls.back().params["frame_index"] == 0);
  REQUIRE(ch.calls.back().params["expr"] == "1+6");
}

TEST_CASE("on_continue: process.continue + emit stopped event with real threadId",
          "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 1}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  ch.on_ok("process.continue",
           json{{"state", "running"}, {"pid", 1}});
  // Polled once and finds "stopped".
  ch.on_ok("process.state",
           json{{"state", "stopped"}, {"stop_reason", "breakpoint"},
                {"pid", 1}});
  // thread.list called to resolve the stopped thread's id.
  ch.on_ok("thread.list",
           json{{"threads", json::array(
               {{{"tid", 7777}, {"index", 0}, {"name", "main"},
                 {"state", "stopped"}, {"pc", 0}, {"sp", 0}}})},
               {"total", 1}});

  Session s(ch);
  s.on_attach({{"processId", 1}});
  ch.calls.clear();

  auto r = s.on_continue({{"threadId", 100}});
  REQUIRE(r.success);
  REQUIRE(r.body["allThreadsContinued"] == true);

  REQUIRE(ch.calls[0].method == "process.continue");
  REQUIRE(ch.calls[0].params["target_id"] == 1);

  REQUIRE_FALSE(r.events.empty());
  auto& ev = r.events.back();
  REQUIRE(ev["event"] == "stopped");
  REQUIRE(ev["body"]["reason"] == "breakpoint");
  // threadId must reflect the actual stopped thread, not a hardcoded 0.
  REQUIRE(ev["body"]["threadId"] == 7777);
}

TEST_CASE("on_continue: exited event carries real exitCode",
          "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 2}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 2}});
  ch.on_ok("process.continue", json{{"state", "running"}, {"pid", 2}});
  ch.on_ok("process.state",
           json{{"state", "exited"}, {"exit_code", 42}, {"pid", 2}});

  Session s(ch);
  s.on_attach({{"processId", 2}});
  ch.calls.clear();

  auto r = s.on_continue({});
  REQUIRE(r.success);
  REQUIRE_FALSE(r.events.empty());
  auto& ev = r.events.back();
  REQUIRE(ev["event"] == "exited");
  REQUIRE(ev["body"]["exitCode"] == 42);
}

TEST_CASE("on_next: exited event carries real exitCode",
          "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 3}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 3}});
  ch.on_ok("process.step",
           json{{"state", "exited"}, {"exit_code", 5}, {"pid", 3}});

  Session s(ch);
  s.on_attach({{"processId", 3}});
  ch.calls.clear();

  auto r = s.on_next({{"threadId", 1}});
  REQUIRE(r.success);
  REQUIRE_FALSE(r.events.empty());
  auto& ev = r.events.back();
  REQUIRE(ev["event"] == "exited");
  REQUIRE(ev["body"]["exitCode"] == 5);
}

TEST_CASE("on_next/stepIn/stepOut: process.step with kind", "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 1}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  Session s(ch);
  s.on_attach({{"processId", 1}});

  ch.on_ok("process.step", {{"state", "stopped"}, {"pid", 1}});
  ch.calls.clear();
  auto r = s.on_next({{"threadId", 100}});
  REQUIRE(r.success);
  REQUIRE(ch.calls[0].method == "process.step");
  REQUIRE(ch.calls[0].params["kind"] == "over");
  REQUIRE(ch.calls[0].params["tid"] == 100);

  ch.on_ok("process.step", {{"state", "stopped"}, {"pid", 1}});
  ch.calls.clear();
  s.on_step_in({{"threadId", 100}});
  REQUIRE(ch.calls[0].params["kind"] == "in");

  ch.on_ok("process.step", {{"state", "stopped"}, {"pid", 1}});
  ch.calls.clear();
  s.on_step_out({{"threadId", 100}});
  REQUIRE(ch.calls[0].params["kind"] == "out");
}

TEST_CASE("on_set_breakpoints: probe.create per source line",
          "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 9}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  Session s(ch);
  s.on_attach({{"processId", 1}});

  ch.on_ok("probe.create", {{"probe_id", 1}, {"kind", "lldb_breakpoint"}});
  ch.on_ok("probe.create", {{"probe_id", 2}, {"kind", "lldb_breakpoint"}});

  ch.calls.clear();
  auto r = s.on_set_breakpoints(
      {{"source", {{"path", "/tmp/main.c"}}},
       {"breakpoints", json::array({{{"line", 10}}, {{"line", 20}}})}});
  REQUIRE(r.success);
  REQUIRE(r.body["breakpoints"].size() == 2);
  REQUIRE(r.body["breakpoints"][0]["verified"] == true);
  REQUIRE(r.body["breakpoints"][0]["line"] == 10);
  REQUIRE(r.body["breakpoints"][1]["line"] == 20);

  // Two probe.create calls, one per breakpoint.
  REQUIRE(ch.calls.size() == 2);
  for (const auto& c : ch.calls) {
    REQUIRE(c.method == "probe.create");
    REQUIRE(c.params["target_id"] == 9);
    REQUIRE(c.params["kind"] == "lldb_breakpoint");
    REQUIRE(c.params["where"]["file"] == "/tmp/main.c");
    REQUIRE(c.params.value("action", "") == "stop");
  }
  REQUIRE(ch.calls[0].params["where"]["line"] == 10);
  REQUIRE(ch.calls[1].params["where"]["line"] == 20);
}

TEST_CASE("on_disconnect: process.kill + target.close, terminate=true",
          "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 1}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  Session s(ch);
  s.on_attach({{"processId", 1}});

  ch.on_ok("process.detach", {{"state", "detached"}, {"pid", 1}});
  ch.on_ok("target.close", json::object());
  ch.calls.clear();

  auto r = s.on_disconnect(json::object());
  REQUIRE(r.success);
  REQUIRE(r.terminate);

  // Default disconnect = detach (less destructive than kill). Two
  // calls: process.detach then target.close.
  REQUIRE(ch.calls.size() == 2);
  REQUIRE(ch.calls[0].method == "process.detach");
  REQUIRE(ch.calls[1].method == "target.close");
}

TEST_CASE("on_disconnect: terminateDebuggee=true uses process.kill",
          "[dap][handlers]") {
  StubChannel ch;
  ch.on_ok("target.create_empty",
           {{"target_id", 1}, {"triple", "x"}, {"modules", json::array()}});
  ch.on_ok("target.attach", {{"state", "stopped"}, {"pid", 1}});
  Session s(ch);
  s.on_attach({{"processId", 1}});

  ch.on_ok("process.kill", {{"state", "exited"}, {"pid", 1}});
  ch.on_ok("target.close", json::object());
  ch.calls.clear();

  auto r = s.on_disconnect({{"terminateDebuggee", true}});
  REQUIRE(r.success);
  REQUIRE(ch.calls[0].method == "process.kill");
}

TEST_CASE("dispatch: unknown command returns failure with error message",
          "[dap][handlers]") {
  StubChannel ch;
  Session s(ch);
  auto r = s.dispatch("setExceptionBreakpoints", json::object());
  REQUIRE_FALSE(r.success);
  REQUIRE_FALSE(r.message.empty());
  // No daemon calls — the shim refuses up front.
  REQUIRE(ch.calls.empty());
}
