#include "dap/handlers.h"

#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

// Each handler is a pure function over (DapResult, RpcChannel). The
// shim keeps a tiny amount of state between requests:
//   * `target_id_` — set by launch/attach, used by every subsequent
//     daemon-bound call.
//   * `var_refs_` / `frame_refs_` — DAP "references" the IDE uses to
//     re-target a future call. We allocate them here and resolve them
//     on `variables` / `evaluate`.
//
// The "events emitted as a side effect" pattern (DapResult::events)
// keeps the main loop straightforward: the loop writes the response,
// then drains events. The polling-based stop/exit detection used by
// `continue`/`step` (poll process.state on a small interval until
// stopped or exited) is documented on poll_until_settled().

namespace ldb::dap {

namespace {

// DAP allows clients to request paths in client-relative form. We
// preserve whatever they sent so that `setBreakpoints` round-trips
// cleanly back to the IDE.
std::string get_string(const json& j, const std::string& key,
                       const std::string& fallback = "") {
  if (auto it = j.find(key); it != j.end() && it->is_string()) {
    return it->get<std::string>();
  }
  return fallback;
}

std::int64_t get_int(const json& j, const std::string& key,
                     std::int64_t fallback = 0) {
  if (auto it = j.find(key); it != j.end()) {
    if (it->is_number_integer())  return it->get<std::int64_t>();
    if (it->is_number_unsigned()) return static_cast<std::int64_t>(
                                       it->get<std::uint64_t>());
  }
  return fallback;
}

bool get_bool(const json& j, const std::string& key, bool fallback = false) {
  if (auto it = j.find(key); it != j.end() && it->is_boolean()) {
    return it->get<bool>();
  }
  return fallback;
}

DapResult fail(const std::string& message) {
  DapResult r;
  r.success = false;
  r.message = message;
  return r;
}

// Default capability advertisement. Honest about what we don't
// support — the IDE uses these to grey out menu items.
json default_capabilities() {
  return json{
      {"supportsConfigurationDoneRequest", true},
      {"supportsEvaluateForHovers", false},
      {"supportsStepBack", false},
      {"supportsRestartRequest", false},
      {"supportsLoadedSourcesRequest", false},
      {"supportsTerminateRequest", false},
      {"supportsConditionalBreakpoints", false},
      {"supportsHitConditionalBreakpoints", false},
      {"supportsFunctionBreakpoints", false},
      {"supportsExceptionFilterOptions", false},
      {"supportsExceptionInfoRequest", false},
      {"supportsSetVariable", false},
      {"supportsSetExpression", false},
      {"supportsValueFormattingOptions", false},
      {"supportsLogPoints", false},
      {"supportsCompletionsRequest", false},
      {"supportsModulesRequest", false},
      {"supportsDataBreakpoints", false},
      {"supportsReadMemoryRequest", false},
      {"supportsWriteMemoryRequest", false},
      {"supportsDisassembleRequest", false},
      {"supportsSteppingGranularity", false},
      {"supportsInstructionBreakpoints", false},
      {"supportsBreakpointLocationsRequest", false},
      {"supportsClipboardContext", false},
      {"supportsTerminateThreadsRequest", false},
      {"supportsCancelRequest", false},
  };
}

}  // namespace

int Session::allocate_var_ref(std::int64_t tid, std::uint32_t frame_index,
                              ScopeKind kind) {
  int id = next_var_ref_++;
  var_refs_[id] = VarRef{tid, frame_index, kind};
  return id;
}

int Session::allocate_frame_id(std::int64_t tid, std::uint32_t frame_index) {
  int id = next_frame_id_++;
  frame_refs_[id] = FrameRef{tid, frame_index};
  return id;
}

DapResult Session::on_initialize(const json& /*args*/) {
  DapResult r;
  r.body = default_capabilities();
  r.success = true;
  // DAP requires the `initialized` event to follow the initialize
  // response, before the IDE issues `configurationDone`. Wire it.
  r.events.push_back(json{{"event", "initialized"}, {"body", json::object()}});
  return r;
}

DapResult Session::on_launch(const json& args) {
  if (!args.contains("program") || !args["program"].is_string()) {
    return fail("launch requires string `program`");
  }
  auto open = channel_.call("target.open",
                             {{"path", args["program"].get<std::string>()}});
  if (!open.ok) return fail(open.error_message);
  target_id_ = get_int(open.data, "target_id");

  json launch_params = {{"target_id", target_id_}};
  if (args.contains("stopOnEntry") && args["stopOnEntry"].is_boolean()) {
    launch_params["stop_at_entry"] = args["stopOnEntry"].get<bool>();
  }
  auto run = channel_.call("process.launch", launch_params);
  if (!run.ok) return fail(run.error_message);

  process_running_ = (get_string(run.data, "state") == "running");

  DapResult r;
  r.body = json::object();
  return r;
}

DapResult Session::on_attach(const json& args) {
  if (!args.contains("processId")) {
    return fail("attach requires `processId`");
  }
  std::int64_t pid = get_int(args, "processId");
  auto target = channel_.call("target.create_empty", json::object());
  if (!target.ok) return fail(target.error_message);
  target_id_ = get_int(target.data, "target_id");

  auto attach = channel_.call("target.attach",
                               {{"target_id", target_id_}, {"pid", pid}});
  if (!attach.ok) return fail(attach.error_message);
  process_running_ = (get_string(attach.data, "state") == "running");

  DapResult r;
  r.body = json::object();
  return r;
}

DapResult Session::on_configuration_done(const json&) {
  DapResult r;
  r.body = json::object();
  return r;
}

DapResult Session::on_disconnect(const json& args) {
  bool terminate_debuggee = get_bool(args, "terminateDebuggee", false);
  if (target_id_ != 0) {
    if (terminate_debuggee) {
      channel_.call("process.kill", {{"target_id", target_id_}});
    } else {
      // Default: detach. Less destructive — matches DAP's default
      // semantics when terminateDebuggee is unset.
      channel_.call("process.detach", {{"target_id", target_id_}});
    }
    channel_.call("target.close", {{"target_id", target_id_}});
  }
  DapResult r;
  r.body = json::object();
  r.terminate = true;
  // Emit a `terminated` event so the IDE can clean up its UI before
  // we exit.
  r.events.push_back(json{{"event", "terminated"}, {"body", json::object()}});
  return r;
}

DapResult Session::on_set_breakpoints(const json& args) {
  std::string source_path;
  if (auto it = args.find("source"); it != args.end() && it->is_object()) {
    source_path = get_string(*it, "path");
  }
  if (source_path.empty()) {
    return fail("setBreakpoints requires `source.path`");
  }
  if (target_id_ == 0) {
    return fail("setBreakpoints called before launch/attach");
  }
  auto bps_it = args.find("breakpoints");
  json result_bps = json::array();
  if (bps_it == args.end() || !bps_it->is_array()) {
    DapResult r;
    r.body = json{{"breakpoints", result_bps}};
    return r;
  }
  for (const auto& bp : *bps_it) {
    int line = static_cast<int>(get_int(bp, "line"));
    json req = {
        {"target_id", target_id_},
        {"kind", "lldb_breakpoint"},
        {"action", "stop"},
        {"where", {{"file", source_path}, {"line", line}}},
    };
    auto resp = channel_.call("probe.create", req);
    json out = {
        {"verified", resp.ok},
        {"line", line},
        {"source", {{"path", source_path}}},
    };
    if (resp.ok) {
      out["id"] = get_int(resp.data, "probe_id");
    } else {
      out["message"] = resp.error_message;
    }
    result_bps.push_back(out);
  }
  DapResult r;
  r.body = json{{"breakpoints", result_bps}};
  return r;
}

DapResult Session::on_threads(const json&) {
  if (target_id_ == 0) return fail("threads called before launch/attach");
  auto resp = channel_.call("thread.list", {{"target_id", target_id_}});
  if (!resp.ok) return fail(resp.error_message);
  json arr = json::array();
  if (auto it = resp.data.find("threads");
      it != resp.data.end() && it->is_array()) {
    for (const auto& t : *it) {
      arr.push_back({
          {"id", get_int(t, "tid")},
          {"name", get_string(t, "name", "thread")},
      });
    }
  }
  DapResult r;
  r.body = json{{"threads", arr}};
  return r;
}

DapResult Session::on_stack_trace(const json& args) {
  std::int64_t tid = get_int(args, "threadId");
  if (target_id_ == 0) return fail("stackTrace called before launch/attach");
  json req = {{"target_id", target_id_}, {"tid", tid}};
  auto resp = channel_.call("thread.frames", req);
  if (!resp.ok) return fail(resp.error_message);

  json frames = json::array();
  if (auto it = resp.data.find("frames");
      it != resp.data.end() && it->is_array()) {
    for (const auto& f : *it) {
      std::uint32_t idx = static_cast<std::uint32_t>(get_int(f, "index"));
      int frame_id = allocate_frame_id(tid, idx);
      json out = {
          {"id", frame_id},
          {"name", get_string(f, "function", "<anonymous>")},
          {"line", get_int(f, "line")},
          {"column", 0},
      };
      std::string file = get_string(f, "file");
      if (!file.empty()) {
        out["source"] = json{{"path", file}, {"name", file}};
      }
      out["instructionPointerReference"] = std::to_string(get_int(f, "pc"));
      frames.push_back(std::move(out));
    }
  }
  DapResult r;
  r.body = json{{"stackFrames", frames}, {"totalFrames", frames.size()}};
  return r;
}

DapResult Session::on_scopes(const json& args) {
  int frame_id = static_cast<int>(get_int(args, "frameId"));
  auto it = frame_refs_.find(frame_id);
  if (it == frame_refs_.end()) {
    return fail("scopes: unknown frameId " + std::to_string(frame_id));
  }
  auto [tid, frame_index] = it->second;

  int locals_ref    = allocate_var_ref(tid, frame_index, ScopeKind::kLocals);
  int args_ref      = allocate_var_ref(tid, frame_index, ScopeKind::kArgs);
  int registers_ref = allocate_var_ref(tid, frame_index, ScopeKind::kRegisters);

  json scopes = json::array({
      {{"name", "Locals"},     {"variablesReference", locals_ref},
       {"expensive", false},   {"presentationHint", "locals"}},
      {{"name", "Arguments"},  {"variablesReference", args_ref},
       {"expensive", false},   {"presentationHint", "arguments"}},
      {{"name", "Registers"},  {"variablesReference", registers_ref},
       {"expensive", true},    {"presentationHint", "registers"}},
  });
  DapResult r;
  r.body = json{{"scopes", scopes}};
  return r;
}

DapResult Session::on_variables(const json& args) {
  int ref = static_cast<int>(get_int(args, "variablesReference"));
  auto it = var_refs_.find(ref);
  if (it == var_refs_.end()) {
    return fail("variables: unknown variablesReference " +
                std::to_string(ref));
  }
  const auto& v = it->second;
  std::string method;
  std::string array_key;
  switch (v.kind) {
    case ScopeKind::kLocals:
      method = "frame.locals"; array_key = "locals"; break;
    case ScopeKind::kArgs:
      method = "frame.args"; array_key = "args"; break;
    case ScopeKind::kRegisters:
      method = "frame.registers"; array_key = "registers"; break;
  }
  json req = {
      {"target_id", target_id_},
      {"tid", v.tid},
      {"frame_index", v.frame_index},
  };
  auto resp = channel_.call(method, req);
  if (!resp.ok) return fail(resp.error_message);

  json vars = json::array();
  if (auto vs = resp.data.find(array_key);
      vs != resp.data.end() && vs->is_array()) {
    for (const auto& vv : *vs) {
      json out = {
          {"name", get_string(vv, "name", "<anon>")},
          {"value", get_string(vv, "value", "")},
          {"type", get_string(vv, "type", "")},
          {"variablesReference", 0},  // we don't expose child structure yet
      };
      vars.push_back(std::move(out));
    }
  }
  DapResult r;
  r.body = json{{"variables", vars}};
  return r;
}

DapResult Session::on_evaluate(const json& args) {
  std::string expr = get_string(args, "expression");
  if (expr.empty()) return fail("evaluate requires `expression`");
  int frame_id = static_cast<int>(get_int(args, "frameId"));
  std::int64_t tid = 0;
  std::uint32_t frame_index = 0;
  if (frame_id > 0) {
    auto it = frame_refs_.find(frame_id);
    if (it != frame_refs_.end()) {
      tid = it->second.tid;
      frame_index = it->second.frame_index;
    }
  }
  json req = {
      {"target_id", target_id_},
      {"tid", tid},
      {"frame_index", frame_index},
      {"expr", expr},
  };
  auto resp = channel_.call("value.eval", req);
  if (!resp.ok) return fail(resp.error_message);

  // value.eval result shape: {value: {...ValueInfo}} on success.
  std::string result_str;
  std::string type_str;
  if (auto vit = resp.data.find("value");
      vit != resp.data.end() && vit->is_object()) {
    result_str = get_string(*vit, "value");
    type_str   = get_string(*vit, "type");
  } else if (auto eit = resp.data.find("error");
             eit != resp.data.end() && eit->is_string()) {
    return fail(eit->get<std::string>());
  }

  DapResult r;
  r.body = json{
      {"result", result_str},
      {"type", type_str},
      {"variablesReference", 0},
  };
  return r;
}

json Session::poll_until_settled() {
  // Simple polling loop. After a continue/step, the daemon's
  // process.state goes "running" → eventually "stopped" or "exited".
  // We poll on a small interval; the event we emit corresponds to the
  // first non-running state we see. Capped at ~5 seconds in case the
  // peer is stuck — DAP clients tolerate this since they see a
  // running indicator until the next event arrives, but we don't want
  // to lock the shim forever.
  using namespace std::chrono_literals;
  const auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < 5s) {
    auto resp = channel_.call("process.state", {{"target_id", target_id_}});
    if (!resp.ok) return resp.data;
    std::string state = get_string(resp.data, "state");
    if (state != "running") return resp.data;
    std::this_thread::sleep_for(50ms);
  }
  // Timeout — return whatever the last call gave us indirectly via a
  // synthesized "running" object, so the caller still emits *something*.
  return json{{"state", "running"}};
}

DapResult Session::on_continue(const json&) {
  if (target_id_ == 0) return fail("continue called before launch/attach");
  auto resp = channel_.call("process.continue", {{"target_id", target_id_}});
  if (!resp.ok) return fail(resp.error_message);

  // Poll for the next stable state. Emit a `stopped` or `exited`
  // event on the way out, depending.
  json final_state = poll_until_settled();
  std::string state = get_string(final_state, "state", "running");

  DapResult r;
  r.body = json{{"allThreadsContinued", true}};
  if (state == "stopped") {
    // Resolve the stopped thread's ID via thread.list; use the first
    // thread whose state is "stopped". Falls back to 0 if thread.list
    // fails (e.g. target already closed) — clients tolerate that.
    std::int64_t stop_tid = 0;
    auto tl = channel_.call("thread.list", {{"target_id", target_id_}});
    if (tl.ok) {
      if (auto arr = tl.data.find("threads");
          arr != tl.data.end() && arr->is_array()) {
        for (const auto& t : *arr) {
          if (get_string(t, "state") == "stopped") {
            stop_tid = get_int(t, "tid");
            break;
          }
        }
      }
    }
    r.events.push_back(json{
        {"event", "stopped"},
        {"body", {{"reason", get_string(final_state, "stop_reason", "step")},
                  {"threadId", stop_tid},
                  {"allThreadsStopped", true}}},
    });
  } else if (state == "exited" || state == "crashed") {
    r.events.push_back(json{
        {"event", "exited"},
        {"body", {{"exitCode", get_int(final_state, "exit_code", 0)}}},
    });
  }
  return r;
}

DapResult Session::do_step(const json& args, const std::string& kind) {
  std::int64_t tid = get_int(args, "threadId");
  if (target_id_ == 0) return fail("step called before launch/attach");
  json req = {
      {"target_id", target_id_},
      {"tid", tid},
      {"kind", kind},
  };
  auto resp = channel_.call("process.step", req);
  if (!resp.ok) return fail(resp.error_message);

  DapResult r;
  r.body = json::object();
  // step is synchronous in the daemon (returns once stopped). Emit
  // the stopped event without polling.
  std::string state = get_string(resp.data, "state");
  if (state == "stopped" || state.empty()) {
    r.events.push_back(json{
        {"event", "stopped"},
        {"body", {{"reason", "step"}, {"threadId", tid},
                  {"allThreadsStopped", true}}},
    });
  } else if (state == "exited" || state == "crashed") {
    r.events.push_back(json{
        {"event", "exited"},
        {"body", {{"exitCode", get_int(resp.data, "exit_code", 0)}}},
    });
  }
  return r;
}

DapResult Session::on_next(const json& args)     { return do_step(args, "over"); }
DapResult Session::on_step_in(const json& args)  { return do_step(args, "in"); }
DapResult Session::on_step_out(const json& args) { return do_step(args, "out"); }

DapResult Session::dispatch(const std::string& command, const json& args) {
  if (command == "initialize")          return on_initialize(args);
  if (command == "launch")              return on_launch(args);
  if (command == "attach")              return on_attach(args);
  if (command == "configurationDone")   return on_configuration_done(args);
  if (command == "disconnect")          return on_disconnect(args);
  if (command == "setBreakpoints")      return on_set_breakpoints(args);
  if (command == "threads")             return on_threads(args);
  if (command == "stackTrace")          return on_stack_trace(args);
  if (command == "scopes")              return on_scopes(args);
  if (command == "variables")           return on_variables(args);
  if (command == "evaluate")            return on_evaluate(args);
  if (command == "continue")            return on_continue(args);
  if (command == "next")                return on_next(args);
  if (command == "stepIn")              return on_step_in(args);
  if (command == "stepOut")             return on_step_out(args);
  return fail("DAP command not supported by this shim: " + command);
}

}  // namespace ldb::dap
