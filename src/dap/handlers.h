#pragma once

#include "dap/rpc_channel.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

// DAP request → LDB JSON-RPC translation.
//
// `Session` holds the per-DAP-connection state the handlers need to
// translate stateless DAP requests into the daemon's stateful API:
//   * `target_id` from the most recent `launch`/`attach`.
//   * variablesReference table that maps DAP refs back to
//     (tid, frame_index, kind={locals|args|registers}) tuples.
//   * frameId table (frameId → (tid, frame_index)) so `evaluate` knows
//     which frame to evaluate against.
//   * the next server-side `seq` counter for events emitted to the IDE.
//   * a sequence counter for stopped/continued event correlation.
//
// Each handler is a pure function that takes the DAP request body and
// returns the DAP response body. They never write to stdout themselves
// — the caller (the main loop) is responsible for framing and emitting
// the response. This keeps the handlers unit-testable without a real
// stream.
//
// Events that the handler wants emitted (e.g. `stopped` after a
// `continue`) are returned via the `events` out-vector on the result;
// the main loop drains them after writing the response.

namespace ldb::dap {

using json = nlohmann::json;

struct DapResult {
  // The response body to send (typed as DAP "Response" — the caller
  // wraps it with seq/type/request_seq/command/success).
  json body = json::object();
  // True if the request succeeded; mapped to DAP "success" field.
  bool success = true;
  // Human-readable error message; populated only when success=false.
  std::string message;
  // Events to emit AFTER sending the response. Each entry is a fully-
  // formed DAP event body (`{event: "stopped", body: {...}}` style).
  std::vector<json> events;
  // Set to true when the shim should exit after sending this response.
  // Currently used by `disconnect`.
  bool terminate = false;
};

class Session {
 public:
  explicit Session(RpcChannel& channel) : channel_(channel) {}

  // Each shipped DAP request gets one of these. The handler reads from
  // the DAP request body and may mutate session state (target_id,
  // variablesReference table, etc.).
  DapResult on_initialize(const json& args);
  DapResult on_launch(const json& args);
  DapResult on_attach(const json& args);
  DapResult on_configuration_done(const json& args);
  DapResult on_disconnect(const json& args);
  DapResult on_set_breakpoints(const json& args);
  DapResult on_threads(const json& args);
  DapResult on_stack_trace(const json& args);
  DapResult on_scopes(const json& args);
  DapResult on_variables(const json& args);
  DapResult on_evaluate(const json& args);
  DapResult on_continue(const json& args);
  DapResult on_next(const json& args);
  DapResult on_step_in(const json& args);
  DapResult on_step_out(const json& args);

  // Generic dispatch — the main loop calls this with the DAP "command"
  // string and arguments. Returns a DapResult; if the command isn't
  // implemented, success=false with a typed message (DAP error
  // -32601-equivalent).
  DapResult dispatch(const std::string& command, const json& args);

  // Test/observation hooks.
  std::int64_t target_id() const { return target_id_; }

 private:
  enum class ScopeKind { kLocals, kArgs, kRegisters };

  // Allocate a variablesReference for (tid, frame_index, kind). Returns
  // a stable integer >= 1; 0 is reserved by DAP for "no expansion".
  int allocate_var_ref(std::int64_t tid, std::uint32_t frame_index,
                       ScopeKind kind);
  // Allocate a frameId for (tid, frame_index). Stable across one
  // session; the IDE pairs it with a future `scopes`/`evaluate`.
  int allocate_frame_id(std::int64_t tid, std::uint32_t frame_index);

  // Helper for step-family handlers.
  DapResult do_step(const json& args, const std::string& kind);

  // Polls process.state until stopped/exited or the budget expires.
  // Returns the final daemon `data` object. Stretches out indefinitely
  // for now (DAP clients tolerate this; they show a "running" indicator
  // until a `stopped` event arrives).
  json poll_until_settled();

  RpcChannel& channel_;
  std::int64_t target_id_ = 0;
  bool process_running_ = false;

  struct VarRef {
    std::int64_t tid;
    std::uint32_t frame_index;
    ScopeKind kind;
  };
  std::unordered_map<int, VarRef> var_refs_;
  int next_var_ref_ = 1;

  struct FrameRef {
    std::int64_t tid;
    std::uint32_t frame_index;
  };
  std::unordered_map<int, FrameRef> frame_refs_;
  int next_frame_id_ = 1;
};

}  // namespace ldb::dap
