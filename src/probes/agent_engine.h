// SPDX-License-Identifier: Apache-2.0
#pragma once

// AgentEngine — daemon-side wrapper around the ldb-probe-agent
// subprocess (post-V1 plan #12 phase-2).
//
// Phase-1 (commits 8656fb2 + cf88607) landed the freestanding agent
// binary that speaks length-prefixed JSON over its stdio. This module
// is the daemon's other side of that wire.
//
// Phase-2 scope (this file): spawn the agent, perform a single
// `hello` round-trip, shut it down. That proves the wire works
// end-to-end through ldbd and unblocks the orchestrator wiring (a
// later commit) that will route `engine: "agent"` probe creates here.
//
// Lifetime / threading: a Session owns its subprocess pipes and is
// not thread-safe — the dispatcher is single-threaded today, and the
// AgentEngine is constructed-then-used-then-destroyed inside one
// handler. The destructor sends a `shutdown` frame, closes stdin,
// waits for the child (with a short SIGKILL deadline), and reaps.

#include "probe_agent/protocol.h"
#include "backend/debugger_backend.h"  // backend::Error

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ldb::probes {

class AgentEngine {
 public:
  // Locate ldb-probe-agent: $LDB_PROBE_AGENT first, then PATH lookup,
  // then sibling-to-current-ldbd. Returns "" if not found.
  static std::string discover_agent();

  // Spawn the agent. argv defaults to {agent_path} but callers can
  // append --version-style flags for diagnostics. Throws
  // backend::Error on spawn failure (executable missing, pipe()
  // failed, posix_spawn failed).
  explicit AgentEngine(std::string agent_path);
  ~AgentEngine();

  AgentEngine(const AgentEngine&)            = delete;
  AgentEngine& operator=(const AgentEngine&) = delete;

  // Synchronous hello round-trip. Writes a hello frame, reads one
  // frame back, parses as HelloOk. Throws backend::Error on:
  //   - frame I/O error,
  //   - response is an AgentError envelope,
  //   - response not a well-formed hello_ok shape.
  ldb::probe_agent::HelloOk hello();

  // ------------- Persistent-session API (post-V1 plan #12 phase-3) -------
  //
  // Each `attach_*` returns the agent-assigned attach_id; the caller
  // stores it on its ProbeState and passes it back to `poll_events` /
  // `detach`. The session stays alive across many calls; the agent is
  // shut down only when this AgentEngine is destroyed.
  //
  // All four throw backend::Error on:
  //   - frame I/O error,
  //   - the agent returning an AgentError envelope (whose `code` and
  //     `message` are included in the thrown text — agents reading the
  //     error string can grep for "not_supported" / "no_capability" /
  //     "no_btf" to branch),
  //   - shape mismatch on the response.

  std::string attach_uprobe(std::string_view program,
                            std::string_view path,
                            std::string_view symbol,
                            std::optional<std::int64_t> pid);
  std::string attach_kprobe(std::string_view program,
                            std::string_view function);
  std::string attach_tracepoint(std::string_view program,
                                std::string_view category,
                                std::string_view name);

  // Pull up to `max` events that have accumulated since the last
  // poll_events for this attach_id. Empty `events` is the steady-state
  // for an idle attach. The `dropped` counter is informational — the
  // agent's ring buffer over-runs are surfaced but not fatal.
  ldb::probe_agent::PollEvents poll_events(std::string_view attach_id,
                                            std::uint32_t max);

  // Idempotent: detaching an unknown id is treated as success by the
  // agent (the bookkeeping is gone already either way).
  void detach(std::string_view attach_id);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  // Common helper — write a request, read a frame, dispatch on type.
  // Used by all the attach/poll/detach methods; surfaces AgentError
  // via backend::Error.
  nlohmann::json round_trip(const nlohmann::json& request,
                            std::string_view op_name_for_error);
};

}  // namespace ldb::probes
