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

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::probes
