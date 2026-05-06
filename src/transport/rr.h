#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// rr (Mozilla record/replay debugger) transport primitive — Tier 4 §13
// of post-v0.1 progress.
//
// Roadmap framing: "Reverse execution via rr — LDB connects to rr as a
// remote target via RSP; replay is just another `target.connect_remote`
// URL." `rr replay` exposes a gdb-remote-protocol port; LLDB's
// gdb-remote client handles reverse-execution semantics over the wire.
// The daemon's job is just to spawn `rr replay` against a given trace
// directory, learn the listening port, and tunnel that into the
// existing `target.connect_remote` path.
//
// URL syntax: `rr://<absolute-trace-dir>[?port=<N>]`.
//   • The trace dir MUST be absolute (rr's own CLI accepts only paths
//     it can stat; relative paths are ambiguous and we refuse them up
//     front so the operator gets a sharp error).
//   • If `port` is omitted, the daemon picks a free TCP port (bind 0,
//     getsockname, close) and asks rr to listen there.
//
// Why a dedicated header (not inline in lldb_backend.cpp):
//   • Pure URL parsing has nothing to do with LLDB. It's testable as a
//     plain function, and we cover edge cases (relative path, malformed
//     query, non-numeric port) without spinning up a debugger.
//   • Binary discovery (`LDB_RR_BIN` env override, /usr/bin, /usr/local/
//     bin, PATH) is reused by both the live test and the runtime path.
//   • The long-lived `rr replay` subprocess wrapper is RAII so the
//     existing `attach_target_resource` machinery in LldbBackend can
//     bind it to the target's lifetime without leaking the child.

namespace ldb::transport {

// Parsed rr:// URL.
struct RrUrl {
  std::string                  trace_dir;   // absolute path
  std::optional<std::uint16_t> port;        // nullopt → pick free port
};

// Parse `rr://<absolute-trace-dir>[?port=N]`.
// Throws ldb::backend::Error on:
//   • missing `rr://` prefix,
//   • empty trace dir,
//   • relative trace dir,
//   • non-numeric / out-of-range port,
//   • unknown query keys.
RrUrl parse_rr_url(const std::string& url);

// Discover the rr binary in priority order:
//   1. $LDB_RR_BIN if set + executable.
//   2. /usr/bin/rr.
//   3. /usr/local/bin/rr.
//   4. `rr` on PATH (via `command -v rr`).
// Returns absolute path, or empty string if rr is not installed. The
// caller surfaces the install hint (we don't throw here so the unit
// test can distinguish "rr installed" from "discovery failed for a
// different reason").
std::string find_rr_binary();

// Bind a TCP socket on 127.0.0.1:0, read the kernel-assigned port,
// close. Same trick as ssh.cpp::pick_ephemeral_port; exposed here so
// the rr connect path can use it without depending on the SSH module.
// Throws ldb::backend::Error on socket / bind / getsockname failure.
std::uint16_t pick_ephemeral_port_local();

// Long-lived `rr replay` subprocess holding the gdb-remote port open.
// Lifetime: ctor spawns `rr replay --debugger-port=<port> -k <trace_dir>`
// then polls `connect(127.0.0.1:port)` until the gdb-remote listener
// accepts (bounded by setup_timeout). Dtor SIGTERMs, waits 250 ms,
// then SIGKILLs. Same teardown discipline as SshTunneledCommand.
//
// Invariants on success:
//   • alive() == true.
//   • A TCP `connect()` to 127.0.0.1:port succeeds (rr's gdb-remote
//     server is accepting connections).
//
// On failure (rr child died early, port never opened, setup_timeout
// elapsed): the dtor reaps the child and the ctor throws
// ldb::backend::Error with a diagnostic that captures stderr.
class RrReplayProcess {
 public:
  RrReplayProcess(std::string                rr_bin,
                  std::string                trace_dir,
                  std::uint16_t              port,
                  std::chrono::milliseconds  setup_timeout =
                      std::chrono::seconds(10));
  ~RrReplayProcess();

  RrReplayProcess(const RrReplayProcess&)            = delete;
  RrReplayProcess& operator=(const RrReplayProcess&) = delete;
  RrReplayProcess(RrReplayProcess&&)                 = delete;
  RrReplayProcess& operator=(RrReplayProcess&&)      = delete;

  std::uint16_t port()  const noexcept;
  bool          alive() const noexcept;

  // Captured stderr so far (cheap copy under lock). Useful for the
  // diagnostic message when the connect-through-tunnel never opens.
  std::string drain_stderr() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::transport
