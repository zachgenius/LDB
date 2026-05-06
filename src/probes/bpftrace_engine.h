#pragma once

#include "probes/probe_orchestrator.h"  // ProbeEvent
#include "transport/streaming_exec.h"
#include "transport/ssh.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// bpftrace-shellout BPF probe engine (M4 part 4, plan §7.2).
//
// Design summary
// --------------
// A `uprobe_bpf` probe spawns a long-lived bpftrace process either on
// the daemon's own host (when `host` is absent) or on a remote box via
// the SSH transport. bpftrace is fed a generated program — one printf
// line per attachment site, JSON-shaped — and its stdout is streamed
// back through `transport::StreamingExec`. Each line is parsed into a
// `probes::ProbeEvent` and pushed into the same per-probe ring buffer
// the M3 lldb_breakpoint engine writes to.
//
// Lifecycle
// ---------
//   • `start()` on the engine spawns bpftrace and waits up to
//     `setup_timeout` for either:
//       1. the first JSON line (success), or
//       2. the first non-JSON "Attaching N probes..." line followed by
//          a short window of stdout silence (success — bpftrace runs
//          the program forever after attach), or
//       3. process exit (failure — stderr captured for diagnostics), or
//       4. setup_timeout elapsed (failure).
//   • `stop()` calls `terminate()` on the StreamingExec; the reader
//     thread joins and `on_done` fires.
//   • `dtor()` calls `stop()`.
//
// Why not just `start()` and call it good?  bpftrace's exit code is
// 0 only on a clean termination (SIGTERM with no attach error). A
// program with a typo'd uprobe path exits with rc=1 and prints to
// stderr. We need to reflect that as a probe.create failure rather
// than "create succeeded; events never come."
//
// Event mapping
// -------------
//   bpftrace prints, for each hit:
//     {"ts_ns": 1700..., "tid": N, "pid": N, "args": ["0x..", ...]}
//   We map "args" to ProbeEvent::registers as {arg0:..., arg1:...}.
//   `pc`, `site`, and `memory` are zero/empty — this engine doesn't
//   read inferior memory.
//
// Error handling
// --------------
//   • bpftrace not on PATH and not at /usr/{,local/}bin/bpftrace and
//     LDB_BPFTRACE not set → `discover_bpftrace()` returns "" and
//     `start()` throws backend::Error with a clear "install bpftrace"
//     message.
//   • bpftrace runs but exits non-zero during setup → start() throws
//     with the captured stderr. The caller (dispatcher) maps this to
//     -32000 "bpftrace: <stderr>".
//   • bpftrace runs but a hit line is malformed → log to stderr and
//     skip the line. We do NOT crash and do NOT abort the engine.

namespace ldb::probes {

struct UprobeBpfSpec {
  enum class Kind : std::uint8_t {
    kUprobe,        // path:symbol
    kTracepoint,    // category:name
    kKprobe,        // function name
  };

  Kind                          where_kind = Kind::kUprobe;
  std::string                   where_target;          // see Kind
  std::vector<std::string>      captured_args;          // "arg0","arg1",...
  std::optional<std::int64_t>   filter_pid;
  std::string                   rate_limit_text;        // parsed but UNENFORCED
  std::optional<transport::SshHost> remote;             // nullopt → local
};

// Generate the bpftrace program text for a UprobeBpfSpec. Pure string
// transformation; throws std::invalid_argument for unsupported forms
// (e.g. captured_args entries that aren't bpftrace builtins).
std::string generate_bpftrace_program(const UprobeBpfSpec& s);

// bpftrace stdout-line parser. Each line is a JSON object emitted by
// our generated program; this returns nullopt for non-JSON status
// lines bpftrace prints to stdout in some configurations (Attaching ...,
// Lost N events, etc).
struct BpftraceParse {
  static std::optional<ProbeEvent> parse_line(std::string_view line);
};

// Locate the bpftrace binary, honoring the priority list:
//   1. $LDB_BPFTRACE env var (absolute path)
//   2. /usr/bin/bpftrace, /usr/local/bin/bpftrace
//   3. bpftrace via PATH lookup (popen "command -v bpftrace")
// Returns the absolute path, or "" if not found.
std::string discover_bpftrace();

class BpftraceEngine {
 public:
  using EventCallback = std::function<void(const ProbeEvent&)>;
  using ExitCallback  = std::function<void(int exit_code, bool timed_out,
                                           std::string stderr_text)>;

  BpftraceEngine(UprobeBpfSpec spec,
                 EventCallback on_event,
                 ExitCallback  on_exit);
  ~BpftraceEngine();

  BpftraceEngine(const BpftraceEngine&)            = delete;
  BpftraceEngine& operator=(const BpftraceEngine&) = delete;

  // Spawn bpftrace and block until startup is determined (success or
  // failure). Throws backend::Error with a useful message if bpftrace
  // is missing or fails to attach.
  void start(std::chrono::milliseconds setup_timeout =
                 std::chrono::seconds(3));

  // Stop the engine. Idempotent. Sends SIGTERM then SIGKILL on grace
  // expiry. Returns when the reader thread has joined.
  void stop();

  // True between successful start() and stop().
  bool running() const;

  // Buffered stderr from bpftrace (chatty; useful for diagnostics).
  std::string drain_stderr() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::probes
