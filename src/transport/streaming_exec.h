#pragma once

#include "transport/ssh.h"  // SshHost — re-used for remote routing

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// Long-lived line-streaming subprocess primitive (M4 part 4 prep).
//
// `StreamingExec` is the third member of the transport family:
//
//   • `ssh_exec` / `local_exec`  — synchronous one-shot, full stdout
//     captured and returned when the child exits.
//   • `SshTunneledCommand`       — long-lived, holds a port forward,
//     no per-line stdout pump.
//   • `StreamingExec` (here)     — long-lived, async. Reader thread
//     pumps stdout LINE-BY-LINE into a caller-supplied callback so the
//     caller can fan events out as fast as the child produces them.
//
// Why a dedicated primitive (not "ssh_exec with a giant buffer"):
//   • bpftrace is a watch-and-stream tool. The whole point is real-time
//     event delivery. Buffering until child exit defeats the purpose
//     and explodes RAM under high event rates.
//   • Stdout is reserved for ldbd's JSON-RPC channel. The streaming
//     reader runs on a dedicated thread that NEVER touches stdout.
//   • Same RAII teardown discipline as `SshTunneledCommand` — dtor
//     SIGTERMs, waits 250ms, SIGKILLs. No leaked subprocesses.
//
// Concurrency contract:
//   • The reader thread is the ONLY caller of `on_line` and `on_done`.
//     They are called in order (line lines, then exactly one done).
//   • `on_done` is called exactly once over the lifetime of a
//     StreamingExec — either when the child exits naturally (EOF on
//     stdout + reaped), or when `terminate()` / dtor reaps it.
//   • The callbacks must NOT call back into the StreamingExec itself.
//     They CAN take their own external locks; the caller decides
//     mutex discipline (e.g. ProbeOrchestrator's per-probe mutex).
//   • The stdout line buffer is bounded at kMaxLineBytes (32 KiB). If
//     a line exceeds this, the truncated prefix is delivered to
//     `on_line` with a "...[truncated]" marker, and bytes up to the
//     next '\n' are dropped. We never buffer unbounded.

namespace ldb::transport {

class StreamingExec {
 public:
  static constexpr std::size_t kMaxLineBytes  = 32 * 1024;
  static constexpr std::size_t kStderrCapBytes = 64 * 1024;

  using LineCallback = std::function<void(std::string_view)>;
  using DoneCallback = std::function<void(int exit_code, bool timed_out)>;

  // Spawn `argv` either locally (when `remote == nullopt`) or via
  // `ssh user@host -- argv...`. The reader thread starts immediately
  // and pumps stdout into `on_line` line-by-line. Stderr is captured
  // to an internal bounded buffer for diagnostics (`drain_stderr`).
  //
  // Throws ldb::backend::Error on spawn-side failure (no executable
  // on PATH, posix_spawn failed, pipe creation failed). Once
  // construction returns, the subprocess is running and the reader
  // thread is alive.
  StreamingExec(std::optional<SshHost>          remote,
                std::vector<std::string>        argv,
                LineCallback                    on_line,
                DoneCallback                    on_done);

  ~StreamingExec();

  StreamingExec(const StreamingExec&)            = delete;
  StreamingExec& operator=(const StreamingExec&) = delete;
  StreamingExec(StreamingExec&&)                 = delete;
  StreamingExec& operator=(StreamingExec&&)      = delete;

  // True from construction until the child has exited (whether
  // naturally or via terminate()). Once `on_done` has fired, this
  // returns false.
  bool alive() const;

  // Snapshot of bytes captured to stderr so far. Cheap (string copy
  // under lock).
  std::string drain_stderr() const;

  // Send SIGTERM, wait 250 ms, then SIGKILL if still alive. Idempotent
  // — calling repeatedly is harmless. Returns when the reader thread
  // has joined and `on_done` has been invoked (or was about to be).
  // Safe to call from any thread that is NOT the reader thread.
  void terminate();

  // Public so the TU-local reader_loop / deliver_lines helpers in
  // streaming_exec.cpp can name the struct. Anonymous-namespace
  // helpers in the .cpp can't see private nested types of an outer
  // class; making Impl public is the standard pImpl workaround.
  struct Impl;

 private:
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::transport
