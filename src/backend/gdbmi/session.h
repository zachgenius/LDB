// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "backend/gdbmi/parser.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

// GdbMiSession — owns one `gdb --interpreter=mi3` subprocess plus a
// reader thread that drains its stdout into structured MiRecord
// queues.
//
// Threading model:
//   * Caller thread issues send_command(...) which writes the
//     request (with a unique numeric token) to gdb's stdin and waits
//     on a condition variable for the matching ^token^result record.
//   * Reader thread loops on gdb's stdout, parses each line, and
//     either:
//       - matches the token of a result record to a pending request,
//         hands off the record, and notifies the waiter; or
//       - pushes async / stream records onto the async_queue_ for
//         the caller to drain via drain_async() between commands.
//
// Concurrency rules:
//   * One outstanding send_command at a time (no command pipelining).
//     The session does NOT enforce mutual exclusion across threads;
//     the dispatcher's single-threaded loop is the natural caller.
//   * shutdown() is safe to call multiple times and from any thread.
//
// Subprocess lifecycle:
//   * start() forks/execs `gdb --interpreter=mi3 --quiet --silent
//     --nx`, drains the initial prompt, returns true on success.
//   * shutdown() sends `-gdb-exit`, waits up to 500ms for clean
//     termination, then SIGTERM, then SIGKILL after another 500ms.

namespace ldb::backend::gdbmi {

class GdbMiSession {
 public:
  GdbMiSession();
  ~GdbMiSession();

  GdbMiSession(const GdbMiSession&) = delete;
  GdbMiSession& operator=(const GdbMiSession&) = delete;

  // Spawn gdb. Returns false on fork/exec failure or if gdb's
  // initial banner / prompt doesn't arrive within the timeout.
  bool start();

  // Idempotent. After shutdown returns the subprocess is reaped
  // and the reader thread joined.
  void shutdown();

  bool is_running() const;

  // Send an MI command (e.g. `-break-insert main`) and block until
  // the matching ^token^result record arrives. The leading '-' is
  // optional; the session tokens internally. Returns nullopt if the
  // session is shutting down or the subprocess died.
  std::optional<MiRecord> send_command(const std::string& cmd);

  // Move every accumulated async / stream record (since the last
  // drain) out of the queue and return them. The session never
  // discards async records on its own — the caller decides what to
  // do with them.
  std::vector<MiRecord> drain_async();

 private:
  struct PendingRequest {
    std::uint64_t            token = 0;
    std::optional<MiRecord>  response;        // filled by reader thread
    bool                     ready = false;
  };

  void reader_loop();
  void deliver_result(MiRecord r);

  pid_t                       pid_ = -1;
  int                         stdin_fd_  = -1;
  int                         stdout_fd_ = -1;
  int                         stderr_fd_ = -1;

  std::thread                 reader_;
  std::atomic<bool>           shutting_down_{false};
  std::atomic<bool>           reader_eof_{false};

  // Token allocation is single-threaded from the dispatcher.
  std::uint64_t               next_token_ = 1;

  // The reader thread parks responses here keyed by token; the
  // caller's wait blocks on cv_ until its slot's ready flag flips.
  mutable std::mutex          mu_;
  std::condition_variable     cv_;
  std::deque<PendingRequest>  pending_;          // FIFO; usually 1 entry
  std::vector<MiRecord>       async_queue_;
  // Set after the first (gdb) prompt is observed; until then, every
  // record (including the startup banner notify records) goes into
  // async_queue_ and start() returns.
  bool                        ready_ = false;
};

}  // namespace ldb::backend::gdbmi
