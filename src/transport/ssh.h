// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// SSH transport primitive (M4 part 1, plan §9 "Remote target story").
//
// Architecturally:
//
//   ldbd (laptop) ──ssh──► target host:
//                          ├─ lldb-server platform (RSP-extended)
//                          ├─ ldb-probe-agent (uprobe events, optional)
//                          └─ shell-exec for typed observers (allowlisted)
//
// This module is the *internal* C++ surface that next-milestone code
// (M4-2 `target.connect_remote_ssh`, M4-3 typed observers) builds on.
// **It is deliberately NOT exposed as a JSON-RPC endpoint.** `ssh_exec`
// is unbounded code execution; §4.6 puts only narrow allow-listed
// observer endpoints on the wire.
//
// Design choices:
//
//   • posix_spawnp is preferred over fork()+execvp(). The dispatcher is
//     single-threaded today, but probe callbacks already fire on LLDB's
//     thread, so any future call site might be MT. fork() between
//     "fork returned" and "exec called" is async-signal-safe-only;
//     posix_spawnp avoids that whole footgun.
//
//   • Stdout is reserved for ldbd's JSON-RPC channel. The SSH child must
//     never inherit it. We always pipe.
//
//   • Default ssh args: `-o BatchMode=yes -o StrictHostKeyChecking=
//     accept-new -o ConnectTimeout=10 -T`. BatchMode is mandatory —
//     otherwise ssh prompts for passwords/passphrases and hangs.
//     StrictHostKeyChecking=accept-new auto-trusts first-seen hosts but
//     refuses on key change. The caller's `ssh_options` are appended,
//     so they win on duplicate `-o` keys (ssh's "first wins" precedence
//     means we put caller options BEFORE our defaults — see ssh.cpp).
//
//   • Errors: `ssh_exec` throws `ldb::backend::Error` only on
//     spawn-side failure (no `ssh` binary on PATH, posix_spawn failed,
//     pipe creation failed). Remote-side failures (auth refused, host
//     unreachable, command exited non-zero) are reflected in
//     `ExecResult::exit_code` / `stderr_data` / `timed_out`.
//
//   • SIGPIPE: installed once at first call to `SIG_IGN` via
//     std::call_once. ldbd already runs as a daemon; this is a no-op for
//     well-behaved hosts and makes broken pipes fail with EPIPE on
//     write rather than killing the process.
//
//   • Port forward: `SshPortForward` runs `ssh -N -L LOCAL:127.0.0.1:
//     REMOTE -o ExitOnForwardFailure=yes ...`. For `local_port=0` the
//     constructor pre-binds a TCP socket on port 0, reads the
//     kernel-assigned port via getsockname, closes it, and passes that
//     port to ssh. **There is a tiny race here**: another process on
//     the same host could grab the port between our close() and ssh's
//     bind(). In practice ephemeral ports are huge and the race is
//     vanishingly unlikely; for a deterministic guarantee, callers can
//     pick a port themselves. If ssh fails to bind, ExitOnForwardFailure
//     causes it to exit immediately, which `alive()` detects.

namespace ldb::transport {

struct SshHost {
  std::string                 host;            // "user@hostname" or "hostname"
  std::optional<int>          port;
  std::vector<std::string>    ssh_options;     // pass-through "-o" args
};

struct ExecOptions {
  std::chrono::milliseconds   timeout       = std::chrono::seconds(30);
  std::string                 stdin_data;
  std::uint64_t               stdout_cap    = 4ULL * 1024 * 1024;
  std::uint64_t               stderr_cap    = 1ULL * 1024 * 1024;
  bool                        merge_stderr  = false;
};

struct ExecResult {
  std::string                 stdout_data;
  std::string                 stderr_data;
  int                         exit_code         = 0;
  bool                        timed_out         = false;
  bool                        stdout_truncated  = false;
  bool                        stderr_truncated  = false;
  std::chrono::milliseconds   duration{0};
};

// Spawn `ssh` and run `argv` on the remote. The local ssh client wraps
// argv into a single shell-quoted command (we DO quote — ssh otherwise
// concatenates argv with spaces and re-parses on the remote with /bin/sh
// glob expansion, which is a footgun for any path with spaces).
//
// Throws ldb::backend::Error on spawn-side failures only.
ExecResult ssh_exec(const SshHost&                       host,
                    const std::vector<std::string>&      argv,
                    const ExecOptions&                   opts = {});

// Cheap reachability check. Internally runs `ssh ... -o ConnectTimeout=N
// /bin/true` with the given total deadline. `ok` reflects exit_code==0;
// `detail` is non-empty on failure (stderr from ssh, or our own deadline
// note). Cheaper than a full ssh_exec because we cap stdout/stderr
// hard.
struct ReachabilityResult {
  bool          ok = false;
  std::string   detail;
};
ReachabilityResult ssh_probe(const SshHost&                  host,
                             std::chrono::milliseconds       timeout =
                                 std::chrono::seconds(3));

// RAII -L tunnel. Spawns `ssh -N -L LOCAL:127.0.0.1:REMOTE -o
// ExitOnForwardFailure=yes ...`. Polls a TCP connect() on the assigned
// local port until success or `setup_timeout` expires. Throws
// ldb::backend::Error if the forward never came up (spawn failed, ssh
// exited early, or setup_timeout reached).
//
// Setup-probe footgun: the readiness check above opens (and immediately
// closes) one TCP connection through the tunnel, which means the remote
// server sees one extra connection before the "real" caller's connect.
// Servers that handle each connection independently (lldb-server,
// http, …) don't notice. A "one-shot" server that closes after the
// first connection WILL be hit by the probe. Callers who need to test
// against a one-shot server should either drop the probe (use a
// timed sleep + alive() poll) or accept multiple connections.
class SshPortForward {
 public:
  SshPortForward(const SshHost&                  host,
                 std::uint16_t                   local_port,
                 std::uint16_t                   remote_port,
                 std::chrono::milliseconds       setup_timeout =
                     std::chrono::seconds(5));
  ~SshPortForward();

  SshPortForward(const SshPortForward&)            = delete;
  SshPortForward& operator=(const SshPortForward&) = delete;
  SshPortForward(SshPortForward&&)                 = delete;
  SshPortForward& operator=(SshPortForward&&)      = delete;

  std::uint16_t local_port() const noexcept;

  // Cheap liveness check: did the ssh child exit yet?
  bool alive() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Ask the remote host for a free TCP port. Tries `python3 -c '...'`
// first (universally available on Linux distros and macOS); falls back
// to a `ss`-based AWK scan if python3 is missing. Throws backend::Error
// if both probes fail (e.g. neither tool present, or ssh itself fails).
//
// **Caveat — TOCTOU race:** the port we hand back is "free as of a few
// hundred ms ago." Another process on the remote can grab the port
// before our caller binds it. For MVP this is acceptable; both ssh -L
// and lldb-server will fail loudly on EADDRINUSE and the caller can
// retry.
std::uint16_t pick_remote_free_port(
    const SshHost&            host,
    std::chrono::milliseconds timeout = std::chrono::seconds(10));

// Single ssh subprocess that simultaneously holds a `-L LOCAL:127.0.0.1:
// REMOTE` port forward AND runs `argv` on the remote in the foreground.
//
// Why one subprocess (not two): `lldb-server gdbserver --listen
// 127.0.0.1:RPORT -- inferior` is the remote command, and the same
// ssh client tunnels its listening port back to us. When we tear down
// this object, ssh exits, the remote shell hangs up, and lldb-server
// dies via SIGHUP — single PID to manage.
//
// Construction:
//   1. local_port=0  → kernel-assigned (same trick as SshPortForward).
//   2. spawn `ssh -L ... -- <quoted argv>`.
//   3. wait until either:
//        a. our setup probe — TCP connect to 127.0.0.1:local_port —
//           succeeds (forward is open AND remote is listening), or
//        b. the ssh child exits early (throw), or
//        c. setup_timeout elapses (throw).
//
// **Setup-probe semantics differ from SshPortForward:** here the probe
// loops with retries, because the remote command (e.g. lldb-server)
// takes 50–200 ms to bind its port AFTER ssh's tunnel handshake
// completes. SshPortForward's single-shot probe assumes the remote is
// already listening; this one waits for the remote to come up.
//
// **Probe kind matters for single-accept servers.** Each probe retry
// DOES open a real TCP connection through the tunnel. Multi-accept
// servers (HTTP, lldb-server platform) tolerate that fine; single-
// accept servers (`lldb-server gdbserver`, which exits after its first
// connection closes) will be DRAINED by the probe. For those, pass
// `ProbeKind::kAliveOnly`: we only verify ssh is alive after spawn,
// no destructive TCP probe. The caller then retries its real protocol
// connect with backoff.
enum class ProbeKind : std::uint8_t {
  kTunneledConnect,  // poll TCP connect through the tunnel until success
  kAliveOnly,        // just verify ssh stays alive past the spawn
};

class SshTunneledCommand {
 public:
  SshTunneledCommand(const SshHost&                  host,
                     std::uint16_t                   local_port,
                     std::uint16_t                   remote_port,
                     const std::vector<std::string>& remote_argv,
                     std::chrono::milliseconds       setup_timeout =
                         std::chrono::seconds(10),
                     ProbeKind                       probe_kind =
                         ProbeKind::kTunneledConnect);
  ~SshTunneledCommand();

  SshTunneledCommand(const SshTunneledCommand&)            = delete;
  SshTunneledCommand& operator=(const SshTunneledCommand&) = delete;
  SshTunneledCommand(SshTunneledCommand&&)                 = delete;
  SshTunneledCommand& operator=(SshTunneledCommand&&)      = delete;

  std::uint16_t local_port()  const noexcept;
  std::uint16_t remote_port() const noexcept;
  bool          alive()       const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::transport
