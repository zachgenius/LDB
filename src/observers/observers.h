#pragma once

#include "transport/ssh.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Typed observers (M4 part 3, plan §4.6 — replaces `run_host_command`).
//
// Each entry-point function:
//   • takes a hardcoded argv (no operator-supplied shell strings) plus
//     positional integer / filter args validated up-front;
//   • dispatches to `local_exec` (when `remote == nullopt`) or
//     `ssh_exec` (otherwise) using identical ExecOptions semantics;
//   • parses the captured stdout into a structured C++ value with
//     pure-text parsers in `proc.cpp` / `net_sockets.cpp`;
//   • throws `ldb::backend::Error` on transport failure, non-zero
//     subprocess exit, or unrecoverable parse failure.
//
// **Allowlist contract:** these endpoints are NOT free-form command
// runners. The §4.6 escape hatch (`observer.exec({cmd, allowlisted})`)
// is deferred — it needs an operator-configured allowlist design slice
// before it can ship safely.

namespace ldb::observers {

// ---- proc.fds ----------------------------------------------------------

// One entry per /proc/<pid>/fd/<fd> readlink target. `type` is a coarse
// classifier we infer from the link target prefix:
//   "socket"   — "socket:[N]"
//   "pipe"     — "pipe:[N]"
//   "anon"     — "anon_inode:..."
//   "file"     — anything starting with "/"
//   "other"    — fallback (e.g. "[eventfd]")
struct FdEntry {
  int          fd     = -1;
  std::string  target;
  std::string  type;
};

struct FdsResult {
  std::vector<FdEntry> fds;
  std::uint64_t        total = 0;
};

// Run `find /proc/<pid>/fd -mindepth 1 -maxdepth 1 -printf '%f %l\n'`.
// `pid` MUST be a positive integer (caller's job to validate; we
// double-check and throw on negative). Empty output → empty result with
// total=0. Throws on transport failure or non-zero exit code.
FdsResult fetch_proc_fds(const std::optional<transport::SshHost>& remote,
                         std::int32_t                              pid);

// Pure parser: feeds canned `find -printf` output. Exposed so
// tests can exercise the parsing layer with no subprocess at all.
FdsResult parse_proc_fds(const std::string& find_printf_output);


// ---- proc.maps ---------------------------------------------------------

struct MapsRegion {
  std::uint64_t              start  = 0;
  std::uint64_t              end    = 0;
  std::string                perm;       // e.g. "r-xp"
  std::uint64_t              offset = 0;
  std::string                dev;        // "MAJ:MIN" as text
  std::uint64_t              inode  = 0;
  std::optional<std::string> path;       // present iff path column non-empty
};

struct MapsResult {
  std::vector<MapsRegion> regions;
  std::uint64_t           total = 0;
};

MapsResult fetch_proc_maps(const std::optional<transport::SshHost>& remote,
                           std::int32_t                              pid);

MapsResult parse_proc_maps(const std::string& maps_text);


// ---- proc.status -------------------------------------------------------

// We surface only the most-useful subset of /proc/<pid>/status; all
// fields are optional (zombie processes don't expose VmRSS, etc.).
struct ProcStatus {
  std::string                name;
  std::optional<std::int32_t> pid;
  std::optional<std::int32_t> ppid;
  std::string                state;     // e.g. "S (sleeping)"
  std::optional<std::uint32_t> uid;     // real uid (first column)
  std::optional<std::uint32_t> gid;     // real gid (first column)
  std::optional<std::uint32_t> threads;
  std::optional<std::uint64_t> vm_rss_kb;
  std::optional<std::uint64_t> vm_size_kb;
  std::optional<std::uint64_t> vm_peak_kb;
  std::optional<std::uint64_t> fd_size;
  // Anything else the agent might want is deferred — the parser keeps
  // the raw key/value pairs available via raw_fields for the rare case.
  std::vector<std::pair<std::string, std::string>> raw_fields;
};

ProcStatus fetch_proc_status(const std::optional<transport::SshHost>& remote,
                             std::int32_t                              pid);

ProcStatus parse_proc_status(const std::string& status_text);


// ---- net.sockets -------------------------------------------------------

struct SocketEntry {
  std::string                proto;     // "tcp"|"udp"
  std::string                state;     // "LISTEN"|"ESTAB"|"UNCONN"|...
  std::string                local;     // "addr:port"
  std::string                peer;      // "addr:port" (or "*:*")
  std::optional<std::int32_t> pid;      // first user pid if reported
  std::optional<std::string>  comm;     // first user command name
  std::optional<std::int32_t> fd;       // first user fd
};

struct SocketsResult {
  std::vector<SocketEntry> sockets;
  std::uint64_t            total = 0;
};

// `filter` is a substring match applied to the rendered "proto local
// peer state" line. Empty filter → no filter. We do NOT pass it to ss
// (avoids accidental shell-meta interpretation); we filter post-parse.
SocketsResult fetch_net_sockets(const std::optional<transport::SshHost>& remote,
                                const std::string&                       filter);

SocketsResult parse_ss_tunap(const std::string& ss_output);

}  // namespace ldb::observers
