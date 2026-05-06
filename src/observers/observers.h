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


// ---- net.igmp ----------------------------------------------------------
//
// /proc/net/igmp + /proc/net/igmp6 (the latter optional). We read
// these as static text — no subprocess needed locally — and merge V4
// and V6 results into a single `groups` array. For V4 each per-
// interface header line begins a group with one or more indented
// address rows; for V6 each line is a single membership and we surface
// it as its own group with one address.
//
// Address byte order: kernel prints the IPv4 group as a hex word in
// little-endian (`010000E0` ⇒ 224.0.0.1). The IPv6 address is 32 hex
// chars in network order, which we render as 8 colon-separated groups
// of 4 (no zero-compression — tooling that wants the canonical form
// can post-process).
struct IgmpAddress {
  std::string   address;        // dotted-quad (V4) or "ffff:...:0001" (V6)
  std::uint32_t users = 0;
  std::uint64_t timer = 0;
};

struct IgmpGroup {
  std::uint32_t                idx     = 0;
  std::string                  device;     // "lo", "eth0", ...
  std::optional<std::uint32_t> count;      // V4 only (header column)
  std::optional<std::string>   querier;    // V4 only ("V3" | "V2" | "V1")
  std::vector<IgmpAddress>     addresses;
};

struct IgmpEntry {
  std::vector<IgmpGroup> groups;
  std::uint64_t          total = 0;
};

// Local: ifstream from /proc/net/igmp and (if present) /proc/net/igmp6.
// Remote: `cat /proc/net/igmp` and `cat /proc/net/igmp6` over ssh_exec;
// igmp6 absence is tolerated. Throws backend::Error only on
// hard remote-transport failure for the V4 path.
IgmpEntry list_igmp(const std::optional<transport::SshHost>& remote);

// Pure parsers. Exposed so tests can exercise the parsing layer with
// canned input and zero filesystem / subprocess access.
IgmpEntry parse_proc_net_igmp(const std::string& v4_text);
IgmpEntry parse_proc_net_igmp6(const std::string& v6_text);

}  // namespace ldb::observers
