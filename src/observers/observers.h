#pragma once

#include "transport/ssh.h"

#include <chrono>
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


// ---- net.tcpdump -------------------------------------------------------
//
// Bounded one-shot live capture (plan §4.6). Spawns
//   tcpdump -nn -tt -l -c <count> -i <iface> -s <snaplen> [bpf]
// either locally or via SSH using `transport::StreamingExec` (NOT
// `local_exec` / `ssh_exec` — those are blocking one-shots and would
// either buffer indefinitely or starve us of intermediate events).
// Each stdout line is parsed into a PacketEntry; we collect up to
// `count` packets, then `terminate()` the streaming subprocess.
//
// **Privilege:** tcpdump needs CAP_NET_RAW or root. When the binary
// reports "permission denied" / "Operation not permitted" we surface
// that as a clean `backend::Error` and the dispatcher maps it to
// -32000 with the underlying stderr text in the message.
//
// **Bounding:** per-call wall-clock cap defaults to 30 s. If tcpdump
// hasn't produced `count` packets by then, we stop, return what we
// have, and set `truncated = true`.
struct PacketEntry {
  double                          ts_epoch = 0.0;   // float seconds (epoch)
  std::optional<std::string>      iface;            // populated only when caller passes it
  std::optional<std::string>      src;
  std::optional<std::string>      dst;
  std::optional<std::string>      proto;            // "IP" | "IP6" | "ARP" | etc.
  std::optional<std::uint64_t>    len;              // parsed from "length N" suffix
  std::string                     summary;          // tcpdump line minus the leading ts
};

struct TcpdumpRequest {
  std::string                     iface;            // required, non-empty
  std::optional<std::string>      bpf;              // optional BPF expression
  std::uint32_t                   count    = 0;     // required, 1..10000
  std::optional<std::uint32_t>    snaplen;          // 1..65535; default 256
  std::optional<transport::SshHost> remote;         // nullopt → local
  std::chrono::milliseconds       timeout  = std::chrono::seconds(30);
};

struct TcpdumpResult {
  std::vector<PacketEntry>        packets;
  std::uint32_t                   total     = 0;
  bool                            truncated = false;
};

// Invokes tcpdump and returns when either count packets have been
// captured, the child exits, or the wall-clock timeout fires.
// Throws backend::Error on transport failure or tcpdump permission
// errors. The `iface` arg from the request is propagated into each
// PacketEntry's `iface` field.
TcpdumpResult tcpdump(const TcpdumpRequest& req);

// Pure parser: feeds `tcpdump -nn -tt -l` text into PacketEntry
// values. Exposed for unit tests that don't want a subprocess.
// Lines beginning with '#' are skipped (so committed fixtures may
// include leading comments documenting where the capture came from).
std::vector<PacketEntry> parse_tcpdump_lines(const std::string& text);

// Single-line variant. Returns nullopt when the line is empty,
// comment-only, or malformed in a way that prevents us from
// extracting at least the timestamp + a non-empty summary.
std::optional<PacketEntry> parse_tcpdump_line(const std::string& line);

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
