// SPDX-License-Identifier: Apache-2.0
#pragma once

// Typed builders + parsers for the GDB RSP packet vocabulary the v1.6
// client speaks (docs/25-own-rsp-client.md §2.2). This layer is
// stateless and exception-free; channel.{h,cpp} composes framing
// (lower) + packets (this) + I/O (higher).
//
// Builders emit the payload bytes that go between $ and # —
// framing::encode_packet wraps + checksums. Keeping the split clean
// means a future RLE/binary-protocol experiment touches only one
// layer.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ldb::transport::rsp {

// ----------- Request builders (client → server) ------------------

// qSupported feature negotiation. `features` is the client's
// declared feature set, joined with ';'. Empty list → bare
// "qSupported".
std::string build_qSupported(const std::vector<std::string>& features);

// `?` — "what is the inferior doing right now?" Initial-stop query
// after connect; the server replies with a stop-reply packet.
std::string build_stop_query();

// `g` — read every register on the currently-selected thread.
std::string build_register_read_all();

// `G hexbytes` — write every register on the currently-selected
// thread. `bytes` is the raw register block; we hex-encode here.
std::string build_register_write_all(std::string_view bytes);

// `p NN` — read a single register (NN is the architecture-defined
// register number, hex).
std::string build_register_read_one(std::uint32_t reg_num);

// `P NN=VV...` — write a single register. `bytes` is the raw value;
// we hex-encode here.
std::string build_register_write_one(std::uint32_t reg_num,
                                      std::string_view bytes);

// `m AAA,LL` — read `length` bytes from `address`.
std::string build_memory_read(std::uint64_t address, std::uint32_t length);

// `M AAA,LL:DD...` — write bytes. Phase-1 builds it for framing
// coverage; the dispatcher doesn't expose a write_memory endpoint
// over RSP yet.
std::string build_memory_write(std::uint64_t address,
                                std::string_view bytes);

// `c [addr]` — continue at current PC (legacy). The newer `vCont;c`
// is preferred; this exists for servers that don't advertise vCont
// support in qSupported.
std::string build_continue_legacy(std::optional<std::uint64_t> resume_at = std::nullopt);

// `s [addr]` — single-step (legacy).
std::string build_step_legacy(std::optional<std::uint64_t> resume_at = std::nullopt);

// vCont action descriptors. Each carries an action character + an
// optional signal byte + an optional thread-id scope. `tid == 0`
// means "all threads"; per-thread non-stop uses tid != 0.
struct VContAction {
  char         action = 'c';  // 'c' continue, 's' step, 't' stop, 'C'/'S' with signal
  std::uint8_t signal = 0;    // when action is 'C' or 'S'
  std::int64_t tid    = 0;    // 0 = all threads (the gdb-remote default)
};

// `vCont;action:tid[;action:tid...]` — non-stop / per-thread
// resumption. The phase-1 non-stop runtime (#21) drives this.
std::string build_vCont(const std::vector<VContAction>& actions);

// `qfThreadInfo` — start a thread enumeration. Server responds with
// `m<tid>[,<tid>...]`; client then issues `qsThreadInfo` repeatedly
// until the server replies `l` (end).
std::string build_qfThreadInfo();
std::string build_qsThreadInfo();

// `Hg tid` / `Hc tid` — select the thread future `g`/`m`/`c` packets
// apply to. tid=0 ≡ "any thread" per the gdb wire convention; tid=-1
// ≡ "all threads."
std::string build_thread_select_general(std::int64_t tid);
std::string build_thread_select_continue(std::int64_t tid);

// `qXfer:features:read:target.xml:<offset>,<length>` — pull the
// target description (register layout, architecture). The client
// concatenates returned chunks; the server signals end-of-data with
// 'l' as the chunk-status byte.
std::string build_qXfer_features_read(std::string_view annex,
                                       std::uint32_t offset,
                                       std::uint32_t length);

// Reverse-execution (rr's gdbserver implements these).
//   bc — reverse-continue (run backwards until the next event)
//   bs — reverse-step (one instruction backwards)
std::string build_reverse_continue();
std::string build_reverse_step();

// `QStartNoAckMode` — negotiate that subsequent packets won't carry
// ack bytes. Issued only when qSupported advertised the feature.
std::string build_QStartNoAckMode();

// ----------- Tracepoint vocabulary (v1.6 #26 phase-2) -------------
//
// gdb-remote's in-target tracepoint family. The high-level dance:
//
//   QTinit                  — wipe all tracepoints from the server
//   QTDP:T<id>:<addr>:...   — define a tracepoint (one packet per
//                              tracepoint; condition / action come in
//                              follow-up `QTDP:-T...` packets)
//   QTStart                 — begin collection
//   QTStop                  — halt collection (buffer is preserved)
//   qTStatus                — query collection state
//   qTBuffer:<off>,<len>    — drain the trace buffer
//
// See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Tracepoint-Packets.html
// and docs/34-tracepoints-in-target.md for the orchestrator wiring.
//
// Phase-2 ships builders + struct vocabulary only. The dispatcher
// integration (emit-QTDP-on-tracepoint.create against an RspChannel
// target) is phase-2.5.

// `QTinit` — reset all tracepoints. Always the first packet of a
// new tracepoint session; the server replies OK or "" (unsupported).
std::string build_QTinit();

// `QTDP:T<id>:<addr>:{E|D}:<step>:<pass>` — primary define. We pin
// step=0 (no single-step collection) for phase-2; the predicate gates
// on a normal hit. pass_count==0 means "no pass limit" — the inferior
// keeps firing every hit. `enabled` toggles between 'E' (enabled) and
// 'D' (disabled) in the third field. Tracepoint id is hex (1-based
// per the spec).
std::string build_QTDP_define(std::uint32_t tracepoint_id,
                               std::uint64_t addr,
                               bool          enabled,
                               std::uint32_t pass_count);

// `QTDP:-<id>:<addr>:X<len>,<bytes>` — set the condition (predicate)
// agent-expression bytecode for an already-defined tracepoint. Per the
// spec (gdb remote.c, remote_add_target_side_condition) this is a
// *follow-up* QTDP. The leading `T` is on the PRIMARY define packet
// only; the continuation uses `QTDP:-<id>:...` with no `T`.
// `len` is the byte count in hex; `bytes` is the bytecode hex-encoded.
// Throws `backend::Error` if `bytecode` is empty — the gdb spec does
// not define a zero-length agent expression and servers may NAK it.
std::string build_QTDP_condition(std::uint32_t tracepoint_id,
                                  std::uint64_t addr,
                                  std::string_view bytecode);

// `QTStart` / `QTStop` — collection control. The server replies OK on
// success or "" if it doesn't support tracepoints.
std::string build_QTStart();
std::string build_QTStop();

// `qTStatus` — query whether collection is active. Reply shape:
//   T0;...   collection inactive
//   T1;...   collection active
//   ...kv pairs after the leading T flag carry buffer / frame stats.
std::string build_qTStatus();

// `qTBuffer:<offset>,<length>` — read raw trace-buffer bytes. The
// reply is hex-encoded (decode via decode_hex_bytes).
std::string build_qTBuffer(std::uint64_t offset, std::uint32_t length);

// `QTFrame:<n>` — select a trace frame for inspection (subsequent
// register / memory reads target the selected frame's snapshot).
// Special values: `QTFrame:-1` deselects.
std::string build_QTFrame(std::int64_t frame);

// Compact in-memory description of a tracepoint as it appears on the
// wire. The dispatcher's RSP-backed-target integration (phase-2.5)
// composes this from the orchestrator's ProbeSpec when an RspChannel
// is bound to the target. Keeping it separate from probes::ProbeSpec
// means the transport layer doesn't have to depend on probes/.
struct TracepointWire {
  std::uint32_t          tracepoint_id = 0;  // 1-based per spec
  std::uint64_t          addr          = 0;
  bool                   enabled       = true;
  // 0 ≡ unlimited. We don't expose pass_count to the user surface in
  // phase-2 — the orchestrator's rate-limit already covers that case
  // daemon-side; pass_count here is wire-only.
  std::uint32_t          pass_count    = 0;
  // Agent-expression bytecode, raw bytes (NOT base64). Empty means
  // "no predicate; fire on every hit."
  std::string            predicate_bytecode;
};

// Parsed qTStatus reply. The wire is `T<flag>[;k:v]*` where flag is
// '0' (inactive) or '1' (active); extra kv pairs carry buffer stats
// ('tnotrun', 'tstop', 'tframes', 'tcreated', 'tsize', 'tfree', etc.).
// We expose the parsed flag + the kv-pair map; callers that need a
// specific stat look it up by key.
struct TStatus {
  bool running = false;
  std::vector<std::pair<std::string, std::string>> kv;
};
std::optional<TStatus> parse_tstatus_reply(std::string_view payload);

// ----------- Response parsers (server → client) ------------------

// Top-level classification of a payload. Most callers can branch on
// the kind and then call a typed parser if they need the inner data.
enum class ResponseKind {
  kUnsupported,   // empty payload ""
  kOk,            // payload "OK"
  kError,         // payload "E NN" (NN = two-hex error code)
  kStopReply,     // payload starting with 'T', 'S', 'W', 'X'
  kHex,           // payload that's pure hex (register / memory read)
  kQReply,        // qSupported / qfThreadInfo / qXfer chunks: caller knows the request
  kOther,
};

ResponseKind classify_response(std::string_view payload);

// Parse "E NN" → 8-bit code. Returns nullopt when the payload isn't
// an error-shape response.
std::optional<std::uint8_t> parse_error_code(std::string_view payload);

// Stop reply summary. The full gdb shape is rich (per-register
// updates, watchpoint reasons, fork events); phase-1 extracts the
// pieces the dispatcher needs today.
struct StopReply {
  // Reply type: 'T' = thread-stopped with kv-pairs, 'S' = thread-
  // stopped with just a signal, 'W' = exited (signal byte holds
  // exit status), 'X' = terminated by signal.
  char         type = '?';
  std::uint8_t signal = 0;
  // For 'T' replies, the gdb spec lists key-value pairs (e.g.
  // `thread:1234;reason:trace;`). We expose the parsed map; common
  // keys: "thread", "core", "reason", "watch".
  std::vector<std::pair<std::string, std::string>> kv;
};
std::optional<StopReply> parse_stop_reply(std::string_view payload);

// Decode a hex-only payload (g, m, single-register responses).
// Each pair of hex digits becomes one byte. Returns nullopt on
// odd-length input or non-hex characters.
std::optional<std::vector<std::uint8_t>> decode_hex_bytes(std::string_view hex);

// Parse a qSupported reply: feature1[+|-|=value];feature2;...
// `+` = supported, `-` = unsupported, `=value` carries a payload.
struct QSupported {
  std::vector<std::pair<std::string, std::string>> features;
  std::uint32_t packet_size = 0;  // PacketSize=NN (decimal)
};
std::optional<QSupported> parse_qSupported_reply(std::string_view payload);

// Parse a qfThreadInfo / qsThreadInfo chunk. Reply shape:
//   `m<tid>[,<tid>...]`   — partial list, more to come
//   `l`                    — end-of-list
// Returns nullopt on shape error; otherwise `end == true` when
// the server signaled end-of-list.
struct ThreadInfoChunk {
  std::vector<std::int64_t> tids;
  bool end = false;
};
std::optional<ThreadInfoChunk> parse_thread_info_reply(std::string_view payload);

// Parse a qXfer chunk. Reply shape:
//   `m<data>` — partial, more chunks to fetch
//   `l<data>` — last chunk
// The leading byte is consumed; only the payload bytes are returned.
struct QXferChunk {
  std::string data;
  bool end = false;
};
std::optional<QXferChunk> parse_qXfer_reply(std::string_view payload);

}  // namespace ldb::transport::rsp
