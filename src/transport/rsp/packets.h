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
