// SPDX-License-Identifier: Apache-2.0
#pragma once

// Wire protocol shared by the daemon-side AgentEngine and the standalone
// `ldb-probe-agent` binary. Spec lives in docs/21-probe-agent.md.
//
// This header is pure header-only-ish: it depends only on the bundled
// nlohmann json (for JSON shape) and <iostream>/<cstdint> (for framing).
// It does NOT link libbpf - the daemon side must compile against the
// same header without pulling in libbpf, and the unit tests must work
// on any host regardless of kernel features.

#include <nlohmann/json.hpp>

#include <cstdint>
#include <istream>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace ldb::probe_agent {

// Hard limit on a single frame's payload size. Chosen so an oversize
// frame can be rejected without allocating ~4 GiB; 16 MiB is far past
// any sane JSON command we'd send.
inline constexpr std::uint32_t kMaxFrameBytes = 0x01000000;  // 16 MiB

enum class FrameError {
  kOk = 0,
  kEof,         // stream closed before a length header was read.
  kTruncated,   // header read, but body short.
  kTooLarge,    // length prefix exceeded kMaxFrameBytes.
  kIoError,     // generic istream/ostream failure.
};

// Read one length-prefixed frame from `in`. On kOk, `*payload` holds the
// raw JSON body. On any error, `*payload` is left empty. Never throws.
FrameError read_frame(std::istream& in, std::string* payload);

// Write one length-prefixed frame to `out`. Returns false on stream
// failure or oversize payload. Never throws.
bool write_frame(std::ostream& out, std::string_view payload);

// ----------------- Command request builders (daemon -> agent) -------------

nlohmann::json make_hello_request();

nlohmann::json make_attach_uprobe_request(std::string_view program,
                                          std::string_view path,
                                          std::string_view symbol,
                                          std::optional<std::int64_t> pid);

nlohmann::json make_attach_kprobe_request(std::string_view program,
                                          std::string_view function);

nlohmann::json make_attach_tracepoint_request(std::string_view program,
                                              std::string_view category,
                                              std::string_view name);

nlohmann::json make_poll_events_request(std::string_view attach_id,
                                        std::uint32_t max);

nlohmann::json make_detach_request(std::string_view attach_id);

nlohmann::json make_shutdown_request();

// ----------------- Response parsers (agent -> daemon) ---------------------

struct HelloOk {
  std::string version;
  std::string libbpf_version;
  bool        btf_present = false;
  std::vector<std::string> embedded_programs;
};

struct Attached {
  std::string attach_id;
};

struct AgentError {
  std::string code;
  std::string message;
};

struct EventRecord {
  std::uint64_t ts_ns = 0;
  std::int64_t  pid   = 0;
  std::int64_t  tid   = 0;
  std::vector<std::uint8_t> payload;
};

struct PollEvents {
  std::vector<EventRecord> events;
  std::uint64_t            dropped = 0;
};

// Each parser returns nullopt when the input is missing required fields
// or carries a `type` mismatch. They are otherwise tolerant of extra
// fields (forward-compat) - agents and daemons may version-skew during
// a rolling deploy.
std::optional<HelloOk>    parse_hello_ok(const nlohmann::json& j);
std::optional<Attached>   parse_attached(const nlohmann::json& j);
std::optional<AgentError> parse_error(const nlohmann::json& j);
std::optional<PollEvents> parse_events(const nlohmann::json& j);

// ----------------- Base64 (RFC 4648, no line wrap) ------------------------
//
// Used for `payload_b64` event bodies. We can't shove arbitrary BPF
// output through JSON strings without escaping; base64 is the smallest
// portable encoding both sides agree on and incurs ~33% overhead, which
// is fine at our event rates.

std::string base64_encode(const std::uint8_t* bytes, std::size_t len);
bool        base64_decode(std::string_view s, std::vector<std::uint8_t>* out);

}  // namespace ldb::probe_agent
