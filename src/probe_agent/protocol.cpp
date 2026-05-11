// SPDX-License-Identifier: Apache-2.0
#include "probe_agent/protocol.h"

#include <array>
#include <cstring>

namespace ldb::probe_agent {

namespace {

bool read_exact(std::istream& in, char* buf, std::size_t n) {
  in.read(buf, static_cast<std::streamsize>(n));
  return in.gcount() == static_cast<std::streamsize>(n);
}

bool read_some(std::istream& in, char* buf, std::size_t n,
               std::size_t* got) {
  in.read(buf, static_cast<std::streamsize>(n));
  *got = static_cast<std::size_t>(in.gcount());
  return *got > 0;
}

constexpr char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::array<int, 256> make_b64_decode_table() {
  std::array<int, 256> t{};
  for (auto& x : t) x = -1;
  for (int i = 0; i < 64; ++i) {
    t[static_cast<unsigned char>(kB64Alphabet[i])] = i;
  }
  return t;
}

}  // namespace

FrameError read_frame(std::istream& in, std::string* payload) {
  payload->clear();
  char hdr[4];
  std::size_t got = 0;
  if (!read_some(in, hdr, 4, &got)) return FrameError::kEof;
  if (got != 4) return FrameError::kTruncated;
  std::uint32_t n =
      (static_cast<std::uint32_t>(static_cast<unsigned char>(hdr[0])) << 24) |
      (static_cast<std::uint32_t>(static_cast<unsigned char>(hdr[1])) << 16) |
      (static_cast<std::uint32_t>(static_cast<unsigned char>(hdr[2])) << 8) |
      (static_cast<std::uint32_t>(static_cast<unsigned char>(hdr[3])));
  if (n > kMaxFrameBytes) return FrameError::kTooLarge;
  if (n == 0) return FrameError::kOk;
  payload->resize(n);
  if (!read_exact(in, payload->data(), n)) {
    payload->clear();
    return FrameError::kTruncated;
  }
  return FrameError::kOk;
}

bool write_frame(std::ostream& out, std::string_view payload) {
  if (payload.size() > kMaxFrameBytes) return false;
  std::uint32_t n = static_cast<std::uint32_t>(payload.size());
  char hdr[4];
  hdr[0] = static_cast<char>((n >> 24) & 0xff);
  hdr[1] = static_cast<char>((n >> 16) & 0xff);
  hdr[2] = static_cast<char>((n >>  8) & 0xff);
  hdr[3] = static_cast<char>( n        & 0xff);
  out.write(hdr, 4);
  if (n > 0) {
    out.write(payload.data(), static_cast<std::streamsize>(n));
  }
  out.flush();
  return static_cast<bool>(out);
}

// ----------------- Command builders --------------------------------------

nlohmann::json make_hello_request() {
  nlohmann::json j;
  j["type"] = "hello";
  return j;
}

nlohmann::json make_attach_uprobe_request(std::string_view program,
                                          std::string_view path,
                                          std::string_view symbol,
                                          std::optional<std::int64_t> pid) {
  nlohmann::json j;
  j["type"]    = "attach_uprobe";
  j["program"] = std::string(program);
  j["path"]    = std::string(path);
  j["symbol"]  = std::string(symbol);
  if (pid.has_value()) j["pid"] = *pid;
  return j;
}

nlohmann::json make_attach_kprobe_request(std::string_view program,
                                          std::string_view function) {
  nlohmann::json j;
  j["type"]     = "attach_kprobe";
  j["program"]  = std::string(program);
  j["function"] = std::string(function);
  return j;
}

nlohmann::json make_attach_tracepoint_request(std::string_view program,
                                              std::string_view category,
                                              std::string_view name) {
  nlohmann::json j;
  j["type"]     = "attach_tracepoint";
  j["program"]  = std::string(program);
  j["category"] = std::string(category);
  j["name"]     = std::string(name);
  return j;
}

nlohmann::json make_poll_events_request(std::string_view attach_id,
                                        std::uint32_t max) {
  nlohmann::json j;
  j["type"]      = "poll_events";
  j["attach_id"] = std::string(attach_id);
  j["max"]       = max;
  return j;
}

nlohmann::json make_detach_request(std::string_view attach_id) {
  nlohmann::json j;
  j["type"]      = "detach";
  j["attach_id"] = std::string(attach_id);
  return j;
}

nlohmann::json make_shutdown_request() {
  nlohmann::json j;
  j["type"] = "shutdown";
  return j;
}

// ----------------- Response parsers --------------------------------------

namespace {

bool type_is(const nlohmann::json& j, std::string_view expected) {
  auto it = j.find("type");
  if (it == j.end() || !it->is_string()) return false;
  return it->get<std::string>() == expected;
}

}  // namespace

std::optional<HelloOk> parse_hello_ok(const nlohmann::json& j) {
  if (!type_is(j, "hello_ok")) return std::nullopt;
  HelloOk h;
  if (auto it = j.find("version"); it != j.end() && it->is_string()) {
    h.version = it->get<std::string>();
  }
  if (auto it = j.find("libbpf_version"); it != j.end() && it->is_string()) {
    h.libbpf_version = it->get<std::string>();
  }
  if (auto it = j.find("btf_present"); it != j.end() && it->is_boolean()) {
    h.btf_present = it->get<bool>();
  }
  if (auto it = j.find("embedded_programs");
      it != j.end() && it->is_array()) {
    for (const auto& p : *it) {
      if (p.is_string()) h.embedded_programs.push_back(p.get<std::string>());
    }
  }
  return h;
}

std::optional<Attached> parse_attached(const nlohmann::json& j) {
  if (!type_is(j, "attached")) return std::nullopt;
  Attached a;
  auto it = j.find("attach_id");
  if (it == j.end() || !it->is_string()) return std::nullopt;
  a.attach_id = it->get<std::string>();
  return a;
}

std::optional<AgentError> parse_error(const nlohmann::json& j) {
  if (!type_is(j, "error")) return std::nullopt;
  AgentError e;
  if (auto it = j.find("code"); it != j.end() && it->is_string()) {
    e.code = it->get<std::string>();
  }
  if (auto it = j.find("message"); it != j.end() && it->is_string()) {
    e.message = it->get<std::string>();
  }
  return e;
}

std::optional<PollEvents> parse_events(const nlohmann::json& j) {
  if (!type_is(j, "events")) return std::nullopt;
  PollEvents pe;
  if (auto it = j.find("dropped");
      it != j.end() && it->is_number_unsigned()) {
    pe.dropped = it->get<std::uint64_t>();
  }
  auto eit = j.find("events");
  if (eit == j.end() || !eit->is_array()) return pe;
  pe.events.reserve(eit->size());
  for (const auto& er : *eit) {
    EventRecord rec;
    if (auto t = er.find("ts_ns"); t != er.end() && t->is_number()) {
      rec.ts_ns = t->get<std::uint64_t>();
    }
    if (auto t = er.find("pid"); t != er.end() && t->is_number()) {
      rec.pid = t->get<std::int64_t>();
    }
    if (auto t = er.find("tid"); t != er.end() && t->is_number()) {
      rec.tid = t->get<std::int64_t>();
    }
    if (auto t = er.find("payload_b64"); t != er.end() && t->is_string()) {
      base64_decode(t->get<std::string>(), &rec.payload);
    }
    pe.events.push_back(std::move(rec));
  }
  return pe;
}

// ----------------- Base64 -------------------------------------------------

std::string base64_encode(const std::uint8_t* bytes, std::size_t len) {
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  std::size_t i = 0;
  while (i + 3 <= len) {
    std::uint32_t v = (static_cast<std::uint32_t>(bytes[i])     << 16) |
                      (static_cast<std::uint32_t>(bytes[i + 1]) <<  8) |
                      (static_cast<std::uint32_t>(bytes[i + 2]));
    out.push_back(kB64Alphabet[(v >> 18) & 0x3f]);
    out.push_back(kB64Alphabet[(v >> 12) & 0x3f]);
    out.push_back(kB64Alphabet[(v >>  6) & 0x3f]);
    out.push_back(kB64Alphabet[ v        & 0x3f]);
    i += 3;
  }
  if (i < len) {
    std::uint32_t v = static_cast<std::uint32_t>(bytes[i]) << 16;
    bool two = (i + 1 < len);
    if (two) v |= static_cast<std::uint32_t>(bytes[i + 1]) << 8;
    out.push_back(kB64Alphabet[(v >> 18) & 0x3f]);
    out.push_back(kB64Alphabet[(v >> 12) & 0x3f]);
    out.push_back(two ? kB64Alphabet[(v >> 6) & 0x3f] : '=');
    out.push_back('=');
  }
  return out;
}

bool base64_decode(std::string_view s, std::vector<std::uint8_t>* out) {
  out->clear();
  if (s.size() % 4 != 0) return false;
  static const auto table = make_b64_decode_table();
  out->reserve((s.size() / 4) * 3);
  for (std::size_t i = 0; i < s.size(); i += 4) {
    int v[4];
    for (int k = 0; k < 4; ++k) {
      char c = s[i + static_cast<std::size_t>(k)];
      if (c == '=') { v[k] = -2; continue; }
      int t = table[static_cast<unsigned char>(c)];
      if (t < 0) { out->clear(); return false; }
      v[k] = t;
    }
    // Pads (-2) are only allowed in the last two positions of the final
    // group. Any other layout is malformed.
    if (i + 4 < s.size() && (v[0] < 0 || v[1] < 0 || v[2] < 0 || v[3] < 0)) {
      out->clear();
      return false;
    }
    if (v[0] < 0 || v[1] < 0) { out->clear(); return false; }
    std::uint32_t w =
        (static_cast<std::uint32_t>(v[0]) << 18) |
        (static_cast<std::uint32_t>(v[1]) << 12) |
        (v[2] >= 0 ? (static_cast<std::uint32_t>(v[2]) << 6) : 0u) |
        (v[3] >= 0 ?  static_cast<std::uint32_t>(v[3])       : 0u);
    out->push_back(static_cast<std::uint8_t>((w >> 16) & 0xff));
    if (v[2] >= 0) {
      out->push_back(static_cast<std::uint8_t>((w >> 8) & 0xff));
    }
    if (v[3] >= 0) {
      out->push_back(static_cast<std::uint8_t>(w & 0xff));
    }
  }
  return true;
}

}  // namespace ldb::probe_agent
