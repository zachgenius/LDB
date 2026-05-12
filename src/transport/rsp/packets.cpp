// SPDX-License-Identifier: Apache-2.0
#include "transport/rsp/packets.h"

#include <cctype>
#include <cstdio>
#include <cstring>

namespace ldb::transport::rsp {

namespace {

char hex_lower(unsigned nibble) {
  return static_cast<char>(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));
}

void append_hex_bytes(std::string* out, std::string_view bytes) {
  out->reserve(out->size() + bytes.size() * 2);
  for (unsigned char c : bytes) {
    out->push_back(hex_lower((c >> 4) & 0xf));
    out->push_back(hex_lower(c & 0xf));
  }
}

// Lower-hex of a 64-bit integer, no leading zeros. gdb-remote
// accepts and emits this short form; the spec is permissive.
std::string to_hex(std::uint64_t v) {
  if (v == 0) return "0";
  char buf[17];
  int n = std::snprintf(buf, sizeof(buf), "%llx",
                        static_cast<unsigned long long>(v));
  return std::string(buf, static_cast<std::size_t>(n));
}

// Signed-aware hex for thread ids. `Hg -1` is a real spec-defined
// shape; we don't hexify the sign byte.
std::string to_hex_signed(std::int64_t v) {
  if (v < 0) return std::string("-") + to_hex(static_cast<std::uint64_t>(-v));
  return to_hex(static_cast<std::uint64_t>(v));
}

bool from_hex_digit(char c, unsigned* out) {
  if (c >= '0' && c <= '9') { *out = static_cast<unsigned>(c - '0'); return true; }
  if (c >= 'a' && c <= 'f') { *out = static_cast<unsigned>(c - 'a' + 10); return true; }
  if (c >= 'A' && c <= 'F') { *out = static_cast<unsigned>(c - 'A' + 10); return true; }
  return false;
}

bool parse_hex_u8(std::string_view s, std::uint8_t* out) {
  if (s.size() != 2) return false;
  unsigned hi = 0, lo = 0;
  if (!from_hex_digit(s[0], &hi) || !from_hex_digit(s[1], &lo)) return false;
  *out = static_cast<std::uint8_t>((hi << 4) | lo);
  return true;
}

bool parse_hex_int64(std::string_view s, std::int64_t* out) {
  if (s.empty()) return false;
  std::int64_t v = 0;
  for (char c : s) {
    unsigned n;
    if (!from_hex_digit(c, &n)) return false;
    v = (v << 4) | static_cast<std::int64_t>(n);
  }
  *out = v;
  return true;
}

bool parse_hex_u32(std::string_view s, std::uint32_t* out) {
  if (s.empty()) return false;
  std::uint32_t v = 0;
  for (char c : s) {
    unsigned n;
    if (!from_hex_digit(c, &n)) return false;
    v = (v << 4) | n;
  }
  *out = v;
  return true;
}

// Split `s` on `delim`, returning every non-empty segment. Empty
// segments (e.g. trailing ';' that gdb often emits) are dropped.
std::vector<std::string_view>
split_view(std::string_view s, char delim) {
  std::vector<std::string_view> out;
  std::size_t i = 0;
  while (i <= s.size()) {
    std::size_t j = s.find(delim, i);
    if (j == std::string_view::npos) {
      if (i < s.size()) out.push_back(s.substr(i));
      break;
    }
    if (j > i) out.push_back(s.substr(i, j - i));
    i = j + 1;
  }
  return out;
}

}  // namespace

// ----------- Request builders --------------------------------------

std::string build_qSupported(const std::vector<std::string>& features) {
  if (features.empty()) return "qSupported";
  std::string out = "qSupported:";
  for (std::size_t i = 0; i < features.size(); ++i) {
    if (i) out.push_back(';');
    out += features[i];
  }
  return out;
}

std::string build_stop_query()         { return "?"; }
std::string build_register_read_all()  { return "g"; }
std::string build_qfThreadInfo()       { return "qfThreadInfo"; }
std::string build_qsThreadInfo()       { return "qsThreadInfo"; }
std::string build_reverse_continue()   { return "bc"; }
std::string build_reverse_step()       { return "bs"; }
std::string build_QStartNoAckMode()    { return "QStartNoAckMode"; }

std::string build_register_write_all(std::string_view bytes) {
  std::string out = "G";
  append_hex_bytes(&out, bytes);
  return out;
}

std::string build_register_read_one(std::uint32_t reg_num) {
  return "p" + to_hex(reg_num);
}

std::string build_register_write_one(std::uint32_t reg_num,
                                      std::string_view bytes) {
  std::string out = "P" + to_hex(reg_num) + "=";
  append_hex_bytes(&out, bytes);
  return out;
}

std::string build_memory_read(std::uint64_t address, std::uint32_t length) {
  return "m" + to_hex(address) + "," + to_hex(length);
}

std::string build_memory_write(std::uint64_t address,
                                std::string_view bytes) {
  std::string out = "M" + to_hex(address) + ","
                        + to_hex(bytes.size()) + ":";
  append_hex_bytes(&out, bytes);
  return out;
}

std::string build_continue_legacy(std::optional<std::uint64_t> resume_at) {
  if (!resume_at.has_value()) return "c";
  return "c" + to_hex(*resume_at);
}

std::string build_step_legacy(std::optional<std::uint64_t> resume_at) {
  if (!resume_at.has_value()) return "s";
  return "s" + to_hex(*resume_at);
}

std::string build_vCont(const std::vector<VContAction>& actions) {
  std::string out = "vCont";
  for (const auto& a : actions) {
    out.push_back(';');
    out.push_back(a.action);
    // Signal byte attaches directly to 'C' / 'S' (e.g. C09); other
    // action chars don't carry one.
    if (a.action == 'C' || a.action == 'S') {
      char buf[3];
      std::snprintf(buf, sizeof(buf), "%02x", a.signal);
      out.append(buf, 2);
    }
    // Per-thread scope; absent ≡ "default" (which the wire reads as
    // all-threads for the first action in a vCont, per spec).
    if (a.tid != 0) {
      out.push_back(':');
      out += to_hex_signed(a.tid);
    }
  }
  return out;
}

std::string build_thread_select_general(std::int64_t tid) {
  return "Hg" + to_hex_signed(tid);
}

std::string build_thread_select_continue(std::int64_t tid) {
  return "Hc" + to_hex_signed(tid);
}

std::string build_qXfer_features_read(std::string_view annex,
                                       std::uint32_t offset,
                                       std::uint32_t length) {
  std::string out = "qXfer:features:read:";
  out += annex;
  out.push_back(':');
  out += to_hex(offset);
  out.push_back(',');
  out += to_hex(length);
  return out;
}

// ----------- Response parsers --------------------------------------

ResponseKind classify_response(std::string_view payload) {
  if (payload.empty()) return ResponseKind::kUnsupported;
  if (payload == "OK") return ResponseKind::kOk;
  if (payload.size() >= 1) {
    char c = payload[0];
    if (c == 'E' && payload.size() == 3) {
      // Conservative: only call it kError when the rest decodes as
      // a two-hex-digit code. Otherwise hex-only payload starting
      // with E (a register block) might be misclassified.
      std::uint8_t code;
      if (parse_hex_u8(payload.substr(1), &code)) return ResponseKind::kError;
    }
    if (c == 'T' || c == 'S' || c == 'W' || c == 'X')
      return ResponseKind::kStopReply;
  }
  // Pure-hex shape — every byte is a hex digit.
  bool all_hex = !payload.empty();
  for (char c : payload) {
    if (!((c >= '0' && c <= '9') ||
          (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) { all_hex = false; break; }
  }
  if (all_hex) return ResponseKind::kHex;
  return ResponseKind::kQReply;
}

std::optional<std::uint8_t> parse_error_code(std::string_view payload) {
  if (payload.size() != 3 || payload[0] != 'E') return std::nullopt;
  std::uint8_t out;
  if (!parse_hex_u8(payload.substr(1), &out)) return std::nullopt;
  return out;
}

std::optional<StopReply> parse_stop_reply(std::string_view payload) {
  if (payload.empty()) return std::nullopt;
  char t = payload[0];
  if (t != 'T' && t != 'S' && t != 'W' && t != 'X') return std::nullopt;
  if (payload.size() < 3) return std::nullopt;
  std::uint8_t sig;
  if (!parse_hex_u8(payload.substr(1, 2), &sig)) return std::nullopt;
  StopReply r;
  r.type   = t;
  r.signal = sig;
  // S/W/X carry only the signal; T carries kv-pairs.
  if (t == 'T') {
    auto rest = payload.substr(3);
    // kv-pairs are `name:value;` (the final pair may or may not have
    // a trailing ';'). The "name" part can contain hex digits or
    // identifier chars; the "value" runs until the next ';'.
    for (auto kv : split_view(rest, ';')) {
      auto colon = kv.find(':');
      if (colon == std::string_view::npos) continue;  // malformed; skip
      r.kv.emplace_back(std::string(kv.substr(0, colon)),
                        std::string(kv.substr(colon + 1)));
    }
  }
  return r;
}

std::optional<std::vector<std::uint8_t>>
decode_hex_bytes(std::string_view hex) {
  if (hex.size() % 2 != 0) return std::nullopt;
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    std::uint8_t b;
    if (!parse_hex_u8(hex.substr(i, 2), &b)) return std::nullopt;
    out.push_back(b);
  }
  return out;
}

std::optional<QSupported>
parse_qSupported_reply(std::string_view payload) {
  if (payload.empty()) return std::nullopt;
  QSupported out;
  for (auto feat : split_view(payload, ';')) {
    if (feat.empty()) continue;
    // Three shapes:
    //   name=value   (e.g. PacketSize=20000)
    //   name+        (supported)
    //   name-        (unsupported)
    auto eq = feat.find('=');
    if (eq != std::string_view::npos) {
      std::string name(feat.substr(0, eq));
      std::string val(feat.substr(eq + 1));
      if (name == "PacketSize") {
        std::uint32_t sz;
        if (parse_hex_u32(val, &sz)) out.packet_size = sz;
      }
      out.features.emplace_back(std::move(name), std::move(val));
    } else if (!feat.empty() &&
               (feat.back() == '+' || feat.back() == '-')) {
      out.features.emplace_back(std::string(feat.substr(0, feat.size() - 1)),
                                std::string(1, feat.back()));
    } else {
      // Bare feature name without +/- — accept as supported.
      out.features.emplace_back(std::string(feat), "+");
    }
  }
  return out;
}

std::optional<ThreadInfoChunk>
parse_thread_info_reply(std::string_view payload) {
  if (payload.empty()) return std::nullopt;
  ThreadInfoChunk out;
  if (payload == "l") { out.end = true; return out; }
  if (payload[0] != 'm') return std::nullopt;
  auto rest = payload.substr(1);
  if (rest.empty()) return std::nullopt;  // bare "m" is malformed
  for (auto tid_s : split_view(rest, ',')) {
    std::int64_t tid;
    if (!parse_hex_int64(tid_s, &tid)) return std::nullopt;
    out.tids.push_back(tid);
  }
  return out;
}

std::optional<QXferChunk> parse_qXfer_reply(std::string_view payload) {
  if (payload.empty()) return std::nullopt;
  char lead = payload[0];
  if (lead != 'm' && lead != 'l') return std::nullopt;
  QXferChunk out;
  out.end  = (lead == 'l');
  out.data.assign(payload.substr(1));
  return out;
}

}  // namespace ldb::transport::rsp
