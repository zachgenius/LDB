// SPDX-License-Identifier: Apache-2.0
// Wire-protocol semantic versioning (Tier 1 §3a, see
// docs/05-protocol-versioning.md).
//
// The protocol version is a `<major>.<minor>` pair carried in the
// `hello` handshake. It is *separate* from the daemon version
// (`ldb::kVersionString`) — the daemon version moves on every release,
// while the protocol version moves only when the wire shape changes:
//
//   * Minor bump: backward-compatible addition (new optional field, new
//     endpoint, new view option). Old clients keep working.
//   * Major bump: breaking change (renamed/removed field, semantics
//     change). Old clients must upgrade.
//
// Pre-1.0, minor bumps MAY be breaking; documented in `docs/05`.
//
// `kProtocolMinSupportedMinor` is the oldest minor of the same major
// that the daemon will still accept from a client's `protocol_min`.
// For MVP it equals the current minor — we serve exactly one version.
// A later daemon that wants to support multiple minors lowers this and
// keeps backward-compat code in the affected handlers.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ldb::protocol {

inline constexpr int kProtocolVersionMajor = 0;
inline constexpr int kProtocolVersionMinor = 1;
inline constexpr const char* kProtocolVersionString = "0.1";

// Oldest version we still serve. For MVP this equals the current
// version — the daemon ships exactly one minor. Future daemons that
// keep backward-compat code for older minors can lower this.
inline constexpr int kProtocolMinSupportedMajor = 0;
inline constexpr int kProtocolMinSupportedMinor = 1;

struct ProtocolVersion {
  int major = 0;
  int minor = 0;

  friend constexpr bool operator==(ProtocolVersion a, ProtocolVersion b) {
    return a.major == b.major && a.minor == b.minor;
  }
  friend constexpr bool operator!=(ProtocolVersion a, ProtocolVersion b) {
    return !(a == b);
  }
  friend constexpr bool operator<(ProtocolVersion a, ProtocolVersion b) {
    if (a.major != b.major) return a.major < b.major;
    return a.minor < b.minor;
  }
  friend constexpr bool operator<=(ProtocolVersion a, ProtocolVersion b) {
    return !(b < a);
  }
  friend constexpr bool operator>(ProtocolVersion a, ProtocolVersion b) {
    return b < a;
  }
  friend constexpr bool operator>=(ProtocolVersion a, ProtocolVersion b) {
    return !(a < b);
  }

  std::string to_string() const {
    return std::to_string(major) + "." + std::to_string(minor);
  }
};

inline constexpr ProtocolVersion kProtocolCurrent{
    kProtocolVersionMajor, kProtocolVersionMinor};
inline constexpr ProtocolVersion kProtocolMinSupported{
    kProtocolMinSupportedMajor, kProtocolMinSupportedMinor};

// Strict parser for `<major>.<minor>` — both components must be
// non-empty runs of ASCII digits, no leading sign, no trailing junk,
// no extra dots. Returns nullopt on any malformation; caller maps that
// to -32602 kInvalidParams.
std::optional<ProtocolVersion> parse_protocol_version(std::string_view s);

}  // namespace ldb::protocol
