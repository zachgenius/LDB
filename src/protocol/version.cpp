#include "protocol/version.h"

namespace ldb::protocol {

std::optional<ProtocolVersion> parse_protocol_version(std::string_view s) {
  // Strict grammar: ^[0-9]+\.[0-9]+$
  if (s.empty()) return std::nullopt;

  std::size_t dot = s.find('.');
  if (dot == std::string_view::npos) return std::nullopt;
  // Reject multiple dots ("1.0.0", "1..0").
  if (s.find('.', dot + 1) != std::string_view::npos) return std::nullopt;

  std::string_view major_s = s.substr(0, dot);
  std::string_view minor_s = s.substr(dot + 1);
  if (major_s.empty() || minor_s.empty()) return std::nullopt;

  auto all_digits = [](std::string_view t) {
    for (char c : t) {
      if (c < '0' || c > '9') return false;
    }
    return !t.empty();
  };
  if (!all_digits(major_s) || !all_digits(minor_s)) return std::nullopt;

  // Bound check: keep in int range.
  long long maj = 0, min_ = 0;
  for (char c : major_s) {
    maj = maj * 10 + (c - '0');
    if (maj > 1'000'000'000LL) return std::nullopt;
  }
  for (char c : minor_s) {
    min_ = min_ * 10 + (c - '0');
    if (min_ > 1'000'000'000LL) return std::nullopt;
  }

  return ProtocolVersion{static_cast<int>(maj), static_cast<int>(min_)};
}

}  // namespace ldb::protocol
