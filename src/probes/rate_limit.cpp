// SPDX-License-Identifier: Apache-2.0
#include "probes/rate_limit.h"

#include <cctype>
#include <cerrno>
#include <cstdlib>

namespace ldb::probes {

bool RateLimit::allow_event(std::chrono::steady_clock::time_point now) {
  if (kind_ == Kind::kTotal) {
    if (lifetime_ >= cap_) {
      ++rate_limited_;
      return false;
    }
    ++lifetime_;
    return true;
  }
  // kPerWindow — fixed-pivot sliding window. On the first call
  // pivot_ is the default-constructed (zero) time_point; we always
  // re-pivot when the gap exceeds the window.
  if (in_window_ == 0 ||
      now - pivot_ >= window_) {
    pivot_     = now;
    in_window_ = 0;
  }
  if (in_window_ >= cap_) {
    ++rate_limited_;
    return false;
  }
  ++in_window_;
  return true;
}

namespace {

bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

std::string_view trim(std::string_view s) {
  while (!s.empty() && is_ws(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_ws(s.back()))  s.remove_suffix(1);
  return s;
}

}  // namespace

std::optional<RateLimit> parse_rate_limit(std::string_view text) {
  auto t = trim(text);
  if (t.empty()) return std::nullopt;
  auto slash = t.find('/');
  if (slash == std::string_view::npos) return std::nullopt;
  auto lhs = t.substr(0, slash);
  auto rhs = t.substr(slash + 1);
  if (lhs.empty() || rhs.empty()) return std::nullopt;

  // Parse N (positive integer). Reject negatives, zero, and any
  // trailing non-digit content.
  std::string lhs_owned(lhs);
  errno = 0;
  char* endp = nullptr;
  long long v = std::strtoll(lhs_owned.c_str(), &endp, 10);
  if (errno == ERANGE || endp == nullptr ||
      endp != lhs_owned.c_str() + lhs_owned.size() ||
      v <= 0) {
    return std::nullopt;
  }
  std::uint64_t cap = static_cast<std::uint64_t>(v);

  if (rhs == "s") {
    return RateLimit::per_window(cap, std::chrono::microseconds(1'000'000));
  }
  if (rhs == "ms") {
    return RateLimit::per_window(cap, std::chrono::microseconds(1'000));
  }
  if (rhs == "us") {
    return RateLimit::per_window(cap, std::chrono::microseconds(1));
  }
  if (rhs == "total") {
    return RateLimit::total(cap);
  }
  return std::nullopt;
}

bool rate_limit_grammar_valid(std::string_view text) {
  auto t = trim(text);
  if (t.empty()) return true;  // absent is valid
  return parse_rate_limit(text).has_value();
}

}  // namespace ldb::probes
