// SPDX-License-Identifier: Apache-2.0
#pragma once

// Rate-limit grammar + enforcement for probes / tracepoints
// (post-V1 #26 phase-1, docs/30-tracepoints.md §2).
//
// Grammar: "<int>/<unit>" where unit ∈ {s, ms, us, total}.
//
//   "1000/s"      — at most 1000 events per second (sliding window)
//   "10/ms"       — at most 10 events per millisecond
//   "500/total"   — at most 500 events lifetime
//
// The enforcer is a single-thread state machine: one mutex on the
// orchestrator already serialises hit-callback access, so the
// rate-limit state doesn't need its own. RateLimit::allow_event
// returns true if the event passes the limit; false if it should
// be dropped. `rate_limited()` exposes the running drop counter for
// probe.list / tracepoint.list.

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ldb::probes {

class RateLimit {
 public:
  enum class Kind { kPerWindow, kTotal };

  // Window grammar: cap events per `window` duration.
  static RateLimit per_window(std::uint64_t cap,
                               std::chrono::microseconds window) {
    return RateLimit(Kind::kPerWindow, cap, window);
  }
  // Lifetime grammar: cap events total; once exceeded, every
  // future call returns false.
  static RateLimit total(std::uint64_t cap) {
    return RateLimit(Kind::kTotal, cap, std::chrono::microseconds(0));
  }

  Kind                           kind()      const noexcept { return kind_; }
  std::uint64_t                  cap()       const noexcept { return cap_; }
  std::chrono::microseconds      window()    const noexcept { return window_; }
  std::uint64_t                  rate_limited() const noexcept { return rate_limited_; }

  // Decide whether to allow this event at `now`. Mutates internal
  // state (window pivot, lifetime counter). Returns true on allow;
  // false on drop (the drop counter is incremented).
  bool allow_event(std::chrono::steady_clock::time_point now);

 private:
  RateLimit(Kind k, std::uint64_t cap, std::chrono::microseconds w)
      : kind_(k), cap_(cap), window_(w) {}

  Kind                                    kind_;
  std::uint64_t                           cap_           = 0;
  std::chrono::microseconds               window_;
  // Per-window state: a sliding pivot + per-pivot count.
  std::chrono::steady_clock::time_point   pivot_{};
  std::uint64_t                           in_window_     = 0;
  // Lifetime / kTotal state + cross-mode drop counter.
  std::uint64_t                           lifetime_      = 0;
  std::uint64_t                           rate_limited_  = 0;
};

// Parse a rate_limit grammar string. Returns nullopt on empty
// input (no limit configured) OR malformed input (caller surfaces
// -32602 for the malformed case after also checking
// rate_limit_grammar_valid for distinguishability — phase-1 keeps
// it simple by returning nullopt on both).
std::optional<RateLimit> parse_rate_limit(std::string_view text);

// True if `text` looked like a rate-limit grammar attempt but
// failed parsing — distinguishes "no limit" from "bad limit" for
// the dispatcher's -32602 path. Phase-1 keeps the contract
// simple: empty/whitespace returns true (treated as "no limit"
// is valid); anything non-empty must parse.
bool rate_limit_grammar_valid(std::string_view text);

}  // namespace ldb::probes
