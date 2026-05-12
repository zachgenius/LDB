// SPDX-License-Identifier: Apache-2.0
// Tests for the rate_limit grammar parser + windowed enforcer
// (post-V1 #26 phase-1, docs/30-tracepoints.md §2).
//
// Coverage:
//   * Grammar parsing: positive cases for "N/s", "N/ms", "N/us",
//     "N/total"; rejects malformed input.
//   * Enforcement: time-windowed limits allow up through the cap +
//     reject the (cap+1)-th event in the same window; window
//     advances correctly; "total" cap is lifetime.
//   * Empty / absent rate_limit → no enforcement (allow_event
//     always returns true).
//   * Zero or negative N → parse error.

#include <catch_amalgamated.hpp>

#include "probes/rate_limit.h"

#include <chrono>

using ldb::probes::RateLimit;
using ldb::probes::parse_rate_limit;

namespace {
// Synthetic clock so tests don't depend on wall time.
class FakeClock {
 public:
  std::chrono::steady_clock::time_point now() const { return t_; }
  template <typename Duration>
  void advance(Duration d) {
    t_ += std::chrono::duration_cast<
              std::chrono::steady_clock::duration>(d);
  }
 private:
  std::chrono::steady_clock::time_point t_{};
};

bool tick(RateLimit& rl, FakeClock& clk) {
  return rl.allow_event(clk.now());
}
}  // namespace

TEST_CASE("rate_limit: parse N/s", "[rate_limit][parse]") {
  auto rl = parse_rate_limit("1000/s");
  REQUIRE(rl.has_value());
  CHECK(rl->kind() == RateLimit::Kind::kPerWindow);
  CHECK(rl->cap()  == 1000);
  // Window is stored as microseconds; 1s = 1_000_000 us.
  CHECK(rl->window() == std::chrono::microseconds(1'000'000));
}

TEST_CASE("rate_limit: parse N/ms / N/us / N/total",
          "[rate_limit][parse]") {
  auto a = parse_rate_limit("10/ms");
  REQUIRE(a.has_value());
  CHECK(a->window() == std::chrono::microseconds(1000));

  auto b = parse_rate_limit("5/us");
  REQUIRE(b.has_value());
  CHECK(b->window() == std::chrono::microseconds(1));

  auto c = parse_rate_limit("500/total");
  REQUIRE(c.has_value());
  CHECK(c->kind() == RateLimit::Kind::kTotal);
  CHECK(c->cap()  == 500);
}

TEST_CASE("rate_limit: empty string → nullopt (no enforcement)",
          "[rate_limit][parse]") {
  CHECK_FALSE(parse_rate_limit("").has_value());
  CHECK_FALSE(parse_rate_limit("  ").has_value());
}

TEST_CASE("rate_limit: malformed grammar → nullopt",
          "[rate_limit][parse][error]") {
  CHECK_FALSE(parse_rate_limit("1000").has_value());     // missing /
  CHECK_FALSE(parse_rate_limit("/s").has_value());       // missing N
  CHECK_FALSE(parse_rate_limit("1000/").has_value());    // missing unit
  CHECK_FALSE(parse_rate_limit("abc/s").has_value());    // non-int
  CHECK_FALSE(parse_rate_limit("1000/hours").has_value());// unknown unit
  CHECK_FALSE(parse_rate_limit("-5/s").has_value());     // negative
  CHECK_FALSE(parse_rate_limit("0/s").has_value());      // zero
}

TEST_CASE("rate_limit: kPerWindow allows up to cap inside one window",
          "[rate_limit][allow]") {
  auto rl = parse_rate_limit("3/s");
  REQUIRE(rl.has_value());
  FakeClock clk;
  // Three events at t=0 — all allowed.
  CHECK(tick(*rl, clk));
  CHECK(tick(*rl, clk));
  CHECK(tick(*rl, clk));
  // Fourth in the same window — rejected.
  CHECK_FALSE(tick(*rl, clk));
  // Counter exposes the drop.
  CHECK(rl->rate_limited() == 1);
  // Advance past the 1-second window; allowance resets.
  clk.advance(std::chrono::milliseconds(1001));
  CHECK(tick(*rl, clk));
  CHECK(tick(*rl, clk));
  CHECK(rl->rate_limited() == 1);   // window reset doesn't clear counter
}

TEST_CASE("rate_limit: kTotal caps lifetime regardless of time",
          "[rate_limit][allow]") {
  auto rl = parse_rate_limit("2/total");
  REQUIRE(rl.has_value());
  FakeClock clk;
  CHECK(tick(*rl, clk));
  CHECK(tick(*rl, clk));
  CHECK_FALSE(tick(*rl, clk));
  // Advance time arbitrarily — total is hard cap.
  clk.advance(std::chrono::hours(24));
  CHECK_FALSE(tick(*rl, clk));
  CHECK(rl->rate_limited() == 2);
}

TEST_CASE("rate_limit: per-ms window is tight",
          "[rate_limit][allow]") {
  auto rl = parse_rate_limit("2/ms");
  REQUIRE(rl.has_value());
  FakeClock clk;
  CHECK(tick(*rl, clk));
  CHECK(tick(*rl, clk));
  CHECK_FALSE(tick(*rl, clk));
  clk.advance(std::chrono::microseconds(1100));
  CHECK(tick(*rl, clk));   // new window
}
