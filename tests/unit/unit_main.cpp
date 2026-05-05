// Catch2 v3 amalgamated provides its own main when CATCH_AMALGAMATED_CUSTOM_MAIN
// is NOT defined. We let it provide main(); this file just exists to give the
// CMake target a tiny TU that anchors per-target options if needed later.

#include <catch_amalgamated.hpp>

// Sanity test — proves the harness compiles, links, runs, and ctest sees
// a pass. If this fails the build environment itself is broken.
TEST_CASE("catch2 harness is wired up", "[harness]") {
  REQUIRE(1 + 1 == 2);
  REQUIRE_FALSE(false);
}
