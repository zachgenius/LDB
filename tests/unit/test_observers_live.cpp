// SPDX-License-Identifier: Apache-2.0
// Live-local tests for ldb::observers (M4 part 3).
//
// Each case invokes the observer entry-point against the current
// unit-test process and checks the parsed structure for plausibility.
// Local dispatch (no `host` set) ⇒ the observer routes through
// `local_exec` rather than `ssh_exec`. SKIP cleanly when /proc is
// unavailable (macOS/BSD) so the suite can build there once we get
// to v0.3.

#include <catch_amalgamated.hpp>

#include "observers/observers.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <unistd.h>

#include <filesystem>

namespace {

bool has_proc_self_status() {
  std::error_code ec;
  return std::filesystem::exists("/proc/self/status", ec);
}

}  // namespace

TEST_CASE("fetch_proc_fds: live against current process",
          "[observers][live][proc][fds]") {
  if (!has_proc_self_status()) {
    SKIP("/proc unavailable on this host (not Linux?) — observers "
         "rely on procfs");
  }
  auto r = ldb::observers::fetch_proc_fds(std::nullopt, ::getpid());
  REQUIRE(r.total >= 3);  // 0/1/2 are guaranteed by stdio

  bool saw_stdout = false;
  for (const auto& e : r.fds) {
    CHECK(e.fd >= 0);
    CHECK(!e.target.empty());
    CHECK(!e.type.empty());
    if (e.fd == 1) saw_stdout = true;
  }
  CHECK(saw_stdout);
}

TEST_CASE("fetch_proc_maps: live against current process",
          "[observers][live][proc][maps]") {
  if (!has_proc_self_status()) {
    SKIP("/proc unavailable on this host (not Linux?)");
  }
  auto r = ldb::observers::fetch_proc_maps(std::nullopt, ::getpid());
  REQUIRE(r.total > 5);
  // Every region must have start < end.
  for (const auto& reg : r.regions) {
    CHECK(reg.start < reg.end);
    CHECK(!reg.perm.empty());
  }
}

TEST_CASE("fetch_proc_status: live against current process",
          "[observers][live][proc][status]") {
  if (!has_proc_self_status()) {
    SKIP("/proc unavailable on this host (not Linux?)");
  }
  auto r = ldb::observers::fetch_proc_status(std::nullopt, ::getpid());
  CHECK(!r.name.empty());
  REQUIRE(r.pid.has_value());
  CHECK(*r.pid == ::getpid());
  CHECK(!r.state.empty());
  REQUIRE(r.threads.has_value());
  CHECK(*r.threads >= 1u);
}

TEST_CASE("fetch_proc_fds: invalid pid is rejected",
          "[observers][proc][fds][error]") {
  // Negative pid must be refused before we ever spawn.
  REQUIRE_THROWS(ldb::observers::fetch_proc_fds(std::nullopt, -1));
  REQUIRE_THROWS(ldb::observers::fetch_proc_fds(std::nullopt, 0));
}

TEST_CASE("fetch_net_sockets: live local ss -tunap",
          "[observers][live][net][sockets]") {
  if (!has_proc_self_status()) {
    SKIP("/proc unavailable on this host (not Linux?)");
  }
  // Some minimal Linux containers don't have iproute2's `ss`. SKIP
  // cleanly if that's our case here.
  auto r_opt = [&]() -> std::optional<ldb::observers::SocketsResult> {
    try {
      return ldb::observers::fetch_net_sockets(std::nullopt, "");
    } catch (const ldb::backend::Error& e) {
      WARN(std::string("ss not available on this host: ") + e.what());
      return std::nullopt;
    }
  }();
  if (!r_opt.has_value()) {
    SKIP("ss(8) not available on this host");
  }
  // We don't care if there are zero sockets — what we care about is
  // that parsing succeeded at all.
  CHECK(r_opt->total == r_opt->sockets.size());
}

TEST_CASE("fetch_net_sockets: filter is applied post-parse",
          "[observers][live][net][sockets]") {
  if (!has_proc_self_status()) {
    SKIP("/proc unavailable on this host (not Linux?)");
  }
  std::optional<ldb::observers::SocketsResult> all_opt;
  try {
    all_opt = ldb::observers::fetch_net_sockets(std::nullopt, "");
  } catch (const ldb::backend::Error&) {
    SKIP("ss(8) not available on this host");
  }
  // Filter on the literal "tcp" prefix — every entry returned must be
  // tcp; the count cannot exceed the unfiltered total.
  auto tcp = ldb::observers::fetch_net_sockets(std::nullopt, "tcp");
  CHECK(tcp.total <= all_opt->total);
  for (const auto& s : tcp.sockets) {
    CHECK(s.proto == "tcp");
  }
}
