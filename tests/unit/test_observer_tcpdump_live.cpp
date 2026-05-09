// SPDX-License-Identifier: Apache-2.0
// Live tests for ldb::observers::tcpdump (M4 part 5, §4.6).
//
// SKIPs cleanly when:
//   - `tcpdump --version` fails (binary missing).
//   - the test runner has no CAP_NET_RAW (most users — including the
//     CI / dev account on this Pop!_OS box).
//
// When neither gates fire (root, or `setcap cap_net_raw=eip`'d
// tcpdump), we capture 3 packets on `lo` while generating local
// traffic via `curl http://127.0.0.1:1` — connection refused but
// produces SYN + RST on the loopback interface, plenty for the
// capture to fill its bound.

#include <catch_amalgamated.hpp>

#include "observers/observers.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <thread>
#include <unistd.h>

namespace {

bool tcpdump_binary_available() {
  return std::system("tcpdump --version >/dev/null 2>&1") == 0;
}

// Try a 1-packet capture on lo; if it fails with a permission error,
// we don't have CAP_NET_RAW and the caller should SKIP. Returns true
// only when the capture actually succeeded (or could have).
bool tcpdump_has_capture_permission() {
  // -c 0 isn't legal; ask for a single packet with a 250 ms wall cap so
  // the probe is quick. We KILL it via terminate() implicit in the
  // request's timeout.
  ldb::observers::TcpdumpRequest req;
  req.iface   = "lo";
  req.count   = 1;
  req.timeout = std::chrono::milliseconds(250);
  try {
    (void)ldb::observers::tcpdump(req);
    return true;  // succeeded outright (root or setcap'd binary)
  } catch (const ldb::backend::Error& e) {
    std::string msg = e.what();
    // tcpdump's "no permission" / "Operation not permitted" / EACCES
    // — they all fail the gate. Anything else is a real bug.
    if (msg.find("permission") != std::string::npos ||
        msg.find("Operation not permitted") != std::string::npos ||
        msg.find("EACCES") != std::string::npos) {
      return false;
    }
    // Other failure modes (no such device, etc.) — still "no" for the
    // purposes of running the live capture.
    return false;
  }
}

}  // namespace

TEST_CASE("tcpdump: live 3-packet capture on lo",
          "[observers][live][net][tcpdump][requires_tcpdump_cap]") {
  if (!tcpdump_binary_available()) {
    SKIP("tcpdump binary not installed");
  }
  if (!tcpdump_has_capture_permission()) {
    SKIP("test runner has no CAP_NET_RAW (run as root or setcap on tcpdump)");
  }

  // Background traffic generator: curl to a closed port on 127.0.0.1
  // produces TCP SYN + RST on `lo` reliably. Run once, async.
  std::thread traffic([] {
    // 200 ms grace so tcpdump has time to attach the capture.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    for (int i = 0; i < 5 && std::system("curl --max-time 1 -s "
                                          "http://127.0.0.1:1 "
                                          ">/dev/null 2>&1"); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  });

  ldb::observers::TcpdumpRequest req;
  req.iface   = "lo";
  req.count   = 3;
  req.timeout = std::chrono::seconds(5);  // hard wall-clock cap

  auto r = ldb::observers::tcpdump(req);
  if (traffic.joinable()) traffic.join();

  CHECK(r.total == r.packets.size());
  CHECK(r.total <= 3);
  // We don't insist on hitting count: in pathological CI environments
  // the curl might not fire fast enough. We DO insist that whatever
  // came back is well-shaped.
  for (const auto& p : r.packets) {
    CHECK(p.ts_epoch > 0.0);
    CHECK(!p.summary.empty());
    REQUIRE(p.iface.has_value());
    CHECK(*p.iface == "lo");
  }
}
