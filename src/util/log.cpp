// SPDX-License-Identifier: Apache-2.0
#include "log.h"

#include <chrono>
#include <iomanip>
#include <mutex>
#include <sstream>

namespace ldb::log {

namespace {
Level g_level = Level::kInfo;
std::mutex g_mu;

const char* tag(Level lvl) {
  switch (lvl) {
    case Level::kDebug: return "DBG";
    case Level::kInfo:  return "INF";
    case Level::kWarn:  return "WRN";
    case Level::kError: return "ERR";
  }
  return "???";
}
}  // namespace

void set_level(Level lvl) { g_level = lvl; }
Level level() { return g_level; }

void log(Level lvl, std::string_view msg) {
  if (static_cast<int>(lvl) < static_cast<int>(g_level)) return;

  using clk = std::chrono::system_clock;
  auto now = clk::now();
  auto t = clk::to_time_t(now);
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(
              now.time_since_epoch()).count() % 1'000'000;

  std::ostringstream os;
  std::tm tm_local{};
#ifdef _WIN32
  localtime_s(&tm_local, &t);
#else
  localtime_r(&t, &tm_local);
#endif
  os << std::put_time(&tm_local, "%H:%M:%S")
     << '.' << std::setw(6) << std::setfill('0') << us
     << " [" << tag(lvl) << "] " << msg;

  std::lock_guard<std::mutex> lk(g_mu);
  std::cerr << os.str() << '\n';
}

}  // namespace ldb::log
