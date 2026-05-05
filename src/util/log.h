#pragma once

#include <iostream>
#include <string_view>

namespace ldb::log {

// Logs go to stderr — stdout is reserved for the JSON-RPC channel.
// Minimal logger for M0; will swap for spdlog later.

enum class Level { kDebug, kInfo, kWarn, kError };

void set_level(Level lvl);
Level level();

void log(Level lvl, std::string_view msg);

inline void debug(std::string_view m) { log(Level::kDebug, m); }
inline void info(std::string_view m)  { log(Level::kInfo,  m); }
inline void warn(std::string_view m)  { log(Level::kWarn,  m); }
inline void error(std::string_view m) { log(Level::kError, m); }

}  // namespace ldb::log
