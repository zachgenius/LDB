#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "daemon/stdio_loop.h"
#include "ldb/version.h"
#include "util/log.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

namespace {

void print_usage() {
  std::cerr <<
    "ldbd " << ldb::kVersionString << "\n"
    "Usage: ldbd [--stdio] [--log-level debug|info|warn|error] [-h|--help]\n"
    "\n"
    "Modes:\n"
    "  --stdio    Read JSON-RPC from stdin, write responses to stdout (default)\n"
    "\n"
    "Logs go to stderr; the JSON-RPC channel is exclusive on stdout.\n";
}

bool parse_log_level(const std::string& s, ldb::log::Level& out) {
  if (s == "debug") { out = ldb::log::Level::kDebug; return true; }
  if (s == "info")  { out = ldb::log::Level::kInfo;  return true; }
  if (s == "warn")  { out = ldb::log::Level::kWarn;  return true; }
  if (s == "error") { out = ldb::log::Level::kError; return true; }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  bool stdio_mode = true;  // M0 has only stdio; flag is forward-compat.

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      print_usage();
      return 0;
    } else if (a == "--version") {
      std::cout << ldb::kVersionString << '\n';
      return 0;
    } else if (a == "--stdio") {
      stdio_mode = true;
    } else if (a == "--log-level" && i + 1 < argc) {
      ldb::log::Level lvl;
      if (!parse_log_level(argv[++i], lvl)) {
        std::cerr << "invalid log level: " << argv[i] << '\n';
        return 2;
      }
      ldb::log::set_level(lvl);
    } else {
      std::cerr << "unknown argument: " << a << "\n\n";
      print_usage();
      return 2;
    }
  }

  ldb::log::info(std::string("ldbd ") + ldb::kVersionString + " starting");

  std::shared_ptr<ldb::backend::DebuggerBackend> backend;
  try {
    backend = std::make_shared<ldb::backend::LldbBackend>();
  } catch (const std::exception& e) {
    ldb::log::error(std::string("backend init failed: ") + e.what());
    return 1;
  }

  ldb::daemon::Dispatcher dispatcher(backend);

  if (stdio_mode) {
    return ldb::daemon::run_stdio_loop(dispatcher);
  }
  return 0;
}
