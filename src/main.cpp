#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "daemon/stdio_loop.h"
#include "ldb/version.h"
#include "probes/probe_orchestrator.h"
#include "store/artifact_store.h"
#include "store/session_store.h"
#include "util/log.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

namespace {

void print_usage() {
  std::cerr <<
    "ldbd " << ldb::kVersionString << "\n"
    "Usage: ldbd [--stdio] [--log-level debug|info|warn|error]\n"
    "            [--store-root <path>] [-h|--help]\n"
    "\n"
    "Modes:\n"
    "  --stdio    Read JSON-RPC from stdin, write responses to stdout (default)\n"
    "\n"
    "Storage:\n"
    "  --store-root <path>   Directory for the artifact store (sqlite\n"
    "                        index + on-disk blobs). Overridden by the\n"
    "                        LDB_STORE_ROOT environment variable.\n"
    "                        Default: $HOME/.ldb\n"
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

// Resolution order (first non-empty wins): env LDB_STORE_ROOT, --store-root
// arg, $HOME/.ldb. The env var takes precedence over the CLI flag so a
// containerized launcher can pin the path without rewriting argv. If
// $HOME isn't set either, we fall back to a stable relative path
// "./.ldb" rather than scribbling on /; the operator should set one
// explicitly in that case.
std::filesystem::path resolve_store_root(const std::string& cli_arg) {
  if (const char* env = std::getenv("LDB_STORE_ROOT");
      env && *env) {
    return std::filesystem::path(env);
  }
  if (!cli_arg.empty()) return std::filesystem::path(cli_arg);
  if (const char* home = std::getenv("HOME"); home && *home) {
    return std::filesystem::path(home) / ".ldb";
  }
  return std::filesystem::path(".ldb");
}

}  // namespace

int main(int argc, char** argv) {
  bool stdio_mode = true;  // M0 has only stdio; flag is forward-compat.
  std::string store_root_arg;

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
    } else if (a == "--store-root" && i + 1 < argc) {
      store_root_arg = argv[++i];
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

  auto root = resolve_store_root(store_root_arg);
  std::shared_ptr<ldb::store::ArtifactStore> artifacts;
  try {
    artifacts = std::make_shared<ldb::store::ArtifactStore>(root);
    ldb::log::debug(std::string("artifact store at ") + root.string());
  } catch (const std::exception& e) {
    // Don't fail startup — the daemon is useful without artifact.* if
    // the store can't be opened (read-only homedir, full disk). The
    // dispatcher returns -32002 (kBadState) for any artifact.* call when
    // the store is null, so the agent gets a clear typed error.
    ldb::log::warn(std::string("artifact store unavailable: ") + e.what());
  }

  std::shared_ptr<ldb::store::SessionStore> sessions;
  try {
    sessions = std::make_shared<ldb::store::SessionStore>(root);
    ldb::log::debug(std::string("session store at ") + root.string() +
                    "/sessions");
  } catch (const std::exception& e) {
    // Same reasoning as artifact store: don't fail startup. session.*
    // returns -32002 when sessions is null.
    ldb::log::warn(std::string("session store unavailable: ") + e.what());
  }

  // Probe orchestrator. The orchestrator owns the table of active
  // probes and their callbacks; it depends on the backend (for the
  // breakpoint hooks) and optionally on the artifact store (for
  // action=store_artifact). Construction is infallible — the
  // orchestrator's lifecycle is purely in-memory in this slice.
  auto probes = std::make_shared<ldb::probes::ProbeOrchestrator>(
      backend, artifacts);

  ldb::daemon::Dispatcher dispatcher(backend, artifacts, sessions, probes);

  if (stdio_mode) {
    return ldb::daemon::run_stdio_loop(dispatcher);
  }
  return 0;
}
