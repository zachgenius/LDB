// SPDX-License-Identifier: Apache-2.0
#include "backend/gdbmi/backend.h"
#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "daemon/socket_loop.h"
#include "daemon/stdio_loop.h"
#include "ldb/version.h"
#include "observers/exec_allowlist.h"
#include "probes/probe_orchestrator.h"
#include "protocol/output_channel.h"
#include "protocol/transport.h"
#include "store/artifact_store.h"
#include "store/recipe_store.h"
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
    "Usage: ldbd [--stdio | --listen unix:PATH] [--format json|cbor]\n"
    "            [--log-level debug|info|warn|error]\n"
    "            [--store-root <path>]\n"
    "            [--observer-exec-allowlist <path>] [-h|--help]\n"
    "\n"
    "Modes:\n"
    "  --stdio          Read JSON-RPC from stdin, write responses to stdout\n"
    "                   (default).\n"
    "  --listen unix:PATH\n"
    "                   Bind a unix-domain socket at PATH and serve\n"
    "                   JSON-RPC connections one at a time (phase 1:\n"
    "                   single-client, persistent daemon). target_id and\n"
    "                   other dispatcher state survive across client\n"
    "                   disconnects. Access control is filesystem-only:\n"
    "                   socket mode 0600, parent dir 0700 if we create\n"
    "                   it. A `${PATH}.lock` file is taken with flock\n"
    "                   LOCK_EX|LOCK_NB to prevent two daemons binding\n"
    "                   the same path. See docs/35-field-report-followups.md\n"
    "                   §2. Mutually exclusive with --stdio.\n"
    "\n"
    "                   Default path policy when PATH is omitted by the\n"
    "                   client side (the daemon always wants an\n"
    "                   explicit PATH):\n"
    "                     $XDG_RUNTIME_DIR/ldbd.sock   (if set)\n"
    "                     $TMPDIR/ldbd-$UID.sock       (else)\n"
    "                     /tmp/ldbd-$UID.sock          (last resort)\n"
    "  --format <fmt>   Wire format on stdin/stdout. `json` (default) is\n"
    "                   line-delimited JSON. `cbor` is length-prefixed RFC\n"
    "                   8949 binary frames (4-byte big-endian uint32 length\n"
    "                   followed by N bytes of CBOR). Per-session\n"
    "                   negotiation via `hello` is post-MVP.\n"
    "\n"
    "Storage:\n"
    "  --store-root <path>   Directory for the artifact store (sqlite\n"
    "                        index + on-disk blobs). Overridden by the\n"
    "                        LDB_STORE_ROOT environment variable.\n"
    "                        Default: $HOME/.ldb\n"
    "\n"
    "Backend:\n"
    "  --backend <lldb|gdb>  Which DebuggerBackend implementation to use.\n"
    "                        Default `lldb` (LLDB SBAPI). `gdb` selects\n"
    "                        the v1.4 GdbMiBackend (gdb --interpreter=mi3\n"
    "                        subprocess; see docs/18-gdbmi-backend.md).\n"
    "                        LDB_BACKEND env takes precedence over flag.\n"
    "\n"
    "Observer policy:\n"
    "  --observer-exec-allowlist <path>\n"
    "                        Path to a plaintext file of fnmatch glob\n"
    "                        patterns enabling observer.exec. Without\n"
    "                        this flag (or LDB_OBSERVER_EXEC_ALLOWLIST)\n"
    "                        observer.exec returns -32002 on every call.\n"
    "                        Env var takes precedence over the flag.\n"
    "\n"
    "Logs go to stderr; the JSON-RPC channel is exclusive on stdout.\n";
}

bool parse_wire_format(const std::string& s, ldb::protocol::WireFormat& out) {
  if (s == "json") { out = ldb::protocol::WireFormat::kJson; return true; }
  if (s == "cbor") { out = ldb::protocol::WireFormat::kCbor; return true; }
  return false;
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

// Same precedence rule as the store root: env var beats the CLI flag,
// so a launcher can pin policy without rewriting argv. Empty string ⇒
// not configured ⇒ observer.exec returns -32002.
std::string resolve_observer_exec_allowlist(const std::string& cli_arg) {
  if (const char* env = std::getenv("LDB_OBSERVER_EXEC_ALLOWLIST");
      env && *env) {
    return env;
  }
  return cli_arg;
}

// Post-V1 #8: backend selection. Env LDB_BACKEND wins over the
// --backend flag; default `lldb`. Returns the canonical lowercase
// name ("lldb" or "gdb"), or empty string if the input was invalid.
std::string resolve_backend(const std::string& cli_arg) {
  std::string raw;
  if (const char* env = std::getenv("LDB_BACKEND"); env && *env) {
    raw = env;
  } else if (!cli_arg.empty()) {
    raw = cli_arg;
  } else {
    return "lldb";
  }
  for (auto& c : raw) c = static_cast<char>(std::tolower(c));
  if (raw == "lldb" || raw == "gdb") return raw;
  return "";
}

}  // namespace

int main(int argc, char** argv) {
  bool stdio_mode = true;  // M0 has only stdio; flag is forward-compat.
  bool listen_mode = false;
  std::string listen_socket_path;
  std::string store_root_arg;
  std::string observer_exec_allowlist_arg;
  std::string backend_arg;
  ldb::protocol::WireFormat wire_format = ldb::protocol::WireFormat::kJson;

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
    } else if (a == "--listen" && i + 1 < argc) {
      // Currently only the `unix:PATH` form is accepted. A future
      // `tcp:HOST:PORT` form would land here behind the same flag.
      std::string spec = argv[++i];
      constexpr const char* kPrefix = "unix:";
      if (spec.rfind(kPrefix, 0) != 0) {
        std::cerr << "ldbd: --listen requires a unix:PATH argument; got "
                  << spec << "\n";
        return 2;
      }
      listen_socket_path = spec.substr(std::strlen(kPrefix));
      if (listen_socket_path.empty()) {
        std::cerr << "ldbd: --listen unix: requires a non-empty PATH\n";
        return 2;
      }
      listen_mode = true;
      stdio_mode = false;
    } else if (a == "--format" && i + 1 < argc) {
      if (!parse_wire_format(argv[++i], wire_format)) {
        std::cerr << "invalid format: " << argv[i]
                  << " (expected json|cbor)\n";
        return 2;
      }
    } else if (a == "--log-level" && i + 1 < argc) {
      ldb::log::Level lvl;
      if (!parse_log_level(argv[++i], lvl)) {
        std::cerr << "invalid log level: " << argv[i] << '\n';
        return 2;
      }
      ldb::log::set_level(lvl);
    } else if (a == "--store-root" && i + 1 < argc) {
      store_root_arg = argv[++i];
    } else if (a == "--observer-exec-allowlist" && i + 1 < argc) {
      observer_exec_allowlist_arg = argv[++i];
    } else if (a == "--backend" && i + 1 < argc) {
      backend_arg = argv[++i];
    } else {
      std::cerr << "unknown argument: " << a << "\n\n";
      print_usage();
      return 2;
    }
  }

  ldb::log::info(std::string("ldbd ") + ldb::kVersionString + " starting");

  std::string backend_name = resolve_backend(backend_arg);
  if (backend_name.empty()) {
    std::cerr << "invalid backend (expected lldb|gdb)\n";
    return 2;
  }
  std::shared_ptr<ldb::backend::DebuggerBackend> backend;
  try {
    if (backend_name == "gdb") {
      backend = std::make_shared<ldb::backend::gdbmi::GdbMiBackend>();
    } else {
      backend = std::make_shared<ldb::backend::LldbBackend>();
    }
    ldb::log::info(std::string("backend: ") + backend_name);
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

  // Post-V1 plan #3: file-backed recipes. If LDB_RECIPE_DIR is set on
  // startup, scan it for *.json files and load each as a recipe. The
  // scan never fails the daemon — malformed files are logged to stderr
  // and skipped, since the dispatcher's recipe.* endpoints remain
  // perfectly usable without any file-backed recipes.
  if (artifacts) {
    if (const char* dir_env = std::getenv("LDB_RECIPE_DIR");
        dir_env && *dir_env != '\0') {
      try {
        ldb::store::RecipeStore rs(*artifacts);
        auto results = rs.load_from_directory(std::filesystem::path(dir_env));
        std::size_t ok = 0, err = 0;
        for (const auto& sr : results) {
          if (sr.error.empty()) {
            ++ok;
          } else {
            ++err;
            ldb::log::warn(std::string("recipe scan: ") +
                           sr.path.string() + " — " + sr.error);
          }
        }
        ldb::log::info(std::string("recipe scan: ") + dir_env + " — " +
                       std::to_string(ok) + " loaded, " +
                       std::to_string(err) + " errored");
      } catch (const std::exception& e) {
        ldb::log::warn(std::string("recipe scan failed: ") + e.what());
      }
    }
  }

  // Probe orchestrator. The orchestrator owns the table of active
  // probes and their callbacks; it depends on the backend (for the
  // breakpoint hooks) and optionally on the artifact store (for
  // action=store_artifact). Construction is infallible — the
  // orchestrator's lifecycle is purely in-memory in this slice.
  auto probes = std::make_shared<ldb::probes::ProbeOrchestrator>(
      backend, artifacts);

  // observer.exec policy. Off by default; the operator opts in by
  // pointing at a plaintext file of fnmatch glob patterns. We log
  // (stderr) on either path so the operator gets one-line confirmation
  // of policy at startup. If the file is configured but missing, we
  // log and continue with no allowlist — the dispatcher's -32002 path
  // still fires, and the agent never silently runs anything.
  std::shared_ptr<ldb::observers::ExecAllowlist> exec_allowlist;
  {
    std::string al_path = resolve_observer_exec_allowlist(
        observer_exec_allowlist_arg);
    if (!al_path.empty()) {
      auto al = ldb::observers::ExecAllowlist::from_file(al_path);
      if (al.has_value()) {
        exec_allowlist = std::make_shared<ldb::observers::ExecAllowlist>(
            std::move(*al));
        ldb::log::info("observer.exec allowlist loaded from " + al_path
                       + " (" + std::to_string(exec_allowlist->pattern_count())
                       + " patterns)");
      } else {
        ldb::log::warn("observer.exec allowlist file not readable: " + al_path
                       + " — observer.exec will return -32002");
      }
    }
  }

  ldb::daemon::Dispatcher dispatcher(backend, artifacts, sessions, probes,
                                     exec_allowlist, backend_name);

  if (listen_mode) {
    // §2 phase 1: listen mode owns its own per-connection OutputChannel.
    // run_socket_listener installs and removes the notification sink
    // around each accept()ed connection so async notifications go to
    // the right peer. No stdout writer is created at startup.
    return ldb::daemon::run_socket_listener(dispatcher, listen_socket_path,
                                            wire_format);
  }

  // Post-V1 #21 phase-2 (docs/27): single stdout writer with mutex;
  // the listener thread's thread.event notifications and the
  // dispatcher's replies funnel through this so they never byte-
  // interleave. The sink is borrowed by the dispatcher; both live
  // for the duration of main(), so the borrow is stable.
  ldb::protocol::OutputChannel out(std::cout, wire_format);
  ldb::protocol::StreamNotificationSink notif_sink(out);
  dispatcher.set_notification_sink(&notif_sink);

  if (stdio_mode) {
    return ldb::daemon::run_stdio_loop(dispatcher, out, wire_format);
  }
  return 0;
}
