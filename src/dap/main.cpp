// ldb-dap — Debug Adapter Protocol shim for LDB.
//
// Speaks DAP on its own stdin/stdout (Content-Length-framed JSON) and
// translates each request to LDB JSON-RPC, which it forwards to a
// freshly-spawned `ldbd --stdio --format json` child. The child's
// stderr is left attached to ours so the operator sees daemon logs.
//
// Stdout discipline: this binary's stdout is the DAP channel. The
// child's stdout is the JSON-RPC channel (separate fd inside the
// shim). They never cross. Logs go to stderr.
//
// Discovery order for the ldbd binary (matches the `ldb` CLI's
// in-tree fallback):
//   1. --ldbd <path>
//   2. anywhere on PATH (`ldbd`)
//   3. ./build/bin/ldbd

#include "dap/handlers.h"
#include "dap/rpc_channel.h"
#include "dap/transport.h"
#include "ldb/version.h"
#include "util/log.h"

#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

void print_usage() {
  std::cerr <<
    "ldb-dap " << ldb::kVersionString << "\n"
    "Usage: ldb-dap [--ldbd <path>] [--log-level debug|info|warn|error]\n"
    "               [-h|--help] [--version]\n"
    "\n"
    "Speaks Debug Adapter Protocol on stdin/stdout. Spawns ldbd as a\n"
    "child subprocess for JSON-RPC translation. Stderr carries the\n"
    "shim's logs and the daemon child's stderr verbatim.\n";
}

bool parse_log_level(const std::string& s, ldb::log::Level& out) {
  if (s == "debug") { out = ldb::log::Level::kDebug; return true; }
  if (s == "info")  { out = ldb::log::Level::kInfo;  return true; }
  if (s == "warn")  { out = ldb::log::Level::kWarn;  return true; }
  if (s == "error") { out = ldb::log::Level::kError; return true; }
  return false;
}

// Resolve the ldbd executable per the documented discovery order.
// Empty string means "not found anywhere".
std::string resolve_ldbd(const std::string& cli_arg) {
  namespace fs = std::filesystem;
  if (!cli_arg.empty()) {
    if (fs::exists(cli_arg)) return cli_arg;
    return "";
  }
  // PATH search — let execvp do it lazily, but only if `ldbd` is at
  // least visible somewhere. We check each entry to short-circuit
  // before forking.
  if (const char* path = std::getenv("PATH"); path && *path) {
    std::string p(path);
    std::size_t start = 0;
    while (start <= p.size()) {
      auto end = p.find(':', start);
      std::string entry = (end == std::string::npos)
                              ? p.substr(start)
                              : p.substr(start, end - start);
      if (!entry.empty()) {
        fs::path candidate = fs::path(entry) / "ldbd";
        std::error_code ec;
        if (fs::exists(candidate, ec) &&
            ::access(candidate.c_str(), X_OK) == 0) {
          return candidate.string();
        }
      }
      if (end == std::string::npos) break;
      start = end + 1;
    }
  }
  // In-tree dev fallback.
  fs::path local = fs::path("./build/bin/ldbd");
  if (fs::exists(local) && ::access(local.c_str(), X_OK) == 0) {
    return local.string();
  }
  return "";
}

// Wrap a handler-produced body into a fully-formed DAP "response"
// envelope. Caller assigns the seq.
ldb::dap::json make_response(const ldb::dap::json& request,
                             std::int64_t seq, bool success,
                             const ldb::dap::json& body,
                             const std::string& message) {
  ldb::dap::json r = {
      {"seq", seq},
      {"type", "response"},
      {"request_seq", request.value("seq", 0)},
      {"command", request.value("command", "")},
      {"success", success},
  };
  if (!body.is_null()) r["body"] = body;
  if (!success && !message.empty()) {
    r["message"] = message;
    r["body"]    = ldb::dap::json{
        {"error", {{"id", 0}, {"format", message}}}};
  }
  return r;
}

ldb::dap::json wrap_event(const ldb::dap::json& event_template,
                          std::int64_t seq) {
  ldb::dap::json out = event_template;
  out["seq"]  = seq;
  out["type"] = "event";
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  std::string ldbd_arg;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      print_usage();
      return 0;
    } else if (a == "--version") {
      std::cout << "ldb-dap " << ldb::kVersionString << '\n';
      return 0;
    } else if (a == "--ldbd" && i + 1 < argc) {
      ldbd_arg = argv[++i];
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

  std::string ldbd_path = resolve_ldbd(ldbd_arg);
  if (ldbd_path.empty()) {
    std::cerr << "ldb-dap: cannot find ldbd. Pass --ldbd <path>, put ldbd "
                 "on PATH, or build it at ./build/bin/ldbd.\n";
    return 1;
  }
  ldb::log::info("ldb-dap " + std::string(ldb::kVersionString) +
                 " starting; ldbd=" + ldbd_path);

  std::unique_ptr<ldb::dap::SubprocessRpcChannel> channel;
  try {
    channel = std::make_unique<ldb::dap::SubprocessRpcChannel>(ldbd_path);
  } catch (const ldb::dap::RpcError& e) {
    std::cerr << "ldb-dap: failed to spawn ldbd: " << e.what() << '\n';
    return 1;
  }

  ldb::dap::Session session(*channel);
  std::int64_t out_seq = 1;

  while (true) {
    std::optional<ldb::dap::json> in_msg;
    try {
      in_msg = ldb::dap::read_dap_message(std::cin);
    } catch (const ldb::dap::Error& e) {
      ldb::log::error(std::string("DAP framing: ") + e.what());
      return 1;
    }
    if (!in_msg.has_value()) {
      ldb::log::info("client closed stdin; shutting down");
      break;
    }
    const auto& msg = *in_msg;

    if (msg.value("type", "") != "request") {
      ldb::log::warn("dropping non-request DAP message");
      continue;
    }
    std::string command = msg.value("command", "");
    ldb::dap::json args = ldb::dap::json::object();
    if (auto it = msg.find("arguments");
        it != msg.end() && (it->is_object() || it->is_array())) {
      if (it->is_object()) args = *it;
    }

    ldb::dap::DapResult result;
    try {
      result = session.dispatch(command, args);
    } catch (const ldb::dap::RpcError& e) {
      result.success = false;
      result.message = std::string("ldbd RPC error: ") + e.what();
    } catch (const std::exception& e) {
      result.success = false;
      result.message = std::string("internal error: ") + e.what();
    }

    auto response = make_response(msg, out_seq++, result.success,
                                  result.body, result.message);
    try {
      ldb::dap::write_dap_message(std::cout, response);
    } catch (const ldb::dap::Error& e) {
      ldb::log::error(std::string("write response: ") + e.what());
      return 1;
    }

    for (const auto& ev : result.events) {
      auto framed = wrap_event(ev, out_seq++);
      try {
        ldb::dap::write_dap_message(std::cout, framed);
      } catch (const ldb::dap::Error& e) {
        ldb::log::error(std::string("write event: ") + e.what());
        return 1;
      }
    }

    if (result.terminate) {
      ldb::log::info("DAP disconnect: shutting down");
      break;
    }
  }

  channel->shutdown();
  return 0;
}
