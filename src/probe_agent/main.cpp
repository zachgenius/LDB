// SPDX-License-Identifier: Apache-2.0
//
// `ldb-probe-agent` — privileged BPF helper for ldbd.
//
// Stdio protocol: length-prefixed JSON frames (docs/21-probe-agent.md).
// Stdout is reserved for protocol frames. Logs go to stderr.

#include "probe_agent/bpf_runtime.h"
#include "probe_agent/protocol.h"

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

namespace pa = ldb::probe_agent;
using json = nlohmann::json;

namespace {

void log_stderr(const std::string& s) {
  std::fprintf(stderr, "ldb-probe-agent: %s\n", s.c_str());
}

json make_error(const std::string& code, const std::string& message) {
  json j;
  j["type"]    = "error";
  j["code"]    = code;
  j["message"] = message;
  return j;
}

json make_hello_ok() {
  json j;
  j["type"]              = "hello_ok";
  j["version"]           = "1";
  j["libbpf_version"]    = pa::libbpf_version_string();
  j["btf_present"]       = pa::kernel_has_btf();
  j["embedded_programs"] = pa::embedded_program_names();
  return j;
}

bool send_frame(const json& j) {
  std::string body = j.dump();
  return pa::write_frame(std::cout, body);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 1 && std::string(argv[1]) == "--version") {
    // Minimal version output — single line on stdout, allowed because
    // this is not the protocol mode. Once the protocol loop starts,
    // nothing but length-prefixed frames go to stdout.
    std::printf("ldb-probe-agent libbpf %s btf=%s embedded=%zu\n",
                pa::libbpf_version_string().c_str(),
                pa::kernel_has_btf() ? "yes" : "no",
                pa::embedded_program_names().size());
    return 0;
  }
  // Disable iostream sync — we never mix C stdio with C++ streams on
  // the protocol channel, and the speedup matters when an attached
  // probe is firing.
  std::ios_base::sync_with_stdio(false);

  std::unique_ptr<pa::BpfRuntime> runtime;

  while (true) {
    // If a prior send_frame hit a broken pipe (daemon died, parent
    // closed stdout), std::cout enters a fail state and every
    // subsequent write_frame returns false silently. Without this
    // gate the loop would spin reading frames + dropping responses
    // until stdin closed too. Bail out as soon as the channel
    // becomes one-way unusable.
    if (!std::cout) {
      log_stderr("stdout closed; exiting protocol loop");
      return 0;
    }
    std::string body;
    auto ferr = pa::read_frame(std::cin, &body);
    if (ferr == pa::FrameError::kEof) break;
    if (ferr != pa::FrameError::kOk) {
      log_stderr("frame error; closing channel");
      return 1;
    }

    json req;
    try {
      req = json::parse(body);
    } catch (const std::exception& e) {
      send_frame(make_error("internal", std::string("parse: ") + e.what()));
      continue;
    }

    auto type_it = req.find("type");
    if (type_it == req.end() || !type_it->is_string()) {
      send_frame(make_error("internal", "missing 'type'"));
      continue;
    }
    std::string type = type_it->get<std::string>();

    if (type == "hello") {
      send_frame(make_hello_ok());
      continue;
    }
    if (type == "shutdown") {
      json bye;
      bye["type"] = "bye";
      send_frame(bye);
      break;
    }

    // Every other command needs a loaded BPF runtime.
    if (!runtime) {
      runtime = std::make_unique<pa::BpfRuntime>();
      pa::LastError err;
      if (!runtime->load(&err)) {
        send_frame(make_error(err.code, err.message));
        runtime.reset();  // unusable; recreate on next attempt
        continue;
      }
    }

    if (type == "attach_uprobe") {
      pa::LastError err;
      auto id = runtime->attach_uprobe(
          req.value("program", ""),
          req.value("path", ""),
          req.value("symbol", ""),
          req.contains("pid") ? std::optional<std::int64_t>(req["pid"].get<std::int64_t>())
                              : std::nullopt,
          &err);
      if (!id) { send_frame(make_error(err.code, err.message)); continue; }
      json j; j["type"] = "attached"; j["attach_id"] = *id;
      send_frame(j);
      continue;
    }
    if (type == "attach_kprobe") {
      pa::LastError err;
      auto id = runtime->attach_kprobe(req.value("program", ""),
                                       req.value("function", ""), &err);
      if (!id) { send_frame(make_error(err.code, err.message)); continue; }
      json j; j["type"] = "attached"; j["attach_id"] = *id;
      send_frame(j);
      continue;
    }
    if (type == "attach_tracepoint") {
      pa::LastError err;
      auto id = runtime->attach_tracepoint(req.value("program", ""),
                                           req.value("category", ""),
                                           req.value("name", ""), &err);
      if (!id) { send_frame(make_error(err.code, err.message)); continue; }
      json j; j["type"] = "attached"; j["attach_id"] = *id;
      send_frame(j);
      continue;
    }
    if (type == "detach") {
      pa::LastError err;
      if (!runtime->detach(req.value("attach_id", ""), &err)) {
        send_frame(make_error(err.code, err.message));
        continue;
      }
      json j; j["type"] = "detached";
      send_frame(j);
      continue;
    }
    if (type == "poll_events") {
      pa::LastError err;
      std::vector<pa::BpfRuntime::PolledEvent> evs;
      std::uint64_t dropped = 0;
      std::uint32_t max =
          req.contains("max") ? req["max"].get<std::uint32_t>() : 64u;
      std::size_t n = runtime->poll_events(req.value("attach_id", ""),
                                           max, &evs, &dropped, &err);
      if (!err.code.empty()) {
        send_frame(make_error(err.code, err.message));
        continue;
      }
      json j;
      j["type"]    = "events";
      j["dropped"] = dropped;
      json arr = json::array();
      for (std::size_t i = 0; i < n; ++i) {
        const auto& ev = evs[i];
        json e;
        e["ts_ns"]       = ev.ts_ns;
        e["pid"]         = ev.pid;
        e["tid"]         = ev.tid;
        e["payload_b64"] = pa::base64_encode(ev.payload.data(),
                                             ev.payload.size());
        arr.push_back(std::move(e));
      }
      j["events"] = std::move(arr);
      send_frame(j);
      continue;
    }

    send_frame(make_error("internal", std::string("unknown type: ") + type));
  }

  return 0;
}
