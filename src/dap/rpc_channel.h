#pragma once

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// RpcChannel — abstract bidirectional JSON-RPC channel for the DAP
// shim's translation layer.
//
// The shim's handlers are written against this interface so they can
// be unit-tested with a stub channel that records calls. The concrete
// implementation (`SubprocessRpcChannel`) spawns `ldbd --stdio --format
// json` and pipes line-delimited JSON-RPC over a socket pair.
//
// Concurrency:
//   * `call(method, params)` is synchronous: it writes the request,
//     drains any spurious response frames whose id doesn't match, and
//     returns the matching response.
//   * The shim is single-threaded (one DAP message at a time), so we
//     don't need a request multiplexer.

namespace ldb::dap {

using json = nlohmann::json;

// Thrown for transport-level RPC failures (channel closed, framing
// error, malformed daemon response). Distinct from a daemon-side
// `ok=false` response — those come back through `RpcResponse` with the
// error fields populated.
class RpcError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Decoded daemon response. Mirrors the ldbd `ok` field directly so
// handlers don't have to second-guess: if `ok` is true, `data` carries
// the payload; otherwise `error` does.
struct RpcResponse {
  bool ok = false;
  json data = json::object();
  int error_code = 0;
  std::string error_message;
  json error_data = json();
};

class RpcChannel {
 public:
  virtual ~RpcChannel() = default;

  // Send a JSON-RPC request and block until the matching response
  // arrives. Throws `RpcError` on transport failure.
  virtual RpcResponse call(const std::string& method, const json& params) = 0;
};

// Concrete subprocess-backed channel. Spawns `ldbd_path` with
// `["--stdio", "--format", "json"]` arguments, writes line-delimited
// JSON-RPC to its stdin, and reads responses from its stdout. The
// daemon's stderr is forwarded to the shim's stderr.
class SubprocessRpcChannel : public RpcChannel {
 public:
  // Spawn `ldbd_path` and connect. Throws `RpcError` if the binary
  // isn't executable or fork/exec fails.
  explicit SubprocessRpcChannel(const std::string& ldbd_path,
                                std::vector<std::string> extra_args = {});
  ~SubprocessRpcChannel() override;

  SubprocessRpcChannel(const SubprocessRpcChannel&) = delete;
  SubprocessRpcChannel& operator=(const SubprocessRpcChannel&) = delete;

  RpcResponse call(const std::string& method, const json& params) override;

  // Reap the child. Idempotent. Sends SIGTERM if still alive. Returns
  // the exit status; -1 if the process was already gone.
  int shutdown();

 private:
  struct Impl;
  std::unique_ptr<Impl> p_;
  std::uint64_t next_id_ = 1;
};

}  // namespace ldb::dap
