#pragma once

#include "protocol/jsonrpc.h"

#include <memory>

namespace ldb::backend { class DebuggerBackend; }

namespace ldb::daemon {

// Routes a parsed Request to the appropriate handler and returns a Response.
// All handlers are synchronous in M0.
class Dispatcher {
 public:
  explicit Dispatcher(std::shared_ptr<backend::DebuggerBackend> backend);
  ~Dispatcher();

  protocol::Response dispatch(const protocol::Request& req);

 private:
  std::shared_ptr<backend::DebuggerBackend> backend_;

  // Handlers
  protocol::Response handle_hello(const protocol::Request& req);
  protocol::Response handle_describe_endpoints(const protocol::Request& req);
  protocol::Response handle_target_open(const protocol::Request& req);
  protocol::Response handle_module_list(const protocol::Request& req);
  protocol::Response handle_target_close(const protocol::Request& req);
  protocol::Response handle_type_layout(const protocol::Request& req);
};

}  // namespace ldb::daemon
