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
  protocol::Response handle_target_create_empty(const protocol::Request& req);
  protocol::Response handle_target_attach(const protocol::Request& req);
  protocol::Response handle_target_load_core(const protocol::Request& req);
  protocol::Response handle_module_list(const protocol::Request& req);
  protocol::Response handle_target_close(const protocol::Request& req);
  protocol::Response handle_type_layout(const protocol::Request& req);
  protocol::Response handle_symbol_find(const protocol::Request& req);
  protocol::Response handle_string_list(const protocol::Request& req);
  protocol::Response handle_disasm_range(const protocol::Request& req);
  protocol::Response handle_disasm_function(const protocol::Request& req);
  protocol::Response handle_xref_addr(const protocol::Request& req);
  protocol::Response handle_string_xref(const protocol::Request& req);

  protocol::Response handle_process_launch(const protocol::Request& req);
  protocol::Response handle_process_state(const protocol::Request& req);
  protocol::Response handle_process_continue(const protocol::Request& req);
  protocol::Response handle_process_kill(const protocol::Request& req);
  protocol::Response handle_process_detach(const protocol::Request& req);
  protocol::Response handle_process_save_core(const protocol::Request& req);

  protocol::Response handle_thread_list(const protocol::Request& req);
  protocol::Response handle_thread_frames(const protocol::Request& req);

  protocol::Response handle_frame_locals(const protocol::Request& req);
  protocol::Response handle_frame_args(const protocol::Request& req);
  protocol::Response handle_frame_registers(const protocol::Request& req);

  protocol::Response handle_mem_read(const protocol::Request& req);
  protocol::Response handle_mem_read_cstr(const protocol::Request& req);
  protocol::Response handle_mem_regions(const protocol::Request& req);
  protocol::Response handle_mem_search(const protocol::Request& req);
};

}  // namespace ldb::daemon
