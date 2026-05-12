// SPDX-License-Identifier: Apache-2.0
#pragma once

// Thin wrapper around libbpf for the `ldb-probe-agent` binary. Hides
// the C API behind a couple of RAII handles so main.cpp's command
// dispatch stays in C++ idiom.
//
// All methods report errors via `LastError` rather than exceptions —
// libbpf's failure modes (EPERM, ENOENT BTF, ELF parse failure, ...)
// are routine and need structured codes for the wire protocol to
// expose. See docs/21-probe-agent.md "Failure matrix".

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ldb::probe_agent {

struct LastError {
  std::string code;     // protocol error code (no_capability, no_btf, ...)
  std::string message;  // human-readable detail
};

// Returns the libbpf version string ("X.Y.Z"). Empty if the agent was
// built without libbpf — that path is selected at link time, but the
// header is always present so main.cpp can compile uniformly.
std::string libbpf_version_string();

// True if /sys/kernel/btf/vmlinux is readable. We don't try to mmap it;
// just a stat() check at handshake time.
bool kernel_has_btf();

// True if this binary was built with the embedded BPF skeleton.
bool has_embedded_program();

// Names of embedded BPF programs known to this build. Empty when the
// build lacked clang+bpftool at configure time.
std::vector<std::string> embedded_program_names();

class Attachment;

// Holds a loaded BPF skeleton + the ring buffer it publishes to. There
// is at most one live BpfRuntime per agent process.
class BpfRuntime {
 public:
  BpfRuntime();
  ~BpfRuntime();
  BpfRuntime(const BpfRuntime&) = delete;
  BpfRuntime& operator=(const BpfRuntime&) = delete;

  // Open + load the skeleton. Sets `err` and returns false on failure.
  // After this returns false, the BpfRuntime is in a permanent failed
  // state and must be destroyed.
  bool load(LastError* err);

  // Attach the given embedded program to the named kernel hook. Returns
  // an opaque `attach_id` on success.
  std::optional<std::string> attach_kprobe(std::string_view program,
                                           std::string_view function,
                                           LastError* err);
  std::optional<std::string> attach_uprobe(std::string_view program,
                                           std::string_view path,
                                           std::string_view symbol,
                                           std::optional<std::int64_t> pid,
                                           LastError* err);
  std::optional<std::string> attach_tracepoint(std::string_view program,
                                               std::string_view category,
                                               std::string_view name,
                                               LastError* err);

  bool detach(std::string_view attach_id, LastError* err);

  struct PolledEvent {
    std::uint64_t ts_ns = 0;
    std::int64_t  pid   = 0;
    std::int64_t  tid   = 0;
    std::vector<std::uint8_t> payload;
  };

  // Poll the ring buffer for up to `max` events. Returns the number
  // collected (which may be 0). `dropped` reflects librbf's lost-event
  // counter since last poll.
  std::size_t poll_events(std::string_view attach_id,
                          std::uint32_t max,
                          std::vector<PolledEvent>* out,
                          std::uint64_t* dropped,
                          LastError* err);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::probe_agent
