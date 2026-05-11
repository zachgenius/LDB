// SPDX-License-Identifier: Apache-2.0
#include "probe_agent/bpf_runtime.h"

#include <bpf/libbpf.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <sys/stat.h>
#include <unistd.h>

// LDB_BPF_HAS_SKELETON is set by CMake when clang + bpftool are
// available at configure time. When unset, the agent still links and
// runs, but reports embedded_programs:[] and answers attach_* with
// "not_supported". This keeps the build green on stripped hosts (no
// clang, no bpftool) while preserving the protocol surface.

#if defined(LDB_BPF_HAS_SKELETON)
#  include "probe_agent/bpf/hello.skel.h"  // generated at build time
#endif

namespace ldb::probe_agent {

std::string libbpf_version_string() {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%u.%u",
                libbpf_major_version(), libbpf_minor_version());
  return buf;
}

bool kernel_has_btf() {
  struct stat st;
  return ::stat("/sys/kernel/btf/vmlinux", &st) == 0 && S_ISREG(st.st_mode);
}

bool has_embedded_program() {
#if defined(LDB_BPF_HAS_SKELETON)
  return true;
#else
  return false;
#endif
}

std::vector<std::string> embedded_program_names() {
  std::vector<std::string> out;
#if defined(LDB_BPF_HAS_SKELETON)
  out.emplace_back("syscall_count");
#endif
  return out;
}

// ---------------------------------------------------------------------------

struct BpfRuntime::Impl {
#if defined(LDB_BPF_HAS_SKELETON)
  struct hello_bpf* skel = nullptr;
#endif
  // attach_id -> bpf_link*. Stored as opaque uintptr to dodge needing
  // the libbpf header in this header.
  std::map<std::string, struct bpf_link*> links;
  std::uint64_t next_id = 1;
};

BpfRuntime::BpfRuntime() : impl_(std::make_unique<Impl>()) {}

BpfRuntime::~BpfRuntime() {
  if (!impl_) return;
  for (auto& kv : impl_->links) {
    if (kv.second) bpf_link__destroy(kv.second);
  }
#if defined(LDB_BPF_HAS_SKELETON)
  if (impl_->skel) hello_bpf__destroy(impl_->skel);
#endif
}

bool BpfRuntime::load(LastError* err) {
#if defined(LDB_BPF_HAS_SKELETON)
  if (!kernel_has_btf()) {
    *err = {"no_btf", "/sys/kernel/btf/vmlinux not readable"};
    return false;
  }
  impl_->skel = hello_bpf__open();
  if (!impl_->skel) {
    *err = {"internal", std::string("hello_bpf__open: ") + std::strerror(errno)};
    return false;
  }
  int rc = hello_bpf__load(impl_->skel);
  if (rc != 0) {
    int e = -rc;
    if (e == EPERM || e == EACCES) {
      *err = {"no_capability", "CAP_BPF/root required to load BPF program"};
    } else {
      *err = {"internal",
              std::string("hello_bpf__load rc=") + std::to_string(rc) +
              " errno=" + std::strerror(e)};
    }
    hello_bpf__destroy(impl_->skel);
    impl_->skel = nullptr;
    return false;
  }
  return true;
#else
  (void)err;
  *err = {"not_supported",
          "agent built without an embedded BPF skeleton "
          "(install clang + bpftool and rebuild)"};
  return false;
#endif
}

#if defined(LDB_BPF_HAS_SKELETON)
namespace {

std::string make_id(std::uint64_t n) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "a%llu",
                static_cast<unsigned long long>(n));
  return buf;
}

}  // namespace
#endif

std::optional<std::string> BpfRuntime::attach_kprobe(
    std::string_view /*program*/, std::string_view /*function*/,
    LastError* err) {
#if defined(LDB_BPF_HAS_SKELETON)
  // Phase-1 embedded program does not expose a kprobe; reject cleanly
  // so the smoke test can SKIP rather than crash.
  *err = {"not_supported",
          "embedded program syscall_count has no kprobe entry"};
  return std::nullopt;
#else
  *err = {"not_supported", "no embedded BPF skeleton"};
  return std::nullopt;
#endif
}

std::optional<std::string> BpfRuntime::attach_uprobe(
    std::string_view /*program*/, std::string_view /*path*/,
    std::string_view /*symbol*/, std::optional<std::int64_t> /*pid*/,
    LastError* err) {
#if defined(LDB_BPF_HAS_SKELETON)
  *err = {"not_supported",
          "embedded program syscall_count has no uprobe entry"};
  return std::nullopt;
#else
  *err = {"not_supported", "no embedded BPF skeleton"};
  return std::nullopt;
#endif
}

std::optional<std::string> BpfRuntime::attach_tracepoint(
    std::string_view program, std::string_view /*category*/,
    std::string_view /*name*/, LastError* err) {
#if defined(LDB_BPF_HAS_SKELETON)
  if (program != "syscall_count") {
    *err = {"not_supported",
            std::string("unknown embedded program: ") + std::string(program)};
    return std::nullopt;
  }
  if (!impl_->skel) {
    *err = {"internal", "skeleton not loaded"};
    return std::nullopt;
  }
  struct bpf_link* link =
      bpf_program__attach(impl_->skel->progs.tp_sys_enter);
  if (!link) {
    int e = errno;
    if (e == EPERM || e == EACCES) {
      *err = {"no_capability", "CAP_BPF required to attach tracepoint"};
    } else {
      *err = {"internal",
              std::string("bpf_program__attach errno=") + std::strerror(e)};
    }
    return std::nullopt;
  }
  std::string id = make_id(impl_->next_id++);
  impl_->links.emplace(id, link);
  return id;
#else
  (void)program;
  *err = {"not_supported", "no embedded BPF skeleton"};
  return std::nullopt;
#endif
}

bool BpfRuntime::detach(std::string_view attach_id, LastError* err) {
  auto it = impl_->links.find(std::string(attach_id));
  if (it == impl_->links.end()) {
    *err = {"unknown_attach_id", std::string(attach_id)};
    return false;
  }
  if (it->second) bpf_link__destroy(it->second);
  impl_->links.erase(it);
  return true;
}

std::size_t BpfRuntime::poll_events(
    std::string_view attach_id, std::uint32_t /*max*/,
    std::vector<PolledEvent>* out, std::uint64_t* dropped,
    LastError* err) {
  out->clear();
  *dropped = 0;
#if defined(LDB_BPF_HAS_SKELETON)
  auto it = impl_->links.find(std::string(attach_id));
  if (it == impl_->links.end()) {
    *err = {"unknown_attach_id", std::string(attach_id)};
    return 0;
  }
  // Phase-1 program writes to a per-cpu hash counter, not a ring buffer.
  // We surface the aggregate value as a single synthetic event so the
  // smoke test can prove the pipe end-to-end. Phase-2 swaps to a real
  // BPF_MAP_TYPE_RINGBUF.
  if (!impl_->skel) return 0;
  int map_fd = bpf_map__fd(impl_->skel->maps.counts);
  if (map_fd < 0) {
    *err = {"internal", "counts map has no fd"};
    return 0;
  }
  // Sum per-cpu values for the single key (pid_tgid of any process; we
  // bucket on key=0 to keep the schema trivial for phase-1).
  std::uint32_t key = 0;
  std::uint64_t total = 0;
  int ncpu = libbpf_num_possible_cpus();
  if (ncpu < 1) ncpu = 1;
  std::vector<std::uint64_t> per_cpu(static_cast<std::size_t>(ncpu), 0);
  if (bpf_map_lookup_elem(map_fd, &key, per_cpu.data()) == 0) {
    for (auto v : per_cpu) total += v;
  }
  if (total > 0) {
    PolledEvent ev;
    ev.ts_ns = 0;  // aggregate counter — no per-event timestamp
    ev.pid   = 0;
    ev.tid   = 0;
    ev.payload.resize(8);
    for (int i = 0; i < 8; ++i) {
      ev.payload[static_cast<std::size_t>(i)] =
          static_cast<std::uint8_t>((total >> (i * 8)) & 0xff);
    }
    out->push_back(std::move(ev));
  }
  return out->size();
#else
  (void)attach_id;
  *err = {"not_supported", "no embedded BPF skeleton"};
  return 0;
#endif
}

}  // namespace ldb::probe_agent
