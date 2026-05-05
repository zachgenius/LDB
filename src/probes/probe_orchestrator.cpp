#include "probes/probe_orchestrator.h"

#include "store/artifact_store.h"
#include "util/log.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <deque>
#include <stdexcept>
#include <string>
#include <utility>

namespace ldb::probes {

// ProbeState is the per-probe record stored under shared_ptr inside
// the orchestrator's `probes_` map AND used as the breakpoint
// callback's baton (raw pointer is stable for the shared_ptr's
// lifetime — see header concurrency notes).
struct ProbeOrchestrator::ProbeState {
  std::string                  probe_id;
  std::string                  kind;
  std::string                  where_expr;
  ProbeSpec                    spec;
  std::int32_t                 bp_id     = 0;
  bool                         enabled   = true;
  std::uint64_t                hit_count = 0;

  // Ring buffer of recent events. We keep up to kEventBufferCap; a
  // dropped-event counter is currently not exposed (acceptable since
  // probes at MVP-scale rarely overflow), but the underlying deque is
  // bounded so memory growth is O(cap).
  std::deque<ProbeEvent>       events;

  // Pointer back to the orchestrator so the static C-callback shim
  // can find its way back to the data store. Holding by raw pointer
  // is fine because the orchestrator outlives every ProbeState
  // (orchestrator's dtor reaps everything).
  ProbeOrchestrator*           owner = nullptr;
};

namespace {

std::int64_t now_ns() {
  using clock = std::chrono::system_clock;
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             clock::now().time_since_epoch()).count();
}

std::string render_where(const backend::BreakpointSpec& w) {
  if (w.function.has_value()) return *w.function;
  if (w.address.has_value()) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(*w.address));
    return buf;
  }
  if (w.file.has_value()) {
    std::string s = *w.file;
    if (w.line.has_value() && *w.line > 0) {
      s += ":";
      s += std::to_string(*w.line);
    }
    return s;
  }
  return "<unset>";
}

// Substitute "{hit}" in a name template with the per-hit sequence
// number. Other placeholders are left alone (forward-compat for
// {pid}, {tid}, {ts} ...).
std::string substitute_hit(const std::string& templ, std::uint64_t hit) {
  std::string out;
  out.reserve(templ.size() + 8);
  std::size_t i = 0, n = templ.size();
  while (i < n) {
    if (i + 5 <= n && templ.compare(i, 5, "{hit}") == 0) {
      out += std::to_string(hit);
      i += 5;
    } else {
      out.push_back(templ[i++]);
    }
  }
  return out;
}

}  // namespace

ProbeOrchestrator::ProbeOrchestrator(
    std::shared_ptr<backend::DebuggerBackend> backend,
    std::shared_ptr<store::ArtifactStore> artifacts)
    : backend_(std::move(backend)),
      artifacts_(std::move(artifacts)) {}

ProbeOrchestrator::~ProbeOrchestrator() {
  // Reap every probe so the trampoline can never fire after `*this`
  // is gone. Errors here are logged-and-ignored — we're tearing down,
  // any individual delete failure shouldn't cascade.
  std::lock_guard<std::mutex> lk(mu_);
  for (auto& [id, st] : probes_) {
    try {
      backend_->disable_breakpoint(st->spec.target_id, st->bp_id);
    } catch (const std::exception& e) {
      log::warn(std::string("probe dtor: disable failed: ") + e.what());
    }
    try {
      backend_->delete_breakpoint(st->spec.target_id, st->bp_id);
    } catch (const std::exception& e) {
      log::warn(std::string("probe dtor: delete failed: ") + e.what());
    }
  }
  probes_.clear();
}

std::string ProbeOrchestrator::create(const ProbeSpec& spec_in) {
  if (spec_in.kind != "lldb_breakpoint") {
    throw std::invalid_argument(
        "probe.create: only kind=\"lldb_breakpoint\" is supported in this "
        "slice (uprobe_bpf is M4)");
  }
  if (spec_in.action == Action::kStoreArtifact) {
    if (spec_in.build_id.empty()) {
      throw std::invalid_argument(
          "probe.create: action=store_artifact requires non-empty build_id");
    }
    if (spec_in.artifact_name_template.empty()) {
      throw std::invalid_argument(
          "probe.create: action=store_artifact requires "
          "artifact_name_template");
    }
    if (!artifacts_) {
      throw std::invalid_argument(
          "probe.create: action=store_artifact requires the artifact store "
          "to be configured");
    }
  }
  // Backend creates the breakpoint. throws backend::Error on bad
  // target_id / no resolved location / etc.
  auto handle = backend_->create_breakpoint(spec_in.target_id, spec_in.where);

  ProbeSpec spec = spec_in;
  spec.where_expr = render_where(spec.where);

  auto st = std::make_shared<ProbeState>();
  st->kind        = spec.kind;
  st->where_expr  = spec.where_expr;
  st->spec        = std::move(spec);
  st->bp_id       = handle.bp_id;
  st->enabled     = true;
  st->owner       = this;

  std::string probe_id;
  {
    std::lock_guard<std::mutex> lk(mu_);
    probe_id = "p" + std::to_string(next_probe_seq_++);
    st->probe_id = probe_id;
    probes_.emplace(probe_id, st);
  }

  // Install the callback after the probe is in the table so the
  // trampoline-side lookup will find us. We pass the ProbeState's raw
  // pointer as the baton; lifetime is owned by the shared_ptr in the
  // table — see header.
  backend_->set_breakpoint_callback(
      st->spec.target_id, handle.bp_id,
      &ProbeOrchestrator::on_breakpoint_hit,
      static_cast<void*>(st.get()));

  return probe_id;
}

void ProbeOrchestrator::enable(const std::string& probe_id) {
  std::shared_ptr<ProbeState> st;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = probes_.find(probe_id);
    if (it == probes_.end()) {
      throw backend::Error("unknown probe_id: " + probe_id);
    }
    st = it->second;
  }
  backend_->enable_breakpoint(st->spec.target_id, st->bp_id);
  std::lock_guard<std::mutex> lk(mu_);
  st->enabled = true;
}

void ProbeOrchestrator::disable(const std::string& probe_id) {
  std::shared_ptr<ProbeState> st;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = probes_.find(probe_id);
    if (it == probes_.end()) {
      throw backend::Error("unknown probe_id: " + probe_id);
    }
    st = it->second;
  }
  backend_->disable_breakpoint(st->spec.target_id, st->bp_id);
  std::lock_guard<std::mutex> lk(mu_);
  st->enabled = false;
}

void ProbeOrchestrator::remove(const std::string& probe_id) {
  // Removal contract (see header): disable first, then delete on the
  // backend, then erase the table entry. SBBreakpoint::SetCallback
  // with nullptr inside the backend's delete unhooks the trampoline,
  // and SetEnabled(false) blocks any further callback invocations
  // before that. By the time we erase from `probes_`, no callback
  // can be in flight against the baton we're about to free.
  std::shared_ptr<ProbeState> st;
  {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = probes_.find(probe_id);
    if (it == probes_.end()) {
      throw backend::Error("unknown probe_id: " + probe_id);
    }
    st = it->second;
  }
  // Best-effort disable; if it fails the delete still proceeds and
  // the trampoline is unhooked there.
  try {
    backend_->disable_breakpoint(st->spec.target_id, st->bp_id);
  } catch (const std::exception& e) {
    log::warn(std::string("probe.remove: disable failed: ") + e.what());
  }
  backend_->delete_breakpoint(st->spec.target_id, st->bp_id);
  std::lock_guard<std::mutex> lk(mu_);
  probes_.erase(probe_id);
}

std::vector<ProbeOrchestrator::ListEntry> ProbeOrchestrator::list() {
  std::vector<ListEntry> out;
  std::lock_guard<std::mutex> lk(mu_);
  out.reserve(probes_.size());
  for (const auto& [id, st] : probes_) {
    ListEntry e;
    e.probe_id   = id;
    e.kind       = st->kind;
    e.where_expr = st->where_expr;
    e.enabled    = st->enabled;
    e.hit_count  = st->hit_count;
    out.push_back(std::move(e));
  }
  return out;
}

std::optional<ProbeOrchestrator::ListEntry>
ProbeOrchestrator::info(const std::string& probe_id) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = probes_.find(probe_id);
  if (it == probes_.end()) return std::nullopt;
  ListEntry e;
  e.probe_id   = probe_id;
  e.kind       = it->second->kind;
  e.where_expr = it->second->where_expr;
  e.enabled    = it->second->enabled;
  e.hit_count  = it->second->hit_count;
  return e;
}

std::vector<ProbeEvent>
ProbeOrchestrator::events(const std::string& probe_id,
                          std::uint64_t since, std::uint64_t max) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = probes_.find(probe_id);
  if (it == probes_.end()) {
    throw backend::Error("unknown probe_id: " + probe_id);
  }
  auto& events_buf = it->second->events;

  std::vector<ProbeEvent> out;
  out.reserve(events_buf.size());
  for (const auto& e : events_buf) {
    if (e.hit_seq <= since) continue;
    out.push_back(e);
    if (max != 0 && out.size() >= max) break;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hit handler — runs on LLDB's process-event thread.
// ---------------------------------------------------------------------------

bool ProbeOrchestrator::on_breakpoint_hit(
    void* baton, const backend::BreakpointCallbackArgs& args) {
  auto* st = static_cast<ProbeState*>(baton);
  if (!st || !st->owner) return false;
  ProbeOrchestrator* self = st->owner;

  // Build the event before taking the orchestrator lock — register
  // and memory reads can talk to the backend (which has its own
  // synchronization) and we want to release as quickly as possible.
  ProbeEvent ev;
  ev.ts_ns = now_ns();
  ev.tid   = args.tid;
  ev.pc    = args.pc;
  ev.site.function = args.function;
  ev.site.file     = args.file;
  ev.site.line     = args.line;

  // Capture registers. Unknown registers come back as 0 (backend
  // documents the conflation; it's a captured-as-zero, not an error).
  for (const auto& rname : st->spec.capture.registers) {
    auto v = self->backend_->read_register(
        st->spec.target_id, args.tid, /*frame_index=*/0, rname);
    ev.registers[rname] = v;
  }

  // Capture memory. For register-rooted reads we resolve the register
  // to an address, then read [addr, addr+len). For absolute reads we
  // read the explicit address.
  for (const auto& m : st->spec.capture.memory) {
    if (m.len == 0) continue;
    std::uint64_t addr = 0;
    if (m.source == CaptureSpec::MemSpec::Source::kRegister) {
      addr = self->backend_->read_register(
          st->spec.target_id, args.tid, /*frame_index=*/0, m.reg_name);
      if (addr == 0) continue;  // null/unset reg → skip rather than crash
    } else {
      addr = m.addr;
    }
    try {
      auto bytes = self->backend_->read_memory(
          st->spec.target_id, addr, m.len);
      ProbeEvent::MemCapture mc;
      mc.name  = m.name.empty() ? ("mem_" + std::to_string(addr)) : m.name;
      mc.bytes = std::move(bytes);
      ev.memory.push_back(std::move(mc));
    } catch (const std::exception& e) {
      log::warn(std::string("probe ") + st->probe_id +
                ": read_memory at 0x" + std::to_string(addr) +
                " failed: " + e.what());
      // Continue — partial events are better than no events.
    }
  }

  // Action == kStoreArtifact: write captured memory blobs to the
  // store. Done OUTSIDE the orchestrator lock; ArtifactStore takes
  // its own internal lock. Failures don't poison the event — we log
  // and leave the artifact_id/name fields unset.
  bool stop = (st->spec.action == Action::kStop);
  std::uint64_t hit_seq_for_action = 0;

  // Reserve hit_seq under the lock so concurrent dispatcher reads of
  // hit_count don't see a half-applied event. We don't append the
  // event to the ring yet — we may still need to call into
  // ArtifactStore::put which can be slow under heavy contention.
  {
    std::lock_guard<std::mutex> lk(self->mu_);
    st->hit_count += 1;
    hit_seq_for_action = st->hit_count;
  }
  ev.hit_seq = hit_seq_for_action;

  if (st->spec.action == Action::kStoreArtifact && self->artifacts_) {
    bool multi = ev.memory.size() > 1;
    std::size_t idx = 0;
    std::int64_t first_id = 0;
    std::string  first_name;
    for (const auto& mc : ev.memory) {
      std::string name = substitute_hit(st->spec.artifact_name_template,
                                        ev.hit_seq);
      if (multi) {
        name += "_";
        name += std::to_string(idx);
      }
      ++idx;
      try {
        auto row = self->artifacts_->put(
            st->spec.build_id, name, mc.bytes, /*format=*/std::nullopt,
            nlohmann::json::object({{"probe_id", st->probe_id},
                                    {"hit_seq", ev.hit_seq},
                                    {"capture_name", mc.name}}));
        if (first_id == 0) {
          first_id   = row.id;
          first_name = row.name;
        }
      } catch (const std::exception& e) {
        log::warn(std::string("probe ") + st->probe_id +
                  ": artifact.put '" + name + "' failed: " + e.what());
      }
    }
    if (first_id != 0) {
      ev.artifact_id   = first_id;
      ev.artifact_name = first_name;
    }
  }

  // Append to ring buffer. Bounded — drop-oldest if at cap.
  {
    std::lock_guard<std::mutex> lk(self->mu_);
    auto& buf = st->events;
    if (buf.size() >= ProbeOrchestrator::kEventBufferCap) {
      buf.pop_front();
    }
    buf.push_back(std::move(ev));
  }

  return stop;
}

}  // namespace ldb::probes
