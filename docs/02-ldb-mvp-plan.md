# LDB MVP Plan

> Scope: 8–10 weeks of focused work. Outcome: an LLM agent can complete the user's stated reverse-engineering workflow end-to-end against a Linux x86-64 unstripped binary, locally and over SSH, without touching `gdb`, `pahole`, `objdump`, `strings`, `strace`, `tcpdump`, or `ss` directly.
> Reference workflow this MVP must execute autonomously: static struct recovery → passive probe → stub responder iteration → live attach → memory extraction (the `btp_schema.xml`-from-memory case).

---

## 1. Goals & non-goals

### Goals (must-haves)

- Single C++17/20 daemon `ldbd` exposing a schema-first protocol over stdio + TCP.
- LLDB SBAPI as the in-process debug + static-analysis backend.
- Live attach, core-dump postmortem, and binary-only static analysis through one surface.
- Probes (auto-resuming breakpoints with structured capture) for low-rate functions.
- eBPF/uprobe shim for high-rate libc/syscall tracing.
- Typed observers for `/proc`, `ss`, `tcpdump`, `igmp`, `lsof`-style data.
- Build-ID-keyed, portable artifact store with sqlite index.
- Sqlite-backed session log; every RPC is replayable.
- Remote target via `lldb-server platform` + optional `ldb-probe-agent`.
- macOS arm64 builds and runs (parity through SBAPI; not separately optimized).

### Non-goals (explicitly deferred)

- Windows / PDB.
- ARM64 Linux, RISC-V (will likely work via LLDB but not validated).
- Kernel debugging.
- Reverse execution / record-replay.
- Custom probe DSL — agent issues call sequences, session log captures them as recipes.
- IDE / DAP compatibility shim.
- Web UI.
- Pretty-printer ecosystem (pre-built std lib formatters).
- JIT runtime debugging (V8/JVM/Python).
- Multi-tenant daemon (one user, one daemon for now).

---

## 2. Architecture

```
┌──────────────────────────────────────────────────┐
│  LLM agent host  /  human via ldb CLI            │
└──────────────────────────────────────────────────┘
                ↕  CBOR (binary) | JSON (compact/tabular)
┌──────────────────────────────────────────────────┐
│  ldbd  — C++17/20 daemon, runs on operator host  │
│  • Protocol server (stdio + TCP)                 │
│  • Session manager (sqlite WAL log)              │
│  • Artifact store (build-ID keyed, .ldbpack)     │
│  • View descriptor engine                        │
│  • Probe orchestrator                            │
│  • Typed observer plugins                        │
│  • Embedded Python (extension scripts only)      │
│  • DebuggerBackend abstraction                   │
└──────────────────────────────────────────────────┘
       ↓                                    ↓
  liblldb (SBAPI in-process)           SSH transport
       ↓                                    ↓
  local target / core file        remote target host:
                                    • lldb-server platform
                                    • ldb-probe-agent (opt.)
                                    • typed observer probes
                                       (strace, ss, tcpdump, /proc)
```

**Key invariant:** `ldbd` runs on the operator's machine. The target host runs only standard tools (`lldb-server`, plus the small `ldb-probe-agent` static binary when needed). No daemon code on the target.

---

## 3. Protocol

### 3.1 Wire format

Content-negotiated, three modes:

| Mode | When | Notes |
|---|---|---|
| `application/cbor` | Tooling clients | RFC 8949. Default for non-LLM clients. Streaming via indefinite-length arrays. |
| `application/json` | Human inspection | Pretty-printed. Default for `ldb` CLI in interactive mode. |
| `application/json; profile=compact` | LLM agents | Whitespace-stripped, short keys, omit-nulls. Tabular mode for arrays of homogeneous structs. |

Negotiated by first message (`hello`) or per-request `format` field.

### 3.2 Request / response shape

JSON-RPC 2.0 framing with extensions. Each request:

```json
{ "id": "r7", "method": "type.layout", "params": {...},
  "view": {...}, "format": "compact" }
```

Each response:

```json
{ "id": "r7", "ok": true, "data": {...},
  "_cost": {"bytes": 1842, "items": 14, "tokens_est": 480},
  "_provenance": {"build_id": "...", "snapshot": "s4",
                  "deterministic": true} }
```

Streaming responses use NDJSON-over-CBOR-streams: one frame per chunk, terminated by `{"id":"r7","done":true}`.

Errors carry a typed `error.code` from a fixed enum (so the agent can match on code, not prose).

### 3.3 View descriptors

Every method that returns structured data accepts `view`:

```json
{ "fields": ["off", "sz", "name"],   // projection
  "limit": 100, "cursor": "...",      // pagination
  "summary": false,                   // counts + sample only
  "max_string": 1024,                 // cap embedded strings
  "max_bytes": 4096,                  // cap embedded byte buffers
  "tabular": true }                   // emit cols+rows for arrays
```

This is the single biggest token-saving lever — bigger than format choice.

### 3.4 Sessions

A session is a sqlite database (`~/.ldb/sessions/<uuid>.db`) holding the RPC log plus side-state. Methods:

- `session.create({name, target?})` → `{id}`
- `session.attach({id})` — every subsequent call belongs to it
- `session.fork({id, at_call?})` — branch from a known-good point
- `session.list()`, `session.export({id})` → `.ldbsession` tarball, `session.import(...)`
- `session.replay({id, until?})` — re-issue logged calls; useful for verifying determinism

### 3.5 Provenance

Every response carries `_provenance.snapshot` — a stable identifier of the inferior state at fetch time. For cores it's the file hash; for live processes it's a counter that bumps on every resume + a register-snapshot hash. Identical `(method, params, snapshot)` MUST yield byte-identical `data`. We test this in CI.

---

## 4. RPC surface (MVP endpoints)

Three groups (Static / Dynamic / Memory & Extraction), per the consultant's phase split, plus session/artifact infrastructure.

### 4.1 Target & module

| Method | Purpose |
|---|---|
| `target.open({path})` | Create SBTarget without a process; module + DWARF available |
| `target.attach({pid})` | Attach to live process |
| `target.load_core({path})` | Postmortem load |
| `target.connect_remote({url})` | Connect to `lldb-server` |
| `target.close({})` | Tear down |
| `module.list({})` | Loaded modules: path, build_id, slide, sections |
| `module.section({mod, name})` | Section bytes / metadata |

### 4.2 Static / DWARF (replaces `pahole`, `ptype`, `nm`, `readelf`, `strings`)

| Method | Replaces | Returns |
|---|---|---|
| `type.layout({name})` | `pahole` | `{name, byte_size, fields:[{name, type, off, sz, holes_after}], holes_total, padding_total}` |
| `type.info({name})` | `ptype` | nested struct expansion, with cycle protection |
| `type.find({pattern, kind?})` | `nm`-ish | matching types |
| `symbol.find({pattern, kind?})` | `nm` | `{name, addr, size, kind, mangled, demangled, source_line?}` |
| `symbol.at({addr})` | `addr2line`, `nm` | reverse-lookup of an address |
| `string.list({section?, min_len})` | `strings` | strings + addresses |
| `string.xref({addr_or_text})` | `strings` + grep + objdump | callsites referencing the string |
| `disasm.range({start, end})` | `objdump -d` | `{addr, bytes, mnemonic, ops, comment, target?}[]` |
| `disasm.function({name})` | `objdump -d --disassemble=foo` | function-bounded |
| `xref.imm({value})` | grep over disasm | instructions referencing immediate |
| `xref.addr({addr})` | grep over disasm | instructions referencing address |
| `line.from_addr({addr})`, `line.to_addr({file, line})` | DWARF line tables | source ↔ PC |

`type.layout` JSON shape (as agreed with the consultant, with our additions):

```json
{
  "name": "dxp_login_frame",
  "byte_size": 128,
  "alignment": 8,
  "fields": [
    {"name":"magic","type":"uint32_t","off":0,"sz":4,"holes_after":0},
    {"name":"sid","type":"uint64_t","off":8,"sz":8,"holes_after":0,
     "padding_before":4}
  ],
  "holes_total": 4,
  "padding_total": 4
}
```

### 4.3 Process / thread / frame / value

| Method | Purpose |
|---|---|
| `process.state({})` | running/stopped/exited + last stop reason |
| `process.resume({})` / `process.stop({})` / `process.step({kind})` | control |
| `thread.list({})` | threads with state, name |
| `thread.frames({tid, depth})` | backtrace, projected via view |
| `frame.locals({tid, fid})` | local vars, lazy |
| `frame.args({tid, fid})` | function args |
| `frame.registers({tid, fid, set?})` | gpr/fpr/vector sets |
| `value.eval({expr, frame?})` | LLDB expression eval (Clang) |
| `value.read({path, view})` | structured read of a typed value tree |

### 4.4 Memory

| Method | Purpose |
|---|---|
| `mem.read({addr, len, view})` | bytes (chunked when big) |
| `mem.read_cstr({addr, max})` | NUL-terminated, capped |
| `mem.search({addr?, len?, pattern, regex?})` | regex/byte search; multiple hits with offsets |
| `mem.regions({})` | mapped regions w/ permissions |
| `mem.dump_artifact({addr, len, name, format?})` | read + store as artifact in one call |

### 4.5 Probes (replaces `strace` for low-rate; auto-resuming breakpoints)

```json
// probe.create
{
  "kind": "lldb_breakpoint",            // or "uprobe_bpf"
  "where": {"function": "init_schema"}, // or {"address":"0x..."} or {"file":"...", "line": 42}
  "capture": {
    "registers": ["rdi","rsi","rdx"],
    "memory": [{"reg":"rdi","len":4096}],
    "args_typed": ["const char*", "size_t"]   // pulls via SBValue
  },
  "action": "log_and_continue",         // or "stop", or "store_artifact"
  "artifact_name": "schema_dump_{hit}.bin",
  "rate_limit": "100/s"
}
→ {"probe_id":"p3"}
```

Subsequent calls:

- `probe.events({probe_id, since?, view})` — pull captured events (paginated).
- `probe.disable({probe_id})`, `probe.delete({probe_id})`.
- `probe.list({})`.

Behind the scenes:
- `lldb_breakpoint` → `SBBreakpoint::SetScriptCallbackBody` returning `False` to auto-resume.
- `uprobe_bpf` → spawn `bpftrace` (or our own libbpf-based `ldb-probe-agent`) on the target via SSH, structured stdout streamed back as events.

Same JSON event shape regardless of backend. The agent picks the kind via heuristic: high-rate / syscall-level → BPF; semantic / app-level → LLDB.

### 4.6 Typed observers (replaces `run_host_command`)

Whitelisted, typed; each parses the host data into structured JSON.

| Method | What it reads |
|---|---|
| `observer.proc.fds({pid})` | `/proc/<pid>/fd` enumerated, with type and remote endpoint |
| `observer.proc.maps({pid})` | `/proc/<pid>/maps` parsed |
| `observer.proc.status({pid})` | parsed `status` |
| `observer.net.sockets({filter})` | `ss -tunap` parsed |
| `observer.net.igmp({})` | `/proc/net/igmp` parsed |
| `observer.net.tcpdump({iface, bpf, count, snaplen})` | live capture, structured per-packet |
| `observer.exec({cmd, allowlisted})` | escape hatch — only if `cmd` is in operator-configured allowlist |

All run on the target host via the SSH transport (or locally if target is local).

### 4.7 Artifacts

| Method | Purpose |
|---|---|
| `artifact.put({build_id, name, bytes, format?, meta?})` | store |
| `artifact.get({build_id, name})` | fetch |
| `artifact.list({build_id?, name_pattern?})` | enumerate |
| `artifact.export({build_id?})` → `.ldbpack` | portable tarball |
| `artifact.import({path})` | merge a `.ldbpack` |
| `artifact.tag({id, tags})` | annotate |

Stored at `~/.ldb/builds/<build-id>/artifacts/...` with sqlite index `~/.ldb/index.db` for cross-build search.

### 4.8 Capability advertisement

`describe.endpoints()` returns the full method catalog with parameter schemas, return schemas, cost hints, and which require the inferior to be stopped. Agents call this once per session to know what's available; they don't hardcode.

---

## 5. The reference workflow as RPC trace

This is the user's stated workflow expressed in MVP calls — the acceptance test for "MVP done."

```
target.open({path:"/usr/bin/quoter"})
module.list({})                          → confirms build-id, sections
type.layout({name:"dxp_login_frame"})    → struct layout
string.list({section:".rodata", min_len:6})
string.xref({addr_or_text:"btp_schema.xml"})
                                         → callsite in init_schema
disasm.function({name:"init_schema"})
                                         → identifies arg-1 buffer
target.attach({pid:31415})               // or target.connect_remote(...)
probe.create({
  kind:"lldb_breakpoint",
  where:{function:"xml_parse"},
  capture:{registers:["rdi"], memory:[{reg:"rdi", len:8192}]},
  action:"store_artifact",
  artifact_name:"btp_schema.xml"
})
process.resume({})
                                         (binary handshakes; bp fires; auto-continues)
probe.events({probe_id:"p3", view:{summary:true}})
                                         → 1 hit, artifact stored
artifact.get({build_id:"<bid>", name:"btp_schema.xml"})
                                         → the XML payload
observer.net.tcpdump({iface:"eth0", bpf:"port 9001", count:200})
                                         → wire frames for stub validation
observer.proc.fds({pid:31415})           → confirms FD lifetimes
session.export({id:"<sid>"})             → portable record of the investigation
```

This sequence — and only this sequence — is the MVP acceptance test. If a Claude / Codex / Cursor agent can run this autonomously against a real binary, MVP is done.

---

## 6. The DebuggerBackend abstraction

Even though MVP only ships LLDB, the daemon is built against an abstract interface so v0.3 GDB and v1.0 native backends slot in without rewrites.

```cpp
// ldb/backend/debugger_backend.h  (sketch)
class DebuggerBackend {
public:
  virtual ~DebuggerBackend() = default;

  // Target lifecycle
  virtual TargetH    open_executable(std::string_view path) = 0;
  virtual TargetH    load_core(std::string_view path) = 0;
  virtual ProcessH   attach_pid(TargetH, pid_t) = 0;
  virtual ProcessH   connect_remote(TargetH, std::string_view url) = 0;
  virtual void       detach(ProcessH) = 0;

  // Static
  virtual std::vector<ModuleInfo>  modules(TargetH) = 0;
  virtual std::optional<TypeInfo>  find_type(TargetH, std::string_view) = 0;
  virtual std::vector<SymbolInfo>  find_symbol(TargetH, const SymbolQuery&) = 0;
  virtual SectionData              read_section(TargetH, std::string_view mod,
                                                std::string_view sec) = 0;
  virtual std::vector<DisasmInsn>  disassemble(TargetH, addr_t, size_t) = 0;

  // Dynamic
  virtual ProcessState process_state(ProcessH) = 0;
  virtual void         resume(ProcessH) = 0;
  virtual void         stop(ProcessH) = 0;
  virtual std::vector<ThreadInfo> threads(ProcessH) = 0;
  virtual std::vector<FrameInfo>  frames(ThreadH, size_t depth) = 0;
  virtual std::vector<VarInfo>    locals(FrameH) = 0;
  virtual ValueResult             eval(FrameH, std::string_view expr) = 0;
  virtual std::vector<uint8_t>    read_memory(ProcessH, addr_t, size_t) = 0;

  // Probes
  virtual ProbeH       create_breakpoint(ProcessH, const ProbeSpec&,
                                         ProbeCallback) = 0;
  virtual void         disable(ProbeH) = 0;
  virtual void         remove(ProbeH) = 0;

  // Snapshots & determinism
  virtual SnapshotId   snapshot(ProcessH) = 0;
};
```

`LldbBackend` implements this against SBAPI. `GdbMiBackend` (v0.3) implements it by spawning `gdb --interpreter=mi3`. `NativeBackend` (post-v1) is hypothetical.

---

## 7. Probe orchestrator details

Two engines, one event shape:

### 7.1 `lldb_breakpoint` engine

`SBBreakpoint::SetScriptCallbackBody` accepts a Python source string. We embed a small Python helper that:

```python
def __ldb_probe_cb_<id>(frame, bp_loc, internal_dict):
    # captures registers, reads memory, posts event over a unix socket
    # back to ldbd, returns False to auto-continue
    ...
    return False
```

The unix socket goes to a thread inside `ldbd` that drains events into the per-probe ring buffer.

For low-rate functions this is fine. We measure overhead in CI.

### 7.2 `uprobe_bpf` engine

For high-rate libc/syscall tracing on Linux, we spawn `bpftrace` (or our own `ldb-probe-agent`) on the target with a generated program like:

```
uprobe:/lib/x86_64-linux-gnu/libc.so.6:bind {
  printf("{\"ts\":%lu,\"tid\":%d,\"fd\":%d}\n", nsecs, tid, arg0);
}
```

Stdout is parsed and emitted as the same `ProbeEvent` shape. Rate limits are honored at the BPF side via `count` maps when possible.

We ship `ldb-probe-agent` as a static x86-64 binary that the daemon scp's to the target on first use; it's a thin libbpf-based wrapper that takes a program spec and emits structured events. This avoids requiring `bpftrace` on locked-down hosts.

### 7.3 Event shape

```json
{
  "probe_id": "p3",
  "hit_seq": 42,
  "ts_ns": 17304219831921,
  "tid": 1234,
  "pc": "0x412af0",
  "registers": {"rdi":"0x7fff...", ...},
  "memory": [{"name":"rdi_buf","bytes":"<base64>"}],
  "args_typed": [{"name":"buf","type":"const char*","value":"..."}],
  "site": {"function":"init_schema","file":"q.c","line":221}
}
```

Same regardless of engine.

---

## 8. Artifact store layout

```
~/.ldb/
├── index.db                 # sqlite: artifacts, sessions, builds, tags
├── builds/
│   └── <build-id>/
│       ├── meta.json        # path, arch, dwarf-version, observed-at
│       ├── artifacts/
│       │   ├── btp_schema.xml
│       │   ├── login_frame.0001.bin
│       │   └── ...
│       └── notes.md         # free-form, agent-writable
├── sessions/
│   └── <session-uuid>.db    # WAL log + side state
└── packs/
    └── *.ldbpack            # imports / exports
```

A `.ldbpack` is a tarball with a manifest, signed against the build-IDs included. Sharable across machines; importable by any `ldbd`.

---

## 9. Remote target story

The operator runs `ldbd` locally. The target host runs:

1. **Always:** `lldb-server platform --listen *:1234` (one binary, distro packaged).
2. **Optional, on demand:** `ldb-probe-agent` (small static binary, scp'd by `ldbd` over the SSH transport when first BPF probe is created).
3. **Available:** standard observer tools — `tcpdump`, `ss`, `ip`, `cat /proc/...`. We use what's there; we don't install a runtime.

Connection model:

```
ldbd (laptop) ──ssh──► target host:
                       ├─ lldb-server platform (RSP-extended)
                       ├─ ldb-probe-agent (uprobe events, optional)
                       └─ shell-exec for typed observers (allowlisted)
```

`SBPlatform::ConnectRemote` (already in SBAPI) gives us the LLDB half; the SSH transport carries the observer + probe-agent half.

---

## 10. Tech stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | C++17 (LLDB headers are C++17), C++20 features where helpful | aligns with LLDB; user preference |
| Build | CMake | LLDB ecosystem standard |
| LLDB | link `liblldb` from `/Users/zach/Downloads/llvm-project-llvmorg-22.1.4` | source-built so we can pin |
| JSON | `nlohmann::json` | header-only, ergonomic |
| CBOR | `TinyCBOR` or `nlohmann::json::to_cbor` | start with the latter, switch if needed |
| Sqlite | `sqlite3` (system) | sessions, artifact index |
| Embedded Python | CPython 3.11+ via `pybind11` | for user extension scripts only |
| Networking | `asio` standalone or `Boost.Asio` | proven event loop |
| eBPF | shell out to `bpftrace` initially; `libbpf` for `ldb-probe-agent` | iterate to native after MVP |
| Logging | `spdlog` | structured, fast |
| Testing | `Catch2` + golden-file tests for protocol shapes | determinism enforced via diff |

---

## 11. Milestones (10 weeks)

### M0 — Bootstrap (week 1)
- CMake skeleton; link `liblldb`; `ldbd` opens, accepts a stdio JSON-RPC `hello`, returns version.
- `target.open` and `module.list` working.
- Determinism CI scaffold: golden-file test that catches non-stable output.

### M1 — Static surface (weeks 2–3)
- All Static / DWARF endpoints (§4.2).
- View descriptors: projection, pagination, summary, max_string, max_bytes.
- Tabular mode for arrays.
- Reference workflow steps 1–3 reproducible: open binary, layout struct, xref string, disasm function.
- Acceptance: `pahole`-equivalent layout for 5 hand-picked real-world structs from libc / `quoter` / a test corpus.

### M2 — Live debug + core (weeks 4–5)
- Process / thread / frame / value endpoints (§4.3).
- Memory endpoints (§4.4).
- `target.attach`, `target.load_core`, `target.connect_remote`.
- macOS arm64 build + smoke tests pass (same SBAPI; bring-up only).
- Acceptance: backtrace + locals + memory dump on a live process and a core file, identical RPC shapes.

### M3 — Probes + artifacts + sessions (weeks 6–7)
- Probe orchestrator with `lldb_breakpoint` engine.
- Artifact store + `.ldbpack` import/export.
- Session log + replay + fork.
- Acceptance: the **full reference workflow §5** executed end-to-end against a local target, with `btp_schema.xml`-style payload extracted, stored as artifact, and re-fetchable from a fresh `ldbd` after restart.

### M4 — Remote + observers + BPF (weeks 8–9)
- SSH transport.
- `lldb-server platform` connection.
- Typed observers (proc, ss, igmp, tcpdump).
- `uprobe_bpf` probe engine via `bpftrace` shellout.
- Acceptance: full reference workflow against a real remote host (the user's `192.168.191.90`-class target).

### M5 — Polish (week 10)
- CBOR transport.
- Capability advertisement (`describe.endpoints`) with full schemas.
- `ldb` CLI (thin client, mainly for humans / scripts).
- Cost-preview metadata on every response.
- Public test corpus + replayable session goldens.
- Cut MVP tag.

---

## 12. Out of MVP, but we design hooks for them now

These get explicit interface seams in MVP code so they slot in without rewriting:

- **Second backend (GDB/MI):** `DebuggerBackend` interface already abstracts.
- **Reverse execution / rr replay:** the snapshot model (`SnapshotId`) is the seam.
- **DAP shim:** built atop `describe.endpoints` later; no MVP work needed.
- **Probe DSL:** session-replay + view-descriptors mean the agent can build recipes; we promote them to a DSL only when patterns demonstrably repeat.
- **Semantic queries (heap walk, mutex graph):** built on `mem.search` + `type.layout`; no special MVP support but the primitives suffice.
- **Pretty-printer ecosystem:** SBAPI has `SBValue::SetSyntheticChildrenProvider`; we expose it post-MVP.

---

## 13. Risks & decisions to revisit

| Risk | Mitigation |
|---|---|
| `liblldb` ABI/build pain across Linux distros and macOS | Build LLDB ourselves from the user's pinned source; ship as a vendored dependency for now. |
| Probe callback overhead in Python embedded in LLDB | Measure early (M3). If unacceptable for any user-facing case, move callbacks to a C++ hook before MVP cut. |
| Determinism on live processes | Document explicitly: snapshots are best-effort; cores are byte-deterministic. CI tests cores; live tests use a frozen-after-attach process. |
| `bpftrace` not available on locked-down targets | `ldb-probe-agent` static binary is the fallback (M4 / post-MVP if needed). |
| LLDB SBAPI gaps (e.g., specific DWARF queries) | Direct LLVM `DebugInfoDWARF` access via `liblldb`-internal accessors *only as a last resort*; prefer adding to SBAPI upstream. |
| Token budget blow-up on huge binaries / cores | Default summary mode for any list with >50 items; agent has to opt into full data. |
