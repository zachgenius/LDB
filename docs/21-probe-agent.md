# `ldb-probe-agent` — libbpf + CO-RE Probe Engine (Phase 1)

> Post-V1 plan item **#12** (`docs/17-version-plan.md`). Phase-1 landable
> cut. Companion to `docs/08-probe-recipes.md` (recipe shape) and
> `src/probes/bpftrace_engine.{h,cpp}` (the engine this eventually
> replaces).

## Why a separate binary

`bpftrace_engine.cpp` shells out to `/usr/bin/bpftrace` and parses
stdout JSON. That works, but it has three real problems:

1. **Heavy dependency.** bpftrace pulls in clang/LLVM at install time;
   on stripped-down target hosts (containers, embedded Linux, hardened
   appliances) it's not available and can't be installed.
2. **Per-host recompile.** bpftrace JIT-compiles the BPF program at run
   time against the *target* kernel's headers. CO-RE (Compile Once,
   Run Everywhere) eliminates that — one BPF object works across kernel
   versions because libbpf relocates type accesses at load time using
   `/sys/kernel/btf/vmlinux`.
3. **Privilege coupling.** bpftrace must be invoked as root (or with
   CAP_BPF + CAP_PERFMON). Today `ldbd` becomes the privileged process
   by spawning bpftrace; an attacker who pwns `ldbd`'s JSON-RPC surface
   inherits that. A separate `ldb-probe-agent` lets the daemon stay
   unprivileged and confines BPF privilege to a small static binary
   with a narrow stdio interface.

So phase-1 ships an opt-in `engine: "agent"` recipe that talks to a
`ldb-probe-agent` subprocess. The existing bpftrace path stays the
default — this is the **add-a-parallel-codepath** strategy, not a
replacement. We need real-world miles on the agent before pulling
bpftrace out.

## Wire protocol (agent ↔ daemon)

Length-prefixed JSON over the agent's stdio. Each frame is:

```
 +--------------+----------------------------+
 | 4 bytes BE   | N bytes UTF-8 JSON         |
 | length = N   | {"type": "...", ...}       |
 +--------------+----------------------------+
```

Reasons for length-prefixed (not LSP-style headers):

- Trivial to write in both C++ (daemon) and C (agent main loop).
- Binary-clean; no header parsing edge cases.
- Bounded read (`read(fd, len_buf, 4)` → `read(fd, body, len)`) — never
  needs to scan for a delimiter.

Max frame: 16 MiB (`0x01000000`). Larger payloads kill the channel.

### Commands (daemon → agent)

| `type` | params | response (`type`) | notes |
|---|---|---|---|
| `hello` | `{}` | `hello_ok` | Capability handshake: agent reports `version`, `libbpf_version`, `btf_present`, `embedded_programs[]`. |
| `attach_uprobe` | `{program, path, symbol, pid?}` | `attached` | Returns `{attach_id}`. `program` is the embedded BPF program name. |
| `attach_kprobe` | `{program, function}` | `attached` | Returns `{attach_id}`. |
| `detach` | `{attach_id}` | `detached` | Idempotent on unknown id (returns `error`). |
| `poll_events` | `{attach_id, max?}` | `events` | Returns `{events: [{ts_ns, pid, tid, payload_b64}], dropped}`. `dropped` counter is best-effort. |
| `shutdown` | `{}` | `bye` | Clean exit. SIGTERM works too. |

### Events (agent → daemon)

Currently events are pulled via `poll_events`. A future phase may push
asynchronously (`type: "event"` frames mid-stream) if poll latency
matters; phase-1 stays request/response to keep the protocol single-
threaded and easy to test.

### Errors

Every command can return `{"type": "error", "code": "...", "message": "..."}`
in lieu of the success type. Codes:

- `not_supported` — agent built without an embedded BPF program, or
  kernel feature missing.
- `no_capability` — running without CAP_BPF (or root).
- `no_btf` — `/sys/kernel/btf/vmlinux` absent.
- `target_not_found` — uprobe path/symbol didn't resolve.
- `unknown_attach_id`.
- `internal` — libbpf API call failed; message contains errno string.

## CO-RE strategy

- **Skeleton**, not raw ELF. At build time `bpftool gen skeleton hello.bpf.o >
  hello.skel.h`. The skeleton bakes in struct offsets to a baseline kernel
  and ships relocations alongside; libbpf adjusts them on load against the
  target's `/sys/kernel/btf/vmlinux`.
- BTF discovery: libbpf finds vmlinux BTF at `/sys/kernel/btf/vmlinux`
  automatically. We don't ship a vendored BTF for now — design assumes
  Linux 5.5+ (when in-kernel BTF became standard on most distros). Pre-5.5
  hosts SKIP the agent.
- Build-time gating: clang and `bpftool` are required to compile the BPF
  source and generate the skeleton. If either is absent at CMake configure,
  we still build the agent binary (commands return `not_supported`) — the
  protocol surface is exercised, only the actual BPF program is missing.
  That keeps the protocol/integration tests buildable on bare boxes.

## Embedded BPF programs (phase 1)

Phase-1 ships one program:

- **`syscall_count`** — `tracepoint/raw_syscalls/sys_enter`, counts hits
  per (pid, syscall_nr) into a per-cpu hash map. The smoke test attaches
  it, triggers a few `getpid()` syscalls, reads the map, asserts count > 0.

This is intentionally trivial. The point of phase-1 is the *pipeline*:
agent binary builds, protocol round-trips, libbpf loads + attaches +
unmaps cleanly. Real recipe-formats land in phase-2.

## Failure matrix

| Condition | Symptom | Surface to caller |
|---|---|---|
| `ldb-probe-agent` not built (no libbpf at configure time) | binary missing under `$<TARGET_FILE:...>` | `probe.create(engine=agent)` returns `-32000 "probe agent binary not built"`. Smoke test SKIPs. |
| Not root / no CAP_BPF | libbpf `load()` returns EPERM | agent returns `{type: error, code: no_capability}`. Smoke test SKIPs. |
| No `/sys/kernel/btf/vmlinux` | libbpf returns -2 from `btf__load_from_kernel_by_id` | agent returns `{type: error, code: no_btf}`. Smoke test SKIPs. |
| Kernel < 5.5 (rare on modern distros) | tracepoint attach fails or BTF missing | mapped to `no_btf` / `not_supported`. |
| uprobe path/symbol missing | `bpf_program__attach_uprobe` returns NULL | agent returns `target_not_found`. Surfaces as `-32000` from the daemon. |
| Build w/ clang+bpftool absent | agent built, but no embedded skeleton | agent's `hello` reports `embedded_programs: []`; commands return `not_supported`. |

## How this coexists with `bpftrace_engine`

Recipes today look like:

```jsonc
{"method": "probe.create",
 "params": {"kind": "uprobe_bpf", "where": {"kprobe": "do_sys_open"}}}
```

Phase-1 adds an optional `engine` discriminator on `uprobe_bpf`:

```jsonc
{"method": "probe.create",
 "params": {"kind": "uprobe_bpf", "engine": "agent",
            "where": {"tracepoint": "raw_syscalls/sys_enter"}}}
```

- `engine: "bpftrace"` (default when unset) → existing `BpftraceEngine`.
  No change.
- `engine: "agent"` → new `AgentEngine`. Daemon spawns `ldb-probe-agent`
  (first-use lazy spawn, single agent shared across probes), sends a
  `hello`, then issues `attach_*`. `probe.events` calls into the engine
  which issues `poll_events`. `probe.delete` issues `detach`.

The dispatcher schema is updated additively: `engine` joins the
`uprobe_bpf` param block as an optional string enum
`["bpftrace", "agent"]`, default `"bpftrace"`.

## Integration points

- **Dispatcher** (`src/daemon/dispatcher.cpp`): parses `engine` field,
  routes to `ProbeOrchestrator` as a new `bpftrace_engine_kind` field on
  `ProbeSpec`.
- **Orchestrator** (`src/probes/probe_orchestrator.cpp`): branches at
  `create_uprobe_bpf` on the engine kind.
- **AgentEngine** (`src/probes/agent_engine.{h,cpp}`): new class, same
  shape as `BpftraceEngine`. Holds a per-orchestrator `AgentChannel`
  (a singleton `ldb-probe-agent` subprocess wrapper).
- **`ldb-probe-agent` binary** (`src/probe_agent/`): standalone main,
  links libbpf, embeds the skeleton header.

## Out of scope for phase 1

- Pushing events asynchronously (agent → daemon mid-stream).
- USDT semaphore-tagged probes.
- Multi-CPU ring buffer aggregation order guarantees.
- BPF program upload from the daemon (recipes carrying BPF C source).
  Phase-1 supports only the *embedded* programs.
- Replacing bpftrace entirely. The agent is opt-in.
- Remote agent deploy (over SSH). The transport hook is the same as
  `BpftraceEngine`'s SSH-host parameter, but phase-1 wires only the
  local-spawn path.

## Phase-2 questions (deferred)

- Should the agent run as a long-lived systemd service, or per-session
  subprocess? Per-session is simpler for now; service mode unlocks
  multi-daemon sharing.
- Do we need a BPF-byte-code verifier proxy on the daemon side to
  reject programs the kernel will refuse early? Probably not for
  embedded-only programs; revisit when we accept user-authored ones.
- Should `probe.events` proxy directly to ring-buffer EPOLLs in the
  agent, or stick with poll? Poll is fine for the rates we care about
  (~10 Hz event-stream pull); ring-buffer EPOLL is a phase-2 optimization
  if needed.
