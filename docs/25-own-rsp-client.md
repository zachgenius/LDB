# Own RSP client — design note

Post-V1 plan item **#17 (own GDB RSP client)** from
`docs/15-post-v1-plan.md`, and the first item in v1.6's non-stop
chain per `docs/17-version-plan.md`. The roadmap rationale:

> Replaces LLDB's `process gdb-remote`. Unlocks gdbserver/QEMU/OpenOCD
> direct talk, custom q-packets, packet-level retry control. Probably
> makes #2 (reverse-exec) free.

This note answers, in order:

1. **Do we need an own RSP client at all?** v1.5 #18 framed the same
   question for DWARF and answered "no — cache the SBAPI output."
   The argument for RSP is different; the answer is "yes, narrowly."
2. **What does the v1.6 phase-1 cut look like?** Transport layer,
   packet vocabulary, async event loop, and the boundary with
   LldbBackend.
3. **How does it slot under `target.connect_remote` without breaking
   the existing wire?**
4. **What does #21 (non-stop runtime) actually need from us?**

## TL;DR

- **Yes, own RSP client.** Unlike DWARF (LLDB tracks LLVM, our
  job is caching), RSP is the *transport contract* for every
  remote / replay / probe-agent path. Owning it gives us
  packet-level retry, custom q-packets, vendored transport (no
  liblldb runtime dep for gdbserver/QEMU/OpenOCD), and the async
  pump #21 needs. Phase-1 boundary: byte-stream + packet framing
  + the minimal vocabulary already present in
  `process plugin packet send` shims (`?`, `g`, `G`, `m`, `M`,
  `c`, `s`, `vCont`, `qSupported`, `qXfer:features:read`, `bc`,
  `bs`). LLDB stays in charge of session / debug-info /
  unwinding — we don't replace SBProcess.
- **`src/transport/rsp/`** — new module. `RspChannel` over a
  `transport::Stream` interface (existing `local_exec` /
  `ssh_exec` / `streaming_exec` give us the byte-streams). The
  channel handles framing (`$packet#cs`, `+`/`-` ack, RLE,
  escape), retry, and async receive (a reader thread feeds a
  bounded queue; the dispatcher pumps via `poll(timeout_ms)` or
  blocks via `recv()`).
- **`target.connect_remote_v2` opt-in flag**, not a replacement.
  Phase-1 ships a new endpoint `target.connect_remote_rsp` (and
  matches `process.send_rsp_packet` for debug / probe). Existing
  `target.connect_remote` keeps calling LLDB's plugin. Once the
  own-RSP path is debugged across the matrix (lldb-server,
  gdbserver, rr, qemu), v1.7 flips the default and deprecates the
  LLDB-plugin path.
- **The async pump is the load-bearing piece for #21.** Today the
  dispatcher is single-threaded; non-stop needs per-thread events
  arriving without blocking the RPC loop. The reader thread is
  the first piece of that puzzle; the rest (per-thread state
  machine, suspend/resume primitives, push events on a JSON-RPC
  notification channel) follows in #21.

## 1. Do we actually need this?

Today every remote / replay path funnels through
`LldbBackend::connect_remote_target` (`src/backend/lldb_backend.cpp:2254`).
That helper sets the LLDB process plugin to `gdb-remote` (or `rr` for
`rr://` URLs) and calls `SBTarget::ConnectRemote`. The user-supplied
URL is `connect://<host>:<port>` for plain TCP, or
`lldb-server::<host>:<port>` for LLDB's wrapper, or `rr://<trace>`
for replay.

Things we currently bend through LLDB to do:

- **Custom RSP packets** for reverse-exec (`bc`, `bs`) go through
  `process plugin packet send <packet>` — a CLI shim
  (`lldb_backend.cpp:2782`). It works but it's interpreter-level
  and fragile across LLDB versions.
- **rr replay** spawns `rr replay` as a subprocess, scrapes its
  banner for the gdb-remote port, then has LLDB connect to that
  port. The whole interlock is a kludge.
- **QEMU / OpenOCD targets** would need direct RSP talk to
  exercise vendor-specific qXfer or Q-prefix packets. Today
  these mostly work via LLDB's plugin but anything off-spec
  (Cortex-M custom registers, custom watchpoint counts) hits the
  plugin's hardcoded assumptions and silently fails.
- **Packet-level retry / observability**: an agent investigating a
  flaky probe wire can't see "we sent `m`, got `+`, then a
  malformed `$E03#...`, retried, got the right answer." LLDB
  buries this under SBProcess.

The actual cost of LLDB's RSP plugin:

- ~10k lines in `Process/gdb-remote/`. We don't need most of it
  (auto-detection of unrelated debug servers, JIT debugging
  interop, GdbRemoteCommunicationServerCommon for the server
  side we'll never run).
- The async event pump in `GdbRemoteCommunication` is what #21
  conceptually needs but isn't surface-accessible from SBAPI —
  every event still goes through `SBListener` with LLDB-specific
  stop reasons.

**Net**: an own RSP client is ~1500–2500 lines of well-tested
transport + packet code. It pays for itself because (a) reverse-
exec stops being a CLI-shim hack, (b) #21's async pump becomes a
local concern instead of a "convince LLDB to push us non-stop
events" project, and (c) every future device probe (QEMU,
OpenOCD, ROS gdbserver) becomes one packet vocabulary away rather
than "wait for LLDB to add a plugin."

This is the same shape as v1.5 #18's argument for the symbol
index: **owning the boundary, not the protocol**. We don't fork
gdb's RSP spec; we ship a focused client for the subset we use.

## 2. v1.6 phase-1 deliverable

### 2.1. Module layout

```
src/transport/rsp/
  framing.{h,cpp}      — packet codec ($payload#cs, ack/nack, RLE)
  packets.{h,cpp}      — typed builders/parsers for the v1.6 subset
  channel.{h,cpp}      — RspChannel: connect/send/recv/close + async reader
tests/unit/
  test_rsp_framing.cpp     — checksum, escape, RLE round-trips
  test_rsp_packets.cpp     — typed packet vocab against golden bytes
  test_rsp_channel.cpp     — pipe-backed end-to-end (no real gdbserver)
tests/smoke/
  test_rsp_connect.py      — live: `lldb-server gdbserver` ↔ our channel
                              (SKIP when lldb-server absent)
```

`RspChannel` owns:

- A bidirectional byte stream (`std::iostream` or a thin `Stream`
  abstraction over fd / popen / ssh).
- A reader thread that pulls bytes, frames them into packets,
  pushes onto a bounded `std::queue<Packet>` protected by a
  mutex + condvar. `recv(timeout_ms)` blocks up to the timeout.
- A writer that takes typed packets, frames them, writes to the
  stream, handles retry on `-` (nack) with a packet-level retry
  budget (default 3).
- An `is_alive()` predicate driven by the reader thread's last
  EOF / EAGAIN observation, so dispatcher-level code can probe
  liveness without sending traffic.

### 2.2. Packet vocabulary — phase-1 subset

What we MUST support to replace LLDB's plugin for the existing
LDB endpoints:

| Packet | Used by | Notes |
|---|---|---|
| `qSupported`           | handshake on connect             | parse server features (`PacketSize=`, `multiprocess+`, `vContSupported+`) |
| `?`                    | initial stop query               | "what's the inferior doing right now?" |
| `g` / `G`              | register read / write            | per-thread; depth depends on `qXfer:features:read` |
| `p NN` / `P NN=VAL`    | single register read / write     | newer servers prefer these |
| `m AAA,LL`             | memory read                      | with response-size budget |
| `M AAA,LL:DD…`         | memory write                     | rare; behind `process.write_memory` (out-of-scope today, but framing must work) |
| `c` / `s`              | continue / step (legacy)         | reverse-step `kind=insn` already uses `bs` via this layer |
| `vCont;c:tid`          | continue / step (per-thread)     | the non-stop hook; #21 fans out from here |
| `qfThreadInfo` / `qsThreadInfo` | thread enumeration       | one packet per batch + sequential |
| `Hg tid` / `Hc tid`    | thread selection                 | required by `g`, `m`, `c` per spec |
| `qXfer:features:read`  | target.xml (register layout)     | parsed once at handshake |
| `bc` / `bs`            | reverse-cont / reverse-step      | rr+gdbserver; already in our shim |
| `+` / `-`              | ack / nack                       | framing-level, not exposed |

Out of scope for phase-1 (documented but deferred):

- **`vRun` / extended-remote**: launch a new inferior over RSP.
- **`Z0/z0` software breakpoints over RSP**: we set bps via LLDB's
  SBBreakpoint, which lowers them into the inferior via the
  plugin LLDB owns. Owning the plugin for breakpoints is phase-2.
- **`vFile:*`**: remote file I/O. Useful for cross-compiled targets
  but not on the v1.6 path.
- **`T` stop replies with thread state vector**: we'll parse what
  we need (signal, watchpoint addr) but not the full thread-list
  yet.

### 2.3. Framing details

```
packet := "$" payload "#" cs8
cs8    := two-hex-digit lower-case of payload byte-sum (mod 256)
```

Escape: `}` is the escape byte; inside payload, every `#`, `$`, `}`
is sent as `}` + (byte ^ 0x20). The reader unescapes; the writer
escapes. (gdb's spec wording is uglier than this but the rule
generalises.)

RLE: payload may contain `*N` where N is `<count + 28>` ASCII —
RLE-expands the previous character N times. Reader expands; writer
never produces RLE (waste of cycles for the packet sizes we send).

Ack mode: defaults to ack-required (`+` / `-`). On
`qSupported`-reported `QStartNoAckMode+`, the channel sends
`QStartNoAckMode` and drops ack expectation. Phase-1 supports both;
no-ack is faster but ack-mode is the safe default for unknown
servers.

### 2.4. Async pump (the #21 lever)

The reader thread is the seed of #21's non-stop runtime. Today's
single-threaded dispatcher consumes RSP packets synchronously
inside `connect_remote_target` and `bc`/`bs` calls. With the own
channel, the reader thread runs continuously after `connect()`;
the dispatcher's `recv(timeout)` blocks on the queue.

For #21 specifically:
- "Stop reply with reason" packets (`T`, `S`, `W`) arrive
  asynchronously after `vCont` is sent. The reader funnels them
  to a `StopEvent` queue.
- Per-thread events become per-tid entries on the queue, ready
  for #21's per-thread state machine to consume.
- The push-events plumbing (#21's "tell the agent a thread
  stopped without it asking") is implemented as a JSON-RPC
  notification channel that the dispatcher polls the StopEvent
  queue from. v1.6 phase-1 doesn't ship the notification surface
  — it just ensures the queue is ready.

## 3. Migration: dual stack, no break

Phase-1 ships **alongside** LLDB's plugin. Existing
`target.connect_remote` keeps using `SBTarget::ConnectRemote`
exactly as today. New endpoint:

```
target.connect_remote_rsp({target_id, url}) → process_status
```

The URL grammar is `connect://host:port` for now. `lldb-server`
URLs are routed through the new client when the agent picks the
new endpoint; everyone else stays on the LLDB plugin.

Why a parallel endpoint rather than a behind-the-curtain flip:

- **Debuggability.** Side-by-side comparison: the smoke test
  exercises both paths against the same lldb-server, asserting
  byte-equal `ProcessStatus` returns. Anything off-by-one shows up
  immediately.
- **Roll-back path.** If the own client misbehaves on a vendor
  server (QEMU has known qXfer quirks), `target.connect_remote`
  still works.
- **Wire-shape stability.** v1.0's "no breaking changes" promise
  holds — the existing endpoint's behaviour is unchanged.

v1.7 (or v1.6 phase-2) flips the default once the matrix is
green: `target.connect_remote` routes through the own client;
`target.connect_remote_lldb` exists as the escape hatch.

## 4. What #21 needs from us — non-stop runtime

`docs/11-non-stop.md` has the full surgery list. v1.6 phase-2's
non-stop runtime needs from #17:

- **Per-thread continue/step**: `vCont;c:tid` works whether the
  target supports non-stop or not; servers without non-stop block
  the whole inferior, but the wire shape is identical. Our
  channel implements `vCont` as a typed packet; #21 plumbs
  per-thread state machine on top.
- **Async event pump**: the reader thread + StopEvent queue is
  the foundation. #21 adds a notification channel from
  dispatcher to client.
- **Suspend/resume primitives**: the RSP layer exposes `vCont;t`
  (stop) and `vCont;c` (continue). #21 sequences them per the
  per-thread state machine.
- **Displaced-stepping**: server-side concern (`vCont;C03:tid`,
  signal injection). The own channel passes it through; #21
  decides when to use it.

#17 makes #21 a "wire over a primitive" project rather than a
"convince LLDB to push us non-stop events" project.

## 5. Failure matrix

| Failure | Behaviour |
|---|---|
| TCP connect refused | `-32000 kBackendError` with the OS errno message |
| Handshake (`qSupported`) timeout | retry budget exhausted → `-32000` with `"qSupported timeout"` |
| Server-sent ack on a no-ack stream | log warning, accept anyway |
| Checksum mismatch from server | send `-` (nack), retry; budget = 3 |
| Checksum mismatch from us | server sends `-`; we re-send the last packet |
| Reader thread joins with `is_alive() == false` | future `recv()` returns the EOF marker; channel destruction reaps |
| Unsupported packet (`$#00` reply means "unknown") | parser surfaces as `PacketResponse::kUnsupported`; caller decides |
| Network partition mid-packet | reader EOF → channel marked dead → next dispatcher op returns kBackendError |
| RLE expansion would exceed `PacketSize` from `qSupported` | reject the response → `kBackendError` "server malformed" |
| Reverse-exec packet (`bc`/`bs`) to a non-replay server | server responds `$#00` (unsupported); we translate to `-32003 kNotSupported` |

## 6. Phase-1 scope vs. phase-2

**Phase-1 (this design, plus the next 3–5 commits):**
- `src/transport/rsp/` module: framing + packets + channel + async reader.
- `target.connect_remote_rsp` endpoint behind a feature flag
  (`LDB_RSP_CLIENT` default ON).
- Smoke test: live `lldb-server gdbserver` round-trip.
- Reverse-exec (`bc`/`bs`) routes through the new channel when
  the target was opened via `connect_remote_rsp`; legacy targets
  keep using `process plugin packet send`.
- Documented matrix coverage (lldb-server, gdbserver, rr-server,
  qemu user-mode). Phase-1 verifies lldb-server + rr; the other
  two are phase-2 hardening.

**Phase-2 (v1.6 follow-on):**
- StopEvent notification channel for #21.
- Default flip — `target.connect_remote` uses the own client;
  legacy LLDB plugin behind `target.connect_remote_lldb` escape
  hatch.
- `Z0/z0` software breakpoints via RSP (own-the-plugin for bps
  too).
- QEMU + OpenOCD smoke matrix.

**Phase-3 (v1.7+):**
- `vRun` / extended-remote (launch over RSP).
- `vFile:*` remote file I/O.
- Vendor-specific Q-prefix passthrough for board bring-up
  (Cortex-M custom registers, etc.).

## 7. Why this is the right v1.6 starting point

`docs/17-version-plan.md` orders v1.6 as: **#17 → #21 → #25 → #26**,
with #20 (own ptrace) as last resort. Each blocks the next:

- **#21 non-stop runtime** needs the async event pump #17
  provides. Doing #21 against LLDB's `SBListener` would mean
  buying into LLDB's stop-reason vocabulary forever; doing it
  against our own queue means we control the event surface.
- **#25 in-target agent-expression predicates** compile probe
  predicates to GDB AE bytecode. The wire that ships them is
  RSP's `QTDP:N:addr:E:S` packet family. Without an own client
  these go through LLDB's plugin and we can't add custom AE
  opcodes.
- **#26 tracepoints** depends on #21 (non-stop) + #25 (AE
  predicates) shipped over RSP.

Skipping #17 to do #21 first is feasible but loads the
"convince LLDB" cost onto every subsequent item. Landing #17
first turns the rest into wire-level packet design instead of
SBAPI-shim design.

That's the plan. Implementation lands in the next commits.
