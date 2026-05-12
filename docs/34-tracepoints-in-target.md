# Tracepoints in-target (QTDP/QTStart/QTStop)

Post-V1 #26 phase-2. Where phase-1
(`docs/30-tracepoints.md`) ships a daemon-side tracepoint that
evaluates the predicate on the orchestrator's hit callback, phase-2
pushes the bytecode into the inferior via the gdb-remote tracepoint
family so the agent runs the predicate without a daemon round-trip.

This document covers:

  * The wire vocabulary that lands in this PR (`packets.{h,cpp}` +
    its unit tests).
  * The orchestrator integration plan — what phase-2.5 wires up.
  * Capability negotiation — how the dispatcher decides between the
    in-target path and the phase-1 daemon-side path.
  * Buffer-drain semantics — what `QTFrame` / `qTBuffer` give us
    once collection is active.

The companion design doc (`docs/30-tracepoints.md` §5) describes the
phase split; treat that as the source of truth on *what* phases-2/3
ship. This file is the *how* for phase-2.

---

## 1. Wire vocabulary (this PR)

Six builders + one parser + one carrier struct land in
`src/transport/rsp/packets.{h,cpp}`. Each builder emits the bytes that
go between `$` and `#` — `framing::encode_packet` wraps them.

### 1.1 QTinit

```
QTinit
```

Reset all tracepoints. Always the first packet of a new tracepoint
session; without it, prior definitions persist and `QTDP:T1:...`
collides with a stale id. Server replies `OK` on success, `""` (empty
payload) when it doesn't speak QTDP at all.

### 1.2 QTDP define — primary

```
QTDP:T<id>:<addr>:{E|D}:<step>:<pass>
```

- `<id>` — tracepoint id, hex, 1-based. The dispatcher assigns ids
  contiguously; phase-2.5 will keep a per-channel `next_id` counter.
- `<addr>` — absolute address, hex.
- `E` enabled / `D` disabled. The orchestrator's existing
  enabled/disabled state maps directly.
- `<step>` — pinned to `0` (no single-step collection) for phase-2.
  The agent fires on the normal breakpoint hit.
- `<pass>` — pass-count cap, hex. `0` means unlimited. The
  orchestrator's `rate_limit_text` covers rate-limiting daemon-side;
  we don't currently expose pass-count to the user surface.

### 1.3 QTDP condition — continuation

```
QTDP:-T<id>:<addr>:X<len>,<bytes>
```

Continuation packet (note `-T` not `T`). Sets the predicate as
agent-expression bytecode for an already-defined tracepoint.

- `<len>` — byte count of the bytecode, hex.
- `<bytes>` — bytecode, hex-encoded (same encoding as `m`/`M`
  payloads). The bytecode itself is whatever `agent_expr::compile`
  produced — same format consumed by the daemon-side VM in #25.

### 1.4 QTStart / QTStop

```
QTStart
QTStop
```

Collection control. After all `QTDP:T...` + `QTDP:-T...` packets are
in place, `QTStart` arms the tracepoints; `QTStop` halts collection
without wiping the buffer. Server replies `OK` / `""`.

### 1.5 qTStatus

```
qTStatus
```

Query collection state. Reply shape:

```
T<flag>[;k:v]*
```

Where `flag` is `0` (inactive) or `1` (active). Trailing kv pairs
carry buffer stats — `tnotrun`, `tstop`, `tframes`, `tcreated`,
`tsize`, `tfree`, `circular`. `parse_tstatus_reply` returns
`{running, kv}`; callers that need a specific stat (`tframes`) look
it up by key.

### 1.6 qTBuffer

```
qTBuffer:<offset>,<length>
```

Drain the trace buffer. Hex offset + hex length. The reply is
hex-encoded; decode via `decode_hex_bytes`. Phase-2.5 will plumb this
into `tracepoint.frames` so that an RSP-backed target's frames come
from the buffer instead of the orchestrator's ring.

### 1.7 QTFrame

```
QTFrame:<n>
```

Select a trace frame for inspection. Subsequent `g` / `m` reads target
the selected frame's snapshot instead of the live inferior. `-1`
deselects. Phase-2 doesn't use this yet; phase-3's
`tracepoint.collect_spec` will pivot to it.

### 1.8 TracepointWire carrier

```cpp
struct TracepointWire {
  std::uint32_t tracepoint_id;
  std::uint64_t addr;
  bool          enabled;
  std::uint32_t pass_count;        // 0 ≡ unlimited
  std::string   predicate_bytecode;  // raw, NOT base64
};
```

Phase-2.5 carries this from the dispatcher's `tracepoint.create`
handler into the transport layer. Keeping it separate from
`probes::ProbeSpec` means `src/transport/rsp/` doesn't have to depend
on `src/probes/`; only the dispatcher mediates the conversion.

### 1.9 Builder examples

Putting it together, the canonical "create one tracepoint + condition
+ start" sequence for tracepoint id=1 at `0x401000` with the synthetic
predicate `push_const8 1; end`:

```
$QTinit#...
$QTDP:T1:401000:E:0:0#...
$QTDP:-T1:401000:X3,080127#...
$QTStart#...
```

All four packets get `OK` / `E NN` replies — `E NN` from the server
means "I parsed it, I refused it." Empty `""` from any of them means
"this server doesn't support tracepoints at all" and the dispatcher
falls back to the phase-1 daemon-side path.

---

## 2. Capability negotiation

The dispatcher decides between QTDP-in-target and daemon-side based
on what the server advertised at handshake. Three signals:

1. **`qSupported` flags.** lldb-server / gdbserver advertise tracing
   support via the qSupported reply. The relevant flags:
   * `tracepoints+` — basic QTDP/QTStart/QTStop support.
   * `EnableDisableTracepoints+` — the `E`/`D` field on QTDP define.
   * `ConditionalTracepoints+` — `QTDP:-T...:X<len>,<bc>` form.
   * `TracepointSource+` — agent-expression carriage (we need this).
   `RspChannel::server_features()` already exposes the parsed string;
   phase-2.5 adds a small `has_feature()` helper.
2. **Empty reply to `QTinit`.** A defensive fallback for servers that
   don't advertise `tracepoints+` but might respond to QTDP anyway,
   and vice versa. If `QTinit` returns `""`, we mark the channel
   "no QTDP" and don't try further.
3. **Empty reply to any individual QTDP packet.** Treat as a
   per-tracepoint fallback: log a warning, remove the in-target
   definition (best-effort `QTDP:-T<id>:<addr>:E:0:0` with `D` is
   not a deletion — the spec lacks per-tracepoint delete, so we just
   leave the disabled definition in place), keep the daemon-side
   probe.

When the server doesn't support tracepoints, phase-1's daemon-side
path is the only path — same as today. `tracepoint.list` reports the
same shape; the user can't tell which path is active without
inspecting logs. (A future `tracepoint.info` could expose
`backend: "in_target" | "daemon"`.)

---

## 3. Orchestrator integration plan (phase-2.5)

The dispatcher is the seam between the orchestrator (which speaks
`ProbeSpec`) and the transport layer (which speaks `TracepointWire`).
The integration touches three call sites:

### 3.1 `tracepoint.create` (dispatcher)

After the orchestrator returns a `tracepoint_id`, the dispatcher
checks whether the target has an `RspChannel` bound (existing
`dispatcher_->rsp_channel_for(target_id)` lookup). If so, *and* the
channel advertised `tracepoints+` + `ConditionalTracepoints+`, build
a `TracepointWire`:

```cpp
TracepointWire w;
w.tracepoint_id      = orch.in_target_id_for(id);   // monotonic 1-based
w.addr               = orch.resolved_address(id);   // post-bp-resolution
w.enabled            = true;
w.pass_count         = 0;                            // rate-limit is daemon-side
w.predicate_bytecode = orch.predicate_bytecode(id);  // encoded once at create
```

Emit, in order:

```cpp
chan->request(build_QTinit());                                  // idempotent
chan->request(build_QTDP_define(w.tracepoint_id, w.addr, true, 0));
if (!w.predicate_bytecode.empty()) {
  chan->request(build_QTDP_condition(w.tracepoint_id, w.addr,
                                     w.predicate_bytecode));
}
chan->request(build_QTStart());
```

On `E NN` or `""` at any step, fall back to daemon-side: the
orchestrator's existing breakpoint callback already does the right
thing for kind=`tracepoint`.

The orchestrator-side tracepoint stays the source of truth. The
in-target tracepoint is a *cache* of the predicate. If it errors or
falls back, the daemon-side path takes over with no user-visible
change.

### 3.2 `tracepoint.enable` / `tracepoint.disable`

The spec doesn't have a single "set enabled state" packet — the
`E`/`D` field is set at define time. Phase-2.5's enable/disable
re-issues `QTDP:T<id>:<addr>:E:0:0` / `D` with the same id. Servers
either accept the redefinition (lldb-server does) or require
`QTinit` + redefine-all (some gdbserver builds). We probe the
"redefine" path first; on `E NN`, fall back to `QTinit`-and-redefine-
all from the orchestrator's snapshot.

### 3.3 `tracepoint.delete`

The gdb-remote spec lacks a per-tracepoint delete. Two options:

* **Disable + leave defined.** `QTDP:T<id>:<addr>:D:0:0`. Simpler;
  the inferior keeps the bp installed but won't fire. Wastes one
  inferior bp slot per deleted tracepoint.
* **Wipe + re-arm.** `QTinit` then redefine every non-deleted
  tracepoint from the orchestrator snapshot. Atomic from the user's
  view; expensive if the user churns many tracepoints.

Phase-2.5 ships option (1). The `QTinit` form is reserved for
`session.shutdown` cleanup (already on the deferred list).

### 3.4 `tracepoint.frames`

Phase-2.5 keeps the orchestrator ring buffer as the source of truth
for frames. The in-target path still streams hits as async stop
replies (`T05reason:trace;tracepoint:<id>;`), which #21's
NonstopListener routes back to the orchestrator. So the
`tracepoint.frames` endpoint stays unchanged in phase-2.5.

Phase-3 will pivot `tracepoint.frames` to `qTBuffer` + `QTFrame` for
in-target-only collection (no daemon-side ring buffer when the agent
itself is collecting).

---

## 4. Failure modes added in phase-2/2.5

| Condition | Behaviour |
|---|---|
| Server doesn't advertise `tracepoints+` | Daemon-side path; in-target path skipped silently. |
| `QTinit` returns `""` | Same as above; cache the no-QTDP flag on the channel. |
| `QTDP:T...` returns `E NN` | Log + emit a `tracepoint.warning` notification; tracepoint stays daemon-side. |
| `QTDP:-T...:X...` (condition) returns `E NN` | Fallback: keep the in-target tracepoint but rebind the predicate to daemon-side. The in-target fires every hit; the daemon-side filter drops the same way as today. |
| `QTStart` returns `E NN` | All-or-nothing: tear down the in-target definitions and fall back to daemon-side entirely. |
| Server returns `T05reason:trace;tracepoint:<unknown_id>;` | Async stop reply for a tracepoint we don't recognise (race against our own delete-disable). Ignore + log. |

---

## 5. Live smoke test (phase-2.5)

`tests/smoke/qtdp_in_target.sh` (deferred to phase-2.5):

1. Start `lldb-server gdbserver localhost:1234 -- /usr/bin/sleep 5`.
2. JSON-RPC `target.connect_remote_rsp` to localhost:1234.
3. Pull `target.qSupported_features`; assert `tracepoints+`.
4. JSON-RPC `tracepoint.create` at `_dl_start` (or another always-hit
   symbol).
5. Tail the daemon log: expect `QTDP:T1:...:E:0:0` framed on the
   wire, plus `OK` reply.
6. JSON-RPC `tracepoint.list`; assert it appears.
7. Continue + observe hits arrive via `tracepoint.frames`.
8. JSON-RPC `tracepoint.delete`; expect `QTDP:T1:...:D:0:0`.
9. JSON-RPC `target.disconnect_remote_rsp`.

Gate the test on `LDB_LLDB_SERVER` (already set by phase-1 #17) so it
SKIPs in CI environments without lldb-server.

---

## 6. Phase split summary

| Phase | Scope |
|---|---|
| **2 (this PR)** | Packet builders + struct vocabulary + unit tests + this design note. **No** dispatcher integration. |
| **2.5** | Dispatcher integration: `tracepoint.create` emits QTDP+QTStart, `tracepoint.delete` emits QTDP-disable, capability detection on channel, live smoke test. |
| **3** | `if_goto`/`goto` opcodes for in-target short-circuit predicates, in-target memory/register capture via `qTBuffer`+`QTFrame`, `tracepoint.collect_spec` shape. |

Phase-2.5 is intentionally a separate PR — the vocabulary is reusable
on its own (a future bpf/perf path could speak QTDP-like packets to a
custom agent), and the integration is large enough that landing it
alongside the vocabulary fights TDD.
