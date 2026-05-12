# Non-stop runtime — design note

Post-V1 plan item **#21 (non-stop + displaced stepping runtime)**
from `docs/15-post-v1-plan.md`, and the centerpiece of v1.6's
non-stop chain per `docs/17-version-plan.md`. Builds directly on
**#17's async pump** (`src/transport/rsp/channel.{h,cpp}` —
already on master at `688b703`).

`docs/11-non-stop.md` is the original v0.3-era research doc.
That note framed non-stop as "deferred to v0.4+." Three years
of LDB releases later, we have the foundation. This note is the
v1.6 implementation contract.

## TL;DR

- **Non-stop = per-thread suspend/resume + asynchronous stop
  events.** Today's `process.continue` resumes every thread; this
  ships `thread.continue tid=N` that resumes thread N and leaves
  every other thread parked at its current PC.
- **Async events use a new JSON-RPC notification channel.** When a
  thread stops while the agent isn't blocked in an RPC,
  `event: "thread.stopped"` is pushed on the daemon's stdout in
  JSON-RPC `notification` shape (no `id` field). Clients that
  don't speak notifications ignore them — wire-compat preserved.
- **The wire reuses the async pump #17 built.** `RspChannel`'s
  reader thread already pushes server packets onto a bounded
  queue. The runtime adds a dedicated *listener* thread that
  drains the queue, parses stop replies, runs the per-thread state
  machine, and emits notifications when a transition fires.
- **Two backend strategies, one runtime.** When the target is open
  via `target.connect_remote_rsp` (#17's channel) the listener
  runs against the RspChannel directly. When the target is
  LLDB-backed (`target.attach` / `target.open` / legacy
  connect_remote), the listener subscribes to `SBListener` events.
  The runtime is backend-agnostic; both paths feed the same
  notification surface.
- **Displaced stepping is a server-side concern that we expose,
  not implement.** rr / lldb-server / gdbserver all support it
  natively. The runtime simply uses `vCont;c:tid` (resume one
  thread, others held) and trusts the server to do the
  displacement. Phase-2 may add agent-side fallback for non-
  cooperative servers.

## 1. What changes on the wire

### New endpoints

```
thread.continue   ({target_id, tid})          → process_status
thread.suspend    ({target_id, tid})          → process_status
thread.list_state ({target_id})               → {threads: [{tid, state, pc, name?}], stop_event_seq}
```

`thread.continue` resumes exactly `tid`; siblings stay where they
are. `thread.suspend` is the inverse — stop a running thread
without stopping the rest. `thread.list_state` is the snapshot
query: which threads are running, which are stopped, and at what
seq (so an agent can ask "anything change since I last looked at
seq=N?").

### New notification

The daemon emits, asynchronously on stdout:

```jsonc
{
  "jsonrpc": "2.0",
  "method":  "thread.event",
  "params": {
    "seq":       42,                   // monotonic per-target
    "target_id": 1,
    "tid":       1234,
    "kind":      "stopped",            // | "exited" | "signalled"
    "pc":        0x7f8c123456,
    "reason":    "trace",              // gdb-stop-reason vocabulary
    "signal":    5                     // when applicable
  }
}
```

Notifications have **no `id` field** — they are the JSON-RPC
notification shape from the spec. Clients that ignore them keep
working; clients that consume them get push events.

### Endpoint extensions (existing, no breaks)

- `hello.data.capabilities` gains `non_stop_runtime: bool` so
  agents can negotiate before relying on the new behaviour.
- `process.continue` adds an optional `all_threads: bool`
  parameter (default `true`). When `false`, the dispatcher
  rejects with `-32602` and tells the agent to use
  `thread.continue` instead. This is the deprecation hook for the
  current "continue everything" semantics; v1.7 may flip the
  default.
- `thread.list` (today) returns each thread's state. The non-stop
  runtime makes "state" a load-bearing field for agents: `stopped`
  vs `running` is now meaningful per-thread, not per-process.

## 2. The runtime — what's actually new

A new module:

```
src/runtime/nonstop_runtime.{h,cpp}
  class NonStopRuntime
    - one per Dispatcher; constructed lazily on first non-stop
      operation
    - owns the listener thread
    - owns the per-target ThreadState map
    - emits notifications via a NotificationSink callback set by
      Dispatcher
tests/unit/
  test_nonstop_runtime.cpp     — state machine on a mock backend
  test_dispatcher_thread_continue.cpp — wire shape (extension)
tests/smoke/
  test_nonstop_basic.py        — live lldb-server + thread.continue
```

### 2.1. Per-thread state machine

```
                  thread.continue / vCont;c:tid
       kStopped ────────────────────────────► kRunning
          ▲                                       │
          │                                       │
          │   stop event from listener            │
          └───────────────────────────────────────┘
                          │
                          ▼
                    thread.event{kind:stopped}
                       notification
```

Transitions are owned by `NonStopRuntime`; the dispatcher only
queries (`get_state(target_id, tid)`) and triggers
(`resume(target_id, tid)` / `suspend(target_id, tid)`). The
listener thread is the sole writer of the state map. All other
threads (dispatcher RPC handlers) read under a `shared_mutex`.

Locking rule (load-bearing for #17's `rsp_channels_` map hazard
flagged in PR #7's reviewer pass): **the listener holds the map
in shared-read mode while consuming events; the dispatcher takes
exclusive lock only when adding or removing a target.** The map
itself is `unordered_map<TargetId, unique_ptr<TargetState>>`; the
`unique_ptr`s never move once inserted (we never resize the map
under read load).

### 2.2. Listener thread

One listener per `NonStopRuntime`, not per target. It pumps:

- For LLDB-backed targets: `SBListener::WaitForEvent` with a
  short timeout, decoding `SBProcess::GetState()` deltas into
  per-thread state transitions.
- For RspChannel-backed targets: `chan->recv(timeout)` against the
  channel's existing reader queue, parsing the payload via
  `packets::parse_stop_reply`.

Both paths feed the same `apply_event(target_id, ThreadEvent)`
function that runs the state machine.

The listener thread's lifecycle mirrors `Dispatcher`'s: created
lazily on the first non-stop call, joined in `~NonStopRuntime`
(destructor of dispatcher). Shutdown ordering:

1. `shutdown_.store(true)` — flag.
2. For each registered channel: `chan->wake_recv()` (a new
   poke method on RspChannel that pushes a sentinel on the
   queue).
3. For LLDB: `SBListener::Stop()`.
4. Join the listener thread.
5. Tear down per-target state.

The poke / stop interlock is the same shape `RspChannel`'s
destructor uses today (it's tested by the channel's destructor
race-test). #17 reviewer's H2 hazard (`Dispatcher::rsp_channels_`
not thread-safe) is closed in this commit: when the listener
needs to read the map, it holds the runtime's `shared_mutex`; when
the dispatcher mutates the map, it takes the same lock exclusively
+ unregisters from the listener first.

### 2.3. Displaced stepping

The runtime emits `vCont;c:tid` (per-thread continue) or
`vCont;s:tid` (per-thread step). Servers that support it (rr,
lldb-server, gdbserver since 2017, qemu since 7.1) do the
displacement themselves: they single-step the named thread
through the breakpoint trap, restore the trap, and resume.

What the runtime does NOT do in v1.6:

- **Agent-side displaced stepping.** Decoding the next
  instruction, allocating a scratch slot in inferior memory,
  rewriting `next_pc` is server-side everywhere we care about.
  Documented; revisit only if a real device-probe target lacks
  server-side support.
- **Schedule-locking and the various `vCont` modifiers gdb's
  client offers** (e.g. `vCont;c:tid;t:other`). Phase-1 emits
  one action per vCont. Phase-2 may grow this.

## 3. The notification channel

JSON-RPC 2.0 spec §4.1: a Notification is a Request without `id`.
The server sends it; the client SHOULD NOT reply. Modern clients
(VS Code DAP, our own ldb REPL) handle this trivially; older
agents either ignore unknown messages or fail with a typed error.

### Wire ordering

```
client → server: {"id":"r1", "method":"thread.continue", ...}
server → client: {"id":"r1", "result": ..., ...}        # reply

  ... some time later, asynchronously ...

server → client: {"method":"thread.event", "params":{...}}   # notification
```

Notifications interleave with reply traffic. The runtime emits a
notification on a thread other than the dispatcher's; the
dispatcher's `serialize_response` already wraps stdout writes in
a stream lock (`src/protocol/transport.cpp`). The
NotificationSink uses the same lock, so notifications never
byte-interleave with replies. **This is the v1.6 equivalent of
#17's reader/writer fd race** — same pattern, different layer.

### Subscription model

By default the channel emits notifications for every target.
Agents that want to be selective can call:

```
event.subscribe({target_ids: [...], kinds: ["stopped", "exited"]})
```

Phase-1 ships the broadcast model. Phase-2 may add subscription
filtering if a real client hits notification-volume problems.

### Why not a separate fd / SSE / WebSocket

- The daemon owns one stdio pair. Splitting events to a side
  channel means agents have to multiplex two streams — burns the
  "agent talks to one peer" simplicity we have today.
- JSON-RPC's notification shape is the standardised answer to
  exactly this problem. Reusing it costs nothing.
- Future #11 ssh-remote transport (already in v1.4) ports
  unchanged. A side channel would need its own ssh-tunneling
  story.

## 4. Failure matrix

| Condition | Behaviour |
|---|---|
| Server doesn't support `vCont` (very old gdbserver) | Fall back to legacy `c`/`s` packet, log warning. thread.continue degrades to process.continue silently (with `stop_event_seq` still advancing on the all-threads stop). |
| LLDB backend doesn't expose `SBProcess::SetAsync(true)` (older builds) | Dispatcher returns `-32002 kBadState` with a hint at the LLDB version. Fall-through to all-threads continue not attempted — the agent must explicitly use `process.continue`. |
| Listener thread fails to start (resource exhaustion) | Constructor of `NonStopRuntime` throws `backend::Error`. Dispatcher catches and surfaces as `-32000`; subsequent thread.* calls return the same. |
| `thread.continue` on an already-running thread | No-op + ok. The state machine treats `kRunning → kRunning` as idempotent. |
| `thread.continue` against a thread that doesn't exist | `-32602 kInvalidParams` with "unknown tid: N" |
| Stop event for a tid the runtime doesn't know about | New thread; insert with `kStopped` and emit a `thread.event{kind:"created"}` notification. Phase-1 emits only `stopped`/`exited`/`signalled`; `created` is phase-2 unless we discover an agent needs it earlier. |
| Notification sink unavailable mid-emit (stdout closed) | Drop the event; the daemon's about to exit anyway. The runtime does NOT buffer events for later replay — agents that need durability use the rpc_log session machinery from v1.5 #16. |
| Race: listener emits `thread.event` while dispatcher mid-reply | Stream lock in `serialize_response` serialises them at the byte level; the JSON-RPC framing is still valid. |

## 5. Migration: opt-in capability, no break

`hello.data.capabilities.non_stop_runtime` is the negotiation
point. Agents that don't check it see no behaviour change —
`thread.continue` is a new endpoint, and `process.continue`'s
default `all_threads=true` keeps the old semantics. Notifications
flow regardless; clients that don't subscribe just see unknown
messages and (per JSON-RPC spec) ignore them.

`thread.list` already returns a state per thread — non-stop
makes that field meaningful at thread granularity, not just at
process granularity. Existing readers don't break.

## 6. Phase scope

### Phase-1 (this PR's territory)

- `src/runtime/nonstop_runtime.{h,cpp}` — class, state machine,
  listener thread, notification sink interface.
- `thread.continue` + `thread.suspend` + `thread.list_state`
  endpoints. `process.continue` extended with `all_threads`
  param.
- Notification framing in `src/protocol/notifications.{h,cpp}` —
  pure JSON-RPC serialisation, no transport assumptions.
- `hello.capabilities.non_stop_runtime` flag.
- Unit tests for the state machine + dispatcher wire shape.
- Live smoke against `lldb-server gdbserver` exercising
  thread.continue + thread.event round-trip.

### Phase-2 (separate commit)

- `event.subscribe` filtering endpoint.
- `thread.event{kind:"created"}` notifications + matching
  destroy.
- LldbBackend integration (today's `SBListener::SetAsync` flip is
  what's needed; the runtime layer is already backend-agnostic).
- DAP shim wiring (`continue` request with `singleThread:true`
  → `thread.continue`).

### Phase-3 (#25 / #26 territory)

- In-target agent-expression predicates ride the same per-thread
  state machine. Tracepoints are no-stop probes that fire on the
  listener thread.

## 7. Why this lands cleanly

`docs/11-non-stop.md`'s 2024-era research framed five engineering
items: event loop, per-thread state machine, suspend/resume,
endpoint review, push events. The v1.4–v1.5 work closed the
prerequisites:

- **Event loop**: #17's `RspChannel` reader thread is exactly this
  for the RSP-backed path.
- **Per-thread state machine**: the runtime owns it; phase-1
  ships it.
- **Suspend/resume primitives**: gdb's `vCont` already does
  per-thread; the runtime emits the right packets.
- **Endpoint review**: `process.continue` adds `all_threads`;
  `thread.continue` is new. No breaks.
- **Push events**: JSON-RPC 2.0 §4.1 notifications. Same channel,
  no side wires.

What's actually new in this commit is the *runtime* — the glue
between the listener and the wire. Everything underneath was
built across v1.4–v1.6's earlier work.

That's the plan. Implementation lands in the next commits.
