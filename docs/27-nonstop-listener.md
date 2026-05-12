# Non-stop runtime — phase-2 listener

Post-V1 #21 phase-2 (extension of `docs/26-nonstop-runtime.md`).
Phase-1 shipped the state-machine contract + wire surface +
notification primitives but left them **write-mirror, not
ground-truth**: `thread.list_state` reported intent expressed via
`thread.continue`, never observed state. Phase-2 closes that gap.

## TL;DR

- **`OutputChannel`** (new) wraps stdout + `WireFormat` + a mutex so
  the dispatcher's reply writes and the listener thread's
  notification writes byte-interleave safely. Replaces direct
  `protocol::write_message(std::cout, …)` calls in `stdio_loop.cpp`.
- **`StreamNotificationSink`** is the concrete `NotificationSink`
  installed into `Dispatcher::nonstop_` at startup. Forwards
  `emit(method, params)` to `OutputChannel::write_notification`.
- **`NonStopListener`** (new) is the listener thread. Owns a
  `shared_mutex`-guarded `target_id → RspChannel*` map; spins on
  `chan->recv(short_timeout)` for each registered channel, parses
  `T`/`S`/`W`/`X` stop replies via the existing
  `transport::rsp::parse_stop_reply`, and calls
  `runtime::NonStopRuntime::set_stopped` — which already emits
  `thread.event{kind:"stopped"}` through the sink.
- **Dispatcher** registers each `RspChannel` with the listener on
  `target.connect_remote_rsp` and unregisters on `target.close`.
- **`thread.suspend` stub stays -32001 in this commit.** Suspending
  a running thread requires emitting `vCont;t:tid` against an RSP
  data path, which is #17-phase-2 territory (operations through our
  own client, not LLDB's gdb-remote plugin). The listener side is
  ready; the writer side waits for #17-phase-2.
- **LldbBackend SetAsync(true) stays off.** Flipping that one line
  cascades behavioural changes across every existing test that
  expects `SBProcess::Continue` to block until stop. Out-of-scope
  for #21 phase-2; revisited when #17-phase-2 lands or as its own
  follow-up phase.

## 1. What's new on the wire (nothing)

This commit changes daemon-internal plumbing only. No new endpoints,
no new params, no new response fields. The pre-existing
`thread.event` notification (defined in docs/26 §1) becomes live for
RspChannel-backed targets: an agent that opens a target via
`target.connect_remote_rsp` and is connected to a real gdb-remote
server will start seeing `thread.event{kind:"stopped"}` push
messages on the daemon's stdout when the server emits stop replies.

`hello.capabilities.non_stop_runtime` was already `true` in
phase-1; the value is unchanged. Clients that branched on it can
now actually consume notifications; clients that didn't see no
behaviour difference (notifications are opt-in by listening).

## 2. OutputChannel — the stream lock

```cpp
class OutputChannel {
 public:
  OutputChannel(std::ostream& out, WireFormat fmt);
  void write_response(const json& reply);
  void write_notification(std::string_view method, json params);
 private:
  std::ostream& out_;
  WireFormat    fmt_;
  std::mutex    mu_;
};
```

Both writes acquire `mu_` briefly, encode via the existing
`protocol::write_message` (JSON line OR length-prefixed CBOR), then
release. The mutex is the entire stream-discipline mechanism — the
JSON-RPC framing inside `write_message` is unchanged; the lock just
prevents two writers from interleaving raw bytes.

`stdio_loop.cpp` is the only existing caller of
`protocol::write_message(std::cout, ...)`. It's rewired to take an
`OutputChannel&` (constructed by `main.cpp` over `std::cout` + the
negotiated format) and call `write_response` instead. The listener
thread is the second caller via `write_notification`.

## 3. NonStopListener

```cpp
class NonStopListener {
 public:
  NonStopListener(NonStopRuntime& runtime, std::chrono::milliseconds poll_interval);
  ~NonStopListener();   // shutdown + join

  void register_target(backend::TargetId, transport::rsp::RspChannel*);
  void unregister_target(backend::TargetId);

  // Test seam: process a single stop reply for a target synchronously
  // (used by unit tests in lieu of the real listener thread).
  void apply_stop_reply_for_test(backend::TargetId, std::string_view payload);
};
```

The listener thread loop:

```
while (!shutdown_.load()) {
  {
    std::shared_lock lk(map_mu_);
    for (auto& [tid, chan] : by_target_) {
      auto p = chan->recv(0ms);    // NON-BLOCKING — checks queue once
      if (p.has_value()) apply_stop_reply_(tid, *p);
    }
  }
  std::this_thread::sleep_for(poll_interval_);   // outside the lock
}
```

The shared_lock is held only across a sequence of non-blocking
`try_recv`s; iteration cost is microseconds even with many channels,
so `unregister_target`'s exclusive lock waits microseconds — not
`N × poll_interval`. The poll cadence comes from the sleep at the
bottom of the loop, which runs outside the lock so an unregister
during the sleep is a clean exclusive-lock acquire.

We deliberately keep the lock held across the `try_recv` calls
rather than snapshotting raw pointers and releasing — dropping the
lock would leave a window where `unregister_target` returns, the
dispatcher destroys the channel via `rsp_channels_.erase`, and the
listener's still-held raw pointer dangles. Shared_lock-across-try_recv
is the cheapest correct ownership discipline. A `shared_ptr<RspChannel>`
refactor would let unregister be instantaneous independent of the
snapshot pattern, but is more invasive than needed today.

`apply_stop_reply_` parses the payload with `parse_stop_reply`,
maps the gdb stop kv-pairs to `runtime::ThreadStop`, and calls
`runtime_.set_stopped(target, tid, info)`. The runtime emits the
notification (already wired in phase-1).

### Why a single listener thread, not one-per-channel

- **Bounded thread count.** A debugger session that opens 50 cores
  + 3 live RSP targets shouldn't spawn 53 listener threads.
- **Shutdown is simpler.** One `shutdown_` flag + one join, not N
  joins behind a barrier.
- **RspChannel already has its own reader thread**, doing the
  hot-path socket drain. The listener's polling work is per-message
  parse + state-machine call, both trivial — the wakeup cadence
  doesn't have to be tight.
- **Adding a per-channel thread later is easy** if profiling shows
  the shared poll is a bottleneck. Starting with one is the cheap
  default.

### Why `chan->recv(short_timeout)` instead of a single condvar

`RspChannel::recv` already uses a condvar internally to wake on
new packets. The listener could in principle subscribe to that
condvar directly, but the existing API only exposes the bounded
`recv` — exposing the internal condvar leaks the channel's
synchronisation primitives. The poll interval (50 ms) is short
enough that latency between server-side stop and notification is
dominated by network RTT, not the poll.

## 4. Dispatcher integration

```cpp
class Dispatcher {
  …
  runtime::NonStopRuntime    nonstop_;
  runtime::NonStopListener   nonstop_listener_;   // declared AFTER nonstop_
};
```

`nonstop_listener_` is a value-typed member constructed eagerly in
the dispatcher's init list with a reference to `nonstop_`. The
declaration order matters: on destruction, the listener joins
*first* (its thread's last reference to `runtime_` is dropped
before the runtime itself goes out of scope). Eager construction is
simpler than lazy (no atomic init-flag, no first-connect race
window) and the thread cost is one OS thread per daemon — well
within budget.

`handle_target_connect_remote_rsp` calls
`nonstop_listener_.register_target(tid, chan.get())` *after*
parking the channel in `rsp_channels_`. The two-step is safe
because the dispatcher is single-threaded (see dispatcher.h's
class comment): no other thread can observe the partial state
between the park and the register.

`handle_target_close` calls `nonstop_listener_.unregister_target(tid)`
*before* destroying the channel — after unregister returns, the
listener cannot be mid-recv on this channel, so the `unique_ptr`'s
destructor can join the channel's reader + close the fd without
racing the listener.

The order of operations in `handle_target_close` becomes:

```
1. backend_->close_target(tid)              // backend tears down its half
2. target_main_module_.erase(tid)
3. nonstop_listener_.unregister_target(tid) // listener stops touching the channel
4. rsp_channels_.erase(tid)                  // channel destructor joins its reader
5. nonstop_.forget_target(tid)
```

`unregister_target` is a single `unique_lock(map_mu_) + erase`. It
waits until the listener thread's current iteration's `shared_lock`
releases. Because the iteration is `try_recv` over each channel
(non-blocking) + apply (microseconds), the upper bound is
microseconds independent of `N`. After `unregister_target` returns,
the listener cannot dereference the channel pointer again until it
re-takes the lock, by which time `rsp_channels_.erase` is the only
reader allowed — and the channel pointer has been removed from
`by_target_`, so the iteration doesn't see it.

## 5. Tests

Phase-1's `tests/unit/test_nonstop_runtime.cpp` already covers the
runtime + sink shape. Phase-2 adds:

- **`tests/unit/test_nonstop_listener.cpp`** — listener with mock
  RspChannel (`AdoptFd` ctor + socketpair). Cases:
  - Apply `T05thread:1234;reason:trace;` payload via the test
    seam → runtime records kStopped, sink captures the
    notification with reason=trace.
  - Apply `W00` (exited) → runtime records kStopped (phase-1
    runtime doesn't model exit yet — that's phase-3 work; phase-2
    treats W/X as a stop with reason="exited"/"signalled").
  - Garbled payload → ignored, listener doesn't crash.
  - Unregister mid-recv (writes a packet, immediately
    unregisters, asserts the listener doesn't process it after
    the unregister returns).
- **`tests/unit/test_output_channel.cpp`** — concurrent
  write_response + write_notification from two threads, assert
  every emitted frame is a valid JSON line (no byte interleave).
- **`tests/unit/test_dispatcher_listener_register.cpp`** — deferred.
  The dispatcher wiring is two lines (register_target after parking
  in rsp_channels_; unregister_target before erasing); the unit-level
  listener tests cover the listener behaviour, and the live integration
  arrives with the smoke test once #17-phase-2 lets us drive `vCont`
  through `RspChannel`. Revisit if a future bug invalidates that
  judgement.

Live smoke (real `lldb-server` over RSP) is deferred to the same
follow-up that wires #17-phase-2's data path through `RspChannel` —
without that, we can't drive `vCont` through the channel, and
spontaneous server stops aren't reliably reproducible.

## 6. Failure modes (delta from docs/26 §4)

| Condition | Behaviour |
|---|---|
| RspChannel's reader thread dies (server EOF) | The channel's recv returns nullopt forever; the listener silently skips that entry. Optional follow-up: the channel could expose a "dead" flag and the listener could auto-unregister. Phase-2 leaves this manual (caller does target.close on a dead session). |
| `set_stopped` throws (sink throws) | `set_stopped` doesn't throw in phase-1's impl — sink->emit catches its own errors. The listener can't crash on this. |
| Two stop events for the same tid in quick succession | Each bumps stop_event_seq; each emits a notification. Idempotent at the state-machine level. |
| Listener shutdown vs in-flight recv | shutdown_ is checked between recv() calls (one poll cycle of latency); the recv itself is bounded by poll_interval. Worst case: dispatcher destructor waits one poll interval before the listener thread observes shutdown. |

## 7. What this unblocks

- **#17-phase-2** can now flip the data path through `RspChannel`
  without re-architecting notifications — the listener already
  consumes the stop replies that `vCont` will produce.
- **#25 (in-target agent-expression predicates)** rides the same
  per-thread state machine + notification surface. A predicate that
  fires becomes a `thread.event{kind:"predicate_hit"}` push.
- **#26 (tracepoints / no-stop collection)** ditto — tracepoints are
  no-stop probes that emit on the listener thread.
- **The LldbBackend SetAsync(true) flip** can land as its own commit
  with its own test cascade rather than blocking #21.
