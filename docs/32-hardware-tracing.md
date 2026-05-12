# Hardware tracing — Intel PT / ARM ETM — deferred design note

Post-V1 plan item **#22** from `docs/15-post-v1-plan.md`, listed in
v1.6's "specialized / opt-in" bucket per `docs/17-version-plan.md`:

> Hardware tracing. Intel PT / ARM ETM via perf or LLDB trace plugin.
> Linux x86-64 first.

This note documents what hardware tracing buys us, the existing
access paths, the integration shape if/when we build it, and the
**substantial** complexity that justifies its deferral. As with
the sibling note on #20 (own ptrace), the default disposition
remains "defer until a concrete user workload demands it."

## TL;DR

- **Deferred.** Hardware tracing is real and powerful but the
  integration is multi-week work and the audience is narrow.
  Watchlist in `docs/15-post-v1-plan.md` §5 already calls it out:
  Intel PT is x86-only and Linux-only in practice; ARM ETM access
  is gated on kernel + board support that is far from universal.
- **The shape, when triggered, is an extension to v1.4 #13's
  `perf.record` family.** Hardware tracing is "another perf event
  type" with a much-heavier-than-usual decoder. We do not invent
  a new endpoint family; we add `event: "intel_pt//"` (and a
  sibling for ARM) to `perf.record`, plus a `trace.decode` endpoint
  that runs `libipt` / `libxdc` over the recorded buffer.
- **Decoder selection is the hard part.** libipt (Intel) +
  libxdc / libopencsd (ARM) are non-trivial deps with their own
  build matrices. We gate the whole feature behind
  `LDB_ENABLE_HARDWARE_TRACING` and ship clean -32003 errors when
  unavailable.
- **Sideband data is the second hard part.** A PT/ETM trace alone
  is meaningless without correlated `mmap` / `sched_switch` /
  binary-load events; the perf subsystem emits these out-of-band
  and we have to reassemble them at decode time.

## 1. What hardware tracing offers

Intel Processor Trace (PT) and ARM Embedded Trace Macrocell (ETM)
are CPU-level facilities that emit a compressed branch trace as
the program executes, with negligible runtime overhead (typically
2–5% slowdown on hot paths). The output stream encodes:

- **Every taken branch** — direct, indirect, function call,
  return. With the binary in hand, the decoder reconstructs the
  exact instruction-by-instruction path the program took.
- **Cycle counts** between branches — call it "instruction-level
  timing without instrumenting." Optional; costs more bandwidth.
- **Context switches** — PT logs `CR3` changes so multi-process
  traces are demultiplexable; ETM logs `CONTEXTIDR`.
- **TSC timestamps** — periodic time-base packets let the decoder
  correlate the trace to wall-clock.

What this means for a debugger:

- **Post-mortem call-flow reconstruction**. "How did we get to
  this `abort()` call?" — a full backtrace is one frame, but PT
  shows you the last N branches that *led* to the frame.
- **Race / re-entrancy investigation**. Two threads on the same
  data; PT for both shows the exact interleaving.
- **Fault analysis on optimised builds**. With CFI / inlining /
  tail-calls the stack is lossy; PT shows the actual control
  flow including the inlined sites.
- **Performance ceiling diagnostics**. `perf record` sampling
  approximates hotspots; PT gives the exact path with cycle
  counts. The gap matters for "why is this 3% slower since the
  last release" investigations sampling can't answer.

LDB's existing surface — `perf.record` + the v1.4 #12 probe-agent
— covers sample-based profiling well. Hardware tracing is the
order-of-magnitude-richer alternative when sampling is too lossy.

## 2. Existing access paths

What the world looks like *today*, without LDB integration:

### 2.1. Linux `perf` (Intel PT)

```
perf record -e intel_pt//u -- ./victim
perf script --itrace=i100us             # decode every 100µs of trace
perf script --itrace=cr                 # call/return summary
```

`perf` ships with the right decoder (vendored libipt under
`tools/perf/util/intel-pt-decoder/`). The output is post-decoded
text; the raw PT data is in `perf.data` and re-decodable.

This is the **default integration path** for an LDB v1.6.1
"hardware tracing phase-0" — `perf.record({event: "intel_pt//u"})`
already works through #13's shell-out path; the artifact stores
the raw trace; `perf script` (also shelled-out) does the decode.
That's not what this note is about — that's just the existing
#13 surface accepting a richer event spec.

The *real* phase-1 of #22 is doing the decode **in-process** so
we can shape the output into the same `{ts_ns, tid, stack}`
schema the rest of LDB's event surface uses. Shelling out to
`perf script` works but the JSON shape it emits is
`perf script --json`'s opinion, not ours.

### 2.2. LLDB's `trace start intel-pt`

```
(lldb) trace start intel-pt --total-size 64MB
(lldb) c
(lldb) trace stop
(lldb) thread trace dump instructions
```

LLDB has had Intel PT support since LLVM 14, exposed via
`SBTrace` (`lldb/include/lldb/API/SBTrace.h`). It uses libipt
internally and surfaces decoded instructions through the SBAPI.

For LDB this is appealing: zero new C++ deps, surface the trace
through SBAPI, ship the agent-facing endpoints. The catch:

- **SBTrace's API surface is incomplete.** No SB way to iterate
  decoded instructions efficiently as JSON-ready records — the
  Python script-interpreter glue is the documented path. From
  C++ we'd have to call SB methods one decode at a time, which
  is multiple orders of magnitude slower than libipt direct.
- **It's Linux-only and Intel-only in practice.** ARM ETM
  support is theoretical in LLDB's tree but never has been
  exercised on a real board.
- **The format LLDB emits doesn't line up with the rest of LDB's
  event shape.** We'd have to transform every record anyway.

Reasonable middle ground: phase-1 uses LLDB's SBTrace to **start
and stop** the trace (it already wires the perf_event_open ABI
correctly), then reads the raw AUX buffer through SBAPI and runs
**our** libipt decode over it. Avoids reinventing the trace
start sequence; lets us own the decode output shape.

### 2.3. Android `simpleperf`

`simpleperf` is the ARM-side perf wrapper that ships with the
Android NDK. It supports ETM on devices that have it (a small
fraction of shipping phones; near-zero on cheap devices). If we
ever ship LDB for Android debugging, `simpleperf` is the right
shell-out — same shape as perf on Linux desktop, different
binary.

### 2.4. `bpftrace -K` / kernel-level helpers

Not hardware tracing per se, but worth mentioning: BPF's `kfunc`
+ `bpf_get_stack` give you call-graph snapshots cheaper than
`perf record` (no buffering, just per-event capture). The
existing v1.4 #12 probe-agent already supports this.

When to pick which:

- **Sampling sufficient?** → `perf.record` (#13) with cycle
  events, dwarf call-graph. Cheapest.
- **Need every branch?** → hardware tracing (#22). Most
  expensive to build, richest output.
- **Need specific syscalls / kfuncs?** → BPF probes (#12 +
  agent-side predicates from #25). Targeted.

## 3. LDB integration shape (when triggered)

### 3.1. Extending `perf.record` (already in v1.4 #13)

The existing endpoint:

```
perf.record({
  pid | command,
  duration_ms,
  frequency_hz,
  events: ["cycles"],
  call_graph: "fp" | "dwarf" | "lbr",
  build_id
})  → {artifact_id, sample_count, duration_ms, ...}
```

Hardware tracing slots in via the `events` field:

```
perf.record({
  pid: 12345,
  duration_ms: 1000,
  events: ["intel_pt//u"],   // user-space PT; "intel_pt//k" for kernel
  // OR
  events: ["cs_etm//u"],     // ARM CoreSight ETM
  // PT-specific knobs:
  intel_pt: {
    cyc:        true,         // emit cycle counts
    psb_freq:   0,            // packet sync bytes; 0 = default
    mtc_freq:   3,            // mini-time-counter rate
    noretcomp:  false,        // disable return compression
    branch:     true          // capture branches; false = direct only
  }
})  → {artifact_id, ...,
       hw_trace: {
         per_cpu_bytes: [...],  // raw AUX buffer sizes
         sideband_bytes: N      // mmap + sched events
       }
     }
```

The shape stays compatible with #13 — agents that don't know
about PT see a plain `perf.data` artifact; agents that *do* know
about PT see the extra `hw_trace` block summarising the raw
buffer state.

### 3.2. New endpoint: `trace.decode`

The decoded output is too rich for `perf.report` (which is shaped
for samples). New endpoint:

```
trace.decode({
  artifact_id:    42,         // the perf.data from a hw-trace-flavored record
  tid?:           54321,      // filter; default = all tids
  time_range?:    [t0, t1],   // ns; default = whole trace
  output:         "instructions" | "calls" | "summary",
  max_records?:   100000      // cap; sensible default
})
  → {
    output: "instructions",
    records: [
      {ts_ns, tid, ip, opcode, mnemonic, branch_kind?, cycle_delta?},
      ...
    ],
    truncated: bool,
    total_decoded: N
  }
```

Three output projections:

- **`instructions`** — every retired instruction (PT's "all
  instructions" decode). High-volume; capped aggressively.
- **`calls`** — the call/return graph projection. Smaller; the
  shape most agents actually want for "what code path led to X."
- **`summary`** — hotspot histogram, branch counts by function.
  Smallest; the "where did time go" projection.

The wire shape mirrors v1.4 #13's sample format where it can:
`{ts_ns, tid, ip, stack}` for the `calls` projection so an agent
that already knows `perf.report` doesn't have to re-learn.

### 3.3. Implementation outline

```
src/hwtrace/
  perf_event.{h,cpp}      // perf_event_open wrapper for PT/ETM mode
  aux_buffer.{h,cpp}      // mmap'd AUX ring + sideband ring management
  decoder_ipt.{h,cpp}     // libipt thin wrapper; outputs DecodedRecord
  decoder_etm.{h,cpp}     // libxdc / libopencsd wrapper (ARM)
  sideband.{h,cpp}        // mmap/sched_switch/comm event correlation
  projection.{h,cpp}      // {instructions, calls, summary} shapers
```

The sideband correlator is the load-bearing piece. PT traces
say "branch taken from IP X to IP Y" — but X/Y are virtual
addresses that mean different things in different processes. To
ground them in code, the decoder needs:

- **Every `mmap` event** the kernel emitted for the traced
  process(es) — which file got mapped at which address range.
- **Every `sched_switch`** between traced and untraced threads
  — so we can mark gaps in the trace.
- **`comm` events** for context (process name changes via
  `prctl(PR_SET_NAME)`).
- **`exec` events** so the decoder swaps its address-space
  understanding mid-trace if needed.

`perf record` emits all of these alongside the PT data; the
parser has to reassemble them. This is non-trivial; libipt does
not do it for us.

### 3.4. Decoder lifecycle

```
1. Open artifact → mmap the perf.data blob.
2. Parse header → enumerate AUX buffer slices per CPU.
3. Build initial address map from sideband mmap events at t=0.
4. For each AUX slice:
     a. Feed sideband events with ts < slice.start_ts into the
        address map.
     b. Open a libipt decoder on the slice.
     c. Step decoder; for each event, look up symbol via the
        v1.5 #18 symbol index (build_id keyed → already cached).
     d. Project to the requested output shape.
     e. Yield records, respecting max_records cap.
5. Close decoder; close mmap.
```

The symbol-index lookup is the v1.5 #18 hook. Without it, we'd
shell out to `addr2line` per-record (catastrophic) or load
debug info per-binary per-decode (still bad). With it, address
resolution is sub-microsecond per record and the decoder runs at
libipt-native speed (~30M instructions/s on modern x86).

### 3.5. Memory pressure

A 1-second PT trace at 5% CPU overhead generates ~200 MB of raw
trace data per core. A 10-second 8-core trace is ~16 GB. Two
mitigations:

- **Streaming decode**. The decoder shouldn't require the whole
  AUX buffer in RAM; `aux_buffer.cpp` exposes a slice iterator
  so the decoder can pull one ~64 MB chunk at a time.
- **Recording-side filtering**. PT supports per-process /
  per-CR3 filtering at the hardware level. `perf.record` should
  expose this — `intel_pt: {filter_cr3: <pid>}` so we don't even
  record traces for unrelated processes.

Even with both, large traces will OOM. The endpoint surface
caps `max_records` aggressively; a "give me everything" decode
of a multi-GB trace returns `truncated: true` with a hint to
narrow the `time_range`.

## 4. Dependencies

| Dep | Purpose | Linux x86-64 status | Linux arm64 status |
|---|---|---|---|
| `libipt` (Intel) | PT decoder | mature; in distro repos (`libipt-dev`) | N/A |
| `libxdc` | ETMv4 decoder | N/A | mature; tied to AFL++/research tools |
| `libopencsd` | ARM CoreSight decoder (incl. ETM) | N/A | mature; in distro repos (`libopencsd-dev`) |
| `linux >= 4.1` | PT support | shipping | N/A |
| `linux >= 4.x` (CoreSight) | ETM support | N/A | shipping kernel; **board firmware required** |
| Hardware | PT (Broadwell+); ETM (Cortex-A57+, but vendor-gated) | desktop CPUs since ~2014 | server/SBC chips, varies wildly |

The **gating** factor on arm64 is hardware + firmware support
for ETM, not software. Many production arm64 server chips
(AWS Graviton, Ampere Altra) expose ETM via CoreSight; many
embedded chips (most Raspberry Pi variants) do not. Phase-1
ships Intel PT first because the hardware base is wider and
more uniform.

CMake gate:

```cmake
option(LDB_ENABLE_HARDWARE_TRACING "Build Intel PT / ARM ETM decoders" OFF)

if (LDB_ENABLE_HARDWARE_TRACING)
  if (ARCH STREQUAL "x86_64")
    find_package(LIBIPT REQUIRED)
  elseif (ARCH STREQUAL "aarch64")
    find_package(LIBOPENCSD REQUIRED)
  endif()
  target_compile_definitions(ldbd PRIVATE LDB_HW_TRACING=1)
endif()
```

When `LDB_HW_TRACING` is undefined, `perf.record({event: "intel_pt//..."})`
returns `-32003 kNotSupported` with the message
"hardware tracing not compiled in; rebuild with -DLDB_ENABLE_HARDWARE_TRACING=ON".

## 5. Complexity assessment

Honest accounting of the work, broken down:

| Component | Effort | Notes |
|---|---|---|
| `perf_event_open` wrapper for PT/ETM | 1 week | Mostly translating documentation; pitfalls in AUX area mmap sizing |
| AUX buffer ring management | 1–2 weeks | Lock-free wraparound, sideband multiplexing |
| libipt integration + thin wrapper | 1 week | Library is well-documented; the wrapping is straightforward |
| Sideband correlator | 2 weeks | The buggy part — mmap/exec/sched events have lots of edge cases |
| Three output projections | 1 week | `instructions` is direct; `calls` requires stack tracking; `summary` is histograms |
| ARM equivalent (libopencsd) | 2–3 weeks | Lower priority; ABI is messier than PT |
| Smoke tests against real hardware | 1 week | Requires PT-capable CI runner |
| Memory-pressure handling + slice iterator | 1 week | Worth doing before any prod load |
| Symbol-index integration (lookups during decode) | 0.5 weeks | Cheap if #18 has landed |
| **Total** | **~10–12 weeks** for x86-64 PT alone | ARM adds another 3–4 weeks |

This is the deferred-for-good-reason figure. Phase-0 (shell-out
to `perf script` for decode) is cheap (~1 week) and might be all
we need; phase-1 (in-process decode + shaped output) is the work
this note describes.

## 6. Triggering signals

What would justify spending the 10+ weeks:

- **A concrete user workload** that hits the gap sample profiling
  leaves. Concrete = "we used `perf record` and the answer wasn't
  there; the next thing we tried was PT and it was." Not "PT
  would be cool."
- **Fault-analysis investigations** where the stack at fault is
  too lossy and PT's pre-fault branch history is the differentiator.
- **Performance regression hunts** where sample profiling can't
  reach a statistically significant difference and PT's exact
  branch counts can.
- **Existing perf-script shell-out (phase-0) revealed as the
  bottleneck.** If we ship phase-0 and find that agents are
  doing tens of decodes per hour and the shell-out overhead
  matters, phase-1's in-process decoder pays for itself.

Until at least one of these has a real ticket attached, the
work stays deferred.

## 7. Failure matrix (anticipated)

| Failure | Behaviour |
|---|---|
| `LDB_HW_TRACING` not compiled in | `perf.record` with PT event returns `-32003 kNotSupported` + build hint |
| Hardware doesn't support PT (pre-Broadwell, Atom, AMD) | `perf_event_open` returns `EOPNOTSUPP` → `-32000` with hardware advice |
| Kernel too old (`< 4.1`) | `perf_event_open` returns `EINVAL` on the PT-specific attribute → `-32000` with kernel hint |
| AUX buffer mmap fails (no permission / huge pages exhausted) | `-32000` with errno text |
| Trace overflows mid-record (overhead too high, buffer too small) | Record completes with a `truncated: true` flag on the artifact; decode surfaces the gap as `[trace_gap]` records in the output |
| libipt decode error (corrupt PSB, malformed packet) | Skip to next PSB sync point; emit `[decode_error: …]` record; continue |
| Sideband correlation can't locate the mmap for an IP | Record output has `sym: null, mod: null`; decode does not abort |
| Symbol-index miss (binary not in the v1.5 #18 cache) | Trigger #18's lazy populate path; decode pauses until populated; large traces may need `index.warm` first |
| Decode would exceed `max_records` cap | Stop and return `truncated: true, total_decoded: N` |
| Decode would OOM (slice > available RAM) | Slice iterator should prevent; if a single slice still OOMs, surface `-32000` with the offending slice size |

The general principle is **degrade gracefully on hardware/kernel
shortfalls** and **truncate-with-receipts on resource limits**.
Hardware tracing's output is intrinsically lossy at high overhead;
the surface must reflect that.

## 8. Recommendation

**Defer.** Build phase-0 (`perf.record` accepting `intel_pt//`
events + shelling out to `perf script` for decode) if there's
even one concrete user request — phase-0 is cheap and covers
~80% of the value. Build phase-1 (in-process decode + shaped
output) only after phase-0's shell-out overhead is *measured*
as a bottleneck.

If/when phase-1 is built:

- **Gate behind `LDB_ENABLE_HARDWARE_TRACING`** so default builds
  don't pull in libipt / libopencsd.
- **x86-64 PT first; ARM ETM second.** Hardware base is wider on
  x86-64 and the libipt path is cleaner.
- **Lean on the v1.5 #18 symbol index** for address resolution
  during decode. Without it, hardware tracing is unusable at
  scale; with it, decode runs at libipt-native speed.
- **Surface `trace.decode` as a distinct endpoint**, not as a
  perf.report variant — the output shapes diverge enough to
  warrant the split.

The down payment in this note is the integration shape and the
dep matrix. A future contributor reading this should know:
where the work lives, what it costs, what triggers the build,
and what shape it ships in.

## 9. Cross-references

- `docs/15-post-v1-plan.md` #22 — catalog entry + watchlist
  ("Hardware tracing on macOS is essentially absent. Intel PT is
  x86-only and Linux-only in practice").
- `docs/17-version-plan.md` v1.6 — specialized/opt-in bucket
  rationale.
- `docs/22-perf-integration.md` — v1.4 #13's perf.record surface
  that this note extends.
- `docs/23-symbol-index.md` — the v1.5 #18 cache that makes
  decode-time address resolution fast.
- libipt: https://github.com/intel/libipt (BSD-3-Clause).
- libopencsd: https://github.com/Linaro/OpenCSD (Apache-2.0 /
  BSD-3-Clause).
- Linux kernel docs: `Documentation/trace/intel_pt.rst`,
  `Documentation/trace/coresight/`.
