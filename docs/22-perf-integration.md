# perf record/report integration

Post-V1 plan item #13 (`docs/15-post-v1-plan.md`, `docs/17-version-plan.md`).
Sibling to probes; reuses `#12`'s event-shape work so a profiling agent
can ingest `perf` samples through the same lens it already uses for
breakpoint hits and BPF events.

## Goals

- Let an agent ask the daemon to sample a running process (or a
  short-lived command) and get back **call-stack-attributed samples**
  shaped like the rest of the probe-event surface.
- Persist the raw `perf.data` blob in the ArtifactStore so a follow-up
  `perf.report` call (or out-of-band `perf script`, `perf annotate`,
  flamegraph tooling) can re-derive whatever the first parse missed.
- Keep the wire shape identical between probe hits and perf samples:
  `{ts_ns, tid, pid, cpu, stack: [{addr, sym, mod}]}`. The shape lines
  up with the `ldb-probe-agent` JSON shape #12 is landing in a parallel
  worktree; convergence is on the contract, not on the parser.

## Why shell out instead of linking libperf / libtraceevent

| factor              | shell-out (`perf record` / `perf script`)            | link libperf / libtraceevent          |
|---------------------|------------------------------------------------------|---------------------------------------|
| **license**         | GPLv2 binary at runtime — exec-only boundary is fine | GPL'd library; ldbd is Apache-2.0     |
| **kernel coupling** | tracks installed kernel — `perf` is the right tool   | per-kernel ABI breaks every release   |
| **build complexity**| zero — `perf` is a syscall away                      | adds bcc/libbpf-style dependency tree |
| **cancel / spawn**  | well-trodden subprocess + dup2-stdout pattern        | thread + ringbuf management           |
| **reversibility**   | replace later with `perf_event_open()` direct        | hard to walk back the link            |

One subprocess fork per `perf.record` invocation; bounded cost, and the
output is a real `perf.data` artifact that survives the daemon. The
license argument alone settles this — every other reason is a bonus.

## RPC surface

Three endpoints, mirror the `probe.*` triple:

### `perf.record`

Spawn `perf record` against a pid or a fresh subcommand, wait for the
trace to finish, ingest the resulting `perf.data` into the
ArtifactStore, and return the artifact id plus a summary.

```jsonc
// params
{
  "pid":          12345,           // OR "command": ["/usr/bin/foo", ...]
  "duration_ms":  500,             // wall clock; required for pid mode
  "frequency_hz": 99,              // -F flag; default 99
  "events":       ["cycles"],      // -e flag; default ["cycles"]
  "call_graph":   "fp",            // "fp" | "dwarf" | "lbr"; default "fp"
  "build_id":     "_perf"          // ArtifactStore key prefix; default "_perf"
}

// returns
{
  "artifact_id":  42,
  "artifact_name":"perf-20260511-123045Z.data",
  "sample_count": 312,
  "duration_ms":  504,
  "perf_argv":    ["perf","record",...],   // exact argv (post-resolution)
  "stderr_tail":  "..."                    // last ~4 KiB of perf stderr (diagnostic)
}
```

### `perf.report`

Re-parse an existing `perf.data` artifact and return its samples. Lets
the agent ask for an alternate projection (different stack depth,
symbol-only vs address+symbol) without re-recording.

```jsonc
// params
{
  "artifact_id": 42,
  "max_samples": 1000,             // cap; default 0 = no cap
  "max_stack_depth": 32            // truncate per-sample stacks; default 0 = no cap
}

// returns
{
  "samples": [
    {
      "ts_ns": 1700000000000000,
      "tid":   12345,
      "pid":   12345,
      "cpu":   3,
      "event": "cycles",
      "comm":  "foo",
      "stack": [
        {"addr": "0x412af0", "sym": "main",          "mod": "foo"},
        {"addr": "0x7ffe...","sym": "__libc_start", "mod": "libc.so.6"}
      ]
    }
  ],
  "total":          312,
  "truncated":      false,
  "perf_data_size": 65536
}
```

### `perf.cancel`

Send SIGTERM (then SIGKILL after a 250 ms grace) to an in-flight
`perf record` subprocess. Used for "stop early" workflows where the
caller already asked for 30 s but found enough at 3 s.

```jsonc
// params
{ "record_id": "r1" }       // returned by perf.record when async (future)
// returns
{ "record_id": "r1", "cancelled": true }
```

**Phase-1 note.** `perf.record` is **synchronous** in this batch: the
endpoint blocks for `duration_ms` and returns the artifact. `perf.cancel`
is registered in `describe.endpoints` for catalog completeness and
returns `-32002 kBadState` ("no in-flight perf.record") until the async
variant lands. The async variant slots in cleanly later because
`PerfRunner` already owns the subprocess as `std::unique_ptr` — async
mode flips the wait to a background thread and threads a `record_id`
through the cancel handler.

## Event shape alignment with `#12`

The `ldb-probe-agent` (#12) work is in a parallel worktree on this
branch. We've agreed (via `docs/08-probe-recipes.md` and the recipe
shape `docs/15-post-v1-plan.md §13`) that BOTH agents and the perf
ingestor will emit one canonical event:

```jsonc
{
  "ts_ns":   <uint64>,
  "tid":     <uint64>,
  "pid":     <uint64>,
  "cpu":     <int>,                // -1 when not known
  "event":   "<bpf-tracepoint-name | perf-event-name>",
  "stack":   [{"addr","sym","mod"}, ...]
}
```

The existing `probes::ProbeEvent` differs slightly (it carries
`registers`, `memory`, `site` for the breakpoint engine that does
NOT do stack walking). We do NOT shoehorn perf samples into
`probes::ProbeEvent`; samples live in their own `perf::Sample` type,
and the JSON shape is what we keep aligned with the BPF agent.

## perf script ingestion format

The parser invokes:

```
perf script -i <perf.data> --header \
            --fields comm,pid,tid,cpu,time,event,ip,sym,dso
```

`perf script` emits one HEADER block (lines starting with `#`), then
one *event header line* followed by zero or more *stack frame lines*
per sample, an empty line, and the next sample. Example (real, abbreviated):

```
# ========
# captured on : Mon May 11 12:00:00 2026
# os release  : 6.18.7-76061807-generic
# ========
foo 12345/12345 [003] 1700000000.123456: cycles:        4...:  412af0 main (foo)
                                                                  7ffe... __libc_start_main (libc.so.6)

foo 12345/12345 [003] 1700000000.124000: cycles:        4...:  412b00 do_work (foo)
                                                                  412af8 main (foo)
                                                                  7ffe... __libc_start_main (libc.so.6)
```

Format we lean on (stable across `perf` 5.x and 6.x; the `--fields`
selector pins the column order):

- Header lines: prefix `#`. Ignored.
- Event header line shape: `COMM PID/TID [CPU] SECS.USECS: EVENT_NAME:        SAMPLE_PERIOD:  IP SYM (DSO)`.
- Stack frame lines: leading whitespace, then `IP SYM (DSO)`.
- Sample boundary: blank line.

The parser is **format-tolerant**: missing `(dso)` is OK, `[unknown]`
sym is OK, the trailing `:` on the event name is consumed iff present.
It refuses to crash on a corrupt sample — that sample is dropped and
parsing continues with the next blank-line boundary.

## Failure matrix

| condition                                                     | response                                                              |
|---------------------------------------------------------------|-----------------------------------------------------------------------|
| `perf` not on PATH                                            | -32000 "perf binary not found on PATH; install linux-tools or set PATH" |
| `kernel.perf_event_paranoid > 1` and unprivileged             | -32000 "perf: permission denied (perf_event_paranoid=N)"              |
| target pid vanished mid-record                                | -32000 "perf record exited with rc=N: <stderr tail>"                  |
| user-supplied pid does not exist                              | -32000 "perf record exited with rc=N: <stderr tail>" (perf prints "couldn't open ...") |
| perf.data missing after record (perf segfaulted)              | -32000 "perf.data missing after record (perf rc=N)"                   |
| perf.data malformed (perf script bails)                       | -32000 "perf script: <stderr>"                                        |
| ArtifactStore not configured                                  | -32002 kBadState "artifact store not configured ..."                  |
| duration_ms > 5 minutes (300_000)                             | -32602 "duration_ms exceeds 300000 (5 min) cap"                       |
| duration_ms == 0 in pid mode                                  | -32602 "duration_ms must be > 0 when pid is set"                      |
| both `pid` and `command` set, or neither set                  | -32602 "exactly one of pid|command must be set"                       |
| ArtifactStore put fails                                       | -32000 "artifact store put failed: <msg>"                             |

## Security note

`perf record -p <pid>` needs either `CAP_SYS_ADMIN` or
`kernel.perf_event_paranoid <= 1`. The daemon does NOT setuid, does
NOT capabilities-grant, and does NOT touch `/proc/sys/kernel/perf_event_paranoid`.
On EPERM-style failures the dispatcher surfaces the kernel's exact
error in the `-32000` message; the operator decides whether to relax
paranoid (typically `sudo sysctl kernel.perf_event_paranoid=1` or
running ldbd under `sudo` for a contained dev session).

This mirrors the bpftrace policy: tools that need privileges fail
clean with a typed error rather than silently asking for them.

## Stdout discipline

`perf record` writes its data to the `-o <file>` argument; the only
chatter on stdout/stderr is the "[ perf record: Captured and wrote
N MB <file> ]" tail-line and possible kernel warnings. We capture
stderr to a bounded buffer for diagnostics, and we route the
subprocess's stdout to /dev/null via the `local_exec` pipe shape (the
child's stdout is a pipe back to ldbd's reader thread, never to fd 1
of the daemon). Same discipline as `bpftrace_engine` and `save_core`.

## Test surface

- **`tests/unit/test_perf_parser.cpp`** — pure parser test against a
  checked-in `tests/fixtures/perf_script_sample.txt` fixture. Verifies
  sample-boundary detection, stack-frame assembly, missing-DSO
  tolerance, and `[unknown]` symbol pass-through. No live perf needed.
- **`tests/smoke/test_perf_record.py`** — SKIPs cleanly when `perf` is
  not on PATH or when `perf stat -e cycles /bin/true` fails (paranoid
  setting). When live, drives a 500ms record against `ldb_fix_sleeper`
  and asserts `sample_count > 0` and that at least one sample's stack
  is non-empty.

## What's out of scope for phase 1

- **Async `perf.record`**: synchronous-only this batch; `perf.cancel`
  exists in the catalog but currently returns "no in-flight".
- **Flame-graph rendering / symbol attribution beyond what `perf script`
  emits**. The follow-up parses with `perf script -F +callindent` or
  pulls DWARF via the existing symbol path. Out of scope here.
- **Remote `perf` over ssh**. The existing `transport::SshHost`
  infrastructure could route a remote `perf record`, but the artifact
  transfer story is unwritten. Phase 1 is local-host only.
- **Kernel-mode samples** with `perf record -e cycles:k`. We pass user
  events only by default (`cycles:u`); the operator can pass any event
  via `events: [...]`, which we forward verbatim.
- **Live streaming** — `perf record --pipe` plus a streamed parser.
  The synchronous shape works fine for the agent's planning loop
  ("record 500ms, then look at the samples"); streaming is a clear
  future addition once we have a use case that needs it.
