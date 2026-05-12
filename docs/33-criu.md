# criu snapshot / fork — deferred design note

Post-V1 plan item **#24** from `docs/15-post-v1-plan.md`, listed in
v1.6's "specialized / opt-in" bucket per `docs/17-version-plan.md`:

> criu snapshot/fork. Linux-only opt-in; fragile (eBPF, io_uring,
> GPU contexts break it).

This note documents what CRIU would buy us, the brutal
compatibility matrix that gates it, the integration shape if a
real user need ever justifies the work, and why the default
disposition remains "defer until concrete demand."

## TL;DR

- **Deferred indefinitely.** CRIU is genuinely useful for a narrow
  set of debugging workflows (rewind without rr's recording
  overhead; parallel-investigation fork; checkpoint long-running
  analysis state). It is also genuinely fragile: a substantial
  fraction of real-world processes don't survive a CRIU dump.
- **Shipping CRIU integration requires honesty about that fragility.**
  An LDB endpoint that succeeds 30% of the time and silently
  corrupts the other 70% is worse than no endpoint. Whatever
  we ship has to detect upfront the incompatibilities, refuse
  cleanly, and document the matrix.
- **Integration shape, when triggered: `session.criu_fork` +
  `session.criu_restore`.** Sits alongside the v1.5 #16
  `session.fork` / `session.replay` (which are *RPC-log* fork /
  replay, not process-state fork). The criu variant operates on
  the live debuggee process tree, not on the dispatcher's
  recorded log.
- **Hard runtime requirements.** Root or CAP_CHECKPOINT_RESTORE;
  CRIU package installed; kernel >= 3.11 with the relevant
  CONFIG flags; matching kernel between checkpoint and restore.
  The endpoint surfaces all of these as clean `-32003 kNotSupported`
  errors when missing.

## 1. What CRIU does

CRIU (Checkpoint/Restore In Userspace) serializes a running
Linux process tree to a directory of files on disk, then later
deserializes that directory into a restored process tree that
resumes execution at the point of checkpoint. What gets
captured:

- **Memory state** — every VMA, page-by-page, including
  anonymous mappings, file-backed mappings, shared memory.
- **Register state** — every thread's GP / FP / vector
  registers (via ptrace under the hood).
- **Open file descriptors** — files, sockets (TCP/UDP/Unix),
  pipes, eventfds, signalfds, timerfds, epoll fds.
- **Process tree** — parent/child relationships, session and
  process group ids, controlling terminal.
- **Namespaces** — mount, network, pid, uts, ipc namespaces
  serialise correctly if the input process is namespaced.
- **Network connections** — TCP connections are captured with
  the kernel's help (via the TCP repair socket option), then
  restored to the same state (sequence numbers, window sizes,
  pending data).
- **Signal state** — pending signals, signal handlers, blocked
  signal masks.
- **Filesystem state** — current working directory, root,
  umask, file leases, file locks.

What CRIU *can* do, with care:

- Restore to a different machine (with a matching kernel and
  matching binaries on disk).
- Restore multiple times from the same checkpoint (each restore
  is independent).
- Optionally restore network connections to a different remote
  peer (with cooperation from criu-libnetlink).

This is a remarkable engineering achievement and a huge surface
for things to go wrong.

## 2. Why this is interesting for a debugger

Two specific user stories justify the deferred slot in the
post-V1 plan:

### 2.1. `session.criu_fork` — parallel investigation

Agent has a long-running debuggee in an interesting state ("the
network thread is wedged on a select; the worker pool has 47
threads, 12 of them holding the contended mutex"). It wants to
explore two hypotheses without losing the state. Today the only
option is "single-step very carefully," which is destructive of
the state and serializes the investigation.

With CRIU:

```
session.criu_fork({target_id: 1, name: "hypothesis-A"})
  → {snapshot_id: "...", artifact_id: 42}

# Agent now investigates hypothesis A on the original target.
# Restores snapshot to investigate hypothesis B in parallel:

session.criu_restore({snapshot_id: "...", as_target: true})
  → {target_id: 2, ...}
```

Now we have two live debuggees, both at the same state. The
agent can investigate hypothesis A and hypothesis B
independently; whichever turns out to be right informs the
next snapshot.

### 2.2. `session.criu_rewind` — rewind without rr overhead

rr (the existing reverse-execution backend, reachable via
`rr://` URL) records every system event ahead-of-time, paying
a 1.5–3× runtime overhead. For workloads where that overhead
is too high — or where the bug only reproduces at full speed —
rr isn't viable.

CRIU offers a coarser alternative: periodic checkpoints during
execution, then restore-to-checkpoint as the rewind primitive.
You can't reverse-step instruction-by-instruction (that's rr's
trick), but you *can* "rewind to 30 seconds ago" with near-zero
runtime overhead.

```
session.criu_checkpoint_periodic({target_id: 1, interval_ms: 30000})
session.criu_list_checkpoints({target_id: 1})
  → [{snapshot_id, ts_ns}, ...]
session.criu_restore({snapshot_id: <30s ago>, as_target: true})
```

This is the **"poor man's rr"** story. It's coarser than rr but
cheaper at runtime, and the workloads that benefit are real:
flaky bugs in latency-sensitive services, GPU-adjacent code rr
can't record at all, long-running analysis sessions where
"checkpoint every 30s, restore when needed" is the right grain.

## 3. What breaks — the compatibility matrix

This is the hard part. CRIU's "Compatibility" doc
(criu.org/Compatibility) lists what's supported and what isn't;
the watchlist in `docs/15-post-v1-plan.md` §5 quotes the
operational summary:

> Many real processes don't survive a CRIU dump (eBPF maps,
> io_uring, GPU contexts).

Concrete list, organized by failure mode:

### 3.1. Hard breaks (dump refused or restore fails)

- **eBPF programs / maps**. The kernel-side state for an
  attached BPF program is not serializable. Any process with
  attached BPF (bpftrace running, libbpf-based agents, perf
  events) refuses to dump.
- **io_uring instances**. The kernel-side SQ/CQ rings and the
  registered file descriptors are not serializable. Modern
  servers using io_uring (Postgres 17+, many Rust runtimes,
  nginx 1.25+ with `worker_use_uring`) cannot be CRIU-dumped.
- **GPU contexts**. CUDA, OpenCL, Vulkan, OpenGL — the driver-
  side state is not serializable. The most useful debugging
  targets (ML inference servers, game clients) are off the
  table.
- **KVM guests inside the target**. The kernel's KVM state is
  not serializable from userspace. A qemu instance can't be
  CRIU-dumped without `--kvm` cooperation that isn't ready.
- **Unsupported namespace flavours**. User namespaces with
  uid/gid maps that change after process start. Some cgroup v2
  layouts. The kernel's `user_namespaces.7` man page enumerates
  the gotchas.

### 3.2. Soft breaks (dump succeeds, restore wrong)

- **Pinned hardware resources**. Memory-mapped device files
  (`/dev/uio*`, `/dev/dri/*`), PCI BAR mappings, hugepages with
  specific physical addresses. Dump captures the VMA but the
  restore can't re-map to the same physical pages.
- **Some shared-memory patterns**. `MAP_SHARED` between processes
  not in the dump set; the restore loses the shared mapping.
  CRIU's `--shell-job` flag helps some cases but not all.
- **Real-time signals with side effects**. POSIX timers, RT
  signal queues with `SA_SIGINFO`. Restored, but the queue
  ordering may differ.
- **Network connections with state outside the kernel**. TLS
  sessions (keys live in userspace; the connection restores but
  the TLS context is invalid). Kerberos credentials. QUIC (kernel
  has minimal state; userspace has all the keys).
- **File leases / mandatory locks**. The kernel may not let us
  re-acquire on restore.

### 3.3. Works fine

- **Vanilla single-process or fork()'d worker tree** with stdio,
  files, plain TCP/UDP, posix shm, pthreads, normal signals.
- **Containerized workloads** that already run inside CRIU-aware
  orchestrators (Podman with `podman container checkpoint`,
  Kubernetes via `kubelet checkpoint` (alpha)).
- **Long-running analysis processes** like REPLs, language
  servers, simple compute jobs — exactly the kind of thing
  where rewind-to-30s-ago would be useful.

The honest summary: **CRIU works fine for the easy cases and
fails for the cases users most want debugging help with**. This
is not a knock on CRIU; it's the law of "everything kernel-
adjacent breaks process serialization." It is the reason this
note recommends deferring.

## 4. LDB integration shape (when triggered)

### 4.1. Endpoints

Three new endpoints. All gated behind `LDB_ENABLE_CRIU` (build-
time) and kernel/runtime CRIU availability (run-time).

```
session.criu_fork({
  target_id:   1,
  name:        "hypothesis-A",
  description?: "..."
}) → {
  snapshot_id:  "<32-hex>",
  artifact_id:  42,                       // dump dir is stored as artifact
  ts_ns:        1700000000000000000,
  bytes:        134217728,                // dump dir size
  compatibility_warnings: ["..."]         // see §4.3
}

session.criu_restore({
  snapshot_id:  "<32-hex>",
  as_target?:   true,                     // default true; if false, error-out + return what would happen
  attach?:      true                      // default true; if false, restore detached
}) → {
  target_id:    2,                        // new debuggee handle
  pid:          54321,                    // post-restore pid (may differ from original)
  ts_ns:        1700000000000010000
}

session.criu_list_snapshots({
  target_id?:   1                         // optional filter; default = all
}) → {
  snapshots: [
    {snapshot_id, target_id, ts_ns, name, bytes},
    ...
  ]
}
```

A fourth endpoint, `session.criu_check`, runs CRIU's dry-run
analysis against a target *without* dumping — surfaces the
compatibility warnings (§4.3) so an agent can ask "would this
work?" before committing to a dump.

```
session.criu_check({target_id: 1}) → {
  would_succeed:        false,
  hard_breaks:          ["bpf-program-attached", "io_uring-detected"],
  soft_breaks:          [],
  hint:                 "detach bpftrace agent and disable io_uring before retrying"
}
```

### 4.2. Implementation

CRIU is invoked as a subprocess (`criu dump --tree <pid> --images-dir
<dir>`). The integration is **not** a library link:

- CRIU is GPLv2. ldbd is Apache 2.0. Same constraint as the v1.4
  #13 perf integration; the right answer is the same — exec
  boundary, not a link.
- CRIU's CLI is the supported interface; the C API is for CRIU
  developers, not consumers.

Module layout:

```
src/criu/
  driver.{h,cpp}        // CRIU subprocess invocation; dump + restore
  compatibility.{h,cpp} // pre-flight checks (BPF detection, io_uring fd scan, etc.)
  snapshot_store.{h,cpp} // snapshot metadata sqlite (separate from artifact DB)
```

A snapshot is stored as:

- A directory under `${LDB_STORE_ROOT}/snapshots/<snapshot_id>/`
  containing CRIU's `core-*.img`, `pages-*.img`, `pstree.img`,
  etc.
- A row in a `criu_snapshots` table in the session DB
  (or a new sibling table) tracking
  `(snapshot_id, target_id, ts_ns, name, bytes, dir_path,
   compatibility_warnings_json)`.
- Optionally, a `.ldbpack` extension that bundles a snapshot for
  cross-host transfer — phase-2 territory.

### 4.3. Pre-flight checks (the load-bearing piece)

Before invoking `criu dump`, scan the target for known
incompatibilities:

```cpp
struct CompatReport {
  bool                      would_succeed;
  std::vector<std::string>  hard_breaks;   // criu would refuse
  std::vector<std::string>  soft_breaks;   // dump ok, restore suspect
  std::string               hint;
};

CompatReport check_compatibility(pid_t root) {
  CompatReport r;

  // 1. eBPF detection: walk /proc/<pid>/fdinfo/*, look for "bpf-prog"
  //    or "bpf-map" anonymous inode signatures.
  if (has_bpf_fds(root)) r.hard_breaks.push_back("bpf-program-attached");

  // 2. io_uring detection: walk /proc/<pid>/fdinfo/*, look for "io_uring"
  //    in the file path. Also check for IORING_SETUP_SQPOLL kernel threads
  //    attached to this pid.
  if (has_iouring_fds(root)) r.hard_breaks.push_back("io_uring-detected");

  // 3. GPU contexts: scan /proc/<pid>/maps for /dev/dri/, /dev/nvidia*,
  //    /dev/kfd, etc.
  if (has_gpu_mmaps(root)) r.hard_breaks.push_back("gpu-context-detected");

  // 4. KVM: scan for /dev/kvm in fdinfo.
  if (has_kvm_fds(root)) r.hard_breaks.push_back("kvm-guest-detected");

  // 5. Mounted device files we can't restore.
  if (has_hot_device_mmaps(root)) r.soft_breaks.push_back("device-mmap-detected");

  // 6. Recursive: include all threads + child processes.
  for (auto child : enumerate_descendants(root)) {
    auto sub = check_compatibility(child);
    merge(r, sub);
  }

  r.would_succeed = r.hard_breaks.empty();
  return r;
}
```

The pre-flight scanner does **not** call `criu dump --check`
itself (CRIU's own dry-run is more thorough but also more
expensive — it forks). Instead it's a cheap O(fdcount + vmacount)
scan that catches the common cases and surfaces them as
structured hints. For the actual go/no-go, we call
`criu dump --pre-dump --leave-running` and check the exit code.

The pre-flight scanner is the difference between "CRIU
integration that's honest about its limits" and "CRIU
integration that fails confusingly half the time."

### 4.4. Snapshot artifact lifecycle

Snapshots are big. A 1 GB anonymous mapping in the target is a
1 GB pages-*.img on disk. The store needs:

- **Garbage collection.** Snapshots auto-expire on a TTL
  (default 7 days). Explicit `session.criu_delete({snapshot_id})`
  removes earlier. Add to the existing artifact-store GC sweep.
- **Quota.** A `LDB_CRIU_MAX_BYTES` env (default 10 GB) caps
  total snapshot storage. Exceeded → oldest auto-expires.
- **Compression.** Phase-2: `criu dump --compress` (LZ4 via CRIU
  plugins). Phase-1 stores raw.

### 4.5. Restoration semantics

`session.criu_restore` is where the wire shape gets interesting:

- **`as_target: true` (default)**: restore the process, attach
  LDB to it (via `ptrace` or `target.attach`), return a new
  `target_id` the dispatcher can route subsequent calls to.
  The restored process's pid is *new* (kernel assigns it) — the
  original pid is captured in the snapshot metadata for
  reference but not preserved on restore.
- **`as_target: false`**: restore the process detached (CRIU's
  default behaviour); LDB doesn't attach. The agent gets back
  the pid; if it wants to debug the restored process later, it
  uses `target.attach({pid})` normally.
- **`attach: false` with `as_target: true`**: invalid; rejected
  at param validation.

The restored process resumes from exactly where the snapshot
captured it. **It does not share state with the original target.**
Network connections in the snapshot were repair-mode-stashed;
on restore they re-enter the network stack as new connections
with the same seq/ack numbers — which works if the peer is still
alive and hasn't moved on, and doesn't work otherwise. Phase-1
documents this; the agent's responsibility.

## 5. Hard requirements

CRIU is fussy about its environment. The endpoint surface
exposes every gate as a clean failure:

### 5.1. Privileges

CRIU needs **either**:

- Root (`CAP_SYS_ADMIN` is the bottom line).
- `CAP_CHECKPOINT_RESTORE` (kernel 5.9+) — the targeted alternative
  to running as root. Recommended.

`ldbd` itself does not need to run with these caps — `criu` is
invoked as a subprocess. But the subprocess needs them, which
means either:

- `ldbd` runs as root (security regression).
- `criu` is suid (CRIU project discourages this).
- The user has configured a sudoers rule or a `cap_set_file
  cap_checkpoint_restore` setcap on the criu binary.

The endpoint surfaces this honestly:

```
session.criu_fork({target_id: 1, name: "..."})
  → -32003 kNotSupported
     "criu requires CAP_CHECKPOINT_RESTORE or root. Either run
      ldbd as root, or `setcap cap_checkpoint_restore=eip /usr/sbin/criu`."
```

### 5.2. CRIU installed

```
session.criu_fork → -32003
  "criu binary not found in PATH. Install criu (apt install criu /
   dnf install criu / brew install criu (no — CRIU is Linux-only)).
   See https://criu.org/Installation"
```

### 5.3. Kernel version

CRIU formally supports Linux 3.11+. Some features (the
`CAP_CHECKPOINT_RESTORE` cap, network repair sockets) need
newer kernels. Phase-1 documents the minimum at 5.9; older
kernels error out with a hint.

### 5.4. Kernel CONFIG flags

CRIU needs `CONFIG_CHECKPOINT_RESTORE=y` and a handful of
related kconfigs. Most distro kernels have these; some hardened
configurations don't. Detection: `criu check --extra` exits 0
when the kernel is suitable. Phase-1 caches this check at daemon
startup; if it fails, all criu endpoints return -32003.

### 5.5. Same kernel for checkpoint and restore

CRIU's images are kernel-version-tagged. Restoring a snapshot
from a different kernel version usually fails. Phase-1 records
the kernel uname in snapshot metadata; restore-time checks it
matches the running kernel and surfaces `-32000` with a hint if
not.

## 6. Triggering signals

Criu is niche. The watchlist's framing — "we shouldn't ship until
demand" — is the right disposition. Specifically, build this
when:

- **One concrete user workflow exists** where:
  (a) the process is CRIU-compatible (no BPF, no io_uring, no
      GPU);
  (b) the alternative (rr, manual restart) is materially worse;
  (c) the user is willing to operate the "set up criu + caps"
      side of the equation.
- **The v1.5 #16 RPC-log fork (`session.fork`) doesn't cover the
  story.** Today's `session.fork` operates on the dispatcher's
  recorded log — replay the call sequence on a fresh daemon.
  It doesn't fork *live process state*, which is what criu_fork
  would buy. If users hit the gap consistently, this is the
  trigger.
- **Phase-0 doesn't exist for CRIU.** Unlike #22 (hardware
  tracing) where shelling out to `perf script` is a reasonable
  phase-0, there is no analogous "shell out to criu and parse
  the output" middle ground — either we orchestrate the dump-
  and-restore through ldbd's endpoints, or the user does it
  manually outside ldbd. The former is the whole integration.

## 7. Failure matrix (anticipated)

| Failure | Behaviour |
|---|---|
| `LDB_ENABLE_CRIU` not compiled in | criu endpoints return `-32003 kNotSupported` + build-flag hint |
| `criu` binary not in PATH | `-32003` + install hint |
| Missing CAP_CHECKPOINT_RESTORE | `-32003` + setcap hint |
| Pre-flight detected eBPF / io_uring / GPU | `-32003` with the specific hard_break and a hint to detach the offending subsystem |
| Pre-flight detected soft_break only | Dump proceeds with `compatibility_warnings` in the response; agent's choice whether to trust the restore |
| `criu dump` fails (non-zero exit) | `-32000 kBackendError` with criu's stderr tail; snapshot directory cleaned up |
| Snapshot directory partially written | Cleaned up on dump failure (RAII guard); never left half-baked |
| Snapshot quota exceeded | Oldest snapshots auto-expire to make room; if even after expiry quota is still exceeded, `-32000` with a hint to raise `LDB_CRIU_MAX_BYTES` |
| `criu restore` fails (e.g. port reuse conflict, missing file) | `-32000` with criu stderr tail; the snapshot itself is left intact for retry |
| Restore-time kernel != snapshot-time kernel | `-32000` with both uname strings; advice to use a matching host |
| Snapshot ID doesn't exist | `-32602 kInvalidParams` |
| Snapshot exists but directory was deleted out-of-band | `-32000` "snapshot directory missing"; snapshot row marked stale |
| `as_target: true` but `attach: false` | `-32602` invalid combo |
| Disk full during dump | criu surfaces ENOSPC → wrapped as `-32000` with a hint |
| Restored process exits immediately (snapshot was captured at exit time) | Surface the exit reason as part of the restore response; `target_id` is still returned but `process.status` will reflect "exited" |

The unifying principle: **fail loudly, fail upfront, never
silently restore a half-broken process**. CRIU's failure modes
are usually decisive (the dump or restore exits non-zero); the
endpoint surface mirrors that decisiveness.

## 8. Recommendation

**Defer.** Without a concrete user workflow that:

- Has a CRIU-compatible process,
- Is poorly served by `rr` and v1.5 #16's `session.fork`,
- Is willing to operate the CRIU + caps side of the integration,

…the cost-benefit doesn't work. CRIU is large (the integration
is ~3–5 weeks counting pre-flight + restore + snapshot store +
tests), the audience is narrow, and the failure mode for naive
users is "it dumped, but the restore is mysteriously broken."

If/when triggered:

- **Gate behind `LDB_ENABLE_CRIU`** (build) + runtime CRIU
  availability check (cached at daemon startup).
- **Pre-flight check is non-optional.** Every `session.criu_fork`
  runs `session.criu_check` semantics first; if hard_breaks is
  non-empty, refuse cleanly with the structured hint. Do not
  let an agent paper over hard_breaks.
- **Don't promise reverse-execution semantics.** CRIU is "rewind
  to checkpoint," not "step backwards." Documentation must be
  honest about the difference vs rr.
- **Plan for the failure case.** Approximately half of real-
  world server processes (anything using BPF, io_uring, or
  GPU) won't be CRIU-compatible. The agent's first interaction
  with criu_check will frequently be "this won't work" — the
  endpoint surface must make that the easy, expected response,
  not a surprise.

The down payment in this note is the compatibility matrix, the
endpoint shape, and the privilege gate. A future contributor
reading this should know: who CRIU is for, who it isn't for, and
how the LDB surface tells those two apart.

## 9. Cross-references

- `docs/15-post-v1-plan.md` #24 — catalog entry + watchlist
  ("criu (#24) is fragile in practice. Many real processes don't
  survive a CRIU dump (eBPF maps, io_uring, GPU contexts).").
- `docs/17-version-plan.md` v1.6 — specialized/opt-in bucket
  rationale.
- `docs/24-session-fork-replay.md` — the v1.5 #16 RPC-log fork
  this is *not* a duplicate of (different axis).
- `docs/16-reverse-exec.md` — the rr backend that's the closest
  existing alternative for the "rewind" use case.
- CRIU project: https://criu.org (GPLv2).
- CRIU compatibility doc: https://criu.org/Compatibility.
- `CAP_CHECKPOINT_RESTORE`: introduced in Linux 5.9; see
  `capabilities(7)`.
