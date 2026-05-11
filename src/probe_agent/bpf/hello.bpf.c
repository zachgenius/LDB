// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Trivial CO-RE BPF program for ldb-probe-agent phase-1 (#12).
// Counts the number of syscall entries observed since attach. The
// daemon-side smoke test attaches this program, triggers a few
// syscalls (getpid), and asserts the counter advanced.
//
// Build:
//   clang -target bpf -O2 -g -D__TARGET_ARCH_x86 \
//         -I/path/to/libbpf/include hello.bpf.c -c -o hello.bpf.o
//   bpftool gen skeleton hello.bpf.o > hello.skel.h
//
// CMake invokes the equivalent at configure-time when clang AND
// bpftool are present; otherwise this file is unused and the agent
// binary is built without an embedded skeleton.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Per-cpu hash so the inferred verifier passes without atomic ops on
// the hot path. We key on a single bucket (0) for phase-1; phase-2
// will key on (pid, syscall_nr).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} counts SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int tp_sys_enter(void *ctx)
{
    unsigned int key = 0;
    unsigned long long *val, init = 1;
    val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        bpf_map_update_elem(&counts, &key, &init, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
