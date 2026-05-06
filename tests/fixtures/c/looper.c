/*
 * Hot-loop fixture for the process.continue round-trip arc of the
 * slice-1c live-provenance gate (docs/POST-V0.1-PROGRESS.md item A3).
 *
 * main() calls work_step() repeatedly with a small per-iteration
 * delay. The harness sets a breakpoint on work_step, drives
 * process.continue, observes the snapshot bumps + the bp is hit
 * twice (loop counter advances between hits).
 *
 * usleep(1ms) between iterations keeps the inferior cooperative —
 * the harness's process.continue is synchronous and blocks until
 * the next stop, so we don't want the kernel scheduler to starve
 * the daemon side.
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

volatile uint64_t g_counter = 0;

int work_step(uint64_t i) {
    /* Make this a real call — keep g_counter visible to the
     * compiler so the loop body isn't dead-code-eliminated. */
    g_counter = i;
    return (int)(i & 0xff);
}

int main(void) {
    printf("PID=%d READY=LOOPER\n", (int)getpid());
    fflush(stdout);
    uint64_t sum = 0;
    for (uint64_t i = 0; i < 1000000; ++i) {
        sum ^= (uint64_t)work_step(i);
        usleep(1000);  /* 1ms — bounded but cooperative */
    }
    return (int)(sum & 0xff);
}
