/*
 * Long-running fixture for attach + memory tests.
 *
 * Prints PID and a known marker on stdout so test drivers can attach by
 * PID and locate the marker in memory, then parks the process until it
 * is killed or detached.
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

const char *const k_marker = "LDB_SLEEPER_MARKER_v1";
volatile uint64_t g_counter = 0;

int main(void) {
    printf("PID=%d READY=%s\n", (int)getpid(), k_marker);
    fflush(stdout);
    for (;;) {
        pause();
        g_counter++;
    }
    return 0;
}
