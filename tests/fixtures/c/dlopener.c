/*
 * Fixture for the dlopen-invalidation arc of the slice-1c live-provenance
 * gate (docs/POST-V0.1-PROGRESS.md item A2).
 *
 * Lifecycle:
 *   1. Print PID and READY=PRE_DLOPEN, then pause() — the test harness
 *      attaches here so the snapshot reflects the pre-dlopen module set.
 *   2. After being kicked (any signal — the loop keeps going until we've
 *      done the dlopen), call dlopen("libpthread.so.0") which pulls a
 *      fresh DSO into the address space and fires
 *      eBroadcastBitModulesLoaded on the SBTarget broadcaster.
 *   3. Print READY=POST_DLOPEN and pause() again — the harness re-attaches
 *      / observes the snapshot here, asserting layout_digest has changed.
 *   4. Loop on pause() forever so the harness can kill us at end of test.
 *
 * Intentionally minimal: no symbols looked up from the loaded DSO, just
 * load + record the handle as a side effect to keep the linker honest.
 */

#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t g_kicked = 0;

static void on_signal(int sig) {
    (void)sig;
    g_kicked = 1;
}

int main(void) {
    /* Catch SIGUSR1 so the harness can advance us past the first pause()
     * without killing us. SIG_IGN won't wake pause(). */
    struct sigaction sa;
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    printf("PID=%d READY=PRE_DLOPEN\n", (int)getpid());
    fflush(stdout);

    /* First wait — harness attaches here, captures snapshot, then
     * detaches and SIGUSR1s us. */
    while (!g_kicked) pause();
    g_kicked = 0;

    /* dlopen a library that isn't already loaded. libpthread is a
     * reliable pick on glibc Linux: it's a separate DSO and isn't
     * pulled in by libc + libdl alone for a non-threaded fixture. If
     * it IS already there (some glibc configurations), the test will
     * SKIP at the harness level. */
    void *h = dlopen("libpthread.so.0", RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        const char *e = dlerror();
        fprintf(stderr, "dlopen failed: %s\n", e ? e : "<unknown>");
        return 1;
    }

    printf("READY=POST_DLOPEN\n");
    fflush(stdout);

    /* Second wait — harness re-attaches / observes, then kills us. */
    for (;;) pause();
    return 0;  /* unreachable */
}
