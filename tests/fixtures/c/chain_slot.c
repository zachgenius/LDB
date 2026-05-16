/*
 * Test fixture for docs/35-field-report-followups.md §3 phase 2.
 *
 * Reproduces the iOS/macOS arm64 LC_DYLD_CHAINED_FIXUPS xref bug in
 * miniature: a string literal lives in __TEXT/__cstring, but every
 * load-site reaches it through a pointer slot in __DATA/__data whose
 * 64-bit value is encoded as a chained-fixup rebase (not a raw VA).
 *
 *   g_slot          → __DATA/__data, chained-pointer slot
 *   "ldb_chain..."  → __TEXT/__cstring, raw bytes
 *   reference_string → ADRP+LDR pair that loads the slot
 *
 * Built only on Apple-silicon hosts; the CMake guard in
 * tests/fixtures/CMakeLists.txt skips it elsewhere. Use:
 *   clang -arch arm64 -Wl,-fixup_chains
 * so the linker emits LC_DYLD_CHAINED_FIXUPS regardless of the host
 * deployment target.
 *
 * The smoke test (tests/smoke/test_xref_chained_fixup.sh) reads the
 * string's file address via string.list, then calls xref.addr against
 * it and expects at least one match attributed to reference_string.
 * Without the phase-2 chained-fixup wire-up the result is empty.
 */

#include <stdint.h>

/* The string lands in __TEXT/__cstring; g_slot is the chained-fixup
 * slot in __DATA/__data that rebases to it at dyld-time. We expose the
 * slot through reference_string() so the call site is a single
 * function with a deterministic ADRP+LDR pair. */
static const char* g_slot = "ldb_chain_test_marker_string";

int reference_string(void) {
  return (int)(uintptr_t)g_slot;
}

int main(void) {
  return reference_string();
}
