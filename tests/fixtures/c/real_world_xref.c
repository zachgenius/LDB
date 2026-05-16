// Phase-4 item 7 fixture (docs/35-field-report-followups.md §3).
//
// Real-binary-style xref-pattern exercise. Not synthetic assembly:
// compile this with -O1 (so the compiler emits ADRP+ADD / ADRP+LDR
// pairs through the chained-fixup pipeline) and verify the resolver
// surfaces every xref the test expects.
//
// Patterns covered:
//
//   1. Static const string table (selref-style ADRP+LDR through
//      indirection): k_string_table[i] is loaded via a chained-fixup
//      slot in __DATA_CONST. Phase 2's slot-indirection match path
//      should surface every consumer.
//
//   2. Multiple functions in one TU. The function-boundary reset must
//      clear adrp_regs between adjacent functions even when they
//      share a translation unit.
//
//   3. Conditional-branch tail-call: branch_or_default() uses an
//      `if (...) return default_string; else return k_string_table[i];`
//      shape, which clang typically lowers to a conditional branch.
//      Phase 4 item 1 must NOT regress the legitimate fall-through
//      xref through k_string_table.
//
//   4. extern malloc / free imports. These hit the bind path (today's
//      BindInfo schema only — phase 5 wires the imports walk). The
//      test asserts the binary parses without throwing, even though
//      no xref against malloc / free is currently surfaced via the
//      chained-fixup map.
//
// Compile flags (set in tests/fixtures/CMakeLists.txt):
//   -arch arm64
//   -O1
//   -fno-omit-frame-pointer
//   -Wl,-fixup_chains       (force LC_DYLD_CHAINED_FIXUPS)

#include <stdint.h>
#include <stddef.h>

extern void *malloc(size_t);
extern void free(void *);
extern int printf(const char *, ...);

// k_string_table[] — three pointers into __TEXT/__cstring. The linker
// stores these as chained-fixup rebases on -Wl,-fixup_chains; xref
// against any of the strings must surface every reader function.
static const char *const k_string_table[] = {
    "real_world_xref_alpha",
    "real_world_xref_beta",
    "real_world_xref_gamma",
};

// Function 1: classic loop reading every entry. The compiler emits
// ADRP + ADD to compute k_string_table, then LDR x0, [x_table, #imm]
// in a loop body — slot-indirection hits.
void real_xref_iterate(void) {
    for (size_t i = 0; i < 3; ++i) {
        const char *s = k_string_table[i];
        printf("%s\n", s);
    }
}

// Function 2: direct index read. Tests the single-ADRP+LDR pattern
// at function entry. boundary-reset from function 1 should clear x_table.
const char *real_xref_pick(int which) {
    if (which < 0 || which > 2) return "default";
    return k_string_table[which];
}

// Function 3: conditional-branch tail-call to a different function.
// The legitimate ADRP+LDR through k_string_table on fall-through must
// still surface; phase 4 item 1's cross-function reset must not eat it.
const char *real_xref_branch_or_default(int which) {
    if (which == 0) {
        return real_xref_pick(0);  // bl real_xref_pick
    }
    return k_string_table[which];
}

// Function 4: malloc / free imports. Exercises the BindInfo schema
// path (binds map is populated by phase 5; phase 4 just records the
// import in the chained-fixup table). The test asserts no false-
// positive xrefs against arbitrary code addresses.
void real_xref_alloc_and_free(size_t n) {
    void *p = malloc(n);
    if (p == NULL) return;
    free(p);
}

int main(void) {
    real_xref_iterate();
    const char *s = real_xref_pick(1);
    printf("picked: %s\n", s);
    s = real_xref_branch_or_default(2);
    printf("branch: %s\n", s);
    real_xref_alloc_and_free(1024);
    return 0;
}
