// Phase-4 counter-bump fixture (docs/35-field-report-followups.md §3
// item 1).
//
// HONEST limitation (phase-4 cleanup N1): this fixture doesn't
// reproduce the false-positive the worklog originally claimed it did.
// On symbolised binaries gate 1's function_name_at boundary reset
// already catches the cross-function cbz on the NEXT iteration (when
// the scanner walks into the target function and sees a different
// name); the fixture's "zero false positives" assertion would pass
// even against pre-phase-4 code. What this fixture DOES prove is that
// phase 4's cross-function cbz path FIRES on this input — the
// adrp_pair_cond_branch_recorded provenance counter bumps. Without
// that counter, a future refactor could silently delete the cbz
// path while gate 1 covered up the regression — the counter is the
// canary.
//
// The TRUE adversarial fixtures for phase-4 cleanup's C1+C2 bugs
// (the silent-wrong-result regressions phase 4 ITEM 1 introduced)
// are xref_cond_fallthrough.s (fall-through preservation) and
// xref_cond_same_fn.s (same-fn target no-poison). Those fail RED
// against pre-cleanup code; this one is the counter-emission canary.
//
// Pattern:
//   _pattern_cond_a:
//     adrp x8, _cond_data_a@PAGE   ; tracked: x8 → page(A)
//     cbz  x9, _pattern_cond_other ; cbz to a DIFFERENT function
//     ret                          ; source fn ends here.
//   _pattern_cond_other:
//     ldr  x0, [x8, #0x10]         ; x8 undefined here; the leak would
//                                  ; resolve to page(A) + 0x10.
//     ret
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _pattern_cond_a
_pattern_cond_a:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	adrp	x8, _cond_data_a@PAGE
	// Conditional branch to a different function. Phase 4 must
	// either pre-emptively clear adrp_regs[x8] here (option b in
	// the spec) or rely on gate 1's function_name_at boundary
	// reset to catch it once the scanner steps into the target
	// function. Either path drops adrp_regs[x8]; the bump on
	// provenance.adrp_pair_cond_branch_reset signals phase 4's
	// new code fired.
	cbz	x9, _pattern_cond_other
	ldp	x29, x30, [sp], #16
	ret

	.globl _pattern_cond_other
_pattern_cond_other:
	// x8 is UNDEFINED here in terms of the scanner's view. Phase 3
	// leaks the previous function's adrp_regs[x8] only when no
	// boundary reset has fired — gate 1's function_name_at check
	// catches the symbolized case. Phase 4's cbz boundary reset
	// closes the stripped-binary case.
	ldr	x0, [x8, #0x10]
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x9, #0
	bl	_pattern_cond_a
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _cond_data_a
_cond_data_a:
	.fill 0x200, 1, 0
