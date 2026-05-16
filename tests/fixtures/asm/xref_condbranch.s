// Phase-4 adversarial fixture (docs/35-field-report-followups.md §3
// item 1).
//
// Reproduces a conditional-branch boundary leak. Phase 3 resets
// adrp_regs only on RET / unconditional B / BR. A conditional branch
// (b.cond / cbz / cbnz / tbz / tbnz) that crosses into a different
// function should also reset, otherwise the scanner walks straight
// into the branch target's body with the source function's
// adrp_regs[x8] still live.
//
// The fixture relies on phase-3's gate 1 (function_name_at-based
// boundary reset) being defeated. That gate IS sufficient on
// symbolized binaries — when the scanner steps from the source
// function's last instruction to the target function's first
// instruction, function_name_at differs and adrp_regs clears. The
// fixture below is symbolized, so gate 1 already prevents the leak.
// The fixture's role: assert phase 4's conditional-branch path also
// fires on the same input (proven via the
// adrp_pair_cond_branch_reset provenance counter), so future
// refactors can't silently delete the path while gate 1 silently
// covers up the regression.
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
