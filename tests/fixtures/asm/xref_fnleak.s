// Phase-3 adversarial fixture (docs/35-field-report-followups.md §3).
//
// Reproduces the cross-function ADRP leak that phase 2's single-pass
// scanner produces. Function A loads ADRP into x8 and uses it. The
// scanner walks straight into function B without clearing adrp_regs.
// Function B has an unrelated LDR through x8 that the scanner now
// wrongly resolves against A's ADRP page.
//
// Pattern:
//   _pattern_fnleak_a:
//     adrp x8, A_data@PAGE
//     ldr  x0, [x8, A_data@PAGEOFF]
//     ret
//   _pattern_fnleak_b:
//     ldr  x0, [x8, #0x10]   ; x8 here is undefined (compiler bug or
//                              raw inline asm); phase 2 resolves it to
//                              A_data_page + 0x10, a false positive.
//
// Phase 3 closes this by clearing adrp_regs at function-boundary
// transitions (RET, or function_name_at(pc) changing).
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _pattern_fnleak_a
_pattern_fnleak_a:
	adrp	x8, _fnleak_data_a@PAGE
	ldr	x0, [x8, _fnleak_data_a@PAGEOFF]
	ret

	.globl _pattern_fnleak_b
_pattern_fnleak_b:
	// x8 is intentionally not re-defined here: in real code the
	// callee-saved register coincidence is what makes this a
	// false positive. Phase 3's function-boundary reset clears the
	// stale adrp_regs[x8] before we reach this LDR.
	ldr	x0, [x8, #0x10]
	ret

	.globl _main
_main:
	bl	_pattern_fnleak_a
	mov	w0, #0
	ret

	.section __DATA,__data
	.p2align 12
	.globl _fnleak_data_a
_fnleak_data_a:
	.fill 0x200, 1, 0
