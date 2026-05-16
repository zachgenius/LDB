// Phase-3 adversarial fixture (docs/35-field-report-followups.md §3).
//
// Reproduces the BL-clobber false-positive that phase 2 produces.
// AAPCS64 says x0..x18 and x30 are caller-saved — a BL invalidates
// them regardless of what the callee does. Phase 2's scanner doesn't
// track this; an ADRP into x0 before a BL is wrongly still "live"
// after the BL.
//
// Pattern (one function so it doesn't conflate with the cross-function
// leak fixture's bug):
//   _pattern_callclobber:
//     adrp x0, _callclobber_data@PAGE
//     bl   _callclobber_helper          ; x0 is dead per AAPCS64
//     ldr  x1, [x0, #0x10]              ; x0 here is the helper's
//                                          return value, NOT the page;
//                                          phase 2 still resolves it.
//     ret
//
// Phase 3 clears adrp_regs[x0..x18, x30] on every BL/BLR.
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _pattern_callclobber
_pattern_callclobber:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	adrp	x0, _callclobber_data@PAGE
	bl	_callclobber_helper
	ldr	x1, [x0, #0x10]
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.globl _callclobber_helper
_callclobber_helper:
	mov	w0, #0
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	bl	_pattern_callclobber
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _callclobber_data
_callclobber_data:
	.fill 0x200, 1, 0
