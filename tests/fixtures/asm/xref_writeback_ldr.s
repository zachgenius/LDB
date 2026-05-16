// Phase-3 post-review fixture (docs/35-field-report-followups.md §3).
//
// Reproduces the pre/post-indexed LDR writeback false-positive that
// the original phase-3 patch missed. The writeback forms of LDR
// rewrite the base register as a side effect — pre-indexed writes
// `xM ← xM + imm` BEFORE the load, post-indexed writes the same
// value AFTER. Either way, the base register no longer holds the
// ADRP-tracked page after the instruction, so any subsequent LDR
// through the same register must NOT resolve against the stale page.
//
// The original phase-3 resolver emitted the LDR's match for the
// legitimate effective address but never cleared adrp_regs[xM],
// leaving a downstream LDR free to false-match the stale page.
//
// Pattern (pre-indexed):
//
//   adrp x8, page
//   ldr  x0, [x8, #0x40]!    ; x8 ← page+0x40, x0 ← *(page+0x40)
//   ldr  x1, [x8, #0x10]     ; effective: (page+0x40)+0x10
//                             ; phase-3-old: page+0x10 (wrong)
//
// (Pre/post-indexed LDR with immediate writeback uses the imm9 9-bit
// signed immediate, [-256, 255]. We use #0x40 to stay inside that
// range and still place the false-positive needle well clear of the
// real load target — page+0x10 ≠ page+0x40+0x10.)
//
// Test acceptance: xref.addr against page+0x10 must return ZERO
// matches inside pattern_writeback_pre / pattern_writeback_post —
// the writeback'd base register can no longer reach the stale page.
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	// Pre-indexed: writeback happens before the load. Even on the
	// first LDR the effective address (page+0x40) is correct, but
	// the second LDR sees x8 = page+0x40 already.
	.globl _pattern_writeback_pre
_pattern_writeback_pre:
	adrp	x8, _writeback_data@PAGE
	ldr	x0, [x8, #0x40]!
	ldr	x1, [x8, #0x10]
	ret

	// Post-indexed: writeback happens after the load. The first
	// LDR's effective address is the bare page (no offset), the
	// second LDR sees x8 = page+0x40. Phase-3 must still clear
	// adrp_regs[x8] after the first LDR.
	.globl _pattern_writeback_post
_pattern_writeback_post:
	adrp	x8, _writeback_data@PAGE
	ldr	x0, [x8], #0x40
	ldr	x1, [x8, #0x10]
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	bl	_pattern_writeback_pre
	bl	_pattern_writeback_post
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _writeback_data
_writeback_data:
	.fill 0x200, 1, 0
