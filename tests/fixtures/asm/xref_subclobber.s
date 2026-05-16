// Phase-3 post-review fixture (docs/35-field-report-followups.md §3).
//
// Reproduces the SUB-clobber false-positive that the original
// phase-3 patch missed. SUB has identical destination-write semantics
// to ADD — `sub xN, xN, #imm` overwrites the page-tracked register
// just as `add xN, xN, #imm` does. The original phase-3 only
// clobbered on ADD/MOV, leaving SUB as a silent false-positive vector.
//
// Pattern:
//
//   adrp x8, page
//   sub  x8, x8, #0x100      ; x8 is now page-0x100, NOT page
//   ldr  x0, [x8, #0x10]     ; effective addr: page-0x100+0x10
//                            ; phase-3-old wrongly resolves to page+0x10
//
// Acceptance: xref.addr against page+0x10 must NOT match the LDR
// inside pattern_subclobber. (The SUB-derived effective address is
// outside _subclobber_data entirely; the smoke test queries the data
// symbol's page+0x10 to confirm the heuristic doesn't fire.)
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _pattern_subclobber
_pattern_subclobber:
	adrp	x8, _subclobber_data@PAGE
	sub	x8, x8, #0x100
	ldr	x0, [x8, #0x10]
	ret

	.globl _main
_main:
	bl	_pattern_subclobber
	mov	w0, #0
	ret

	// Anchored at a page boundary so the smoke test can pin the
	// false-positive target as data_addr + 0x10. Without the SUB
	// clobber the LDR resolves to page+0x10 and matches.
	.section __DATA,__data
	.p2align 12
	.globl _subclobber_data
_subclobber_data:
	.fill 0x200, 1, 0
