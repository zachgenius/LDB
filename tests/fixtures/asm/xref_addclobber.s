// Phase-3 adversarial fixture (docs/35-field-report-followups.md §3).
//
// Reproduces the ADD-clobber false-positive that phase 2's
// "last ADRP wins for this register" map produces. The pattern is:
//
//   adrp x8, page
//   add  x8, x8, #0x100      ; x8 is now page+0x100, NOT page
//   ldr  x0, [x8, #0x10]     ; effective addr: page+0x110
//
// Phase 2 still has adrp_regs[x8] = {page=page} after the ADD because
// the ADD writes back to the same register without clearing the map.
// On the LDR, phase 2 resolves to page+0x10 (wrong) and emits an
// xref against any target that happens to live there. Phase 3 must
// clear adrp_regs[x8] on the self-write ADD so the LDR resolves to
// nothing (or, in this fixture's case, the ADD's own emit of
// page+0x100 is the only legitimate xref).
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _pattern_addclobber
_pattern_addclobber:
	adrp	x8, _addclobber_data@PAGE
	add	x8, x8, #0x100
	ldr	x0, [x8, #0x10]
	ret

	.globl _main
_main:
	bl	_pattern_addclobber
	mov	w0, #0
	ret

	// Symbols live in __DATA. The smoke test resolves
	// _addclobber_data via symbol.find and queries xref.addr against
	// data_addr + 0x10 (phase-2 false-positive target — must return 0
	// matches inside pattern_addclobber) and data_addr + 0x100
	// (the ADD's real target — must return >= 1 match).
	.section __DATA,__data
	.p2align 12
	.globl _addclobber_data
_addclobber_data:
	.fill 0x200, 1, 0
