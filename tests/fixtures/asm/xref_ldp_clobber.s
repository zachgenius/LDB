// Phase-4 cleanup adversarial fixture
// (docs/35-field-report-followups.md §3 phase-4 cleanup C4).
//
// Reproduces a SILENT-WRONG-RESULT false positive that the phase-3+
// resolver missed: LDP / LDPSW / LDXP / LDAR / LDAXR / LDXR all write
// to one or two destination registers from memory or with an atomic
// load, but none of them appear in the resolver's post-emit clobber
// whitelist. Phase 4 modeled LDR/LDUR/LDRH/LDRB as memops and emitted
// matches; loads-from-stack (LDP from sp) clobber adrp-tracked
// registers but the resolver doesn't model the destination write.
//
// Pattern:
//   _ldp_test:
//     sub  sp, sp, #16
//     stp  x10, x11, [sp]
//     adrp x8, _ldp_data@PAGE       ; tracked: x8 → page(data)
//     ldp  x8, x9, [sp]             ; x8/x9 := stack contents.
//     add  x0, x8, _ldp_data@PAGEOFF ; FALSE POSITIVE (phase-4-pre-fix)
//     add  sp, sp, #16
//     ret
//
// Without the C4 fix: `xref.addr(_ldp_data)` returns >= 1 false-
// positive match in _ldp_test (the ADD after LDP).
// With the C4 fix (clobber-by-default catches LDP via destination-reg
// parsing): returns 0.
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _ldp_test
_ldp_test:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	sub	sp, sp, #16
	stp	x10, x11, [sp]
	adrp	x8, _ldp_data@PAGE
	ldp	x8, x9, [sp]
	add	x0, x8, _ldp_data@PAGEOFF
	add	sp, sp, #16
	ldp	x29, x30, [sp], #16
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x10, #0
	mov	x11, #0
	bl	_ldp_test
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _ldp_data
_ldp_data:
	.fill 0x200, 1, 0
