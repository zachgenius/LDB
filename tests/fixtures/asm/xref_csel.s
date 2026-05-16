// Phase-4 cleanup adversarial fixture
// (docs/35-field-report-followups.md §3 phase-4 cleanup C3).
//
// Reproduces a SILENT-WRONG-RESULT false positive that the phase-3+
// resolver missed: CSEL (and the rest of the conditional-select
// family — CSET / CSINC / CSINV / CSNEG) writes a non-ADRP value to
// its destination register but doesn't appear in the resolver's
// post-emit clobber whitelist. The destination retains its prior
// (ADRP-tracked) state and a subsequent LDR through the now-stale
// register false-matches.
//
// This is a COMMON compiler idiom — "pick between two strings"
// patterns emit
//   adrp x8, _str_a@PAGE
//   add  x8, x8, _str_a@PAGEOFF
//   adrp x9, _str_b@PAGE
//   add  x9, x9, _str_b@PAGEOFF
//   csel x8, x9, x8, gt
// where x8's tracked page is no longer either ADRP after the CSEL.
//
// The cleanup-C3 architectural shift is "clobber by default": every
// destination register written by an instruction the resolver doesn't
// recognise gets cleared. The whitelist becomes a propagation-paths
// allowlist; everything else falls through to clobber.
//
// Pattern:
//   _csel_test:
//     adrp x8, _csel_data@PAGE       ; tracked: x8 → page(data)
//     cmp  w0, #0
//     csel x8, x9, x8, gt            ; x8 := (gt ? x9 : x8); not page.
//     ldr  x0, [x8, #0x10]           ; FALSE POSITIVE (phase-4-pre-fix)
//     ret
//
// Without the C3 fix: `xref.addr(_csel_data + 0x10)` returns >= 1
// false-positive match in _csel_test.
// With the C3 fix: returns 0.
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _csel_test
_csel_test:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	adrp	x8, _csel_data@PAGE
	cmp	w0, #0
	csel	x8, x9, x8, gt
	ldr	x0, [x8, #0x10]
	ldp	x29, x30, [sp], #16
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	w0, #0
	mov	x9, #0
	bl	_csel_test
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _csel_data
_csel_data:
	.fill 0x200, 1, 0
