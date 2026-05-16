// Phase-4 cleanup adversarial fixture
// (docs/35-field-report-followups.md §3 phase-4 cleanup C1).
//
// Reproduces a SILENT-WRONG-RESULT regression that phase-4 item 1
// introduced. The phase-4 implementation cleared adrp_regs on EVERY
// cross-function conditional branch — including the fall-through path,
// which by definition is still inside the source function. The
// legitimate xref on the fall-through ADD-after-cbz consumer was
// silently lost.
//
// Spec violated: `docs/35-field-report-followups.md §3 phase 4 item 1`
// reads literally "Fall-through path: preserve state". The reset must
// only fire on the TAKEN side (which the scanner reaches via the
// function_starts hint on a later iteration), not on the source
// function's fall-through instructions.
//
// Pattern:
//   _src_fn:
//     adrp x8, _cond_ft_target@PAGE     ; tracked x8 → page(target)
//     cbz  x9, _other_fn                 ; cross-function cbz
//     add  x0, x8, _cond_ft_target@PAGEOFF  ; FALL-THROUGH consumer.
//     ret                                ; legitimate xref must surface.
//
//   _other_fn:
//     ret                                ; lone exit.
//
// Without the C1 fix: `xref.addr(_cond_ft_target)` returns 0 matches.
// With the C1 fix: returns the ADD in _src_fn.
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _src_fn
_src_fn:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	adrp	x8, _cond_ft_target@PAGE
	cbz	x9, _other_fn
	add	x0, x8, _cond_ft_target@PAGEOFF
	ldp	x29, x30, [sp], #16
	ret

	.globl _other_fn
_other_fn:
	mov	w0, #0
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x9, #1
	bl	_src_fn
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _cond_ft_target
_cond_ft_target:
	.fill 0x200, 1, 0
