// Phase-4 cleanup adversarial fixture
// (docs/35-field-report-followups.md §3 phase-4 cleanup C2).
//
// Reproduces a SILENT-WRONG-RESULT regression that phase-4 item 1
// introduced via item 3's function_starts set. The phase-4 cond-branch
// block unconditionally records the branch target in function_starts —
// even when the target is a SAME-FUNCTION label (e.g. a basic-block
// merge point inside the source function). Gate 3 (function-start
// reset) then clobbers adrp_regs at that label, killing legitimate
// xref tracking that should be preserved across the same-fn cbz.
//
// Fix: the function_starts insert and the adrp_regs reset must both
// be gated on `target_fn != current_function`. A same-function label
// must NOT poison function_starts.
//
// Pattern:
//   _same_fn_test:
//     adrp x8, _same_fn_data@PAGE
//     cbz  x0, Lhere               ; cbz to a SAME-FUNCTION label
//     nop                          ; (also same-fn)
//   Lhere:
//     add  x10, x8, _same_fn_data@PAGEOFF + 0x20  ; legitimate xref
//     ret
//
// Without the C2 fix: `xref.addr(_same_fn_data + 0x20)` returns 0
// matches because Lhere lands in function_starts and gate 3 resets
// adrp_regs at it.
// With the C2 fix: returns the ADD after the local label.
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _same_fn_test
_same_fn_test:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	adrp	x8, _same_fn_data@PAGE
	cbz	x0, Lhere
	nop
Lhere:
	add	x10, x8, _same_fn_data@PAGEOFF + 0x20
	mov	x0, x10
	ldp	x29, x30, [sp], #16
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	mov	x0, #1
	bl	_same_fn_test
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _same_fn_data
_same_fn_data:
	.fill 0x200, 1, 0
