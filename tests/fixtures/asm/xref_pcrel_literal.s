// Phase-4 fixture (docs/35-field-report-followups.md §3 item 4).
//
// Reproduces the PC-relative literal-load shape. LLDB renders
//   ldr xN, _const_label
// as
//   ldr xN, #imm     ; where imm is the PC-relative offset
// or as
//   ldr xN, 0xNNNN   ; resolved file address
// The scanner can't statically dereference the literal-pool slot to
// learn what pointer-value would be loaded — that requires re-reading
// the segment's data bytes. Phase 4 item 4 bumps a provenance counter
// so callers see this happened, instead of silently skipping the load.
//
// Pattern:
//   _pattern_pcrel:
//     ldr  x0, _pcrel_const   ; PC-relative literal load.
//     ret
//   _pcrel_const:
//     .quad 0xfeedbeefcafebabe  ; opaque magic; not a pointer to a
//                                ; data symbol (avoiding text-
//                                ; relocation issues at link time).
//
// The smoke test asserts the provenance counter bumps. xref.addr
// against `_pcrel_data` returns zero matches today — that's the
// current heuristic limit. The counter is what tells the caller
// "the resolver gave up on this load."
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _pattern_pcrel
_pattern_pcrel:
	ldr	x0, _pcrel_const
	ret
	.p2align 3
_pcrel_const:
	.quad 0xfeedbeefcafebabe

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	bl	_pattern_pcrel
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 3
	.globl _pcrel_data
_pcrel_data:
	.quad 0xdeadbeef
