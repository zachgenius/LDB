// Phase-4 adversarial fixture (docs/35-field-report-followups.md §3
// item 3).
//
// Reproduces the stripped-binary function-boundary leak. Phase 3's
// gate 1 uses function_name_at() to detect boundaries; in a stripped
// binary BOTH adjacent functions return "" so the gate can't tell
// them apart. Phase 3's RET/B-based clear catches MOST cases, but
// when adjacent functions are reachable only through B/BL targets
// (no intervening RET visible in the disassembly stream — e.g. tail-
// call patterns, compiler-emitted trampolines), the ADRP page from
// function A leaks into function B.
//
// Phase 4 item 3 closes the gap by recording every B/BL target inside
// __TEXT/__text as a function-start hint. When the scanner reaches an
// instruction whose address is in the function_starts set, adrp_regs
// is reset — works regardless of whether function_name_at can
// resolve the boundary.
//
// Pattern (all functions are `.private_extern` so the strip step
// below can erase the local labels while keeping `_main` for the
// linker to find the entry point):
//
//   <local 1>:  // formerly _pattern_strip_a
//     adrp x8, _strip_data@PAGE
//     bl   <local 2>           ; the BL target becomes a function_start
//     ret
//   <local 2>:  // formerly _pattern_strip_b
//     ldr  x0, [x8, #0x10]     ; x8 here is x0..x18-clobbered by phase-3
//                                gate 2 anyway; this fixture's job is
//                                the function-start reset on the
//                                callee's first instruction.
//     ret
//
// The phase-3 BL caller-saved clear (gate 2) already removes
// adrp_regs[x8] before the bl returns, so the LDR in <local 2> would
// resolve through an empty map regardless. To create a real leak that
// only the function_starts reset catches, we use a callee-saved
// register (x19) which gate 2's AAPCS64 list explicitly preserves:
//
//   <local 1>:
//     adrp x19, _strip_data@PAGE       ; tracked: x19 → page
//     bl   <local 2>                   ; BL clobbers x0-x18+x30; x19
//                                       ; survives per AAPCS64.
//     ret
//   <local 2>:                         ; phase 3 leaks; phase 4 resets.
//     ldr  x0, [x19, #0x10]           ; would resolve to page + 0x10.
//     ret
//
// `_strip_data` is intentionally kept global so the smoke test's
// symbol.find can locate it after strip. The function symbols are
// non-global; strip drops them.
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	// _pattern_strip_a: NOT .globl — survives only as a local
	// symbol that strip can remove.
_pattern_strip_a:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	stp	x19, x20, [sp, #-16]!
	adrp	x19, _strip_data@PAGE
	bl	_pattern_strip_b
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

_pattern_strip_b:
	// x19 is callee-saved per AAPCS64 — gate 2 preserves it
	// across the BL. The scanner's adrp_regs[x19] still points at
	// _strip_data's page when we walk into this function.
	// Phase 3 silently resolves the LDR below; phase 4's
	// function_starts reset catches the boundary.
	ldr	x0, [x19, #0x10]
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	bl	_pattern_strip_a
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _strip_data
_strip_data:
	.fill 0x200, 1, 0
