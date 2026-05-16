// Phase-3 post-review fixture (docs/35-field-report-followups.md §3).
//
// Demonstrates the STR-family consumer false-NEGATIVE that the
// original phase-3 patch missed. The phase-3 resolver only
// recognised ADD and LDR/LDRSW/LDRH/LDRB as ADRP consumers, so
// stores into an ADRP-tracked address were invisible to xref.addr —
// a callee writing through a tracked page would not be surfaced as
// a reference to that page.
//
// Reviewer's classification: real field-report trust gap. A user
// asking "what writes to this global?" got an empty answer.
//
// Pattern:
//
//   pattern_str_through_adrp:
//     adrp x8, str_data@PAGE
//     str  w0, [x8, #0x10]      ; STR w0 to page+0x10
//     ret
//
//   pattern_stp_through_adrp:
//     adrp x8, str_data@PAGE
//     stp  x0, x1, [x8, #0x10]  ; STP — pair store, same address shape
//     ret
//
// Acceptance: xref.addr against `str_data + 0x10` returns matches
// in both pattern_str_through_adrp (STR) and pattern_stp_through_adrp
// (STP). The original phase-3 surfaced neither.
//
// Apple-silicon-arm64 only — see tests/fixtures/CMakeLists.txt guard.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _pattern_str_through_adrp
_pattern_str_through_adrp:
	adrp	x8, _str_data@PAGE
	str	w0, [x8, #0x10]
	ret

	.globl _pattern_stp_through_adrp
_pattern_stp_through_adrp:
	adrp	x8, _str_data@PAGE
	stp	x0, x1, [x8, #0x10]
	ret

	.globl _pattern_strb_through_adrp
_pattern_strb_through_adrp:
	adrp	x8, _str_data@PAGE
	strb	w0, [x8, #0x10]
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	bl	_pattern_str_through_adrp
	bl	_pattern_stp_through_adrp
	bl	_pattern_strb_through_adrp
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _str_data
_str_data:
	.fill 0x200, 1, 0
