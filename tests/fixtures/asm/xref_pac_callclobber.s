// Phase-3 post-review fixture (docs/35-field-report-followups.md §3).
//
// Reproduces the BLRAAZ-clobber false-positive that the original
// phase-3 patch missed. The AAPCS64 caller-saved rule applies
// independently of PAC — a BLRAA / BLRAB / BLRAAZ / BLRABZ is the
// PAC-authenticated sibling of BLR and clobbers x0..x18 + x30 just
// as BL/BLR does. The original phase-3 only matched bare "bl" / "blr"
// mnemonics, leaving the entire PAC call family as silent false-
// positive vectors on arm64e binaries (iOS app store and macOS
// system frameworks).
//
// Pattern (deliberately mirrors xref_callclobber.s, only swapping
// BL for BLRAAZ to exercise the PAC family):
//
//   pattern_pac_callclobber:
//     stp   x29, x30, [sp, #-0x10]!
//     mov   x29, sp
//     adrp  x0, pac_callclobber_data@PAGE   ; x0 = page (caller-saved)
//     adrp  x16, pac_callee@PAGE            ; load function pointer reg
//     add   x16, x16, pac_callee@PAGEOFF
//     blraaz x16                            ; AAPCS64: x0..x18 + x30 clobbered
//     ldr   x1, [x0, #0x10]                 ; phase-3-old still treats x0 as page
//
// Critically, there is NO `add x0, x0, #imm` between the ADRP and
// the BLRAAZ — that would clobber x0 via the ADD rule before the
// BLRAAZ ever ran, and the LDR after BLRAAZ would already see x0
// untracked. The test target then queries the page+0x10 false-
// positive; phase-3-new must clobber x0 on the BLRAAZ.
//
// Apple-silicon arm64e only — see tests/fixtures/CMakeLists.txt
// guard. clang refuses PAC branch mnemonics with -arch arm64.

	.section __TEXT,__text,regular,pure_instructions
	.p2align 2

	.globl _pattern_pac_callclobber
_pattern_pac_callclobber:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	adrp	x0, _pac_callclobber_data@PAGE
	adrp	x16, _pac_callee@PAGE
	add	x16, x16, _pac_callee@PAGEOFF
	blraaz	x16
	ldr	x1, [x0, #0x10]
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.globl _pac_callee
_pac_callee:
	mov	w0, #0
	ret

	.globl _main
_main:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	bl	_pattern_pac_callclobber
	mov	w0, #0
	ldp	x29, x30, [sp], #16
	ret

	.section __DATA,__data
	.p2align 12
	.globl _pac_callclobber_data
_pac_callclobber_data:
	.fill 0x200, 1, 0
