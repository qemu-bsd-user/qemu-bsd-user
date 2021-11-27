# Copyright (c) 2021 Warner Losh
# SPDX-License-Identifier: BSD-2-Clause

	.text
	.abiversion 2
	.file	"hello.s"
	.globl	qemu_start                            # -- Begin function qemu_start
	.p2align	2
	.type	qemu_start,@function
qemu_start:                                   # @qemu_start
.Lfunc_begin0:
.Lfunc_gep0:
	addis 2, 12, .TOC.-.Lfunc_gep0@ha
	addi 2, 2, .TOC.-.Lfunc_gep0@l
.Lfunc_lep0:
	.localentry	qemu_start, .Lfunc_lep0-.Lfunc_gep0
# %bb.0:                                # %entry
	mflr 0
	std 0, 16(1)
	stdu 1, -32(1)
	addis 3, 2, .L.str@toc@ha
	li 5, 12
	addi 4, 3, .L.str@toc@l
	li 3, 1
	li 0, 4				# write
	sc
	li 3, 0
	li 0, 1				# exit
	sc
	.long	0
	.quad	0
.Lfunc_end0:
	.size	qemu_start, .Lfunc_end0-.Lfunc_begin0
                                        # -- End function
	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Hello World\n"
	.size	.L.str, 13
