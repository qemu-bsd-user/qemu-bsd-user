# Copyright (c) 2021 Warner Losh
# SPDX-License-Identifier: BSD-2-Clause

	.text
	.file	"hello.s"
	.globl	qemu_start                            # -- Begin function qemu_start
	.p2align	2
	.type	qemu_start,@function
qemu_start:                                   # @qemu_start
.Lfunc_begin0:
# %bb.0:                                # %entry
	mflr 0
	stw 0, 4(1)
	stwu 1, -16(1)
	lis 3, .L.str@ha
	la 4, .L.str@l(3)
	li 3, 1
	li 5, 12
	li 0, 4			# write
	sc
	li 3, 0
	li 0, 1			# exit
	sc
.Lfunc_end0:
	.size	qemu_start, .Lfunc_end0-.Lfunc_begin0
                                        # -- End function
	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Hello World\n"
	.size	.L.str, 13
