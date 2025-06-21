########################################################################
# Implement fast SHA-512 with SSSE3 instructions. (x86_64)
#
# Copyright (C) 2013 Intel Corporation.
#
# Authors:
#     James Guilford <james.guilford@intel.com>
#     Kirk Yap <kirk.s.yap@intel.com>
#     David Cote <david.m.cote@intel.com>
#     Tim Chen <tim.c.chen@linux.intel.com>
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
########################################################################
#
# This code is described in an Intel White-Paper:
# "Fast SHA-512 Implementations on Intel Architecture Processors"
#
# To find it, surf to http://www.intel.com/p/en_US/embedded
# and search for that title.
#
########################################################################

#include <linux/linkage.h>
#include <linux/objtool.h>

.text

# Virtual Registers
# ARG1
digest =	%rdi
# ARG2
msg =		%rsi
# ARG3
msglen =	%rdx
T1 =		%rcx
T2 =		%r8
a_64 =		%r9
b_64 =		%r10
c_64 =		%r11
d_64 =		%r12
e_64 =		%r13
f_64 =		%r14
g_64 =		%r15
h_64 =		%rbx
tmp0 =		%rax

# Local variables (stack frame)

W_SIZE = 80*8
WK_SIZE = 2*8

frame_W = 0
frame_WK = frame_W + W_SIZE
frame_size = frame_WK + WK_SIZE

# Useful QWORD "arrays" for simpler memory references
# MSG, DIGEST, K_t, W_t are arrays
# WK_2(t) points to 1 of 2 qwords at frame.WK depending on t being odd/even

# Input message (arg1)
#define MSG(i)    8*i(msg)

# Output Digest (arg2)
#define DIGEST(i) 8*i(digest)

# SHA Constants (static mem)
#define K_t(i)    8*i+sha512_K(%rip)

# Message Schedule (stack frame)
#define W_t(i)    8*i+frame_W(%rsp)

# W[t]+K[t] (stack frame)
#define WK_2(i)   8*((i%2))+frame_WK(%rsp)

.macro RotateState
	# Rotate symbols a..h right
	TMP   = h_64
	h_64  = g_64
	g_64  = f_64
	f_64  = e_64
	e_64  = d_64
	d_64  = c_64
	c_64  = b_64
	b_64  = a_64
	a_64  = TMP
.endm

.macro SHA512_Round rnd

	# Compute Round %%t
	mov	f_64, T1          # T1 = f
	mov	e_64, tmp0        # tmp = e
	xor	g_64, T1          # T1 = f ^ g
	ror	$23, tmp0 # 41    # tmp = e ror 23
	and	e_64, T1          # T1 = (f ^ g) & e
	xor	e_64, tmp0        # tmp = (e ror 23) ^ e
	xor	g_64, T1          # T1 = ((f ^ g) & e) ^ g = CH(e,f,g)
	idx = \rnd
	add	WK_2(idx), T1     # W[t] + K[t] from message scheduler
	ror	$4, tmp0  # 18    # tmp = ((e ror 23) ^ e) ror 4
	xor	e_64, tmp0        # tmp = (((e ror 23) ^ e) ror 4) ^ e
	mov	a_64, T2          # T2 = a
	add	h_64, T1          # T1 = CH(e,f,g) + W[t] + K[t] + h
	ror	$14, tmp0 # 14    # tmp = ((((e ror23)^e)ror4)^e)ror14 = S1(e)
	add	tmp0, T1          # T1 = CH(e,f,g) + W[t] + K[t] + S1(e)
	mov	a_64, tmp0        # tmp = a
	xor	c_64, T2          # T2 = a ^ c
	and	c_64, tmp0        # tmp = a & c
	and	b_64, T2          # T2 = (a ^ c) & b
	xor	tmp0, T2          # T2 = ((a ^ c) & b) ^ (a & c) = Maj(a,b,c)
	mov	a_64, tmp0        # tmp = a
	ror	$5, tmp0 # 39     # tmp = a ror 5
	xor	a_64, tmp0        # tmp = (a ror 5) ^ a
	add	T1, d_64          # e(next_state) = d + T1
	ror	$6, tmp0 # 34     # tmp = ((a ror 5) ^ a) ror 6
	xor	a_64, tmp0        # tmp = (((a ror 5) ^ a) ror 6) ^ a
	lea	(T1, T2), h_64    # a(next_state) = T1 + Maj(a,b,c)
	ror	$28, tmp0 # 28    # tmp = ((((a ror5)^a)ror6)^a)ror28 = S0(a)
	add	tmp0, h_64        # a(next_state) = T1 + Maj(a,b,c) S0(a)
	RotateState
.endm

.macro SHA512_2Sched_2Round_sse rnd

	# Compute rounds t-2 and t-1
	# Compute message schedule QWORDS t and t+1

	#   Two rounds are computed based on the values for K[t-2]+W[t-2] and
	# K[t-1]+W[t-1] which were previously stored at WK_2 by the message
	# scheduler.
	#   The two new schedule QWORDS are stored at [W_t(%%t)] and [W_t(%%t+1)].
	# They are then added to their respective SHA512 constants at
	# [K_t(%%t)] and [K_t(%%t+1)] and stored at dqword [WK_2(%%t)]
	#   For brievity, the comments following vectored instructions only refer to
	# the first of a pair of QWORDS.
	# Eg. XMM2=W[t-2] really means XMM2={W[t-2]|W[t-1]}
	#   The computation of the message schedule and the rounds are tightly
	# stitched to take advantage of instruction-level parallelism.
	# For clarity, integer instructions (for the rounds calculation) are indented
	# by one tab. Vectored instructions (for the message scheduler) are indented
	# by two tabs.

	mov	f_64, T1
	idx = \rnd -2
	movdqa	W_t(idx), %xmm2		    # XMM2 = W[t-2]
	xor	g_64, T1
	and	e_64, T1
	movdqa	%xmm2, %xmm0	            # XMM0 = W[t-2]
	xor	g_64, T1
	idx = \rnd
	add	WK_2(idx), T1
	idx = \rnd - 15
	movdqu	W_t(idx), %xmm5		    # XMM5 = W[t-15]
	mov	e_64, tmp0
	ror	$23, tmp0 # 41
	movdqa	%xmm5, %xmm3	            # XMM3 = W[t-15]
	xor	e_64, tmp0
	ror	$4, tmp0 # 18
	psrlq	$61-19, %xmm0		    # XMM0 = W[t-2] >> 42
	xor	e_64, tmp0
	ror	$14, tmp0 # 14
	psrlq	$(8-7), %xmm3		    # XMM3 = W[t-15] >> 1
	add	tmp0, T1
	add	h_64, T1
	pxor	%xmm2, %xmm0                # XMM0 = (W[t-2] >> 42) ^ W[t-2]
	mov	a_64, T2
	xor	c_64, T2
	pxor	%xmm5, %xmm3                # XMM3 = (W[t-15] >> 1) ^ W[t-15]
	and	b_64, T2
	mov	a_64, tmp0
	psrlq	$(19-6), %xmm0		    # XMM0 = ((W[t-2]>>42)^W[t-2])>>13
	and	c_64, tmp0
	xor	tmp0, T2
	psrlq	$(7-1), %xmm3		    # XMM3 = ((W[t-15]>>1)^W[t-15])>>6
	mov	a_64, tmp0
	ror	$5, tmp0 # 39
	pxor	%xmm2, %xmm0	            # XMM0 = (((W[t-2]>>42)^W[t-2])>>13)^W[t-2]
	xor	a_64, tmp0
	ror	$6, tmp0 # 34
	pxor	%xmm5, %xmm3                # XMM3 = (((W[t-15]>>1)^W[t-15])>>6)^W[t-15]
	xor	a_64, tmp0
	ror	$28, tmp0 # 28
	psrlq	$6, %xmm0                   # XMM0 = ((((W[t-2]>>42)^W[t-2])>>13)^W[t-2])>>6
	add	tmp0, T2
	add	T1, d_64
	psrlq	$1, %xmm3                   # XMM3 = (((W[t-15]>>1)^W[t-15])>>6)^W[t-15]>>1
	lea	(T1, T2), h_64
	RotateState
	movdqa	%xmm2, %xmm1	            # XMM1 = W[t-2]
	mov	f_64, T1
	xor	g_64, T1
	movdqa	%xmm5, %xmm4		    # XMM4 = W[t-15]
	and	e_64, T1
	xor	g_64, T1
	psllq	$(64-19)-(64-61) , %xmm1    # XMM1 = W[t-2] << 42
	idx = \rnd + 1
	add	WK_2(idx), T1
	mov	e_64, tmp0
	psllq	$(64-1)-(64-8), %xmm4	    # XMM4 = W[t-15] << 7
	ror	$23, tmp0 # 41
	xor	e_64, tmp0
	pxor	%xmm2, %xmm1		    # XMM1 = (W[t-2] << 42)^W[t-2]
	ror	$4, tmp0 # 18
	xor	e_64, tmp0
	pxor	%xmm5, %xmm4		    # XMM4 = (W[t-15]<<7)^W[t-15]
	ror	$14, tmp0 # 14
	add	tmp0, T1
	psllq	$(64-61), %xmm1		    # XMM1 = ((W[t-2] << 42)^W[t-2])<<3
	add	h_64, T1
	mov	a_64, T2
	psllq	$(64-8), %xmm4		    # XMM4 = ((W[t-15]<<7)^W[t-15])<<56
	xor	c_64, T2
	and	b_64, T2
	pxor	%xmm1, %xmm0		    # XMM0 = s1(W[t-2])
	mov	a_64, tmp0
	and	c_64, tmp0
	idx = \rnd - 7
	movdqu	W_t(idx), %xmm1		    # XMM1 = W[t-7]
	xor	tmp0, T2
	pxor	%xmm4, %xmm3                # XMM3 = s0(W[t-15])
	mov	a_64, tmp0
	paddq	%xmm3, %xmm0		    # XMM0 = s1(W[t-2]) + s0(W[t-15])
	ror	$5, tmp0 # 39
	idx =\rnd-16
	paddq	W_t(idx), %xmm0		    # XMM0 = s1(W[t-2]) + s0(W[t-15]) + W[t-16]
	xor	a_64, tmp0
	paddq	%xmm1, %xmm0	            # XMM0 = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]
	ror	$6, tmp0 # 34
	movdqa	%xmm0, W_t(\rnd)	    # Store scheduled qwords
	xor	a_64, tmp0
	paddq	K_t(\rnd), %xmm0	    # Compute W[t]+K[t]
	ror	$28, tmp0 # 28
	idx = \rnd
	movdqa	%xmm0, WK_2(idx)	    # Store W[t]+K[t] for next rounds
	add	tmp0, T2
	add	T1, d_64
	lea	(T1, T2), h_64
	RotateState
.endm

########################################################################
# void sha512_transform_ssse3(struct sha512_block_state *state,
#			      const u8 *data, size_t nblocks);
# Purpose: Updates the SHA512 digest stored at "state" with the message
# stored in "data".
# The size of the message pointed to by "data" must be an integer multiple
# of SHA512 message blocks.
# "nblocks" is the message length in SHA512 blocks.  Must be >= 1.
########################################################################
SYM_FUNC_START(sha512_transform_ssse3)
	ANNOTATE_NOENDBR	# since this is called only via static_call

	# Save GPRs
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	# Allocate Stack Space
	push	%rbp
	mov	%rsp, %rbp
	sub	$frame_size, %rsp
	and	$~(0x20 - 1), %rsp

.Lupdateblock:

# Load state variables
	mov	DIGEST(0), a_64
	mov	DIGEST(1), b_64
	mov	DIGEST(2), c_64
	mov	DIGEST(3), d_64
	mov	DIGEST(4), e_64
	mov	DIGEST(5), f_64
	mov	DIGEST(6), g_64
	mov	DIGEST(7), h_64

	t = 0
	.rept 80/2 + 1
	# (80 rounds) / (2 rounds/iteration) + (1 iteration)
	# +1 iteration because the scheduler leads hashing by 1 iteration
		.if t < 2
			# BSWAP 2 QWORDS
			movdqa	XMM_QWORD_BSWAP(%rip), %xmm1
			movdqu	MSG(t), %xmm0
			pshufb	%xmm1, %xmm0	# BSWAP
			movdqa	%xmm0, W_t(t)	# Store Scheduled Pair
			paddq	K_t(t), %xmm0	# Compute W[t]+K[t]
			movdqa	%xmm0, WK_2(t)	# Store into WK for rounds
		.elseif t < 16
			# BSWAP 2 QWORDS# Compute 2 Rounds
			movdqu	MSG(t), %xmm0
			pshufb	%xmm1, %xmm0	# BSWAP
			SHA512_Round t-2	# Round t-2
			movdqa	%xmm0, W_t(t)	# Store Scheduled Pair
			paddq	K_t(t), %xmm0	# Compute W[t]+K[t]
			SHA512_Round t-1	# Round t-1
			movdqa	%xmm0, WK_2(t)	# Store W[t]+K[t] into WK
		.elseif t < 79
			# Schedule 2 QWORDS# Compute 2 Rounds
			SHA512_2Sched_2Round_sse t
		.else
			# Compute 2 Rounds
			SHA512_Round t-2
			SHA512_Round t-1
		.endif
		t = t+2
	.endr

	# Update digest
	add	a_64, DIGEST(0)
	add	b_64, DIGEST(1)
	add	c_64, DIGEST(2)
	add	d_64, DIGEST(3)
	add	e_64, DIGEST(4)
	add	f_64, DIGEST(5)
	add	g_64, DIGEST(6)
	add	h_64, DIGEST(7)

	# Advance to next message block
	add	$16*8, msg
	dec	msglen
	jnz	.Lupdateblock

	# Restore Stack Pointer
	mov	%rbp, %rsp
	pop	%rbp

	# Restore GPRs
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx

	RET
SYM_FUNC_END(sha512_transform_ssse3)

########################################################################
### Binary Data

.section	.rodata.cst16.XMM_QWORD_BSWAP, "aM", @progbits, 16
.align 16
# Mask for byte-swapping a couple of qwords in an XMM register using (v)pshufb.
XMM_QWORD_BSWAP:
	.octa 0x08090a0b0c0d0e0f0001020304050607
