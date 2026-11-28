/* SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause */
//
// Accelerated GHASH and POLYVAL implementation with VPCLMULQDQ and AVX2.
//
// Copyright 2025 Google LLC
//
// Author: Eric Biggers <ebiggers@google.com>
//
//------------------------------------------------------------------------------
//
// This file is dual-licensed, meaning that you can use it under your choice of
// either of the following two licenses:
//
// Licensed under the Apache License 2.0 (the "License").  You may obtain a copy
// of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// or
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
//------------------------------------------------------------------------------
//
// This file implements GHASH and POLYVAL using the VPCLMULQDQ instruction on
// 256-bit vectors (ymm registers), each holding two 128-bit blocks.  It also
// requires AVX2.  The math and the overall design are the same as in
// gf128hash-pclmul.S, which documents them.  The main differences are:
//
// - The 8-block stride is processed as 4 vectors.  Lane 0 of each vector holds
//   the earlier block and lane 1 the later one, so the data vectors are
//   multiplied by the key power vectors [H^8, H^7], [H^6, H^5], [H^4, H^3], and
//   [H^2, H^1], which stay in registers.  The unreduced products are summed in
//   each lane, both lanes are reduced at once, and the two reduced lanes are
//   XOR'd together.  This works because the reduction is linear.  The
//   accumulator is kept in lane 0 with lane 1 zero, so XOR'ing it into the
//   first data vector adds it to the first block only.
//
// - The 8-block loop uses Karatsuba multiplication like gf128hash-pclmul.S.
//   To avoid any per-vector loads or shuffles of the precomputed XOR'd halves
//   of the key powers, h_powers_xored stores them in the order H^8, H^6, H^7,
//   H^5, H^4, H^2, H^3, H^1.  The loop loads them into two registers:
//
//	H_POW2_XORED = [H^8_x, H^6_x | H^7_x, H^5_x]
//	H_POW1_XORED = [H^4_x, H^2_x | H^3_x, H^1_x]
//
//   where H^k_x = H^k_L ^ H^k_H, and '|' separates lanes 0 and 1.  vpclmulqdq
//   then selects either the low qword of each lane (for [H^8, H^7] and
//   [H^4, H^3]) or the high qword (for [H^6, H^5] and [H^2, H^1]).  The final
//   2..7 blocks use schoolbook multiplication instead, since when the number of
//   remaining blocks is odd they need key power pairs (e.g. [H^5, H^4]) that
//   this layout doesn't support.
//
// - Single-block multiplications use the precomputed H^1 * x^-64 mod G(x) from
//   key->h_times_xm64 so that only one reduction step is needed, matching
//   gf128hash-pclmul.S.
//
// - preparekey stores H^1 * x^-64 mod G(x) in key->h_times_xm64, squares H^1 to
//   get H^2, precomputes H^2 * x^-64 mod G(x), and then computes [H^4, H^3],
//   [H^6, H^5], and [H^8, H^7] by repeatedly multiplying by [H^2, H^2] using
//   the 1-step reduction.
//
// - When nblocks == 1, only xmm registers are used.  This avoids the overhead
//   of ymm registers and of vzeroupper.

#include <linux/linkage.h>

.section .rodata
.p2align 4

	// vpshufb mask that reverses the order of the bytes in a 16-byte block
.Lbswap_mask:
	.octa	0x000102030405060708090a0b0c0d0e0f

	// Mask for multiplying by x mod G(x): G(x) - x^128 = x^127 + x^126 +
	// x^121 + 1 (bits 127, 126, 121, and 0), and bit 64 for the carry from
	// bit 63 that vpaddq doesn't propagate
.Lgfpoly_and_internal_carrybit:
	.octa	0xc2000000000000010000000000000001

	// (G(x) - x^128 - 1) / x^64 = x^63 + x^62 + x^57, the constant used to
	// multiply by x^-64 mod G(x)
.Lgfpoly:
	.quad	0xc200000000000000

// Offsets in struct gf128hash_key_x86.  h_powers[0..7] holds H^8..H^1,
// h_powers_xored[0..7] holds the XORs of the halves of H^8, H^6, H^7, H^5, H^4,
// H^2, H^3, H^1 (in that order), and h_times_xm64 holds H^1 * x^-64 mod G(x).
#define OFFSETOF_H_POWERS_XORED	0
#define OFFSETOF_H_POWERS	128
#define OFFSETOFEND_H_POWERS	256
#define OFFSETOF_H_TIMES_XM64	304

.text

// Reduce the 256-bit products LO + MI * x^64 + HI * x^128 given in each 128-bit
// lane of \lo, \mi, and \hi: multiply them by x^-128 mod G(x) and store the
// 128-bit results in \hi.  This is done in two steps, MI += LO * x^-64 then
// HI += MI * x^-64.  Works on xmm and ymm registers.  \gfpoly must contain
// .Lgfpoly in the low qword of each lane.  Clobbers \lo, \mi, and \tmp.
.macro	_gf128hash_reduce	lo, mi, hi, gfpoly, tmp
	vpclmulqdq	$0x00, \lo, \gfpoly, \tmp  // LO_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \lo, \lo		   // LO_H + LO_L * x^64
	vpxor		\lo, \mi, \mi		   // Fold LO into MI (1)
	vpxor		\tmp, \mi, \mi		   // Fold LO into MI (2)
	vpclmulqdq	$0x00, \mi, \gfpoly, \tmp  // MI_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \mi, \mi		   // MI_H + MI_L * x^64
	vpxor		\mi, \hi, \hi		   // Fold MI into HI (1)
	vpxor		\tmp, \hi, \hi		   // Fold MI into HI (2)
.endm

// Set each 128-bit lane of \dst to dot(lane of \a, lane of \b), given
// \a_times_xm64 = \a * x^-64 mod G(x) in each lane (see gf128hash-pclmul.S for
// the math).  Works on xmm and ymm registers.  \dst may alias \a,
// \a_times_xm64, or \b.  \gfpoly must contain .Lgfpoly in the low qword of each
// lane.  \t0 and \t1 are temporaries.
.macro	_gf128hash_mul	a, a_times_xm64, b, dst, gfpoly, t0, t1
	vpclmulqdq	$0x01, \a, \b, \t0		// a_L * b_H
	vpclmulqdq	$0x00, \a_times_xm64, \b, \t1	// (a*x^-64)_L * b_L
	vpxor		\t1, \t0, \t0			// MI
	vpclmulqdq	$0x11, \a, \b, \t1		// a_H * b_H
	vpclmulqdq	$0x10, \a_times_xm64, \b, \dst	// (a*x^-64)_H * b_L
	vpxor		\t1, \dst, \dst			// HI
	vpclmulqdq	$0x00, \t0, \gfpoly, \t1	// MI_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \t0, \t0			// MI_H + MI_L * x^64
	vpxor		\t0, \dst, \dst			// Fold MI into HI (1)
	vpxor		\t1, \dst, \dst			// Fold MI into HI (2)
.endm

// Like _gf128hash_mul, but compute dot(\a, \a).  In GF(2)[x], the cross terms
// cancel: (a_L + a_H * x^64)^2 = a_L^2 + a_H^2 * x^128.  So only 2 vpclmulqdq
// are needed for the product, and MI is just LO * x^-64.
.macro	_gf128hash_square	a, dst, gfpoly, t0, t1
	vpclmulqdq	$0x00, \a, \a, \t0	   // LO = a_L^2
	vpclmulqdq	$0x11, \a, \a, \dst	   // HI = a_H^2
	vpclmulqdq	$0x00, \t0, \gfpoly, \t1   // LO_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \t0, \t0		   // LO_H + LO_L * x^64
	vpxor		\t0, \t1, \t1		   // MI = LO * x^-64
	vpclmulqdq	$0x00, \t1, \gfpoly, \t0   // MI_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \t1, \t1		   // MI_H + MI_L * x^64
	vpxor		\t1, \dst, \dst		   // Fold MI into HI (1)
	vpxor		\t0, \dst, \dst		   // Fold MI into HI (2)
.endm

// void {ghash,polyval}_preparekey_vpclmul_avx2(struct gf128hash_key_x86 *key,
//						const u8 raw_key[16]);
//
// Given the raw GHASH key (\is_ghash=1) or POLYVAL key (\is_ghash=0), set
// h_powers[0..7] to H^8..H^1 in POLYVAL format, set h_powers_xored to the
// XORs of the halves of H^8, H^6, H^7, H^5, H^4, H^2, H^3, H^1, and set
// h_times_xm64 to H^1 * x^-64 mod G(x).
.macro	_gf128hash_preparekey	is_ghash
	.set	KEY,		%rdi
	.set	RAW_KEY,	%rsi
	.set	TMP0,		%ymm0
	.set	TMP0_XMM,	%xmm0
	.set	TMP1,		%ymm1
	.set	TMP1_XMM,	%xmm1
	.set	H_CUR,		%ymm2
	.set	H_CUR_XMM,	%xmm2
	.set	H_CUR2,		%ymm3
	.set	H_INC,		%ymm4
	.set	H_INC_XMM,	%xmm4
	.set	H_INC_XM64,	%ymm5
	.set	H_INC_XM64_XMM,	%xmm5
	.set	GFPOLY,		%ymm6
	.set	GFPOLY_XMM,	%xmm6

	vmovdqu		(RAW_KEY), H_CUR_XMM
.if \is_ghash
	// Convert the GHASH key to POLYVAL format: byte-reflect it, then
	// multiply it by x mod G(x).  See gf128hash-pclmul.S for details.
	vpshufb		.Lbswap_mask(%rip), H_CUR_XMM, H_CUR_XMM
	vpshufd		$0xd3, H_CUR_XMM, TMP0_XMM
	vpsrad		$31, TMP0_XMM, TMP0_XMM
	vpaddq		H_CUR_XMM, H_CUR_XMM, H_CUR_XMM
	vpand		.Lgfpoly_and_internal_carrybit(%rip), TMP0_XMM, TMP0_XMM
	vpxor		TMP0_XMM, H_CUR_XMM, H_CUR_XMM
.endif

	vpbroadcastq	.Lgfpoly(%rip), GFPOLY

	// Compute and store H^1 * x^-64 mod G(x) in h_times_xm64.
	vpshufd		$0x4e, H_CUR_XMM, TMP0_XMM
	vpclmulqdq	$0x00, H_CUR_XMM, GFPOLY_XMM, TMP1_XMM
	vpxor		TMP0_XMM, TMP1_XMM, TMP1_XMM
	vmovdqu		TMP1_XMM, OFFSETOF_H_TIMES_XM64(KEY)

	// Square H^1 to get H^2, and compute H^2 * x^-64 mod G(x).
	_gf128hash_square H_CUR_XMM, H_INC_XMM, GFPOLY_XMM, TMP0_XMM, TMP1_XMM
	vpshufd		$0x4e, H_INC_XMM, TMP0_XMM
	vpclmulqdq	$0x00, H_INC_XMM, GFPOLY_XMM, H_INC_XM64_XMM
	vpxor		TMP0_XMM, H_INC_XM64_XMM, H_INC_XM64_XMM

	// Create H_CUR = [H^2, H^1], H_INC = [H^2, H^2], and
	// H_INC_XM64 = [H^2 * x^-64, H^2 * x^-64].
	vinserti128	$1, H_CUR_XMM, H_INC, H_CUR
	vinserti128	$1, H_INC_XMM, H_INC, H_INC
	vinserti128	$1, H_INC_XM64_XMM, H_INC_XM64, H_INC_XM64

	// Compute H_CUR2 = [H^4, H^3].
	_gf128hash_mul	H_INC, H_INC_XM64, H_CUR, H_CUR2, GFPOLY, TMP0, TMP1

	// Store [H^4, H^3, H^2, H^1] in h_powers[4..7].
	vmovdqu		H_CUR, OFFSETOF_H_POWERS+3*32(KEY)
	vmovdqu		H_CUR2, OFFSETOF_H_POWERS+2*32(KEY)

	// Store [H^4_x, H^2_x | H^3_x, H^1_x] in h_powers_xored[4..7].  This
	// layout requires only in-lane unpacking.
	vpunpcklqdq	H_CUR, H_CUR2, TMP0
	vpunpckhqdq	H_CUR, H_CUR2, TMP1
	vpxor		TMP1, TMP0, TMP0
	vmovdqu		TMP0, OFFSETOF_H_POWERS_XORED+32(KEY)

	// Compute H_CUR = [H^6, H^5] and H_CUR2 = [H^8, H^7], and store
	// [H^8, H^7, H^6, H^5] in h_powers[0..3].
	_gf128hash_mul	H_INC, H_INC_XM64, H_CUR2, H_CUR, GFPOLY, TMP0, TMP1
	_gf128hash_mul	H_INC, H_INC_XM64, H_CUR, H_CUR2, GFPOLY, TMP0, TMP1
	vmovdqu		H_CUR, OFFSETOF_H_POWERS+1*32(KEY)
	vmovdqu		H_CUR2, OFFSETOF_H_POWERS+0*32(KEY)

	// Store [H^8_x, H^6_x | H^7_x, H^5_x] in h_powers_xored[0..3].
	vpunpcklqdq	H_CUR, H_CUR2, TMP0
	vpunpckhqdq	H_CUR, H_CUR2, TMP1
	vpxor		TMP1, TMP0, TMP0
	vmovdqu		TMP0, OFFSETOF_H_POWERS_XORED(KEY)

	vzeroupper
	RET
.endm

// Update ACC with 8 blocks (four 32-byte vectors) of data from \data_ptr, using
// aggregated Karatsuba multiplication.  ACC must hold the accumulator in lane 0
// and zero in lane 1, and this property is preserved.
//
// For each data vector M, vpunpckhqdq and vpxor compute M_L ^ M_H in the low
// qword of each lane, for the Karatsuba middle product.
.macro	_gf128hash_4x	data_ptr, bswap_data
	// Vector 0: [M_0 + ACC, M_1] * [H^8, H^7], with the low qwords of
	// H_POW2_XORED.  Initialize LO, MI, and HI.  (HI aliases ACC.)
	vmovdqu		0*32(\data_ptr), TMP1
.if \bswap_data
	vpshufb		BSWAP_MASK, TMP1, TMP1
.endif
	vpxor		ACC, TMP1, TMP1
	vpclmulqdq	$0x00, H_POW4, TMP1, LO
	vpclmulqdq	$0x11, H_POW4, TMP1, HI
	vpunpckhqdq	TMP1, TMP1, TMP0
	vpxor		TMP1, TMP0, TMP0
	vpclmulqdq	$0x00, H_POW2_XORED, TMP0, MI

	// Vector 1: [M_2, M_3] * [H^6, H^5], with the high qwords of
	// H_POW2_XORED.
	vmovdqu		1*32(\data_ptr), TMP1
.if \bswap_data
	vpshufb		BSWAP_MASK, TMP1, TMP1
.endif
	vpclmulqdq	$0x00, H_POW3, TMP1, TMP0
	vpxor		TMP0, LO, LO
	vpclmulqdq	$0x11, H_POW3, TMP1, TMP0
	vpxor		TMP0, HI, HI
	vpunpckhqdq	TMP1, TMP1, TMP0
	vpxor		TMP1, TMP0, TMP0
	vpclmulqdq	$0x10, H_POW2_XORED, TMP0, TMP0
	vpxor		TMP0, MI, MI

	// Vector 2: [M_4, M_5] * [H^4, H^3], with the low qwords of
	// H_POW1_XORED.
	vmovdqu		2*32(\data_ptr), TMP1
.if \bswap_data
	vpshufb		BSWAP_MASK, TMP1, TMP1
.endif
	vpclmulqdq	$0x00, H_POW2, TMP1, TMP0
	vpxor		TMP0, LO, LO
	vpclmulqdq	$0x11, H_POW2, TMP1, TMP0
	vpxor		TMP0, HI, HI
	vpunpckhqdq	TMP1, TMP1, TMP0
	vpxor		TMP1, TMP0, TMP0
	vpclmulqdq	$0x00, H_POW1_XORED, TMP0, TMP0
	vpxor		TMP0, MI, MI

	// Vector 3: [M_6, M_7] * [H^2, H^1], with the high qwords of
	// H_POW1_XORED.
	vmovdqu		3*32(\data_ptr), TMP1
.if \bswap_data
	vpshufb		BSWAP_MASK, TMP1, TMP1
.endif
	vpclmulqdq	$0x00, H_POW1, TMP1, TMP0
	vpxor		TMP0, LO, LO
	vpclmulqdq	$0x11, H_POW1, TMP1, TMP0
	vpxor		TMP0, HI, HI
	vpunpckhqdq	TMP1, TMP1, TMP0
	vpxor		TMP1, TMP0, TMP0
	vpclmulqdq	$0x10, H_POW1_XORED, TMP0, TMP0
	vpxor		TMP0, MI, MI

	// Finish MI by adding LO and HI to it.  Then reduce both lanes, and XOR
	// them together into ACC_XMM.  Writing ACC_XMM zeroes lane 1 of ACC.
	vpxor		LO, MI, MI
	vpxor		HI, MI, MI
	_gf128hash_reduce LO, MI, HI, GFPOLY, TMP0
	vextracti128	$1, HI, TMP0_XMM
	vpxor		TMP0_XMM, HI_XMM, ACC_XMM
.endm

// void {ghash,polyval}_blocks_vpclmul_avx2(struct polyval_elem *acc,
//					    const struct gf128hash_key_x86 *key,
//					    const u8 *data, size_t nblocks);
//
// Update the POLYVAL-format accumulator @acc with @nblocks >= 1 full 16-byte
// blocks from @data.  If \bswap_data=1 (GHASH), each block is byte-reflected to
// convert it to POLYVAL format.
.macro	_gf128hash_blocks	bswap_data
	.set	ACC_PTR,	%rdi
	.set	KEY,		%rsi
	.set	DATA,		%rdx
	.set	NBLOCKS,	%rcx
	.set	POWERS_PTR,	%rax

	.set	TMP0,		%ymm0
	.set	TMP0_XMM,	%xmm0
	.set	TMP1,		%ymm1
	.set	TMP1_XMM,	%xmm1
	.set	TMP2,		%ymm2
	.set	TMP2_XMM,	%xmm2
	.set	LO,		%ymm3
	.set	LO_XMM,		%xmm3
	.set	MI,		%ymm4
	.set	ACC,		%ymm5
	.set	ACC_XMM,	%xmm5
	.set	HI,		%ymm5
	.set	HI_XMM,		%xmm5
	.set	BSWAP_MASK,	%ymm6
	.set	BSWAP_MASK_XMM,	%xmm6
	.set	GFPOLY,		%ymm7
	.set	GFPOLY_XMM,	%xmm7
	.set	H_POW2_XORED,	%ymm8
	.set	H_POW1_XORED,	%ymm9
	.set	H_POW4,		%ymm10
	.set	H_POW3,		%ymm11
	.set	H_POW2,		%ymm12
	.set	H_POW1,		%ymm13

	// Load the accumulator into lane 0 of ACC.  This zeroes lane 1.
	vmovdqu		(ACC_PTR), ACC_XMM

	// Handle nblocks == 1 specially, using only xmm registers.  This case
	// is common (e.g. for short AES-GCM associated data and for the
	// AES-GCM lengths block).
	cmp		$1, NBLOCKS
	jne		.Lblocks_more_than_1block\@

	vmovq		.Lgfpoly(%rip), GFPOLY_XMM
	vmovdqu		(DATA), TMP0_XMM
.if \bswap_data
	vpshufb		.Lbswap_mask(%rip), TMP0_XMM, TMP0_XMM
.endif
	vpxor		TMP0_XMM, ACC_XMM, ACC_XMM
	vmovdqu		OFFSETOFEND_H_POWERS-16(KEY), TMP0_XMM
	vmovdqu		OFFSETOF_H_TIMES_XM64(KEY), TMP1_XMM
	_gf128hash_mul	TMP0_XMM, TMP1_XMM, ACC_XMM, ACC_XMM, GFPOLY_XMM, \
			TMP2_XMM, LO_XMM
	vmovdqu		ACC_XMM, (ACC_PTR)
	RET

.Lblocks_more_than_1block\@:
.if \bswap_data
	vbroadcasti128	.Lbswap_mask(%rip), BSWAP_MASK
.endif
	vpbroadcastq	.Lgfpoly(%rip), GFPOLY

	// Process 8 blocks (128 bytes) at a time.
	sub		$8, NBLOCKS
	jb		.Lblocks_loop_4x_done\@
	vmovdqu		OFFSETOF_H_POWERS_XORED(KEY), H_POW2_XORED
	vmovdqu		OFFSETOF_H_POWERS_XORED+32(KEY), H_POW1_XORED
	vmovdqu		OFFSETOF_H_POWERS+0*32(KEY), H_POW4
	vmovdqu		OFFSETOF_H_POWERS+1*32(KEY), H_POW3
	vmovdqu		OFFSETOF_H_POWERS+2*32(KEY), H_POW2
	vmovdqu		OFFSETOF_H_POWERS+3*32(KEY), H_POW1
.Lblocks_loop_4x\@:
	_gf128hash_4x	DATA, \bswap_data
	sub		$-128, DATA	// DATA += 128 (compact imm8)
	sub		$8, NBLOCKS
	jae		.Lblocks_loop_4x\@
.Lblocks_loop_4x_done\@:
	add		$8, NBLOCKS
	jz		.Lblocks_done\@
	cmp		$1, NBLOCKS
	je		.Lblocks_lastblock\@

	// 2 <= n = NBLOCKS <= 7 blocks remain.  Multiply them by H^n..H^1,
	// starting at h_powers[8-n], using schoolbook multiplication.  Sum the
	// unreduced products, and reduce the sum once at the end.
	mov		NBLOCKS, POWERS_PTR
	shl		$4, POWERS_PTR
	neg		POWERS_PTR
	lea		OFFSETOFEND_H_POWERS(KEY,POWERS_PTR), POWERS_PTR

	// Blocks 0 and 1.  Since lane 1 of ACC is zero, vpxor adds ACC to
	// block 0 only.
	vmovdqu		(DATA), TMP0
.if \bswap_data
	vpshufb		BSWAP_MASK, TMP0, TMP0
.endif
	vpxor		ACC, TMP0, TMP0
	vmovdqu		(POWERS_PTR), TMP1
	vpclmulqdq	$0x00, TMP1, TMP0, LO
	vpclmulqdq	$0x01, TMP1, TMP0, MI
	vpclmulqdq	$0x10, TMP1, TMP0, TMP2
	vpxor		TMP2, MI, MI
	vpclmulqdq	$0x11, TMP1, TMP0, HI
	add		$32, DATA
	add		$32, POWERS_PTR
	sub		$2, NBLOCKS
	jz		.Lblocks_tail_reduce\@

	// Any further pairs of blocks (0, 1, or 2 iterations).
	sub		$2, NBLOCKS
	jb		.Lblocks_tail_odd\@
.Lblocks_tail_loop\@:
	vmovdqu		(DATA), TMP0
.if \bswap_data
	vpshufb		BSWAP_MASK, TMP0, TMP0
.endif
	vmovdqu		(POWERS_PTR), TMP1
	vpclmulqdq	$0x00, TMP1, TMP0, TMP2
	vpxor		TMP2, LO, LO
	vpclmulqdq	$0x01, TMP1, TMP0, TMP2
	vpxor		TMP2, MI, MI
	vpclmulqdq	$0x10, TMP1, TMP0, TMP2
	vpxor		TMP2, MI, MI
	vpclmulqdq	$0x11, TMP1, TMP0, TMP2
	vpxor		TMP2, HI, HI
	add		$32, DATA
	add		$32, POWERS_PTR
	sub		$2, NBLOCKS
	jae		.Lblocks_tail_loop\@
.Lblocks_tail_odd\@:
	add		$2, NBLOCKS
	jz		.Lblocks_tail_reduce\@

	// Final block, if n is odd: multiply it by H^1 in lane 0.  The 128-bit
	// vpclmulqdq zeroes lane 1 of TMP2, so lane 1 of LO, MI, and HI is
	// unchanged.
	vmovdqu		(DATA), TMP0_XMM
.if \bswap_data
	vpshufb		BSWAP_MASK_XMM, TMP0_XMM, TMP0_XMM
.endif
	vmovdqu		(POWERS_PTR), TMP1_XMM
	vpclmulqdq	$0x00, TMP1_XMM, TMP0_XMM, TMP2_XMM
	vpxor		TMP2, LO, LO
	vpclmulqdq	$0x01, TMP1_XMM, TMP0_XMM, TMP2_XMM
	vpxor		TMP2, MI, MI
	vpclmulqdq	$0x10, TMP1_XMM, TMP0_XMM, TMP2_XMM
	vpxor		TMP2, MI, MI
	vpclmulqdq	$0x11, TMP1_XMM, TMP0_XMM, TMP2_XMM
	vpxor		TMP2, HI, HI

.Lblocks_tail_reduce\@:
	// Reduce both lanes, and XOR them together into ACC_XMM.
	_gf128hash_reduce LO, MI, HI, GFPOLY, TMP0
	vextracti128	$1, HI, TMP0_XMM
	vpxor		TMP0_XMM, HI_XMM, ACC_XMM
	jmp		.Lblocks_done\@

.Lblocks_lastblock\@:
	// 1 block remains: ACC = dot(ACC + data[0], H^1).
	vmovdqu		(DATA), TMP0_XMM
.if \bswap_data
	vpshufb		BSWAP_MASK_XMM, TMP0_XMM, TMP0_XMM
.endif
	vpxor		TMP0_XMM, ACC_XMM, ACC_XMM
	vmovdqu		OFFSETOFEND_H_POWERS-16(KEY), TMP0_XMM
	vmovdqu		OFFSETOF_H_TIMES_XM64(KEY), TMP1_XMM
	_gf128hash_mul	TMP0_XMM, TMP1_XMM, ACC_XMM, ACC_XMM, GFPOLY_XMM, \
			TMP2_XMM, LO_XMM

.Lblocks_done\@:
	vmovdqu		ACC_XMM, (ACC_PTR)
	vzeroupper
	RET
.endm

SYM_FUNC_START(ghash_preparekey_vpclmul_avx2)
	_gf128hash_preparekey	1
SYM_FUNC_END(ghash_preparekey_vpclmul_avx2)
SYM_FUNC_START(polyval_preparekey_vpclmul_avx2)
	_gf128hash_preparekey	0
SYM_FUNC_END(polyval_preparekey_vpclmul_avx2)
SYM_FUNC_START(ghash_blocks_vpclmul_avx2)
	_gf128hash_blocks	1
SYM_FUNC_END(ghash_blocks_vpclmul_avx2)
SYM_FUNC_START(polyval_blocks_vpclmul_avx2)
	_gf128hash_blocks	0
SYM_FUNC_END(polyval_blocks_vpclmul_avx2)
