/* SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause */
//
// Accelerated GHASH and POLYVAL implementation with VPCLMULQDQ and AVX512
// (requires VPCLMULQDQ && AVX512BW && AVX512VL && BMI2).
//
// Copyright 2024 Google LLC
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
// 512-bit vectors (zmm registers), each holding four 128-bit blocks.  It also
// requires AVX512BW (for masked byte loads), AVX512VL (for EVEX-coded
// instructions such as vpternlogd on xmm and ymm registers), and BMI2 (for
// bzhi).  The math is documented in gf128hash-pclmul.S.  The design is similar
// to gf128hash-vpclmul-avx2.S, with the following differences:
//
// - The main loop processes 16 blocks per stride, as 4 vectors.  Lane i of
//   each vector holds the i'th block, so the data vectors are multiplied by the
//   key power vectors [H^16..H^13], [H^12..H^9], [H^8..H^5], and [H^4..H^1],
//   which stay in registers.  As in the AVX2 code, the unreduced products are
//   summed in each lane, all lanes are reduced at once, and the reduced lanes
//   are XOR'd together.
//
// - The main loop uses schoolbook multiplication rather than Karatsuba.  The
//   3-input XOR provided by vpternlogd helps schoolbook more than Karatsuba,
//   storing the XOR'd halves of all 16 key powers for Karatsuba would add
//   128 bytes to struct gf128hash_key_x86, and using schoolbook also matches
//   aes-gcm-vaes-avx512.S (which shares the key struct).  In the main loop,
//   the reduction is interleaved with the multiplications to hide the
//   vpclmulqdq latency.
//
// - The key uses the 16-power layout of struct gf128hash_key_x86:
//   h_powers16[0..15] holds H^16..H^1 and is followed by 3 zeroized padding
//   blocks, and then h_times_xm64 (H^1 * x^-64 mod G(x)).  h_powers16[15] and
//   h_times_xm64 are at the same offsets as in the 8-power layout.  The
//   padding allows any remaining 1..15 blocks after the 16-block loop to be
//   processed in one masked loop (with a single deferred reduction at the end):
//   on the last vector (with 1 <= r <= 4 blocks), a zero-masked load avoids
//   reading past the end of the data, and an unmasked load reads
//   [H^r..H^1, 0, ...].
//
// - Single-block multiplications use key->h_times_xm64 so that only one
//   reduction step is needed, matching gf128hash-pclmul.S.
//
// - preparekey stores H^1 * x^-64 mod G(x) in key->h_times_xm64, squares H^1 to
//   get H^2, computes [H^4, H^3] by multiplying [H^2, H^1] by [H^2, H^2], and
//   then computes [H^8..H^5], [H^12..H^9], and [H^16..H^13] by repeatedly
//   multiplying by [H^4, H^4, H^4, H^4], precomputing x^-64 multiples so each
//   multiplication needs only one reduction step.
//
// - When nblocks == 1, only xmm registers are used.  This avoids the overhead
//   of zmm registers and of vzeroupper.

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

// Offsets in struct gf128hash_key_x86, using the 16-power layout.
// h_powers16[0..15] holds H^16..H^1, followed by 3 zeroized padding blocks at
// OFFSETOFEND_H_POWERS, and then h_times_xm64 (H^1 * x^-64 mod G(x)).
#define OFFSETOF_H_POWERS	0
#define OFFSETOFEND_H_POWERS	256
#define OFFSETOF_H_TIMES_XM64	304

.text

// Reduce the 256-bit products LO + MI * x^64 + HI * x^128 given in each 128-bit
// lane of \lo, \mi, and \hi: multiply them by x^-128 mod G(x) and store the
// 128-bit results in \hi.  This is done in two steps, MI += LO * x^-64 then
// HI += MI * x^-64.  Works on xmm, ymm, and zmm registers.  \gfpoly must
// contain .Lgfpoly in the low qword of each lane.  Clobbers \lo, \mi, and \tmp.
.macro	_gf128hash_reduce	lo, mi, hi, gfpoly, tmp
	vpclmulqdq	$0x00, \lo, \gfpoly, \tmp // LO_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \lo, \lo		  // LO_H + LO_L * x^64
	vpternlogd	$0x96, \tmp, \lo, \mi	  // Fold LO into MI
	vpclmulqdq	$0x00, \mi, \gfpoly, \tmp // MI_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \mi, \mi		  // MI_H + MI_L * x^64
	vpternlogd	$0x96, \tmp, \mi, \hi	  // Fold MI into HI
.endm

// Set each 128-bit lane of \dst to dot(lane of \a, lane of \b), given
// \a_times_xm64 = \a * x^-64 mod G(x) in each lane (see gf128hash-pclmul.S for
// the math).  Works on xmm, ymm, and zmm registers.  \dst may alias \a,
// \a_times_xm64, or \b.  \gfpoly must contain .Lgfpoly in the low qword of each
// lane.  \t0 and \t1 are temporaries.
.macro	_gf128hash_mul	a, a_times_xm64, b, dst, gfpoly, t0, t1
	vpclmulqdq	$0x01, \a, \b, \t0		// a_L * b_H
	vpclmulqdq	$0x00, \a_times_xm64, \b, \t1	// (a*x^-64)_L * b_L
	vpxord		\t1, \t0, \t0			// MI
	vpclmulqdq	$0x11, \a, \b, \t1		// a_H * b_H
	vpclmulqdq	$0x10, \a_times_xm64, \b, \dst	// (a*x^-64)_H * b_L
	vpxord		\t1, \dst, \dst			// HI
	vpclmulqdq	$0x00, \t0, \gfpoly, \t1	// MI_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \t0, \t0			// MI_H + MI_L * x^64
	vpternlogd	$0x96, \t1, \t0, \dst		// Fold MI into HI
.endm

// Like _gf128hash_mul, but compute dot(\a, \a).  In GF(2)[x], the cross terms
// cancel: (a_L + a_H * x^64)^2 = a_L^2 + a_H^2 * x^128.  So only 2 vpclmulqdq
// are needed for the product, and MI is just LO * x^-64.
.macro	_gf128hash_square	a, dst, gfpoly, t0, t1
	vpclmulqdq	$0x00, \a, \a, \t0	  // LO = a_L^2
	vpclmulqdq	$0x11, \a, \a, \dst	  // HI = a_H^2
	vpclmulqdq	$0x00, \t0, \gfpoly, \t1  // LO_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \t0, \t0		  // LO_H + LO_L * x^64
	vpxord		\t0, \t1, \t1		  // MI = LO * x^-64
	vpclmulqdq	$0x00, \t1, \gfpoly, \t0  // MI_L*(x^63+x^62+x^57)
	vpshufd		$0x4e, \t1, \t1		  // MI_H + MI_L * x^64
	vpternlogd	$0x96, \t0, \t1, \dst	  // Fold MI into HI
.endm

// void {ghash,polyval}_preparekey_vpclmul_avx512(struct gf128hash_key_x86 *key,
//						  const u8 raw_key[16]);
//
// Given the raw GHASH key (\is_ghash=1) or POLYVAL key (\is_ghash=0), set
// h_powers16[0..15] to H^16..H^1 in POLYVAL format, zeroize the 3 padding
// blocks that follow, and set h_times_xm64 to H^1 * x^-64 mod G(x).
.macro	_gf128hash_preparekey	is_ghash
	.set	KEY,		%rdi
	.set	RAW_KEY,	%rsi
	.set	POWERS_PTR,	%rdx
	.set	H_CUR,		%zmm2
	.set	H_CUR_YMM,	%ymm2
	.set	H_CUR_XMM,	%xmm2
	.set	H_INC,		%zmm3
	.set	H_INC_YMM,	%ymm3
	.set	H_INC_XMM,	%xmm3
	.set	H_INC_XM64,	%zmm4
	.set	H_INC_XM64_YMM,	%ymm4
	.set	H_INC_XM64_XMM,	%xmm4
	.set	GFPOLY,		%zmm5
	.set	GFPOLY_YMM,	%ymm5
	.set	GFPOLY_XMM,	%xmm5

	// Load the raw key.  If it's a GHASH key, also byte-reflect it.
	vmovdqu		(RAW_KEY), H_CUR_XMM
.if \is_ghash
	vpshufb		.Lbswap_mask(%rip), H_CUR_XMM, H_CUR_XMM
.endif

	// Point POWERS_PTR to h_powers16[12], and zeroize the 3 padding blocks.
	lea		OFFSETOFEND_H_POWERS-64(KEY), POWERS_PTR
	vpxor		%xmm0, %xmm0, %xmm0
	vmovdqu		%ymm0, 64(POWERS_PTR)
	vmovdqu		%xmm0, 64+2*16(POWERS_PTR)

.if \is_ghash
	// Finish converting the GHASH key to POLYVAL format by multiplying it
	// by x mod G(x).  See gf128hash-pclmul.S for details.  Here vpternlogd
	// $0x78 does the AND and XOR: dst ^= src1 & src2.
	vpshufd		$0xd3, H_CUR_XMM, %xmm0
	vpsrad		$31, %xmm0, %xmm0
	vpaddq		H_CUR_XMM, H_CUR_XMM, H_CUR_XMM
	vpternlogd	$0x78, .Lgfpoly_and_internal_carrybit(%rip), %xmm0, H_CUR_XMM
.endif

	vpbroadcastq	.Lgfpoly(%rip), GFPOLY

	// Compute and store H^1 * x^-64 mod G(x) in h_times_xm64.
	vpshufd		$0x4e, H_CUR_XMM, %xmm0
	vpclmulqdq	$0x00, H_CUR_XMM, GFPOLY_XMM, %xmm1
	vpxor		%xmm0, %xmm1, %xmm1
	vmovdqu		%xmm1, OFFSETOF_H_TIMES_XM64(KEY)

	// Square H^1 to get H^2, and compute H^2 * x^-64 mod G(x).
	_gf128hash_square H_CUR_XMM, H_INC_XMM, GFPOLY_XMM, %xmm0, %xmm1
	vpshufd		$0x4e, H_INC_XMM, %xmm0
	vpclmulqdq	$0x00, H_INC_XMM, GFPOLY_XMM, H_INC_XM64_XMM
	vpxor		%xmm0, H_INC_XM64_XMM, H_INC_XM64_XMM

	// Create H_CUR_YMM = [H^2, H^1], H_INC_YMM = [H^2, H^2], and
	// H_INC_XM64_YMM = [H^2 * x^-64, H^2 * x^-64].
	vinserti128	$1, H_CUR_XMM, H_INC_YMM, H_CUR_YMM
	vinserti128	$1, H_INC_XMM, H_INC_YMM, H_INC_YMM
	vinserti128	$1, H_INC_XM64_XMM, H_INC_XM64_YMM, H_INC_XM64_YMM

	// Compute H_INC_YMM = [H^4, H^3], then create
	// H_CUR = [H^4, H^3, H^2, H^1], H_INC = [H^4, H^4, H^4, H^4], and
	// H_INC_XM64 = [H^4 * x^-64, ...].
	_gf128hash_mul	H_INC_YMM, H_INC_XM64_YMM, H_CUR_YMM, H_INC_YMM, \
			GFPOLY_YMM, %ymm0, %ymm1
	vinserti64x4	$1, H_CUR_YMM, H_INC, H_CUR
	vshufi64x2	$0, H_INC, H_INC, H_INC
	vpshufd		$0x4e, H_INC, %zmm0
	vpclmulqdq	$0x00, H_INC, GFPOLY, H_INC_XM64
	vpxord		%zmm0, H_INC_XM64, H_INC_XM64

	// Store [H^4, H^3, H^2, H^1] in h_powers16[12..15].
	vmovdqu8	H_CUR, (POWERS_PTR)

	// Compute [H^8..H^5], [H^12..H^9], and [H^16..H^13], and store them in
	// h_powers16[8..11], [4..7], and [0..3] respectively.
	mov		$3, %eax
.Lpreparekey_next\@:
	sub		$64, POWERS_PTR
	_gf128hash_mul	H_INC, H_INC_XM64, H_CUR, H_CUR, GFPOLY, %zmm0, %zmm1
	vmovdqu8	H_CUR, (POWERS_PTR)
	dec		%eax
	jnz		.Lpreparekey_next\@

	vzeroupper
	RET
.endm

// XOR together the four 128-bit lanes of \src (whose low lane is \src_xmm), and
// store the result in \dst_xmm.  Writing \dst_xmm zeroes the upper lanes of the
// corresponding zmm register.
.macro	_horizontal_xor	src, src_xmm, dst_xmm, t0_xmm, t1_xmm, t2_xmm
	vextracti32x4	$1, \src, \t0_xmm
	vextracti32x4	$2, \src, \t1_xmm
	vextracti32x4	$3, \src, \t2_xmm
	vpxor		\t0_xmm, \src_xmm, \dst_xmm
	vpternlogd	$0x96, \t1_xmm, \t2_xmm, \dst_xmm
.endm

// Update ACC with the 16 blocks (four 64-byte vectors) of data in DATA[0-3],
// using aggregated schoolbook multiplication with the reduction interleaved.
// ACC must hold the accumulator in lane 0 and zero in lanes 1..3, and this
// property is preserved.  The products are summed per lane as:
//
//	LO = sum (DATA_i)_L * (H_POW_{4-i})_L
//	MI = sum (DATA_i)_L * (H_POW_{4-i})_H + (DATA_i)_H * (H_POW_{4-i})_L
//	HI = sum (DATA_i)_H * (H_POW_{4-i})_H
.macro	_gf128hash_4x	bswap_data
	// Byte-reflect the data if needed, and add ACC to block 0.
.if \bswap_data
	vpshufb		BSWAP_MASK, DATA0, DATA0
	vpxord		ACC, DATA0, DATA0
	vpshufb		BSWAP_MASK, DATA1, DATA1
	vpshufb		BSWAP_MASK, DATA2, DATA2
	vpshufb		BSWAP_MASK, DATA3, DATA3
.else
	vpxord		ACC, DATA0, DATA0
.endif

	// Compute LO in ACC.
	vpclmulqdq	$0x00, H_POW4, DATA0, ACC	// LO_0
	vpclmulqdq	$0x00, H_POW3, DATA1, TMP0	// LO_1
	vpclmulqdq	$0x00, H_POW2, DATA2, TMP1	// LO_2
	vpxord		TMP0, ACC, ACC			// sum(LO_{1,0})
	vpclmulqdq	$0x00, H_POW1, DATA3, TMP2	// LO_3
	vpternlogd	$0x96, TMP2, TMP1, ACC		// LO = sum(LO_{3..0})

	// Compute MI in TMP0.  Also start folding LO into MI.
	vpclmulqdq	$0x01, H_POW4, DATA0, TMP0	// MI_0
	vpclmulqdq	$0x01, H_POW3, DATA1, TMP1	// MI_1
	vpclmulqdq	$0x01, H_POW2, DATA2, TMP2	// MI_2
	vpternlogd	$0x96, TMP2, TMP1, TMP0		// sum(MI_{2..0})
	vpclmulqdq	$0x01, H_POW1, DATA3, TMP1	// MI_3
	vpclmulqdq	$0x10, H_POW4, DATA0, TMP2	// MI_4
	vpternlogd	$0x96, TMP2, TMP1, TMP0		// sum(MI_{4..0})
	vpclmulqdq	$0x10, H_POW3, DATA1, TMP1	// MI_5
	vpclmulqdq	$0x10, H_POW2, DATA2, TMP2	// MI_6
	vpternlogd	$0x96, TMP2, TMP1, TMP0		// sum(MI_{6..0})
	vpclmulqdq	$0x00, ACC, GFPOLY, TMP2	// LO_L*(x^63+x^62+x^57)
	vpclmulqdq	$0x10, H_POW1, DATA3, TMP1	// MI_7
	vpxord		TMP1, TMP0, TMP0		// MI = sum(MI_{7..0})

	// Compute HI in ACC, interleaved with folding LO into MI and then MI
	// into HI.
	vpshufd		$0x4e, ACC, ACC			// LO_H + LO_L * x^64
	vpclmulqdq	$0x11, H_POW4, DATA0, DATA0	// HI_0
	vpclmulqdq	$0x11, H_POW3, DATA1, DATA1	// HI_1
	vpclmulqdq	$0x11, H_POW2, DATA2, DATA2	// HI_2
	vpternlogd	$0x96, TMP2, ACC, TMP0		// Fold LO into MI
	vpclmulqdq	$0x11, H_POW1, DATA3, DATA3	// HI_3
	vpternlogd	$0x96, DATA2, DATA1, DATA0	// sum(HI_{2..0})
	vpclmulqdq	$0x00, TMP0, GFPOLY, TMP1	// MI_L*(x^63+x^62+x^57)
	vpxord		DATA3, DATA0, ACC		// HI = sum(HI_{3..0})
	vpshufd		$0x4e, TMP0, TMP0		// MI_H + MI_L * x^64
	vpternlogd	$0x96, TMP1, TMP0, ACC		// Fold MI into HI

	// XOR the 4 lanes together into ACC_XMM, zeroing lanes 1..3 of ACC.
	_horizontal_xor	ACC, ACC_XMM, ACC_XMM, DATA0_XMM, DATA1_XMM, DATA2_XMM
.endm

// void {ghash,polyval}_blocks_vpclmul_avx512(struct polyval_elem *acc,
//					      const struct gf128hash_key_x86 *key,
//					      const u8 *data, size_t nblocks);
//
// Update the POLYVAL-format accumulator @acc with @nblocks >= 1 full 16-byte
// blocks from @data.  If \bswap_data=1 (GHASH), each block is byte-reflected to
// convert it to POLYVAL format.
.macro	_gf128hash_blocks	bswap_data
	.set	ACC_PTR,	%rdi
	.set	KEY,		%rsi
	.set	DATA,		%rdx
	.set	NBLOCKS,	%rcx

	// %rax, %r8, %r9, and %k1 are used as temporary registers.
	.set	DATA0,		%zmm0
	.set	DATA0_XMM,	%xmm0
	.set	DATA1,		%zmm1
	.set	DATA1_XMM,	%xmm1
	.set	DATA2,		%zmm2
	.set	DATA2_XMM,	%xmm2
	.set	DATA3,		%zmm3
	.set	BSWAP_MASK,	%zmm4
	.set	ACC,		%zmm5
	.set	ACC_XMM,	%xmm5
	.set	H_POW4,		%zmm6
	.set	H_POW3,		%zmm7
	.set	H_POW2,		%zmm8
	.set	H_POW1,		%zmm9
	.set	H_POW1_XMM,	%xmm9
	.set	GFPOLY,		%zmm10
	.set	GFPOLY_XMM,	%xmm10
	.set	TMP0,		%zmm11
	.set	TMP1,		%zmm12
	.set	TMP2,		%zmm13

	// Load the accumulator into lane 0 of ACC.  This zeroes lanes 1..3.
	vmovdqu		(ACC_PTR), ACC_XMM

	// Handle nblocks == 1 specially, using only xmm registers.  This case
	// is common (e.g. for short AES-GCM associated data and for the
	// AES-GCM lengths block).
	cmp		$1, NBLOCKS
	jne		.Lblocks_more_than_1block\@

	vmovq		.Lgfpoly(%rip), GFPOLY_XMM
	vmovdqu		(DATA), DATA0_XMM
	vmovdqu		OFFSETOFEND_H_POWERS-16(KEY), H_POW1_XMM
	vmovdqu		OFFSETOF_H_TIMES_XM64(KEY), DATA1_XMM
.if \bswap_data
	vpshufb		.Lbswap_mask(%rip), DATA0_XMM, DATA0_XMM
.endif
	vpxor		DATA0_XMM, ACC_XMM, ACC_XMM
	_gf128hash_mul	H_POW1_XMM, DATA1_XMM, ACC_XMM, ACC_XMM, GFPOLY_XMM, \
			DATA0_XMM, DATA2_XMM
	vmovdqu		ACC_XMM, (ACC_PTR)
	RET

.Lblocks_more_than_1block\@:
.if \bswap_data
	vbroadcasti32x4	.Lbswap_mask(%rip), BSWAP_MASK
.endif
	vpbroadcastq	.Lgfpoly(%rip), GFPOLY

	// Process 16 blocks (256 bytes) at a time.
	sub		$16, NBLOCKS
	jb		.Lblocks_loop_4x_done\@
	vmovdqu8	OFFSETOF_H_POWERS+0*64(KEY), H_POW4
	vmovdqu8	OFFSETOF_H_POWERS+1*64(KEY), H_POW3
	vmovdqu8	OFFSETOF_H_POWERS+2*64(KEY), H_POW2
	vmovdqu8	OFFSETOF_H_POWERS+3*64(KEY), H_POW1
.Lblocks_loop_4x\@:
	vmovdqu8	0*64(DATA), DATA0
	vmovdqu8	1*64(DATA), DATA1
	vmovdqu8	2*64(DATA), DATA2
	vmovdqu8	3*64(DATA), DATA3
	_gf128hash_4x	\bswap_data
	add		$256, DATA
	sub		$16, NBLOCKS
	jae		.Lblocks_loop_4x\@
.Lblocks_loop_4x_done\@:
	add		$16, NBLOCKS
	jz		.Lblocks_done\@

	// 1 <= n = NBLOCKS <= 15 blocks remain.  Multiply them by H^n..H^1,
	// starting at h_powers16[16-n], using schoolbook multiplication.  Sum
	// the unreduced products across all remaining vectors, and reduce once
	// at the end.  On each iteration, bzhi builds a byte mask of all 1s if
	// >= 64 bytes remain, or NBLOCKS 1s otherwise (this relies on
	// NBLOCKS <= 16*15 = 240 <= 255).  When fewer than 4 blocks remain,
	// the zero-masked load doesn't access masked-out bytes, and the
	// unmasked key-power load extends into the zeroized padding blocks;
	// unused lanes of DATA0 are zero (vpshufb keeps them zero) and
	// contribute 0.
	.set	LO,		H_POW4
	.set	MI,		H_POW3
	.set	HI,		H_POW2
	.set	HI_XMM,		%xmm8
	.set	POWERS_PTR,	%r8

	shl		$4, NBLOCKS			// NBLOCKS = 16*n
	mov		NBLOCKS, POWERS_PTR
	neg		POWERS_PTR
	lea		OFFSETOFEND_H_POWERS(KEY,POWERS_PTR), POWERS_PTR
	mov		$-1, %r9

	// First vector (up to 4 blocks): XOR ACC into block 0 (lanes 1..3 of
	// ACC are zero) and initialize LO, MI, and HI.
	bzhi		NBLOCKS, %r9, %rax
	kmovq		%rax, %k1
	vmovdqu8	(DATA), DATA0{%k1}{z}
	vmovdqu8	(POWERS_PTR), H_POW1
.if \bswap_data
	vpshufb		BSWAP_MASK, DATA0, DATA0
.endif
	vpxord		ACC, DATA0, DATA0
	vpclmulqdq	$0x00, H_POW1, DATA0, LO
	vpclmulqdq	$0x01, H_POW1, DATA0, MI
	vpclmulqdq	$0x10, H_POW1, DATA0, TMP0
	vpxord		TMP0, MI, MI
	vpclmulqdq	$0x11, H_POW1, DATA0, HI
	sub		$64, NBLOCKS
	jle		.Lblocks_tail_reduce\@

	// Remaining vectors (1..3 iterations).
.Lblocks_tail_loop\@:
	add		$64, DATA
	add		$64, POWERS_PTR
	bzhi		NBLOCKS, %r9, %rax
	kmovq		%rax, %k1
	vmovdqu8	(DATA), DATA0{%k1}{z}
	vmovdqu8	(POWERS_PTR), H_POW1
.if \bswap_data
	vpshufb		BSWAP_MASK, DATA0, DATA0
.endif
	vpclmulqdq	$0x00, H_POW1, DATA0, TMP0
	vpclmulqdq	$0x01, H_POW1, DATA0, TMP1
	vpclmulqdq	$0x10, H_POW1, DATA0, TMP2
	vpclmulqdq	$0x11, H_POW1, DATA0, DATA1
	vpxord		TMP0, LO, LO
	vpternlogd	$0x96, TMP2, TMP1, MI
	vpxord		DATA1, HI, HI
	sub		$64, NBLOCKS
	jg		.Lblocks_tail_loop\@

.Lblocks_tail_reduce\@:
	// Reduce all 4 lanes, and XOR them together into ACC_XMM.
	_gf128hash_reduce LO, MI, HI, GFPOLY, TMP0
	_horizontal_xor	HI, HI_XMM, ACC_XMM, DATA0_XMM, DATA1_XMM, DATA2_XMM

.Lblocks_done\@:
	vmovdqu		ACC_XMM, (ACC_PTR)
	vzeroupper
	RET
.endm

SYM_FUNC_START(ghash_preparekey_vpclmul_avx512)
	_gf128hash_preparekey	1
SYM_FUNC_END(ghash_preparekey_vpclmul_avx512)
SYM_FUNC_START(polyval_preparekey_vpclmul_avx512)
	_gf128hash_preparekey	0
SYM_FUNC_END(polyval_preparekey_vpclmul_avx512)
SYM_FUNC_START(ghash_blocks_vpclmul_avx512)
	_gf128hash_blocks	1
SYM_FUNC_END(ghash_blocks_vpclmul_avx512)
SYM_FUNC_START(polyval_blocks_vpclmul_avx512)
	_gf128hash_blocks	0
SYM_FUNC_END(polyval_blocks_vpclmul_avx512)
