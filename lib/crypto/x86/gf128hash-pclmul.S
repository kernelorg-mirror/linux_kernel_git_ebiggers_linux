/* SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause */
//
// Accelerated GHASH and POLYVAL implementation with PCLMULQDQ and AVX.
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
// This file implements GHASH and POLYVAL using the PCLMULQDQ instruction on
// 128-bit vectors (xmm registers).  Two implementations are generated from the
// same macros: *_pclmul, which uses only non-VEX instructions (PCLMULQDQ, plus
// SSSE3 for pshufb, which all CPUs with PCLMULQDQ have), and *_pclmul_avx
// (USE_AVX=1), which uses the VEX-coded vpclmulqdq in some places to avoid
// movdqa instructions.  (Mixing VEX and non-VEX instructions is tolerated;
// several other crypto assembly files have only non-VEX versions, so upper
// halves of the YMM registers being clean at entry is relied on anyway.)  This
// file also documents the math that is shared with gf128hash-vpclmul-avx2.S and
// gf128hash-vpclmul-avx512.S.
//
// Mathematical background
// -----------------------
//
// GHASH (NIST SP 800-38D) and POLYVAL (RFC 8452) are both polynomial
// evaluation hashes over GF(2^128).  Given a hash key H, each 16-byte message
// block M_i updates an accumulator as acc = (acc + M_i) * H.  The two
// algorithms differ only in how they represent the field.
//
// POLYVAL maps a 16-byte block to a polynomial over GF(2) of degree < 128 using
// little-endian byte order and LSB-first bit order: bit j of byte i is the
// coefficient of x^(8i + j).  The field modulus is
//
//	G(x) = x^128 + x^127 + x^126 + x^121 + 1
//
// and POLYVAL's multiplication operation includes an extra factor of x^-128:
//
//	dot(A, B) = A * B * x^-128 mod G(x)
//
// so each block updates the accumulator as acc = dot(acc + M_i, H).  The extra
// factor makes dot() a Montgomery multiplication, whose reduction cancels the
// low half of the 256-bit product instead of the high half (see "Reduction").
//
// GHASH maps blocks to polynomials using MSB-first bit order (bit 7 of byte 0
// is the coefficient of x^0), uses the field modulus
// F(x) = x^128 + x^7 + x^2 + x + 1, and uses ordinary multiplication: acc =
// (acc + M_i) * H mod F(x).  Reversing the bytes of a GHASH block, without
// reversing the bits within each byte, gives the POLYVAL representation of the
// polynomial with reversed coefficients, A~(x) = x^127 * A(x^-1).  Since
// G(x) = x^128 * F(x^-1), it follows that A~ * B~ = x^127 * (A * B mod F(x))~
// (mod G(x)).  Hence, multiplying H~ by x to cancel the remaining x^-1:
//
//	dot(A~, x * H~) = A~ * H~ * x^-127 = (A * H mod F(x))~  (mod G(x))
//
// So GHASH is computed using the POLYVAL arithmetic by byte-reflecting the
// message blocks and replacing the key H with x * H~ mod G(x).  The accumulator
// is always kept in POLYVAL format; the C code converts it to GHASH format.
//
// Reduction
// ---------
//
// Since G(x) = x^64 * (x^64 + x^63 + x^62 + x^57) + 1, we have:
//
//	x^-64 = x^64 + x^63 + x^62 + x^57  (mod G(x))
//
// So for a 128-bit polynomial P = P_L + P_H * x^64, where P_L and P_H are its
// 64-bit halves:
//
//	P * x^-64 = P_H + P_L * x^64 + P_L * (x^63 + x^62 + x^57)  (mod G(x))
//
// That is, multiplying by x^-64 is a swap of P's halves (pshufd $0x4e) plus
// one 64 x 64 => 128-bit carryless multiplication by the constant .Lgfpoly.
// The result has degree < 128, so it is fully reduced.
//
// To compute dot(A, B), the 256-bit carryless product A * B = LO + MI * x^64 +
// HI * x^128 is computed, where LO, MI, and HI are 128-bit.  Then it is
// multiplied by x^-128 by applying the above step twice: first
// MI += LO * x^-64, then HI += MI * x^-64.  This leaves dot(A, B) in HI.
//
// Implementation notes
// --------------------
//
// - Aggregation: Multiplying the accumulator by H one block at a time would
//   make each block wait for the full multiply-and-reduce latency of the
//   previous one.  Instead, the key powers H^8, ..., H^1 are precomputed,
//   where H^k denotes repeated POLYVAL multiplication: H^1 = H and
//   H^k = dot(H^(k-1), H).  Then 8 blocks are processed at once as:
//
//	acc = dot(acc + M_0, H^8) + dot(M_1, H^7) + ... + dot(M_7, H^1)
//
//   Since the reduction is linear, the 256-bit products are summed and only the
//   sum is reduced, i.e. there is one reduction per 8 blocks.  The loop over
//   the blocks is kept rolled to reduce code size; out-of-order execution
//   overlaps the iterations.
//
// - Karatsuba multiplication: The multi-block code computes MI using Karatsuba
//   multiplication, MI = (a_L + a_H) * (b_L + b_H) + LO + HI, with each
//   (H^k_L + H^k_H) precomputed in h_powers_xored.  Compared to schoolbook
//   multiplication, this saves one pclmulqdq per block, at the cost of one
//   64-bit load, one pshufd, and 0.25 pxors per block.  This is faster on AMD
//   CPUs and on older Intel CPUs, where pclmulqdq is relatively slow, and about
//   the same on newer Intel CPUs.
//
// - The reduction uses 2 pclmulqdq instructions, i.e. 0.25 per block in the
//   8-block loop.  A reduction using only shifts and XORs would avoid these,
//   but it would need many more instructions and would likely be slower.
//
// - Single-block multiplications and preparekey: Precomputing a * x^-64 mod
//   G(x) lets dot(a, b) skip one of the two reduction steps, shortening the
//   dependency chain.  preparekey precomputes H^1 * x^-64 mod G(x) for the
//   serial computation of H^2..H^8 and stores it in key->h_times_xm64 so that
//   single-block multiplications (gf128hash_mul_pclmul{,_avx} and the
//   nblocks == 1 path) also use the 1-step reduction.

#include <linux/linkage.h>

.section .rodata
.p2align 4

	// pshufb mask that reverses the order of the bytes in a 16-byte block
.Lbswap_mask:
	.octa	0x000102030405060708090a0b0c0d0e0f

	// Mask for multiplying by x mod G(x): G(x) - x^128 = x^127 + x^126 +
	// x^121 + 1 (bits 127, 126, 121, and 0), and bit 64 for the carry from
	// bit 63 that paddq doesn't propagate
.Lgfpoly_and_internal_carrybit:
	.octa	0xc2000000000000010000000000000001

	// (G(x) - x^128 - 1) / x^64 = x^63 + x^62 + x^57, the constant used to
	// multiply by x^-64 mod G(x)
.Lgfpoly:
	.quad	0xc200000000000000

// Offsets in struct gf128hash_key_x86.  h_powers[0..7] holds H^8..H^1,
// h_powers_xored[i] holds the XOR of the two 64-bit halves of h_powers[i], and
// h_times_xm64 holds H^1 * x^-64 mod G(x).
#define OFFSETOF_H_POWERS	0
#define OFFSETOFEND_H_POWERS	128
#define OFFSETOF_H_POWERS_XORED	128
#define OFFSETOF_H_TIMES_XM64	192

.text

// Do a vpclmulqdq, or fall back to a movdqa and a pclmulqdq.  The fallback
// assumes that all operands are distinct registers.
.macro	_vpclmulqdq	imm, src1, src2, dst
.if USE_AVX
	vpclmulqdq	\imm, \src1, \src2, \dst
.else
	movdqa		\src2, \dst
	pclmulqdq	\imm, \src1, \dst
.endif
.endm

// Set \b = dot(\a, \b), given \a_times_xm64 = \a * x^-64 mod G(x).  This uses:
//
//	a * b * x^-128 = (a * b_H + (a * x^-64) * b_L) * x^-64
//		       = (MI + HI * x^64) * x^-64
//		       = HI + MI * x^-64  (mod G(x))
//
// where MI = a_L * b_H + (a * x^-64)_L * b_L and
// HI = a_H * b_H + (a * x^-64)_H * b_L.  So only one reduction step is needed,
// to fold MI into HI.  \gfpoly must contain .Lgfpoly, and \t0 and \t1 are
// temporaries.  All operands must be distinct registers.
.macro	_gf128hash_mul	a, a_times_xm64, b, gfpoly, t0, t1
	_vpclmulqdq	$0x01, \a, \b, \t0		// a_L * b_H
	_vpclmulqdq	$0x00, \a_times_xm64, \b, \t1	// (a*x^-64)_L * b_L
	pxor		\t1, \t0			// MI
	_vpclmulqdq	$0x11, \a, \b, \t1		// a_H * b_H
	pclmulqdq	$0x10, \a_times_xm64, \b	// (a*x^-64)_H * b_L
	pxor		\t1, \b				// HI
	pshufd		$0x4e, \t0, \t1			// MI_H + MI_L * x^64
	pclmulqdq	$0x00, \gfpoly, \t0		// MI_L*(x^63+x^62+x^57)
	pxor		\t1, \b				// Fold MI into HI (1)
	pxor		\t0, \b				// Fold MI into HI (2)
.endm

// Reduce the 256-bit product LO + MI * x^64 + HI * x^128 given in \lo, \mi,
// and \hi: multiply it by x^-128 mod G(x) and store the 128-bit result in \hi.
// This is done in two steps, MI += LO * x^-64 then HI += MI * x^-64.  \gfpoly
// must contain .Lgfpoly.  Clobbers \lo, \mi, and \tmp.
.macro	_gf128hash_reduce	lo, mi, hi, gfpoly, tmp
	pshufd		$0x4e, \lo, \tmp		// LO_H + LO_L * x^64
	pclmulqdq	$0x00, \gfpoly, \lo		// LO_L*(x^63+x^62+x^57)
	pxor		\tmp, \mi			// Fold LO into MI (1)
	pxor		\lo, \mi			// Fold LO into MI (2)
	pshufd		$0x4e, \mi, \tmp		// MI_H + MI_L * x^64
	pclmulqdq	$0x00, \gfpoly, \mi		// MI_L*(x^63+x^62+x^57)
	pxor		\tmp, \hi			// Fold MI into HI (1)
	pxor		\mi, \hi			// Fold MI into HI (2)
.endm

// void {ghash,polyval}_preparekey_pclmul{,_avx}(struct gf128hash_key_x86 *key,
//						 const u8 raw_key[16]);
//
// Given the raw GHASH key (\is_ghash=1) or POLYVAL key (\is_ghash=0), set
// h_powers[0..7] to H^8..H^1 in POLYVAL format, set h_powers_xored[i] to the
// XOR of the halves of h_powers[i], and set h_times_xm64 to H^1 * x^-64 mod G.
.macro	_gf128hash_preparekey	is_ghash
	.set	KEY,		%rdi
	.set	RAW_KEY,	%rsi
	.set	H_CUR,		%xmm2
	.set	H_POW1,		%xmm3
	.set	H_POW1_XM64,	%xmm4
	.set	GFPOLY,		%xmm5

	movdqu		(RAW_KEY), H_POW1
.if \is_ghash
	// Convert the GHASH key to POLYVAL format: byte-reflect it, then
	// multiply it by x mod G(x).  Multiplying by x is a left shift by 1,
	// plus an XOR of G(x) - x^128 if bit 127 was set.  paddq shifts each
	// 64-bit half separately, so the carry from bit 63 to bit 64 is added
	// back in too.  pshufd $0xd3 and psrad $31 set dwords 0 and 3 to copies
	// of bit 127 and dword 2 to copies of bit 63, and pand then selects the
	// bits to XOR in.
	pshufb		.Lbswap_mask(%rip), H_POW1
	pshufd		$0xd3, H_POW1, %xmm0
	psrad		$31, %xmm0
	paddq		H_POW1, H_POW1
	pand		.Lgfpoly_and_internal_carrybit(%rip), %xmm0
	pxor		%xmm0, H_POW1
.endif

	// Store H^1 in h_powers[7].
	movdqu		H_POW1, OFFSETOFEND_H_POWERS-16(KEY)

	// Compute H_POW1_XM64 = H^1 * x^-64 mod G(x) =
	// H_H + H_L * x^64 + H_L * (x^63 + x^62 + x^57), and store it in
	// h_times_xm64.
	movq		.Lgfpoly(%rip), GFPOLY
	pshufd		$0x4e, H_POW1, %xmm0
	_vpclmulqdq	$0x00, H_POW1, GFPOLY, H_POW1_XM64
	pxor		%xmm0, H_POW1_XM64
	movdqu		H_POW1_XM64, OFFSETOF_H_TIMES_XM64(KEY)

	// Store H^1_L ^ H^1_H in h_powers_xored[7], reusing the swapped halves
	// of H^1 in %xmm0.
	pxor		H_POW1, %xmm0
	movq		%xmm0, OFFSETOF_H_POWERS_XORED+7*8(KEY)

	// Compute H^2..H^8 and store them in h_powers[6..0], and store the XORs
	// of their halves in h_powers_xored[6..0].  %rax counts down from 6*8
	// to 0 by 8; it is the offset into h_powers_xored, and 2*%rax is the
	// offset into h_powers.
	movdqa		H_POW1, H_CUR
	mov		$6*8, %eax
.Lpreparekey_next\@:
	_gf128hash_mul	H_POW1, H_POW1_XM64, H_CUR, GFPOLY, %xmm0, %xmm1
	movdqu		H_CUR, OFFSETOF_H_POWERS(KEY,%rax,2)
	pshufd		$0x4e, H_CUR, %xmm0
	pxor		H_CUR, %xmm0
	movq		%xmm0, OFFSETOF_H_POWERS_XORED(KEY,%rax)
	sub		$8, %eax
	jge		.Lpreparekey_next\@

	RET
.endm

// void gf128hash_mul_pclmul{,_avx}(struct polyval_elem *acc,
//				    const struct gf128hash_key_x86 *key);
//
// Set *acc = dot(*acc, H^1) using the precomputed H^1 and H^1 * x^-64 in @key.
// The C code uses this to multiply the accumulator by H^1 after XOR'ing in a
// partial block.
.macro	_gf128hash_mul_func
	movdqu		(%rdi), %xmm2
	movdqu		OFFSETOFEND_H_POWERS-16(%rsi), %xmm3
	movdqu		OFFSETOF_H_TIMES_XM64(%rsi), %xmm4
	movq		.Lgfpoly(%rip), %xmm5
	_gf128hash_mul	%xmm3, %xmm4, %xmm2, %xmm5, %xmm0, %xmm1
	movdqu		%xmm2, (%rdi)
	RET
.endm

// void {ghash,polyval}_blocks_pclmul{,_avx}(struct polyval_elem *acc,
//					     const struct gf128hash_key_x86 *key,
//					     const u8 *data, size_t nblocks);
//
// Update the POLYVAL-format accumulator @acc with @nblocks >= 1 full 16-byte
// blocks from @data.  If \bswap_data=1 (GHASH), each block is byte-reflected to
// convert it to POLYVAL format.
.macro	_gf128hash_blocks	bswap_data
	.set	ACC_PTR,	%rdi
	.set	KEY,		%rsi
	.set	DATA,		%rdx
	.set	NBLOCKS,	%rcx
	.set	NBLOCKS_32,	%ecx

	.set	TMP0,		%xmm0
	.set	TMP1,		%xmm1
	.set	TMP2,		%xmm2
	.set	LO,		%xmm3
	.set	MI,		%xmm4
	.set	ACC,		%xmm5
	.set	BSWAP_MASK,	%xmm6
	.set	GFPOLY,		%xmm7

.if \bswap_data
	movdqa		.Lbswap_mask(%rip), BSWAP_MASK
.endif
	movdqu		(ACC_PTR), ACC
	movq		.Lgfpoly(%rip), GFPOLY

	// Handle nblocks == 1 specially.  This case is common (e.g. for short
	// AES-GCM associated data and for the AES-GCM lengths block), and the
	// stride loop below requires at least 2 blocks.
	cmp		$1, NBLOCKS
	je		.Lblocks_1x\@

	// Process the blocks in strides of 8, then process any remaining 2..7
	// blocks as one final stride.  For an n-block stride, let M_0 = acc +
	// data[0], M_i = data[i] for 1 <= i < n, and K_i = H^(n-i).  Compute
	// the unreduced sum of the products M_i * K_i using Karatsuba
	// multiplication:
	//
	//	LO = sum (M_i)_L * (K_i)_L
	//	HI = sum (M_i)_H * (K_i)_H
	//	MI = sum ((M_i)_L + (M_i)_H) * ((K_i)_L + (K_i)_H) + LO + HI
	//
	// HI is accumulated in ACC, and the "+ LO + HI" term of MI is added
	// just once at the end.  Then (LO, MI, HI) is reduced into ACC.
	//
	// In the loop, %rax = 8*i, so K_i is at OFFSETOF_H_POWERS(KEY,%rax,2),
	// M_i is at (DATA,%rax,2), and the XOR of the halves of K_i is at
	// (%r8,%rax).  %r9d = 8*(n-1) is the final value of %rax.  The
	// h_powers_xored entries are loaded with movq instead of being used as
	// pclmulqdq memory operands, since a memory operand would be 16 bytes:
	// without AVX it would need 16-byte alignment, and for the last entry
	// it would extend 8 bytes past the end of h_powers_xored.
	lea		OFFSETOF_H_POWERS_XORED(KEY), %r8
	mov		$7*8, %r9d
	sub		$8, NBLOCKS
	jb		.Lblocks_tail\@
.Lblocks_karatsuba\@:
	// i = 0: XOR ACC into the first block, and initialize LO, MI, and HI.
	xor		%eax, %eax
	movdqu		OFFSETOF_H_POWERS(KEY), TMP0
	movdqu		(DATA), TMP1
.if \bswap_data
	pshufb		BSWAP_MASK, TMP1
.endif
	pxor		TMP1, ACC
	pshufd		$0x4e, ACC, MI
	pxor		ACC, MI
	_vpclmulqdq	$0x00, TMP0, ACC, LO
	pclmulqdq	$0x11, TMP0, ACC
	movq		(%r8), TMP1
	pclmulqdq	$0x00, TMP1, MI

	// i = 1..n-1: accumulate into LO, MI, and HI.
1:
	add		$8, %eax
	movdqu		OFFSETOF_H_POWERS(KEY,%rax,2), TMP0
	movdqu		(DATA,%rax,2), TMP1
.if \bswap_data
	pshufb		BSWAP_MASK, TMP1
.endif
	_vpclmulqdq	$0x00, TMP0, TMP1, TMP2
	pxor		TMP2, LO
	pshufd		$0x4e, TMP1, TMP2
	pxor		TMP1, TMP2
	pclmulqdq	$0x11, TMP0, TMP1
	pxor		TMP1, ACC
	movq		(%r8,%rax), TMP1
	pclmulqdq	$0x00, TMP1, TMP2
	pxor		TMP2, MI
	cmp		%r9d, %eax
	jne		1b

	// Finish MI, then reduce (LO, MI, HI) into ACC.
	pxor		LO, MI
	pxor		ACC, MI
	_gf128hash_reduce LO, MI, ACC, GFPOLY, TMP2

	sub		$-8*16, DATA	// DATA += 128 (compact imm8)
	sub		$8, NBLOCKS
	jae		.Lblocks_karatsuba\@

.Lblocks_tail\@:
	add		$8, NBLOCKS
	jz		.Lblocks_done\@
	cmp		$1, NBLOCKS
	je		.Lblocks_1x\@

	// 2 <= n = NBLOCKS <= 7 blocks remain.  Process them as one more stride
	// that starts with K_0 = H^n = h_powers[8-n]: advance KEY by 16*(8-n)
	// and %r8 by 8*(8-n), and set %r9d = 8*(n-1).  Also set NBLOCKS = 0 so
	// that after the stride, the code above jumps here and then finishes.
	lea		-8(,NBLOCKS,8), %r9d
	mov		$8, %eax
	sub		NBLOCKS, %rax
	shl		$3, %rax
	add		%rax, %r8
	lea		(KEY,%rax,2), KEY
	xor		NBLOCKS_32, NBLOCKS_32
	jmp		.Lblocks_karatsuba\@

.Lblocks_1x\@:
	// Process one block: ACC = dot(ACC + data[0], H^1), using H^1 and
	// H^1 * x^-64 from KEY.
	movdqu		(DATA), TMP0
.if \bswap_data
	pshufb		BSWAP_MASK, TMP0
.endif
	pxor		TMP0, ACC
	movdqu		OFFSETOFEND_H_POWERS-16(KEY), LO
	movdqu		OFFSETOF_H_TIMES_XM64(KEY), MI
	_gf128hash_mul	LO, MI, ACC, GFPOLY, TMP0, TMP1

.Lblocks_done\@:
	movdqu		ACC, (ACC_PTR)
	RET
.endm

.set	USE_AVX, 0
SYM_FUNC_START(ghash_preparekey_pclmul)
	_gf128hash_preparekey	1
SYM_FUNC_END(ghash_preparekey_pclmul)
SYM_FUNC_START(polyval_preparekey_pclmul)
	_gf128hash_preparekey	0
SYM_FUNC_END(polyval_preparekey_pclmul)
SYM_FUNC_START(gf128hash_mul_pclmul)
	_gf128hash_mul_func
SYM_FUNC_END(gf128hash_mul_pclmul)
SYM_FUNC_START(ghash_blocks_pclmul)
	_gf128hash_blocks	1
SYM_FUNC_END(ghash_blocks_pclmul)
SYM_FUNC_START(polyval_blocks_pclmul)
	_gf128hash_blocks	0
SYM_FUNC_END(polyval_blocks_pclmul)

.set	USE_AVX, 1
SYM_FUNC_START(ghash_preparekey_pclmul_avx)
	_gf128hash_preparekey	1
SYM_FUNC_END(ghash_preparekey_pclmul_avx)
SYM_FUNC_START(polyval_preparekey_pclmul_avx)
	_gf128hash_preparekey	0
SYM_FUNC_END(polyval_preparekey_pclmul_avx)
SYM_FUNC_START(gf128hash_mul_pclmul_avx)
	_gf128hash_mul_func
SYM_FUNC_END(gf128hash_mul_pclmul_avx)
SYM_FUNC_START(ghash_blocks_pclmul_avx)
	_gf128hash_blocks	1
SYM_FUNC_END(ghash_blocks_pclmul_avx)
SYM_FUNC_START(polyval_blocks_pclmul_avx)
	_gf128hash_blocks	0
SYM_FUNC_END(polyval_blocks_pclmul_avx)
