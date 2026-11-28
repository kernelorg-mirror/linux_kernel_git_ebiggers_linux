/* SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause */
//
// AES-GCM implementation for x86_64 CPUs that support the following CPU
// features: VAES && VPCLMULQDQ && AVX512BW && AVX512VL && BMI2
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

#include <linux/linkage.h>

.section .rodata
.p2align 6

	// A shuffle mask that reflects the bytes of 16-byte blocks
.Lbswap_mask:
	.octa	0x000102030405060708090a0b0c0d0e0f

	// This is the GHASH reducing polynomial without its constant term, i.e.
	// x^128 + x^7 + x^2 + x, represented using the backwards mapping
	// between bits and polynomial coefficients.
	//
	// Alternatively, it can be interpreted as the naturally-ordered
	// representation of the polynomial x^127 + x^126 + x^121 + 1, i.e. the
	// "reversed" GHASH reducing polynomial without its x^128 term.
.Lgfpoly:
	.octa	0xc2000000000000000000000000000001

	// Values needed to prepare the initial vector of counter blocks.
.Lctr_pattern:
	.octa	0
	.octa	1
	.octa	2
	.octa	3

	// The number of AES blocks per vector, as a 128-bit value.
.Linc_4blocks:
	.octa	4

	// Big-endian 1, for constructing J_0 = nonce || be32(1).
.Lbe_one:
	.long	0x01000000

// Number of powers of the hash key stored in the key struct.  The powers are
// stored from highest (H^NUM_H_POWERS) to lowest (H^1).
#define NUM_H_POWERS		16

// Offset to AES key length (in bytes) in the key struct
#define OFFSETOF_AESKEYLEN	0

// Offset to AES round keys in the key struct
#define OFFSETOF_AESROUNDKEYS	16

// Offset to start of hash key powers array in the key struct
#define OFFSETOF_H_POWERS	256

// Offset to end of hash key powers array in the key struct.
//
// This is immediately followed by three zeroized padding blocks, which are
// included so that partial vectors can be handled more easily.  E.g. if two
// blocks remain, we load the 4 values [H^2, H^1, 0, 0].  The most padding
// blocks needed is 3, which occurs if [H^1, 0, 0, 0] is loaded.
#define OFFSETOFEND_H_POWERS	(OFFSETOF_H_POWERS + (NUM_H_POWERS * 16))
#define OFFSETOF_H_TIMES_XM64	(OFFSETOF_H_POWERS + 304)
#define OFFSETOF_AUTHTAG_LEN	(OFFSETOF_H_POWERS + 320)

.text

// Do one step of 1-step-reduction GHASH multiplication of \b by \a, given
// \a_times_xm64 = \a * x^-64 mod G(x), storing the result in \b.
// To complete all steps, invoke with \i=0 through \i=8.
.macro	_ghash_mul_step	i, a, a_times_xm64, b, gfpoly, t0, t1
.if \i == 0
	vpclmulqdq	$0x01, \a, \b, \t0		// a_L * b_H
.elseif \i == 1
	vpclmulqdq	$0x00, \a_times_xm64, \b, \t1	// (a*x^-64)_L * b_L
.elseif \i == 2
	vpxord		\t1, \t0, \t0			// MI
.elseif \i == 3
	vpclmulqdq	$0x11, \a, \b, \t1		// a_H * b_H
.elseif \i == 4
	vpclmulqdq	$0x10, \a_times_xm64, \b, \b	// (a*x^-64)_H * b_L
.elseif \i == 5
	vpxord		\t1, \b, \b			// HI
.elseif \i == 6
	vpshufd		$0x4e, \t0, \t1			// Swap halves of MI
.elseif \i == 7
	vpclmulqdq	$0x01, \t0, \gfpoly, \t0	// MI_L*(x^63+x^62+x^57)
.elseif \i == 8
	vpternlogd	$0x96, \t1, \t0, \b		// Fold MI into HI
.endif
.endm

// GHASH-multiply the 128-bit lanes of \a by the 128-bit lanes of \b and add the
// *unreduced* products to \lo, \mi, and \hi.
.macro	_ghash_mul_noreduce	a, b, lo, mi, hi, t0, t1, t2, t3
	vpclmulqdq	$0x00, \a, \b, \t0	// a_L * b_L
	vpclmulqdq	$0x01, \a, \b, \t1	// a_L * b_H
	vpclmulqdq	$0x10, \a, \b, \t2	// a_H * b_L
	vpclmulqdq	$0x11, \a, \b, \t3	// a_H * b_H
	vpxord		\t0, \lo, \lo
	vpternlogd	$0x96, \t2, \t1, \mi
	vpxord		\t3, \hi, \hi
.endm

// Reduce the unreduced products from \lo, \mi, and \hi and store the 128-bit
// reduced products in \hi.
.macro	_ghash_reduce	lo, mi, hi, gfpoly, t0
	vpclmulqdq	$0x01, \lo, \gfpoly, \t0
	vpshufd		$0x4e, \lo, \lo
	vpternlogd	$0x96, \t0, \lo, \mi
	vpclmulqdq	$0x01, \mi, \gfpoly, \t0
	vpshufd		$0x4e, \mi, \mi
	vpternlogd	$0x96, \t0, \mi, \hi
.endm

// XOR together the 128-bit lanes of \src (whose low lane is \src_xmm) and store
// the result in \dst_xmm.  This implicitly zeroizes the other lanes of dst.
.macro	_horizontal_xor	src, src_xmm, dst_xmm, t0_xmm, t1_xmm, t2_xmm
	vextracti32x4	$1, \src, \t0_xmm
	vextracti32x4	$2, \src, \t1_xmm
	vextracti32x4	$3, \src, \t2_xmm
	vpxord		\t0_xmm, \src_xmm, \dst_xmm
	vpternlogd	$0x96, \t1_xmm, \t2_xmm, \dst_xmm
.endm

// Do one step of the GHASH update of the data blocks given in the vector
// registers GHASHDATA[0-3].  \i specifies the step to do, 0 through 9.  The
// division into steps allows users of this macro to optionally interleave the
// computation with other instructions.  This macro uses the vector register
// GHASH_ACC as input/output; GHASHDATA[0-3] as inputs that are clobbered;
// H_POW[4-1], GFPOLY, and BSWAP_MASK as inputs that aren't clobbered; and
// GHASHTMP[0-2] as temporaries.  This macro handles the byte-reflection of the
// data blocks.  The parameter registers must be preserved across steps.
//
// The GHASH update does: GHASH_ACC = H_POW4*(GHASHDATA0 + GHASH_ACC) +
// H_POW3*GHASHDATA1 + H_POW2*GHASHDATA2 + H_POW1*GHASHDATA3, where the
// operations are vectorized operations on 512-bit vectors of 128-bit blocks.
// The vectorized terms correspond to the following non-vectorized terms:
//
//       H_POW4*(GHASHDATA0 + GHASH_ACC) => H^16*(blk0 + GHASH_ACC_XMM),
//              H^15*(blk1 + 0), H^14*(blk2 + 0), and H^13*(blk3 + 0)
//       H_POW3*GHASHDATA1 => H^12*blk4, H^11*blk5, H^10*blk6, and H^9*blk7
//       H_POW2*GHASHDATA2 => H^8*blk8,  H^7*blk9,  H^6*blk10, and H^5*blk11
//       H_POW1*GHASHDATA3 => H^4*blk12, H^3*blk13, H^2*blk14, and H^1*blk15
//
// More concretely, this code does:
//   - Do vectorized "schoolbook" multiplications to compute the intermediate
//     256-bit product of each block and its corresponding hash key power.
//   - Sum (XOR) the intermediate 256-bit products across vectors.
//   - Do a vectorized reduction of these 256-bit intermediate values to
//     128-bits each.
//   - Sum (XOR) these values and store the 128-bit result in GHASH_ACC_XMM.
.macro	_ghash_step_4x	i
.if \i == 0
	vpshufb		BSWAP_MASK, GHASHDATA0, GHASHDATA0
	vpxord		GHASH_ACC, GHASHDATA0, GHASHDATA0
	vpshufb		BSWAP_MASK, GHASHDATA1, GHASHDATA1
	vpshufb		BSWAP_MASK, GHASHDATA2, GHASHDATA2
.elseif \i == 1
	vpshufb		BSWAP_MASK, GHASHDATA3, GHASHDATA3
	vpclmulqdq	$0x00, H_POW4, GHASHDATA0, GHASH_ACC	// LO_0
	vpclmulqdq	$0x00, H_POW3, GHASHDATA1, GHASHTMP0	// LO_1
	vpclmulqdq	$0x00, H_POW2, GHASHDATA2, GHASHTMP1	// LO_2
.elseif \i == 2
	vpxord		GHASHTMP0, GHASH_ACC, GHASH_ACC		// sum(LO_{1,0})
	vpclmulqdq	$0x00, H_POW1, GHASHDATA3, GHASHTMP2	// LO_3
	vpternlogd	$0x96, GHASHTMP2, GHASHTMP1, GHASH_ACC	// LO = sum(LO_{3,2,1,0})
	vpclmulqdq	$0x01, H_POW4, GHASHDATA0, GHASHTMP0	// MI_0
.elseif \i == 3
	vpclmulqdq	$0x01, H_POW3, GHASHDATA1, GHASHTMP1	// MI_1
	vpclmulqdq	$0x01, H_POW2, GHASHDATA2, GHASHTMP2	// MI_2
	vpternlogd	$0x96, GHASHTMP2, GHASHTMP1, GHASHTMP0	// sum(MI_{2,1,0})
	vpclmulqdq	$0x01, H_POW1, GHASHDATA3, GHASHTMP1	// MI_3
.elseif \i == 4
	vpclmulqdq	$0x10, H_POW4, GHASHDATA0, GHASHTMP2	// MI_4
	vpternlogd	$0x96, GHASHTMP2, GHASHTMP1, GHASHTMP0	// sum(MI_{4,3,2,1,0})
	vpclmulqdq	$0x10, H_POW3, GHASHDATA1, GHASHTMP1	// MI_5
	vpclmulqdq	$0x10, H_POW2, GHASHDATA2, GHASHTMP2	// MI_6
.elseif \i == 5
	vpternlogd	$0x96, GHASHTMP2, GHASHTMP1, GHASHTMP0	// sum(MI_{6,5,4,3,2,1,0})
	vpclmulqdq	$0x01, GHASH_ACC, GFPOLY, GHASHTMP2	// LO_L*(x^63 + x^62 + x^57)
	vpclmulqdq	$0x10, H_POW1, GHASHDATA3, GHASHTMP1	// MI_7
	vpxord		GHASHTMP1, GHASHTMP0, GHASHTMP0		// MI = sum(MI_{7,6,5,4,3,2,1,0})
.elseif \i == 6
	vpshufd		$0x4e, GHASH_ACC, GHASH_ACC		// Swap halves of LO
	vpclmulqdq	$0x11, H_POW4, GHASHDATA0, GHASHDATA0	// HI_0
	vpclmulqdq	$0x11, H_POW3, GHASHDATA1, GHASHDATA1	// HI_1
	vpclmulqdq	$0x11, H_POW2, GHASHDATA2, GHASHDATA2	// HI_2
.elseif \i == 7
	vpternlogd	$0x96, GHASHTMP2, GHASH_ACC, GHASHTMP0	// Fold LO into MI
	vpclmulqdq	$0x11, H_POW1, GHASHDATA3, GHASHDATA3	// HI_3
	vpternlogd	$0x96, GHASHDATA2, GHASHDATA1, GHASHDATA0 // sum(HI_{2,1,0})
	vpclmulqdq	$0x01, GHASHTMP0, GFPOLY, GHASHTMP1	// MI_L*(x^63 + x^62 + x^57)
.elseif \i == 8
	vpxord		GHASHDATA3, GHASHDATA0, GHASH_ACC	// HI = sum(HI_{3,2,1,0})
	vpshufd		$0x4e, GHASHTMP0, GHASHTMP0		// Swap halves of MI
	vpternlogd	$0x96, GHASHTMP1, GHASHTMP0, GHASH_ACC	// Fold MI into HI
.elseif \i == 9
	_horizontal_xor	GHASH_ACC, GHASH_ACC_XMM, GHASH_ACC_XMM, \
			GHASHDATA0_XMM, GHASHDATA1_XMM, GHASHDATA2_XMM
.endif
.endm

// Update GHASH with four vectors of data blocks.  See _ghash_step_4x for full
// explanation.
.macro	_ghash_4x
.irp i, 0,1,2,3,4,5,6,7,8,9
	_ghash_step_4x	\i
.endr
.endm

// Do one non-last round of AES encryption on the blocks in %zmm[0-3] using the
// round key that has been broadcast to all 128-bit lanes of \round_key.
.macro	_vaesenc_4x	round_key
	vaesenc		\round_key, %zmm0, %zmm0
	vaesenc		\round_key, %zmm1, %zmm1
	vaesenc		\round_key, %zmm2, %zmm2
	vaesenc		\round_key, %zmm3, %zmm3
.endm

// Start the AES encryption of four vectors of counter blocks.
.macro	_ctr_begin_4x

	// Increment LE_CTR four times to generate four vectors of little-endian
	// counter blocks, swap each to big-endian, and store them in %zmm[0-3].
	vpshufb		BSWAP_MASK, LE_CTR, %zmm0
	vpaddd		LE_CTR_INC, LE_CTR, LE_CTR
	vpshufb		BSWAP_MASK, LE_CTR, %zmm1
	vpaddd		LE_CTR_INC, LE_CTR, LE_CTR
	vpshufb		BSWAP_MASK, LE_CTR, %zmm2
	vpaddd		LE_CTR_INC, LE_CTR, LE_CTR
	vpshufb		BSWAP_MASK, LE_CTR, %zmm3
	vpaddd		LE_CTR_INC, LE_CTR, LE_CTR

	// AES "round zero": XOR in the zero-th round key.
	vpxord		RNDKEY0, %zmm0, %zmm0
	vpxord		RNDKEY0, %zmm1, %zmm1
	vpxord		RNDKEY0, %zmm2, %zmm2
	vpxord		RNDKEY0, %zmm3, %zmm3
.endm

// Do the last AES round for four vectors of counter blocks %zmm[0-3], XOR
// source data with the resulting keystream, and write the result to DST and
// GHASHDATA[0-3].  (Implementation differs slightly, but has the same effect.)
.macro	_aesenclast_and_xor_4x
	// XOR the source data with the last round key, saving the result in
	// GHASHDATA[0-3].  This reduces latency by taking advantage of the
	// property vaesenclast(key, a) ^ b == vaesenclast(key ^ b, a).
	vpxord		0*64(SRC), RNDKEYLAST, GHASHDATA0
	vpxord		1*64(SRC), RNDKEYLAST, GHASHDATA1
	vpxord		2*64(SRC), RNDKEYLAST, GHASHDATA2
	vpxord		3*64(SRC), RNDKEYLAST, GHASHDATA3

	// Do the last AES round.  This handles the XOR with the source data
	// too, as per the optimization described above.
	vaesenclast	GHASHDATA0, %zmm0, GHASHDATA0
	vaesenclast	GHASHDATA1, %zmm1, GHASHDATA1
	vaesenclast	GHASHDATA2, %zmm2, GHASHDATA2
	vaesenclast	GHASHDATA3, %zmm3, GHASHDATA3

	// Store the en/decrypted data to DST.
	vmovdqu8	GHASHDATA0, 0*64(DST)
	vmovdqu8	GHASHDATA1, 1*64(DST)
	vmovdqu8	GHASHDATA2, 2*64(DST)
	vmovdqu8	GHASHDATA3, 3*64(DST)
.endm

// void aes_gcm_aad_1block_vaes_avx512(const struct aes_gcm_key *key,
//				       struct polyval_elem *ghash_acc,
//				       const u8 *aad, size_t aadlen);
//
// Load 1 <= @aadlen <= 16 bytes from @aad, zero-pad to 16 bytes, byte-reflect,
// multiply by H^1 in the POLYVAL field using 1-step reduction, and store the
// result in @ghash_acc.
SYM_FUNC_START(aes_gcm_aad_1block_vaes_avx512)
	mov		$-1, %eax
	bzhi		%ecx, %eax, %eax
	kmovd		%eax, %k1
	vmovdqu8	(%rdx), %xmm0{%k1}{z}
	vpshufb		.Lbswap_mask(%rip), %xmm0, %xmm0
	vmovdqu8	OFFSETOFEND_H_POWERS-16(%rdi), %xmm1
	vmovdqu8	OFFSETOF_H_TIMES_XM64(%rdi), %xmm2
	vmovdqa		.Lgfpoly(%rip), %xmm3
.irp i, 0,1,2,3,4,5,6,7,8
	_ghash_mul_step	\i, %xmm1, %xmm2, %xmm0, %xmm3, %xmm4, %xmm5
.endr
	vmovdqu		%xmm0, (%rsi)
	// No need for vzeroupper here, since only xmm registers were used.
	RET
SYM_FUNC_END(aes_gcm_aad_1block_vaes_avx512)

// void aes_gcm_{enc,dec}_update_vaes_avx512(u8 *dst, const u8 *src,
//					     size_t datalen,
//					     struct polyval_elem *ghash_acc,
//					     const __be32 ctr32[4],
//					     const struct aes_gcm_key *key);
//
// This macro generates a GCM encryption or decryption update function with the
// above prototype (with \enc selecting which one).  The function computes the
// next portion of the CTR keystream, XOR's it with |datalen| bytes from |src|,
// and writes the resulting encrypted or decrypted data to |dst|.  It also
// updates the GHASH accumulator |ghash_acc| using the next |datalen| ciphertext
// bytes.
//
// |datalen| must be a multiple of 16, except on the last call where it can be
// any length.  The caller must do any buffering needed to ensure this.  Both
// in-place and out-of-place en/decryption are supported.
//
// |ctr32| must give the current counter in big-endian format.  This function
// loads the counter from |ctr32| and increments the loaded counter as needed,
// but it does *not* store the updated counter back to |ctr32|.  The caller must
// update |ctr32| if any more data segments follow.  Internally, only the low
// 32-bit word of the counter is incremented, following the GCM standard.
.macro	_aes_gcm_update	enc

	// Function arguments
	.set	DST,		%rdi
	.set	SRC,		%rsi
	.set	DATALEN,	%rdx
	.set	DATALEN32,	%edx
	.set	GHASH_ACC_PTR,	%rcx
	.set	BE_CTR_PTR,	%r8
	.set	KEY,		%r9

	// Additional local variables.
	// %rax and %k1 are used as temporary registers.

	// AES key length in bytes
	.set	AESKEYLEN,	%r10d
	.set	AESKEYLEN64,	%r10

	// Pointer to the last AES round key for the chosen AES variant
	.set	RNDKEYLAST_PTR,	%r11

	// In the main loop, %zmm[0-3] are used as AES input and output.
	// Elsewhere they are used as temporary registers.

	// GHASHDATA[0-3] hold the ciphertext blocks and GHASH input data.
	.set	GHASHDATA0,	%zmm4
	.set	GHASHDATA0_XMM,	%xmm4
	.set	GHASHDATA1,	%zmm5
	.set	GHASHDATA1_XMM,	%xmm5
	.set	GHASHDATA2,	%zmm6
	.set	GHASHDATA2_XMM,	%xmm6
	.set	GHASHDATA3,	%zmm7

	// BSWAP_MASK is the shuffle mask for byte-reflecting 128-bit values
	// using vpshufb, copied to all 128-bit lanes.
	.set	BSWAP_MASK,	%zmm8

	// RNDKEY temporarily holds the next AES round key.
	.set	RNDKEY,		%zmm9

	// GHASH_ACC is the accumulator variable for GHASH.  When fully reduced,
	// only the lowest 128-bit lane can be nonzero.  When not fully reduced,
	// more than one lane may be used, and they need to be XOR'd together.
	.set	GHASH_ACC,	%zmm10
	.set	GHASH_ACC_XMM,	%xmm10

	// LE_CTR_INC is the vector of 32-bit words that need to be added to a
	// vector of little-endian counter blocks to advance it forwards.
	.set	LE_CTR_INC,	%zmm11

	// LE_CTR contains the next set of little-endian counter blocks.
	.set	LE_CTR,		%zmm12

	// RNDKEY0, RNDKEYLAST, and RNDKEY_M[9-1] contain cached AES round keys,
	// copied to all 128-bit lanes.  RNDKEY0 is the zero-th round key,
	// RNDKEYLAST the last, and RNDKEY_M\i the one \i-th from the last.
	.set	RNDKEY0,	%zmm13
	.set	RNDKEYLAST,	%zmm14
	.set	RNDKEY_M9,	%zmm15
	.set	RNDKEY_M8,	%zmm16
	.set	RNDKEY_M7,	%zmm17
	.set	RNDKEY_M6,	%zmm18
	.set	RNDKEY_M5,	%zmm19
	.set	RNDKEY_M4,	%zmm20
	.set	RNDKEY_M3,	%zmm21
	.set	RNDKEY_M2,	%zmm22
	.set	RNDKEY_M1,	%zmm23

	// GHASHTMP[0-2] are temporary variables used by _ghash_step_4x.  These
	// cannot coincide with anything used for AES encryption, since for
	// performance reasons GHASH and AES encryption are interleaved.
	.set	GHASHTMP0,	%zmm24
	.set	GHASHTMP1,	%zmm25
	.set	GHASHTMP2,	%zmm26

	// H_POW[4-1] contain the powers of the hash key H^16...H^1.  The
	// descending numbering reflects the order of the key powers.
	.set	H_POW4,		%zmm27
	.set	H_POW3,		%zmm28
	.set	H_POW2,		%zmm29
	.set	H_POW1,		%zmm30

	// GFPOLY contains the .Lgfpoly constant, copied to all 128-bit lanes.
	.set	GFPOLY,		%zmm31

	// Load some constants.
	vbroadcasti32x4	.Lbswap_mask(%rip), BSWAP_MASK
	vbroadcasti32x4	.Lgfpoly(%rip), GFPOLY

	// Load the GHASH accumulator and the starting counter.
	vmovdqu		(GHASH_ACC_PTR), GHASH_ACC_XMM
	vbroadcasti32x4	(BE_CTR_PTR), LE_CTR
	vpshufb		BSWAP_MASK, LE_CTR, LE_CTR

	// Load the AES key length in bytes.
	movl		OFFSETOF_AESKEYLEN(KEY), AESKEYLEN

	// Make RNDKEYLAST_PTR point to the last AES round key.  This is the
	// round key with index 10, 12, or 14 for AES-128, AES-192, or AES-256
	// respectively.  Then load the zero-th and last round keys.
	lea		OFFSETOF_AESROUNDKEYS+6*16(KEY,AESKEYLEN64,4), RNDKEYLAST_PTR
	vbroadcasti32x4	OFFSETOF_AESROUNDKEYS(KEY), RNDKEY0
	vbroadcasti32x4	(RNDKEYLAST_PTR), RNDKEYLAST

	// Finish initializing LE_CTR by adding [0, 1, ...] to its low words.
	vpaddd		.Lctr_pattern(%rip), LE_CTR, LE_CTR

	// Load 4 into all 128-bit lanes of LE_CTR_INC.
	vbroadcasti32x4	.Linc_4blocks(%rip), LE_CTR_INC

	// If there are at least 256 bytes of data, then continue into the loop
	// that processes 256 bytes of data at a time.  Otherwise skip it.
	//
	// Pre-subtracting 256 from DATALEN saves an instruction from the main
	// loop.
	sub		$256, DATALEN
	jl		.Lcrypt_loop_4x_done\@

	// Load powers of the hash key.
	vmovdqu8	OFFSETOFEND_H_POWERS-4*64(KEY), H_POW4
	vmovdqu8	OFFSETOFEND_H_POWERS-3*64(KEY), H_POW3
	vmovdqu8	OFFSETOFEND_H_POWERS-2*64(KEY), H_POW2
	vmovdqu8	OFFSETOFEND_H_POWERS-1*64(KEY), H_POW1

	// Main loop: en/decrypt and hash 4 vectors at a time.
	//
	// When possible, interleave the AES encryption of the counter blocks
	// with the GHASH update of the ciphertext blocks.  This improves
	// performance on many CPUs because the execution ports used by the VAES
	// instructions often differ from those used by vpclmulqdq and other
	// instructions used in GHASH.  For example, many Intel CPUs dispatch
	// vaesenc to ports 0 and 1 and vpclmulqdq to port 5.
	//
	// The interleaving is easiest to do during decryption, since during
	// decryption the ciphertext blocks are immediately available.  For
	// encryption, instead encrypt the first set of blocks, then hash those
	// blocks while encrypting the next set of blocks, repeat that as
	// needed, and finally hash the last set of blocks.

.if \enc
	// Encrypt the first 4 vectors of plaintext blocks.  Leave the resulting
	// ciphertext in GHASHDATA[0-3] for GHASH.
	_ctr_begin_4x
	lea		OFFSETOF_AESROUNDKEYS+16(KEY), %rax
1:
	vbroadcasti32x4	(%rax), RNDKEY
	_vaesenc_4x	RNDKEY
	add		$16, %rax
	cmp		%rax, RNDKEYLAST_PTR
	jne		1b
	_aesenclast_and_xor_4x
	add		$256, SRC
	add		$256, DST
	sub		$256, DATALEN
	jl		.Lghash_last_ciphertext_4x\@
.endif

	// Cache as many additional AES round keys as possible.
.irp i, 9,8,7,6,5,4,3,2,1
	vbroadcasti32x4	-\i*16(RNDKEYLAST_PTR), RNDKEY_M\i
.endr

.Lcrypt_loop_4x\@:

	// If decrypting, load more ciphertext blocks into GHASHDATA[0-3].  If
	// encrypting, GHASHDATA[0-3] already contain the previous ciphertext.
.if !\enc
	vmovdqu8	0*64(SRC), GHASHDATA0
	vmovdqu8	1*64(SRC), GHASHDATA1
	vmovdqu8	2*64(SRC), GHASHDATA2
	vmovdqu8	3*64(SRC), GHASHDATA3
.endif

	// Start the AES encryption of the counter blocks.
	_ctr_begin_4x
	cmp		$24, AESKEYLEN
	jl		128f	// AES-128?
	je		192f	// AES-192?
	// AES-256
	vbroadcasti32x4	-13*16(RNDKEYLAST_PTR), RNDKEY
	_vaesenc_4x	RNDKEY
	vbroadcasti32x4	-12*16(RNDKEYLAST_PTR), RNDKEY
	_vaesenc_4x	RNDKEY
192:
	vbroadcasti32x4	-11*16(RNDKEYLAST_PTR), RNDKEY
	_vaesenc_4x	RNDKEY
	vbroadcasti32x4	-10*16(RNDKEYLAST_PTR), RNDKEY
	_vaesenc_4x	RNDKEY
128:

	// Finish the AES encryption of the counter blocks in %zmm[0-3],
	// interleaved with the GHASH update of the ciphertext blocks in
	// GHASHDATA[0-3].
.irp i, 9,8,7,6,5,4,3,2,1
	_ghash_step_4x  (9 - \i)
	_vaesenc_4x	RNDKEY_M\i
.endr
	_ghash_step_4x	9
	_aesenclast_and_xor_4x
	add		$256, SRC
	add		$256, DST
	sub		$256, DATALEN
	jge		.Lcrypt_loop_4x\@

.if \enc
.Lghash_last_ciphertext_4x\@:
	// Update GHASH with the last set of ciphertext blocks.
	_ghash_4x
.endif

.Lcrypt_loop_4x_done\@:

	// Undo the extra subtraction by 256 and check whether data remains.
	add		$256, DATALEN
	jz		.Ldone\@

	// The data length isn't a multiple of 256 bytes.  Process the remaining
	// data of length 1 <= DATALEN < 256, up to one 64-byte vector at a
	// time.  Going one vector at a time may seem inefficient compared to
	// having separate code paths for each possible number of vectors
	// remaining.  However, using a loop keeps the code size down, and it
	// performs surprising well; modern CPUs will start executing the next
	// iteration before the previous one finishes and also predict the
	// number of loop iterations.  For a similar reason, we roll up the AES
	// rounds.
	//
	// On the last iteration, the remaining length may be less than 64
	// bytes.  Handle this using masking.
	//
	// Since there are enough key powers available for all remaining data,
	// there is no need to do a GHASH reduction after each iteration.
	// Instead, multiply each remaining block by its own key power, and only
	// do a GHASH reduction at the very end.

	// Make POWERS_PTR point to the key powers [H^N, H^(N-1), ...] where N
	// is the number of blocks that remain.
	.set		POWERS_PTR, BE_CTR_PTR	// BE_CTR_PTR is free to be reused.
	mov		DATALEN32, %eax
	neg		%rax
	and		$~15, %rax  // -round_up(DATALEN, 16)
	lea		OFFSETOFEND_H_POWERS(KEY,%rax), POWERS_PTR

	// Start collecting the unreduced GHASH intermediate value LO, MI, HI.
	.set		LO, GHASHDATA0
	.set		LO_XMM, GHASHDATA0_XMM
	.set		MI, GHASHDATA1
	.set		MI_XMM, GHASHDATA1_XMM
	.set		HI, GHASHDATA2
	.set		HI_XMM, GHASHDATA2_XMM
	vpxor		LO_XMM, LO_XMM, LO_XMM
	vpxor		MI_XMM, MI_XMM, MI_XMM
	vpxor		HI_XMM, HI_XMM, HI_XMM

.Lcrypt_loop_1x\@:

	// Select the appropriate mask for this iteration: all 1's if
	// DATALEN >= 64, otherwise DATALEN 1's.  Do this branchlessly using the
	// bzhi instruction from BMI2.  (This relies on DATALEN <= 255.)
	mov		$-1, %rax
	bzhi		DATALEN, %rax, %rax
	kmovq		%rax, %k1

	// Encrypt a vector of counter blocks.  This does not need to be masked.
	vpshufb		BSWAP_MASK, LE_CTR, %zmm0
	vpaddd		LE_CTR_INC, LE_CTR, LE_CTR
	vpxord		RNDKEY0, %zmm0, %zmm0
	lea		OFFSETOF_AESROUNDKEYS+16(KEY), %rax
1:
	vbroadcasti32x4	(%rax), RNDKEY
	vaesenc		RNDKEY, %zmm0, %zmm0
	add		$16, %rax
	cmp		%rax, RNDKEYLAST_PTR
	jne		1b
	vaesenclast	RNDKEYLAST, %zmm0, %zmm0

	// XOR the data with the appropriate number of keystream bytes.
	vmovdqu8	(SRC), %zmm1{%k1}{z}
	vpxord		%zmm1, %zmm0, %zmm0
	vmovdqu8	%zmm0, (DST){%k1}

	// Update GHASH with the ciphertext block(s), without reducing.
	//
	// In the case of DATALEN < 64, the ciphertext is zero-padded to 64
	// bytes.  (If decrypting, it's done by the above masked load.  If
	// encrypting, it's done by the below masked register-to-register move.)
	// Note that if DATALEN <= 48, there will be additional padding beyond
	// the padding of the last block specified by GHASH itself; i.e., there
	// may be whole block(s) that get processed by the GHASH multiplication
	// and reduction instructions but should not actually be included in the
	// GHASH.  However, any such blocks are all-zeroes, and the values that
	// they're multiplied with are also all-zeroes.  Therefore they just add
	// 0 * 0 = 0 to the final GHASH result, which makes no difference.
	vmovdqu8	(POWERS_PTR), H_POW1
.if \enc
	vmovdqu8	%zmm0, %zmm1{%k1}{z}
.endif
	vpshufb		BSWAP_MASK, %zmm1, %zmm0
	vpxord		GHASH_ACC, %zmm0, %zmm0
	_ghash_mul_noreduce	H_POW1, %zmm0, LO, MI, HI, \
				GHASHDATA3, %zmm1, %zmm2, %zmm3
	vpxor		GHASH_ACC_XMM, GHASH_ACC_XMM, GHASH_ACC_XMM

	add		$64, POWERS_PTR
	add		$64, SRC
	add		$64, DST
	sub		$64, DATALEN
	jg		.Lcrypt_loop_1x\@

	// Finally, do the GHASH reduction.
	_ghash_reduce	LO, MI, HI, GFPOLY, %zmm0
	_horizontal_xor	HI, HI_XMM, GHASH_ACC_XMM, %xmm0, %xmm1, %xmm2

.Ldone\@:
	// Store the updated GHASH accumulator back to memory.
	vmovdqu		GHASH_ACC_XMM, (GHASH_ACC_PTR)

	vzeroupper	// This is needed after using ymm or zmm registers.
	RET
.endm

// void aes_gcm_enc_final_vaes_avx512(const struct aes_gcm_key *key,
//				      const struct polyval_elem *ghash_acc,
//				      const u8 nonce[12], u64 ad_len,
//				      u64 data_len, u8 *authtag);
// bool aes_gcm_dec_final_vaes_avx512(const struct aes_gcm_key *key,
//				      const struct polyval_elem *ghash_acc,
//				      const u8 nonce[12], u64 ad_len,
//				      u64 data_len, const u8 *authtag);
//
// Finish computing the GCM authentication tag by updating @ghash_acc with the
// lengths block (ad_len * 8 || data_len * 8), multiplying by H^1 (interleaved
// with AES encryption of J_0 = nonce || be32(1)), converting to GHASH byte
// order, and XOR'ing with AES(key, J_0).
//
// When \enc=1, stores key->authtag_len bytes of the computed tag to @authtag.
// When \enc=0, compares key->authtag_len bytes of the computed tag with
// @authtag in constant time and returns true iff they match.
.macro	_aes_gcm_final	enc
	// Function arguments
	.set	KEY,		%rdi
	.set	GHASH_ACC_PTR,	%rsi
	.set	NONCE,		%rdx
	.set	AD_LEN,		%rcx
	.set	DATA_LEN,	%r8
	.set	TAG,		%r9

	// Additional local variables (%rax is RNDKEYLAST_PTR, %k1 is tag mask)
	.set	AESKEYLEN,	%r10d
	.set	AESKEYLEN64,	%r10
	.set	TAGLEN,		%r11d
	.set	GFPOLY,		%xmm3
	.set	BSWAP_MASK,	%xmm4
	.set	GHASH_ACC,	%xmm5
	.set	H_POW1,		%xmm6
	.set	H_POW1_XM64,	%xmm7

	vmovdqa		.Lgfpoly(%rip), GFPOLY
	vmovdqa		.Lbswap_mask(%rip), BSWAP_MASK
	movl		OFFSETOF_AESKEYLEN(KEY), AESKEYLEN
	movl		OFFSETOF_AUTHTAG_LEN(KEY), TAGLEN

	// Prepare a mask of TAGLEN one bits.
	mov		$-1, %eax
	bzhi		TAGLEN, %eax, %eax
	kmovd		%eax, %k1

.if !\enc
	// Load the transmitted auth tag early so its latency is hidden by AES.
	vmovdqu8	(TAG), %xmm8{%k1}{z}
.endif

	// Build J_0 = nonce || be32(1) directly from NONCE to avoid a
	// store-to-load forwarding stall.
	vmovq		(NONCE), %xmm0
	vpinsrd		$2, 8(NONCE), %xmm0, %xmm0
	vpinsrd		$3, .Lbe_one(%rip), %xmm0, %xmm0

	// Build the lengths block in POLYVAL format and XOR it into GHASH_ACC.
	vmovq		DATA_LEN, GHASH_ACC
	vpinsrq		$1, AD_LEN, GHASH_ACC, GHASH_ACC
	vpsllq		$3, GHASH_ACC, GHASH_ACC	// Bytes to bits
	vpxord		(GHASH_ACC_PTR), GHASH_ACC, GHASH_ACC

	vmovdqu8	OFFSETOFEND_H_POWERS-16(KEY), H_POW1
	vmovdqu8	OFFSETOF_H_TIMES_XM64(KEY), H_POW1_XM64

	// Make %rax point to the last AES round key.
	lea		OFFSETOF_AESROUNDKEYS+6*16(KEY,AESKEYLEN64,4), %rax

	// Start AES encryption of J_0.
	vpxord		OFFSETOF_AESROUNDKEYS(KEY), %xmm0, %xmm0

	cmp		$24, AESKEYLEN
	jl		128f	// AES-128?
	je		192f	// AES-192?
	// AES-256
	vaesenc		-13*16(%rax), %xmm0, %xmm0
	vaesenc		-12*16(%rax), %xmm0, %xmm0
192:
	vaesenc		-11*16(%rax), %xmm0, %xmm0
	vaesenc		-10*16(%rax), %xmm0, %xmm0
128:
	// Interleave the remaining AES rounds with multiplying GHASH_ACC by H^1.
.irp i, 0,1,2,3,4,5,6,7,8
	_ghash_mul_step	\i, H_POW1, H_POW1_XM64, GHASH_ACC, GFPOLY, %xmm1, %xmm2
	vaesenc		(\i-9)*16(%rax), %xmm0, %xmm0
.endr

	// Undo the byte reflection of the GHASH accumulator.
	vpshufb		BSWAP_MASK, GHASH_ACC, GHASH_ACC

	// Do the last AES round and XOR with GHASH_ACC (and transmitted tag if
	// decrypting), using vaesenclast(key ^ b, a) == vaesenclast(key, a) ^ b
	// to take the XOR(s) off the critical path.
.if \enc
	vpxord		(%rax), GHASH_ACC, %xmm1
	vaesenclast	%xmm1, %xmm0, %xmm0
	vmovdqu8	%xmm0, (TAG){%k1}
.else
	vpternlogd	$0x96, (%rax), GHASH_ACC, %xmm8
	vaesenclast	%xmm8, %xmm0, %xmm0
	xor		%eax, %eax
	vmovdqu8	%xmm0, %xmm0{%k1}{z}	// Truncate to TAGLEN bytes
	vptest		%xmm0, %xmm0
	sete		%al
.endif
	// No need for vzeroupper here, since only xmm registers were used.
	RET
.endm

SYM_FUNC_START(aes_gcm_enc_update_vaes_avx512)
	_aes_gcm_update	1
SYM_FUNC_END(aes_gcm_enc_update_vaes_avx512)
SYM_FUNC_START(aes_gcm_dec_update_vaes_avx512)
	_aes_gcm_update	0
SYM_FUNC_END(aes_gcm_dec_update_vaes_avx512)

SYM_FUNC_START(aes_gcm_enc_final_vaes_avx512)
	_aes_gcm_final	1
SYM_FUNC_END(aes_gcm_enc_final_vaes_avx512)
SYM_FUNC_START(aes_gcm_dec_final_vaes_avx512)
	_aes_gcm_final	0
SYM_FUNC_END(aes_gcm_dec_final_vaes_avx512)
