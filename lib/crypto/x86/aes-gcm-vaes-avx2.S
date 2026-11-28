/* SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause */
//
// AES-GCM implementation for x86_64 CPUs that support the following CPU
// features: VAES && VPCLMULQDQ && AVX2
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
// -----------------------------------------------------------------------------
//
// This is similar to aes-gcm-vaes-avx512.S, but it uses AVX2 instead of AVX512.
// This means it can only use 16 vector registers instead of 32, the maximum
// vector length is 32 bytes, and some instructions such as vpternlogd and
// masked loads/stores are unavailable.  However, it is able to run on CPUs that
// have VAES without AVX512, namely AMD Zen 3 (including "Milan" server CPUs),
// various Intel client CPUs such as Alder Lake, and Intel Sierra Forest.
//
// This implementation also uses Karatsuba multiplication instead of schoolbook
// multiplication for GHASH in its main loop.  This does not help much on Intel,
// but it improves performance by ~5% on AMD Zen 3.  Other factors weighing
// slightly in favor of Karatsuba multiplication in this implementation are the
// lower maximum vector length (which means there are fewer key powers, so we
// can cache the halves of each key power XOR'd together and still use less
// memory than the AVX512 implementation), and the unavailability of the
// vpternlogd instruction (which helped schoolbook a bit more than Karatsuba).

#include <linux/linkage.h>

.section .rodata
.p2align 4

	// The below three 16-byte values must be in the order that they are, as
	// they are really two 32-byte tables and a 16-byte value that overlap:
	//
	// - The first 32-byte table begins at .Lselect_high_bytes_table.
	//   For 0 <= len <= 16, the 16-byte value at
	//   '.Lselect_high_bytes_table + len' selects the high 'len' bytes of
	//   another 16-byte value when AND'ed with it.
	//
	// - The second 32-byte table begins at .Lrshift_and_bswap_table.
	//   For 0 <= len <= 16, the 16-byte value at
	//   '.Lrshift_and_bswap_table + len' is a vpshufb mask that does the
	//   following operation: right-shift by '16 - len' bytes (shifting in
	//   zeroes), then reflect all 16 bytes.
	//
	// - The 16-byte value at .Lbswap_mask is a vpshufb mask that reflects
	//   all 16 bytes.
.Lselect_high_bytes_table:
	.octa	0
.Lrshift_and_bswap_table:
	.octa	0xffffffffffffffffffffffffffffffff
.Lbswap_mask:
	.octa	0x000102030405060708090a0b0c0d0e0f

	// Sixteen 0x0f bytes.  By XOR'ing an entry of .Lrshift_and_bswap_table
	// with this, we get a mask that left-shifts by '16 - len' bytes.
.Lfifteens:
	.octa	0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f

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

	// The number of AES blocks per vector, as a 128-bit value.
.Linc_2blocks:
	.octa	2

// Offsets in struct aes_gcm_key
#define OFFSETOF_AESKEYLEN	0
#define OFFSETOF_AESROUNDKEYS	16
#define OFFSETOF_H_POWERS_XORED	(256 + 0)
#define OFFSETOF_H_POWERS	(256 + 128)
#define NUM_H_POWERS		8
#define OFFSETOFEND_H_POWERS	(OFFSETOF_H_POWERS + (NUM_H_POWERS * 16))

.text

// GHASH-multiply the 128-bit lanes of \a by the 128-bit lanes of \b and add the
// *unreduced* products to \lo, \mi, and \hi.
.macro	_ghash_mul_noreduce	a, b, lo, mi, hi, t0
	vpclmulqdq	$0x00, \a, \b, \t0	// a_L * b_L
	vpxor		\t0, \lo, \lo
	vpclmulqdq	$0x01, \a, \b, \t0	// a_L * b_H
	vpxor		\t0, \mi, \mi
	vpclmulqdq	$0x10, \a, \b, \t0	// a_H * b_L
	vpxor		\t0, \mi, \mi
	vpclmulqdq	$0x11, \a, \b, \t0	// a_H * b_H
	vpxor		\t0, \hi, \hi
.endm

// Reduce the unreduced products from \lo, \mi, and \hi and store the 128-bit
// reduced products in \hi.
.macro	_ghash_reduce	lo, mi, hi, gfpoly, t0
	vpclmulqdq	$0x01, \lo, \gfpoly, \t0
	vpshufd		$0x4e, \lo, \lo
	vpxor		\lo, \mi, \mi
	vpxor		\t0, \mi, \mi
	vpclmulqdq	$0x01, \mi, \gfpoly, \t0
	vpshufd		$0x4e, \mi, \mi
	vpxor		\mi, \hi, \hi
	vpxor		\t0, \hi, \hi
.endm

// Do one step of the GHASH update of four vectors of data blocks.
//   \i: the step to do, 0 through 9
//   \ghashdata_ptr: pointer to the data blocks (ciphertext)
//   KEY: pointer to struct aes_gcm_key
//   BSWAP_MASK: mask for reflecting the bytes of blocks
//   H_POW[2-1]_XORED: cached values from KEY->ghash.k.h_powers_xored
//   TMP[0-2]: temporary registers.  TMP[1-2] must be preserved across steps.
//   LO, MI: working state for this macro that must be preserved across steps
//   GHASH_ACC: the GHASH accumulator (input/output)
.macro	_ghash_step_4x	i, ghashdata_ptr
	.set		HI, GHASH_ACC # alias
	.set		HI_XMM, GHASH_ACC_XMM
.if \i == 0
	// First vector
	vmovdqu		0*32(\ghashdata_ptr), TMP1
	vpshufb		BSWAP_MASK, TMP1, TMP1
	vmovdqu		OFFSETOF_H_POWERS+0*32(KEY), TMP2
	vpxor		GHASH_ACC, TMP1, TMP1
	vpclmulqdq	$0x00, TMP2, TMP1, LO
	vpclmulqdq	$0x11, TMP2, TMP1, HI
	vpunpckhqdq	TMP1, TMP1, TMP0
	vpxor		TMP1, TMP0, TMP0
	vpclmulqdq	$0x00, H_POW2_XORED, TMP0, MI
.elseif \i == 1
.elseif \i == 2
	// Second vector
	vmovdqu		1*32(\ghashdata_ptr), TMP1
	vpshufb		BSWAP_MASK, TMP1, TMP1
	vmovdqu		OFFSETOF_H_POWERS+1*32(KEY), TMP2
	vpclmulqdq	$0x00, TMP2, TMP1, TMP0
	vpxor		TMP0, LO, LO
	vpclmulqdq	$0x11, TMP2, TMP1, TMP0
	vpxor		TMP0, HI, HI
	vpunpckhqdq	TMP1, TMP1, TMP0
	vpxor		TMP1, TMP0, TMP0
	vpclmulqdq	$0x10, H_POW2_XORED, TMP0, TMP0
	vpxor		TMP0, MI, MI
.elseif \i == 3
	// Third vector
	vmovdqu		2*32(\ghashdata_ptr), TMP1
	vpshufb		BSWAP_MASK, TMP1, TMP1
	vmovdqu		OFFSETOF_H_POWERS+2*32(KEY), TMP2
.elseif \i == 4
	vpclmulqdq	$0x00, TMP2, TMP1, TMP0
	vpxor		TMP0, LO, LO
	vpclmulqdq	$0x11, TMP2, TMP1, TMP0
	vpxor		TMP0, HI, HI
.elseif \i == 5
	vpunpckhqdq	TMP1, TMP1, TMP0
	vpxor		TMP1, TMP0, TMP0
	vpclmulqdq	$0x00, H_POW1_XORED, TMP0, TMP0
	vpxor		TMP0, MI, MI

	// Fourth vector
	vmovdqu		3*32(\ghashdata_ptr), TMP1
	vpshufb		BSWAP_MASK, TMP1, TMP1
.elseif \i == 6
	vmovdqu		OFFSETOF_H_POWERS+3*32(KEY), TMP2
	vpclmulqdq	$0x00, TMP2, TMP1, TMP0
	vpxor		TMP0, LO, LO
	vpclmulqdq	$0x11, TMP2, TMP1, TMP0
	vpxor		TMP0, HI, HI
	vpunpckhqdq	TMP1, TMP1, TMP0
	vpxor		TMP1, TMP0, TMP0
	vpclmulqdq	$0x10, H_POW1_XORED, TMP0, TMP0
	vpxor		TMP0, MI, MI
.elseif \i == 7
	// Finalize 'mi' following Karatsuba multiplication.
	vpxor		LO, MI, MI
	vpxor		HI, MI, MI

	// Fold lo into mi.
	vbroadcasti128	.Lgfpoly(%rip), TMP2
	vpclmulqdq	$0x01, LO, TMP2, TMP0
	vpshufd		$0x4e, LO, LO
	vpxor		LO, MI, MI
	vpxor		TMP0, MI, MI
.elseif \i == 8
	// Fold mi into hi.
	vpclmulqdq	$0x01, MI, TMP2, TMP0
	vpshufd		$0x4e, MI, MI
	vpxor		MI, HI, HI
	vpxor		TMP0, HI, HI
.elseif \i == 9
	vextracti128	$1, HI, TMP0_XMM
	vpxor		TMP0_XMM, HI_XMM, GHASH_ACC_XMM
.endif
.endm

// Update GHASH with four vectors of data blocks.  See _ghash_step_4x for full
// explanation.
.macro	_ghash_4x	ghashdata_ptr
.irp i, 0,1,2,3,4,5,6,7,8,9
	_ghash_step_4x	\i, \ghashdata_ptr
.endr
.endm

// Load 1 <= %ecx <= 16 bytes from the pointer \src into the xmm register \dst
// and zeroize any remaining bytes.  Clobbers %rax, %rcx, and \tmp{64,32}.
.macro	_load_partial_block	src, dst, tmp64, tmp32
	sub		$8, %ecx		// LEN - 8
	jle		.Lle8\@

	// Load 9 <= LEN <= 16 bytes.
	vmovq		(\src), \dst		// Load first 8 bytes
	mov		(\src, %rcx), %rax	// Load last 8 bytes
	neg		%ecx
	shl		$3, %ecx
	shr		%cl, %rax		// Discard overlapping bytes
	vpinsrq		$1, %rax, \dst, \dst
	jmp		.Ldone\@

.Lle8\@:
	add		$4, %ecx		// LEN - 4
	jl		.Llt4\@

	// Load 4 <= LEN <= 8 bytes.
	mov		(\src), %eax		// Load first 4 bytes
	mov		(\src, %rcx), \tmp32	// Load last 4 bytes
	jmp		.Lcombine\@

.Llt4\@:
	// Load 1 <= LEN <= 3 bytes.
	add		$2, %ecx		// LEN - 2
	movzbl		(\src), %eax		// Load first byte
	jl		.Lmovq\@
	movzwl		(\src, %rcx), \tmp32	// Load last 2 bytes
.Lcombine\@:
	shl		$3, %ecx
	shl		%cl, \tmp64
	or		\tmp64, %rax		// Combine the two parts
.Lmovq\@:
	vmovq		%rax, \dst
.Ldone\@:
.endm

// Store 1 <= %ecx <= 16 bytes from the xmm register \src to the pointer \dst.
// Clobbers %rax, %rcx, and \tmp{64,32}.
.macro	_store_partial_block	src, dst, tmp64, tmp32
	sub		$8, %ecx		// LEN - 8
	jl		.Llt8\@

	// Store 8 <= LEN <= 16 bytes.
	vpextrq		$1, \src, %rax
	mov		%ecx, \tmp32
	shl		$3, %ecx
	ror		%cl, %rax
	mov		%rax, (\dst, \tmp64)	// Store last LEN - 8 bytes
	vmovq		\src, (\dst)		// Store first 8 bytes
	jmp		.Ldone\@

.Llt8\@:
	add		$4, %ecx		// LEN - 4
	jl		.Llt4\@

	// Store 4 <= LEN <= 7 bytes.
	vpextrd		$1, \src, %eax
	mov		%ecx, \tmp32
	shl		$3, %ecx
	ror		%cl, %eax
	mov		%eax, (\dst, \tmp64)	// Store last LEN - 4 bytes
	vmovd		\src, (\dst)		// Store first 4 bytes
	jmp		.Ldone\@

.Llt4\@:
	// Store 1 <= LEN <= 3 bytes.
	vpextrb		$0, \src, 0(\dst)
	cmp		$-2, %ecx		// LEN - 4 == -2, i.e. LEN == 2?
	jl		.Ldone\@
	vpextrb		$1, \src, 1(\dst)
	je		.Ldone\@
	vpextrb		$2, \src, 2(\dst)
.Ldone\@:
.endm

// Do one non-last round of AES encryption on the blocks in the given AESDATA
// vectors using the round key that has been broadcast to all 128-bit lanes of
// \round_key.
.macro	_vaesenc	round_key, vecs:vararg
.irp i, \vecs
	vaesenc		\round_key, AESDATA\i, AESDATA\i
.endr
.endm

// Generate counter blocks in the given AESDATA vectors, then do the zero-th AES
// round on them.  Clobbers TMP0.
.macro	_ctr_begin	vecs:vararg
	vbroadcasti128	.Linc_2blocks(%rip), TMP0
.irp i, \vecs
	vpshufb		BSWAP_MASK, LE_CTR, AESDATA\i
	vpaddd		TMP0, LE_CTR, LE_CTR
.endr
.irp i, \vecs
	vpxor		RNDKEY0, AESDATA\i, AESDATA\i
.endr
.endm

// Generate and encrypt counter blocks in the given AESDATA vectors, excluding
// the last AES round.  Clobbers %rax and TMP0.
.macro	_aesenc_loop	vecs:vararg
	_ctr_begin	\vecs
	lea		OFFSETOF_AESROUNDKEYS+16(KEY), %rax
.Laesenc_loop\@:
	vbroadcasti128	(%rax), TMP0
	_vaesenc	TMP0, \vecs
	add		$16, %rax
	cmp		%rax, RNDKEYLAST_PTR
	jne		.Laesenc_loop\@
.endm

// Finalize the keystream blocks in the given AESDATA vectors by doing the last
// AES round, then XOR those keystream blocks with the corresponding data.
// Reduce latency by doing the XOR before the vaesenclast, utilizing the
// property vaesenclast(key, a) ^ b == vaesenclast(key ^ b, a).  Clobbers TMP0.
.macro	_aesenclast_and_xor	vecs:vararg
.irp i, \vecs
	vpxor		\i*32(SRC), RNDKEYLAST, TMP0
	vaesenclast	TMP0, AESDATA\i, AESDATA\i
.endr
.irp i, \vecs
	vmovdqu		AESDATA\i, \i*32(DST)
.endr
.endm

// void aes_gcm_{enc,dec}_update_vaes_avx2(u8 *dst, const u8 *src,
//					   size_t datalen,
//					   struct polyval_elem *ghash_acc,
//					   const __be32 ctr32[4],
//					   const struct aes_gcm_key *key);
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
	.set	GHASH_ACC_PTR,	%rcx	// Assumed to be %rcx.
					// See .Ltail_xor_and_ghash_1to16bytes
	.set	BE_CTR_PTR,	%r8
	.set	BE_CTR_PTR32,	%r8d
	.set	KEY,		%r9

	// Additional local variables.
	// %rax is used as a temporary register.

	// AES key length in bytes
	.set	AESKEYLEN,	%r10d
	.set	AESKEYLEN64,	%r10

	// Pointer to the last AES round key for the chosen AES variant
	.set	RNDKEYLAST_PTR,	%r11

	// BSWAP_MASK is the shuffle mask for byte-reflecting 128-bit values
	// using vpshufb, copied to all 128-bit lanes.
	.set	BSWAP_MASK,	%ymm0
	.set	BSWAP_MASK_XMM,	%xmm0

	// GHASH_ACC is the accumulator variable for GHASH.  When fully reduced,
	// only the lowest 128-bit lane can be nonzero.  When not fully reduced,
	// more than one lane may be used, and they need to be XOR'd together.
	.set	GHASH_ACC,	%ymm1
	.set	GHASH_ACC_XMM,	%xmm1

	// TMP[0-2] are temporary registers.
	.set	TMP0,		%ymm2
	.set	TMP0_XMM,	%xmm2
	.set	TMP1,		%ymm3
	.set	TMP1_XMM,	%xmm3
	.set	TMP2,		%ymm4
	.set	TMP2_XMM,	%xmm4

	// LO and MI are used to accumulate unreduced GHASH products.
	.set	LO,		%ymm5
	.set	LO_XMM,		%xmm5
	.set	MI,		%ymm6
	.set	MI_XMM,		%xmm6

	// H_POW[2-1]_XORED contain cached values from KEY->ghash.k.h_powers_xored.
	// The descending numbering reflects the order of the key powers.
	.set	H_POW2_XORED,	%ymm7
	.set	H_POW2_XORED_XMM, %xmm7
	.set	H_POW1_XORED,	%ymm8

	// RNDKEY0 caches the zero-th round key, and RNDKEYLAST the last one.
	.set	RNDKEY0,	%ymm9
	.set	RNDKEYLAST,	%ymm10

	// LE_CTR contains the next set of little-endian counter blocks.
	.set	LE_CTR,		%ymm11

	// AESDATA[0-3] hold the counter blocks that are being encrypted by AES.
	.set	AESDATA0,	%ymm12
	.set	AESDATA0_XMM,	%xmm12
	.set	AESDATA1,	%ymm13
	.set	AESDATA1_XMM,	%xmm13
	.set	AESDATA2,	%ymm14
	.set	AESDATA3,	%ymm15

.if \enc
	.set	GHASHDATA_PTR,	DST
.else
	.set	GHASHDATA_PTR,	SRC
.endif

	vbroadcasti128	.Lbswap_mask(%rip), BSWAP_MASK

	// Load the GHASH accumulator and the starting counter.
	vmovdqu		(GHASH_ACC_PTR), GHASH_ACC_XMM
	vbroadcasti128	(BE_CTR_PTR), LE_CTR
	vpshufb		BSWAP_MASK, LE_CTR, LE_CTR

	// Load the AES key length in bytes.
	movl		OFFSETOF_AESKEYLEN(KEY), AESKEYLEN

	// Make RNDKEYLAST_PTR point to the last AES round key.  This is the
	// round key with index 10, 12, or 14 for AES-128, AES-192, or AES-256
	// respectively.  Then load the zero-th and last round keys.
	lea		OFFSETOF_AESROUNDKEYS+6*16(KEY,AESKEYLEN64,4), RNDKEYLAST_PTR
	vbroadcasti128	OFFSETOF_AESROUNDKEYS(KEY), RNDKEY0
	vbroadcasti128	(RNDKEYLAST_PTR), RNDKEYLAST

	// Finish initializing LE_CTR by adding 1 to the second block.
	vpaddd		.Lctr_pattern(%rip), LE_CTR, LE_CTR

	// If there are at least 128 bytes of data, then continue into the loop
	// that processes 128 bytes of data at a time.  Otherwise skip it.
	add		$-128, DATALEN	// 128 is 4 bytes, -128 is 1 byte
	jl		.Lcrypt_loop_4x_done\@

	vmovdqu		OFFSETOF_H_POWERS_XORED(KEY), H_POW2_XORED
	vmovdqu		OFFSETOF_H_POWERS_XORED+32(KEY), H_POW1_XORED

	// Main loop: en/decrypt and hash 4 vectors (128 bytes) at a time.

.if \enc
	// Encrypt the first 4 vectors of plaintext blocks.
	_aesenc_loop	0,1,2,3
	_aesenclast_and_xor	0,1,2,3
	sub		$-128, SRC	// 128 is 4 bytes, -128 is 1 byte
	add		$-128, DATALEN
	jl		.Lghash_last_ciphertext_4x\@
.endif

.align 16
.Lcrypt_loop_4x\@:

	// Start the AES encryption of the counter blocks.
	_ctr_begin	0,1,2,3
	cmp		$24, AESKEYLEN
	jl		128f	// AES-128?
	je		192f	// AES-192?
	// AES-256
	vbroadcasti128	-13*16(RNDKEYLAST_PTR), TMP0
	_vaesenc	TMP0, 0,1,2,3
	vbroadcasti128	-12*16(RNDKEYLAST_PTR), TMP0
	_vaesenc	TMP0, 0,1,2,3
192:
	vbroadcasti128	-11*16(RNDKEYLAST_PTR), TMP0
	_vaesenc	TMP0, 0,1,2,3
	vbroadcasti128	-10*16(RNDKEYLAST_PTR), TMP0
	_vaesenc	TMP0, 0,1,2,3
128:

	// Finish the AES encryption of the counter blocks in AESDATA[0-3],
	// interleaved with the GHASH update of the ciphertext blocks.
.irp i, 9,8,7,6,5,4,3,2,1
	_ghash_step_4x  (9 - \i), GHASHDATA_PTR
	vbroadcasti128	-\i*16(RNDKEYLAST_PTR), TMP0
	_vaesenc	TMP0, 0,1,2,3
.endr
	_ghash_step_4x	9, GHASHDATA_PTR
.if \enc
	sub		$-128, DST	// 128 is 4 bytes, -128 is 1 byte
.endif
	_aesenclast_and_xor	0,1,2,3
	sub		$-128, SRC
.if !\enc
	sub		$-128, DST
.endif
	add		$-128, DATALEN
	jge		.Lcrypt_loop_4x\@

.if \enc
.Lghash_last_ciphertext_4x\@:
	// Update GHASH with the last set of ciphertext blocks.
	_ghash_4x	DST
	sub		$-128, DST
.endif

.Lcrypt_loop_4x_done\@:

	// Undo the extra subtraction by 128 and check whether data remains.
	sub		$-128, DATALEN	// 128 is 4 bytes, -128 is 1 byte
	jz		.Ldone\@

	// The data length isn't a multiple of 128 bytes.  Process the remaining
	// data of length 1 <= DATALEN < 128.
	//
	// Since there are enough key powers available for all remaining data,
	// there is no need to do a GHASH reduction after each iteration.
	// Instead, multiply each remaining block by its own key power, and only
	// do a GHASH reduction at the very end.

	// Make POWERS_PTR point to the key powers [H^N, H^(N-1), ...] where N
	// is the number of blocks that remain.
	.set		POWERS_PTR, BE_CTR_PTR	// BE_CTR_PTR is free to be reused.
	.set		POWERS_PTR32, BE_CTR_PTR32
	mov		DATALEN32, %eax
	neg		%rax
	and		$~15, %rax  // -round_up(DATALEN, 16)
	lea		OFFSETOFEND_H_POWERS(KEY,%rax), POWERS_PTR

	// Start collecting the unreduced GHASH intermediate value LO, MI, HI.
	.set		HI, H_POW2_XORED	// H_POW2_XORED is free to be reused.
	.set		HI_XMM, H_POW2_XORED_XMM
	vpxor		LO_XMM, LO_XMM, LO_XMM
	vpxor		MI_XMM, MI_XMM, MI_XMM
	vpxor		HI_XMM, HI_XMM, HI_XMM

	// 1 <= DATALEN < 128.  Generate 2 or 4 more vectors of keystream blocks
	// excluding the last AES round, depending on the remaining DATALEN.
	cmp		$64, DATALEN
	jg		.Ltail_gen_4_keystream_vecs\@
	_aesenc_loop	0,1
	cmp		$32, DATALEN
	jge		.Ltail_xor_and_ghash_full_vec_loop\@
	jmp		.Ltail_xor_and_ghash_partial_vec\@
.Ltail_gen_4_keystream_vecs\@:
	_aesenc_loop	0,1,2,3

	// XOR the remaining data and accumulate the unreduced GHASH products
	// for DATALEN >= 32, starting with one full 32-byte vector at a time.
.Ltail_xor_and_ghash_full_vec_loop\@:
.if \enc
	_aesenclast_and_xor	0
	vpshufb		BSWAP_MASK, AESDATA0, AESDATA0
.else
	vmovdqu		(SRC), TMP1
	vpxor		TMP1, RNDKEYLAST, TMP0
	vaesenclast	TMP0, AESDATA0, AESDATA0
	vmovdqu		AESDATA0, (DST)
	vpshufb		BSWAP_MASK, TMP1, AESDATA0
.endif
	// The ciphertext blocks (i.e. GHASH input data) are now in AESDATA0.
	vpxor		GHASH_ACC, AESDATA0, AESDATA0
	vmovdqu		(POWERS_PTR), TMP2
	_ghash_mul_noreduce	TMP2, AESDATA0, LO, MI, HI, TMP0
	vmovdqa		AESDATA1, AESDATA0
	vmovdqa		AESDATA2, AESDATA1
	vmovdqa		AESDATA3, AESDATA2
	vpxor		GHASH_ACC_XMM, GHASH_ACC_XMM, GHASH_ACC_XMM
	add		$32, SRC
	add		$32, DST
	add		$32, POWERS_PTR
	sub		$32, DATALEN
	cmp		$32, DATALEN
	jge		.Ltail_xor_and_ghash_full_vec_loop\@
	test		DATALEN, DATALEN
	jz		.Ltail_ghash_reduce\@

.Ltail_xor_and_ghash_partial_vec\@:
	// XOR the remaining data and accumulate the unreduced GHASH products,
	// for 1 <= DATALEN < 32.
	vaesenclast	RNDKEYLAST, AESDATA0, AESDATA0
	cmp		$16, DATALEN
	jle		.Ltail_xor_and_ghash_1to16bytes\@

	// Handle 17 <= DATALEN < 32.

	// Load a vpshufb mask that will right-shift by '32 - DATALEN' bytes
	// (shifting in zeroes), then reflect all 16 bytes.
	lea		.Lrshift_and_bswap_table(%rip), %rax
	vmovdqu		-16(%rax, DATALEN), TMP2_XMM

	// Move the second keystream block to its own register and left-align it
	vextracti128	$1, AESDATA0, AESDATA1_XMM
	vpxor		.Lfifteens(%rip), TMP2_XMM, TMP0_XMM
	vpshufb		TMP0_XMM, AESDATA1_XMM, AESDATA1_XMM

	// Using overlapping loads and stores, XOR the source data with the
	// keystream and write the destination data.  Then prepare the GHASH
	// input data: the full ciphertext block and the zero-padded partial
	// ciphertext block, both byte-reflected, in AESDATA0.
.if \enc
	vpxor		-16(SRC, DATALEN), AESDATA1_XMM, AESDATA1_XMM
	vpxor		(SRC), AESDATA0_XMM, AESDATA0_XMM
	vmovdqu		AESDATA1_XMM, -16(DST, DATALEN)
	vmovdqu		AESDATA0_XMM, (DST)
	vpshufb		TMP2_XMM, AESDATA1_XMM, AESDATA1_XMM
	vpshufb		BSWAP_MASK_XMM, AESDATA0_XMM, AESDATA0_XMM
.else
	vmovdqu		-16(SRC, DATALEN), TMP1_XMM
	vmovdqu		(SRC), TMP0_XMM
	vpxor		TMP1_XMM, AESDATA1_XMM, AESDATA1_XMM
	vpxor		TMP0_XMM, AESDATA0_XMM, AESDATA0_XMM
	vmovdqu		AESDATA1_XMM, -16(DST, DATALEN)
	vmovdqu		AESDATA0_XMM, (DST)
	vpshufb		TMP2_XMM, TMP1_XMM, AESDATA1_XMM
	vpshufb		BSWAP_MASK_XMM, TMP0_XMM, AESDATA0_XMM
.endif
	vpxor		GHASH_ACC_XMM, AESDATA0_XMM, AESDATA0_XMM
	vinserti128	$1, AESDATA1_XMM, AESDATA0, AESDATA0
	vmovdqu		(POWERS_PTR), TMP2
	jmp		.Ltail_ghash_last_vec\@

.Ltail_xor_and_ghash_1to16bytes\@:
	// Handle 1 <= DATALEN <= 16.  Carefully load and store the
	// possibly-partial block, which we mustn't access out of bounds.
	vmovdqu		(POWERS_PTR), TMP2_XMM
	mov		GHASH_ACC_PTR, KEY	// Free up %rcx, assuming GHASH_ACC_PTR == %rcx
	mov		DATALEN32, %ecx
	_load_partial_block	SRC, TMP0_XMM, POWERS_PTR, POWERS_PTR32
	vpxor		TMP0_XMM, AESDATA0_XMM, AESDATA0_XMM
	mov		DATALEN32, %ecx
	_store_partial_block	AESDATA0_XMM, DST, POWERS_PTR, POWERS_PTR32
	mov		KEY, GHASH_ACC_PTR
.if \enc
	lea		.Lselect_high_bytes_table(%rip), %rax
	vpshufb		BSWAP_MASK_XMM, AESDATA0_XMM, AESDATA0_XMM
	vpand		(%rax, DATALEN), AESDATA0_XMM, AESDATA0_XMM
.else
	vpshufb		BSWAP_MASK_XMM, TMP0_XMM, AESDATA0_XMM
.endif
	vpxor		GHASH_ACC_XMM, AESDATA0_XMM, AESDATA0_XMM

.Ltail_ghash_last_vec\@:
	// Accumulate the unreduced GHASH products for the last 1-2 blocks.  The
	// GHASH input data is in AESDATA0.  If only one block remains, then the
	// second block in AESDATA0 is zero and does not affect the result.
	_ghash_mul_noreduce	TMP2, AESDATA0, LO, MI, HI, TMP0

.Ltail_ghash_reduce\@:
	// Finally, do the GHASH reduction.
	vbroadcasti128	.Lgfpoly(%rip), TMP0
	_ghash_reduce	LO, MI, HI, TMP0, TMP1
	vextracti128	$1, HI, GHASH_ACC_XMM
	vpxor		HI_XMM, GHASH_ACC_XMM, GHASH_ACC_XMM

.Ldone\@:
	// Store the updated GHASH accumulator back to memory.
	vmovdqu		GHASH_ACC_XMM, (GHASH_ACC_PTR)

	vzeroupper
	RET
.endm

SYM_FUNC_START(aes_gcm_enc_update_vaes_avx2)
	_aes_gcm_update	1
SYM_FUNC_END(aes_gcm_enc_update_vaes_avx2)
SYM_FUNC_START(aes_gcm_dec_update_vaes_avx2)
	_aes_gcm_update	0
SYM_FUNC_END(aes_gcm_dec_update_vaes_avx2)
