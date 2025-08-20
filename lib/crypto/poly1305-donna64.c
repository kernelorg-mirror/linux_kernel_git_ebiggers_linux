// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is based in part on Andrew Moon's poly1305-donna, which is in the
 * public domain.
 */

#include <crypto/internal/poly1305.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/unaligned.h>

void poly1305_core_setkey(struct poly1305_core_key *key,
			  const u8 raw_key[POLY1305_BLOCK_SIZE])
{
	u64 r0 = get_unaligned_le64(&raw_key[0]) & 0x0ffffffc0fffffff;
	u64 r1 = get_unaligned_le64(&raw_key[8]) & 0x0ffffffc0ffffffc;

	key->key.r64[0] = r0;
	key->key.r64[1] = r1;
	key->key.r64[2] = r1 + (r1 >> 2);
}
EXPORT_SYMBOL(poly1305_core_setkey);

void poly1305_core_blocks(struct poly1305_state *state,
			  const struct poly1305_core_key *key, const void *src,
			  unsigned int nblocks, u32 hibit)
{
	const u8 *data = src;
	u64 h0, h1, h2, r0, r1, rs1;

	if (!nblocks)
		return;

	h0 = state->h64[0];
	h1 = state->h64[1];
	h2 = state->h64[2];

	r0 = key->key.r64[0];
	r1 = key->key.r64[1];
	rs1 = key->key.r64[2];

	do {
		u64 d0, d1, d2, residue, carry0, carry1, tmp0, tmp1;

		residue = (h2 & ~3) + (h2 >> 2); /* 5 * floor(h / 2^130) */
		h2 &= 3; /* h = h mod 2^130 */

		/* d = h + data + residue + (hibit * 2^128) */
		d0 = h0 + get_unaligned_le64(&data[0]);
		carry0 = (d0 < h0);
		d0 += residue;
		carry0 += (d0 < residue);
		d1 = h1 + get_unaligned_le64(&data[8]);
		carry1 = (d1 < h1);
		d1 += carry0;
		carry1 += (d1 < carry0);
		d2 = h2 + hibit + carry1;

		/* h1:h0 = d0 * r0 */
		h0 = d0 * r0;
		h1 = ((u128)d0 * r0) >> 64;

		/*
		 *    h3:h2 += d1 * r1
		 * => h1:h0 += d1 * (5 * r1 / 4)
		 */
		tmp0 = d1 * rs1;
		tmp1 = ((u128)d1 * rs1) >> 64;
		h0 += tmp0;
		h1 += tmp1 + (h0 < tmp0);

		/* h2:h1 += d0 * r1 */
		tmp0 = d0 * r1;
		h1 += tmp0;
		h2 = (((u128)d0 * r1) >> 64) + (h1 < tmp0);

		/* h2:h1 += d1 * r0 */
		tmp0 = d1 * r0;
		h1 += tmp0;
		h2 += (((u128)d1 * r0) >> 64) + (h1 < tmp0);

		/*    h4:h3 += d2 * r1
		 * => h2:h1 += d2 * (5 * r1 / 4)
		 */
		tmp0 = d2 * rs1;
		h1 += tmp0;
		h2 += (h1 < tmp0);

		/*
		 * h2 += d2 * r0
		 *
		 * Product is not more than 64 bits, since
		 * d2 <= 6 && r0 <= 0x0ffffffc0fffffff
		 */
		h2 += d2 * r0;

		data += POLY1305_BLOCK_SIZE;
	} while (--nblocks);

	state->h64[0] = h0;
	state->h64[1] = h1;
	state->h64[2] = h2;
}
EXPORT_SYMBOL(poly1305_core_blocks);

void poly1305_core_emit(const struct poly1305_state *state, const u32 nonce[4],
			void *dst)
{
	u8 *mac = dst;
	u64 h0, h1, h2, g0, g1, g2, carry0, carry1, tmp0, tmp1, mask;

	h0 = state->h64[0];
	h1 = state->h64[1];
	h2 = state->h64[2];

	/* reduce h to [0, 2^130-1] and calculate g = h + 5 */
	tmp0 = (h2 & ~3) + (h2 >> 2); /* 5 * floor(h / 2^130) */
	h2 &= 3; /* h = h mod 2^130 */
	h0 += tmp0;
	g0 = h0 + 5;
	carry0 = (h0 < tmp0);
	carry1 = (g0 < h0);
	h1 += carry0;
	g1 = h1 + carry1;
	carry0 = (h1 < carry0);
	carry1 = (g1 < carry1);
	h2 += carry0;
	g2 = h2 + carry1;
	mask = -(g2 >> 2); /* 0 if h < 2^130-5, (u64)-1 if h >= 2^130-5 */

	/* h = h mod 2^128 if h < x^130-5, else h = h - (2^130-5) mod 2^128 */
	h0 ^= (h0 ^ g0) & mask;
	h1 ^= (h1 ^ g1) & mask;

	if (likely(nonce)) {
		/* h = h + nonce mod 2^128 */
		tmp0 = ((u64)nonce[1] << 32) | nonce[0];
		tmp1 = ((u64)nonce[3] << 32) | nonce[2];
		h0 += tmp0;
		h1 += tmp1 + (h0 < tmp0);
	}

	put_unaligned_le64(h0, &mac[0]);
	put_unaligned_le64(h1, &mac[8]);
}
EXPORT_SYMBOL(poly1305_core_emit);
