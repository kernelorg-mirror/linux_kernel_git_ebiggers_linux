/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Common values for the LEA block cipher algorithm
 */

#ifndef _CRYPTO_LEA_H
#define _CRYPTO_LEA_H

#include <linux/types.h>

#define LEA_BLOCK_SIZE		16

#define LEA_128_KEY_SIZE	16
#define LEA_128_NROUNDS		24

#define LEA_192_KEY_SIZE	24
#define LEA_192_NROUNDS		28

#define LEA_256_KEY_SIZE	32
#define LEA_256_NROUNDS		32

struct lea_tfm_ctx {

	int nrounds;

	/*
	 * Round keys for encryption, in order from first round to last round.
	 *
	 * For LEA-128, RK[1] == RK[3] == RK[5], so we store only the 4 unique
	 * keys per round, in the order (RK[0], RK[1,3,5], RK[2], RK[4]).
	 */
	u32 enc_keys[6 * LEA_256_NROUNDS];

	/*
	 * Round keys for decryption, in order from first decryption round (last
	 * encryption round) to last decryption round (first encryption round).
	 *
	 * For each round, we preprocess the keys to allow reducing data
	 * dependencies.  When there are 6 keys per round (LEA-192 and LEA-256),
	 * we store (RK[0], RK[1], RK[2] ^ RK[1], RK[3], RK[4] ^ RK[3], RK[5]).
	 *
	 * For LEA-128, RK[1] == RK[3] == RK[5], so we store only the 4 unique
	 * keys per round, in the order
	 * (RK[0], RK[1,3,5], RK[2] ^ RK[1], RK[4] ^ RK[3]).
	 */
	u32 dec_keys[6 * LEA_256_NROUNDS];
};

int crypto_lea_setkey(struct lea_tfm_ctx *ctx, const u8 *key,
		      unsigned int keysize);
void crypto_lea_encrypt(const struct lea_tfm_ctx *ctx, u8 *out, const u8 *in);
void crypto_lea_decrypt(const struct lea_tfm_ctx *ctx, u8 *out, const u8 *in);

#endif /* _CRYPTO_LEA_H */
