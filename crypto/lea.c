// SPDX-License-Identifier: GPL-2.0+
/*
 * LEA: a lightweight block cipher
 *
 * Copyright (c) 2018 Google, Inc
 *
 * See: "LEA: A 128-Bit Block Cipher for Fast Encryption on Common Processors"
 * https://seed.kisa.or.kr/html/egovframework/iwt/ds/ko/ref/LEA%20A%20128-Bit%20Block%20Cipher%20for%20Fast%20Encryption%20on%20Common%20Processors-English.pdf
 */

#include <asm/unaligned.h>
#include <crypto/lea.h>
#include <linux/bitops.h>
#include <linux/crypto.h>
#include <linux/module.h>

/* ========== Key schedule ========== */

/*
 * Key schedule constants.  These are the first digits after the decimal point
 * of sqrt(766965) = sqrt("LEA"), written in base 16, read as eight 32-bit
 * constants, then with the constant at 0-based index 'i' rotated left by 'i'
 * bits.  Note: the LEA paper incorrectly says that the ASCII code for 'A' is 95
 * and that the constants use sqrt(766995).  Actually, the constants given in
 * the paper use the correct 'A' code of 65.
 *
 * These can be generated using following bash script:
 *	n=$(printf "%d%d%d" "'L'" "'E'" "'A'")
 *	i=0
 *	for c in $(echo "scale=1000; obase=16; sqrt($n)" | bc \
 *			| sed 's/^.*\.//g' | head -c 64 \
 *			| sed 's/.\{8\}/0x\0 /g'); do
 *		printf "0x%08x, " $(( ((c << i) | (c >> (32-i))) & 0xffffffff ))
 *		(( i++ ))
 *	done
 */
static const u32 lea_constants[8] = {
	0xc3efe9db, 0x88c4d604, 0xe789f229, 0xc6f98763,
	0x15ea49e7, 0xf0bb4158, 0x13bc8ab8, 0xe204abf2,
};

/*
 * Key schedule precomputation.  See 'struct lea_tfm_ctx' for an explanation of
 * how we preprocess the round keys for efficient encryption/decryption.  Note
 * that for LEA-128, we store only the 4 unique keys/round rather than all 6.
 */

static void lea128_setkey(struct lea_tfm_ctx *ctx, const u8 *key)
{
	u32 *enc_keys = ctx->enc_keys;
	u32 *dec_keys = &ctx->dec_keys[(4 * LEA_128_NROUNDS) - 1];
	u32 c[4];
	u32 T[4];
	int i;

	memcpy(c, lea_constants, sizeof(c));
	for (i = 0; i < ARRAY_SIZE(T); i++)
		T[i] = get_unaligned_le32(key + i * sizeof(__le32));

	ctx->nrounds = LEA_128_NROUNDS;

	for (i = 0; i < LEA_128_NROUNDS; i++) {
		u32 c0 = c[i % 4];

		c[i % 4] = rol32(c0, 4);
		T[0] = rol32(T[0] + c0, 1);
		T[1] = rol32(T[1] + rol32(c0, 1), 3);
		T[2] = rol32(T[2] + rol32(c0, 2), 6);
		T[3] = rol32(T[3] + rol32(c0, 3), 11);
		/* RK_{i} is (T[0], T[1], T[2], T[1], T[3], T[1]) */

		*enc_keys++ = T[0];
		*enc_keys++ = T[1];
		*enc_keys++ = T[2];
		*enc_keys++ = T[3];

		*dec_keys-- = T[3] ^ T[1];
		*dec_keys-- = T[2] ^ T[1];
		*dec_keys-- = T[1];
		*dec_keys-- = T[0];
	}
}

static void lea192_setkey(struct lea_tfm_ctx *ctx, const u8 *key)
{
	u32 *enc_keys = ctx->enc_keys;
	u32 *dec_keys = &ctx->dec_keys[(6 * LEA_192_NROUNDS) - 1];
	u32 c[6];
	u32 T[6];
	int i;

	memcpy(c, lea_constants, sizeof(c));
	for (i = 0; i < ARRAY_SIZE(T); i++)
		T[i] = get_unaligned_le32(key + i * sizeof(__le32));

	ctx->nrounds = LEA_192_NROUNDS;

	for (i = 0; i < LEA_192_NROUNDS; i++) {
		u32 c0 = c[i % 6];

		c[i % 6] = rol32(c0, 6);
		T[0] = rol32(T[0] + c0, 1);
		T[1] = rol32(T[1] + rol32(c0, 1), 3);
		T[2] = rol32(T[2] + rol32(c0, 2), 6);
		T[3] = rol32(T[3] + rol32(c0, 3), 11);
		T[4] = rol32(T[4] + rol32(c0, 4), 13);
		T[5] = rol32(T[5] + rol32(c0, 5), 17);

		*enc_keys++ = T[0];
		*enc_keys++ = T[1];
		*enc_keys++ = T[2];
		*enc_keys++ = T[3];
		*enc_keys++ = T[4];
		*enc_keys++ = T[5];

		*dec_keys-- = T[5];
		*dec_keys-- = T[4] ^ T[3];
		*dec_keys-- = T[3];
		*dec_keys-- = T[2] ^ T[1];
		*dec_keys-- = T[1];
		*dec_keys-- = T[0];
	}
}

static void lea256_setkey(struct lea_tfm_ctx *ctx, const u8 *key)
{
	u32 *enc_keys = ctx->enc_keys;
	u32 *dec_keys = &ctx->dec_keys[(6 * LEA_256_NROUNDS) - 1];
	u32 c[8];
	u32 T[8];
	int i;

	memcpy(c, lea_constants, sizeof(c));
	for (i = 0; i < ARRAY_SIZE(T); i++)
		T[i] = get_unaligned_le32(key + i * sizeof(__le32));

	ctx->nrounds = LEA_256_NROUNDS;

	for (i = 0; i < LEA_256_NROUNDS; i++) {
		int i0 = ((6 * i) + 0) % 8;
		int i1 = ((6 * i) + 1) % 8;
		int i2 = ((6 * i) + 2) % 8;
		int i3 = ((6 * i) + 3) % 8;
		int i4 = ((6 * i) + 4) % 8;
		int i5 = ((6 * i) + 5) % 8;
		u32 c0 = c[i % 8];

		c[i % 8] = rol32(c0, 8);
		T[i0] = rol32(T[i0] + c0, 1);
		T[i1] = rol32(T[i1] + rol32(c0, 1), 3);
		T[i2] = rol32(T[i2] + rol32(c0, 2), 6);
		T[i3] = rol32(T[i3] + rol32(c0, 3), 11);
		T[i4] = rol32(T[i4] + rol32(c0, 4), 13);
		T[i5] = rol32(T[i5] + rol32(c0, 5), 17);

		*enc_keys++ = T[i0];
		*enc_keys++ = T[i1];
		*enc_keys++ = T[i2];
		*enc_keys++ = T[i3];
		*enc_keys++ = T[i4];
		*enc_keys++ = T[i5];

		*dec_keys-- = T[i5];
		*dec_keys-- = T[i4] ^ T[i3];
		*dec_keys-- = T[i3];
		*dec_keys-- = T[i2] ^ T[i1];
		*dec_keys-- = T[i1];
		*dec_keys-- = T[i0];
	}
}

int crypto_lea_setkey(struct lea_tfm_ctx *ctx, const u8 *key,
		      unsigned int keysize)
{
	switch (keysize) {
	case LEA_128_KEY_SIZE:
		lea128_setkey(ctx, key);
		return 0;
	case LEA_192_KEY_SIZE:
		lea192_setkey(ctx, key);
		return 0;
	case LEA_256_KEY_SIZE:
		lea256_setkey(ctx, key);
		return 0;
	}
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(crypto_lea_setkey);

static int lea_setkey(struct crypto_tfm *tfm, const u8 *key,
		      unsigned int keysize)
{
	return crypto_lea_setkey(crypto_tfm_ctx(tfm), key, keysize);
}

/* ========== Encryption ========== */

/*
 * One LEA encryption round.  Initially, (a, b, c, d) contain (x0, x1, x2, x3).
 * Afterwards, they contain (x3, x0, x1, x2).
 */
#define LEA_ROUND(a, b, c, d, k)			\
do {							\
	d = ror32((c ^ k[4]) + (d ^ k[5]), 3);		\
	c = ror32((b ^ k[2]) + (c ^ k[3]), 5);		\
	b = rol32((a ^ k[0]) + (b ^ k[1]), 9);		\
	k += 6;						\
} while (0)

/* Four LEA encryption rounds */
#define LEA_4XROUND(x0, x1, x2, x3, k)			\
do {							\
	LEA_ROUND(x0, x1, x2, x3, k);			\
	LEA_ROUND(x1, x2, x3, x0, k);			\
	LEA_ROUND(x2, x3, x0, x1, k);			\
	LEA_ROUND(x3, x0, x1, x2, k);			\
} while (0)

/*
 * The following macros assume the LEA-128 key schedule representation that has
 * 4 keys/round, rather than the full 6.  Otherwise they're the same as above.
 */

#define LEA128_ROUND(a, b, c, d, k)			\
do {							\
	d = ror32((c ^ k[3]) + (d ^ k[1]), 3);		\
	c = ror32((b ^ k[2]) + (c ^ k[1]), 5);		\
	b = rol32((a ^ k[0]) + (b ^ k[1]), 9);		\
	k += 4;						\
} while (0)

#define LEA128_4XROUND(x0, x1, x2, x3, k)		\
do {							\
	LEA128_ROUND(x0, x1, x2, x3, k);		\
	LEA128_ROUND(x1, x2, x3, x0, k);		\
	LEA128_ROUND(x2, x3, x0, x1, k);		\
	LEA128_ROUND(x3, x0, x1, x2, k);		\
} while (0)

void crypto_lea_encrypt(const struct lea_tfm_ctx *ctx, u8 *dst, const u8 *src)
{
	const u32 *k = ctx->enc_keys;
	u32 x0 = get_unaligned_le32(src + 0);
	u32 x1 = get_unaligned_le32(src + 4);
	u32 x2 = get_unaligned_le32(src + 8);
	u32 x3 = get_unaligned_le32(src + 12);
	int i;

	if (ctx->nrounds == LEA_128_NROUNDS) {
		BUILD_BUG_ON(LEA_128_NROUNDS != 24);
		LEA128_4XROUND(x0, x1, x2, x3, k);
		LEA128_4XROUND(x0, x1, x2, x3, k);
		LEA128_4XROUND(x0, x1, x2, x3, k);
		LEA128_4XROUND(x0, x1, x2, x3, k);
		LEA128_4XROUND(x0, x1, x2, x3, k);
		LEA128_4XROUND(x0, x1, x2, x3, k);
	} else {
		for (i = 0; i < ctx->nrounds; i += 4)
			LEA_4XROUND(x0, x1, x2, x3, k);
	}

	put_unaligned_le32(x0, dst + 0);
	put_unaligned_le32(x1, dst + 4);
	put_unaligned_le32(x2, dst + 8);
	put_unaligned_le32(x3, dst + 12);
}
EXPORT_SYMBOL_GPL(crypto_lea_encrypt);

static void lea_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	crypto_lea_encrypt(crypto_tfm_ctx(tfm), dst, src);
}

/* ========== Decryption ========== */

/*
 * One LEA decryption round.  Given:
 *	x3 == prev_x0,
 *	x2 == ror32((prev_x2 ^ RK[4]) + (prev_x3 ^ RK[5]), 3),
 *	x1 == ror32((prev_x1 ^ RK[2]) + (prev_x2 ^ RK[3]), 5),
 *	x0 == rol32((prev_x0 ^ RK[0]) + (prev_x1 ^ RK[1]), 9)
 *
 * ... solve for prev_x1, then prev_x2, then prev_x3:
 *	prev_x1 = (ror32(x0, 9) - (prev_x0 ^ RK[0])) ^ RK[1];
 *	prev_x2 = (rol32(x1, 5) - (prev_x1 ^ RK[2])) ^ RK[3];
 *	prev_x3 = (rol32(x2, 3) - (prev_x2 ^ RK[4])) ^ RK[5];
 *
 * Note: the straightforward version of this would be:
 *	a = (ror32(a, 9) - (d ^ RK[0])) ^ RK[1];
 *	b = (rol32(b, 5) - (a ^ RK[2])) ^ RK[3];
 *	c = (rol32(c, 3) - (b ^ RK[4])) ^ RK[5];
 *
 * However, as an optimization we store k[2] and k[4] XOR'ed with k[1] and k[3],
 * respectively.  This allows breaking the dependency chain slightly, increasing
 * speed on out-of-order processors: 'a' and 'b' become usable for the next
 * calculation prior to k[1] and k[3], respectively, being XOR'ed in.
 *
 * Initially, (a, b, c, d) contain (x0, x1, x2, x3).
 * Afterwards, they contain (x1, x2, x3, x0).
 */
#define LEA_UNROUND(a, b, c, d, k, tmp)			\
do {							\
	tmp = ror32(a, 9) - (d ^ k[0]);			\
	a = tmp ^ k[1];					\
	tmp = rol32(b, 5) - (tmp ^ k[2]);		\
	b = tmp ^ k[3];					\
	c = (rol32(c, 3) - (tmp ^ k[4])) ^ k[5];	\
	k += 6;						\
} while (0)

/* Four LEA decryption rounds */
#define LEA_4XUNROUND(x0, x1, x2, x3, k, tmp)		\
do {							\
	LEA_UNROUND(x0, x1, x2, x3, k, tmp);		\
	LEA_UNROUND(x3, x0, x1, x2, k, tmp);		\
	LEA_UNROUND(x2, x3, x0, x1, k, tmp);		\
	LEA_UNROUND(x1, x2, x3, x0, k, tmp);		\
} while (0)

/*
 * The following macros assume the LEA-128 key schedule representation that has
 * 4 keys/round, rather than the full 6.  Otherwise they're the same as above.
 */

#define LEA128_UNROUND(a, b, c, d, k, tmp)		\
do {							\
	tmp = ror32(a, 9) - (d ^ k[0]);			\
	a = tmp ^ k[1];					\
	tmp = rol32(b, 5) - (tmp ^ k[2]);		\
	b = tmp ^ k[1];					\
	c = (rol32(c, 3) - (tmp ^ k[3])) ^ k[1];	\
	k += 4;						\
} while (0)

#define LEA128_4XUNROUND(x0, x1, x2, x3, k, tmp)	\
do {							\
	LEA128_UNROUND(x0, x1, x2, x3, k, tmp);		\
	LEA128_UNROUND(x3, x0, x1, x2, k, tmp);		\
	LEA128_UNROUND(x2, x3, x0, x1, k, tmp);		\
	LEA128_UNROUND(x1, x2, x3, x0, k, tmp);		\
} while (0)

void crypto_lea_decrypt(const struct lea_tfm_ctx *ctx, u8 *dst, const u8 *src)
{
	const u32 *k = ctx->dec_keys;
	u32 x0 = get_unaligned_le32(src + 0);
	u32 x1 = get_unaligned_le32(src + 4);
	u32 x2 = get_unaligned_le32(src + 8);
	u32 x3 = get_unaligned_le32(src + 12);
	u32 tmp;
	int i;

	if (ctx->nrounds == LEA_128_NROUNDS) {
		BUILD_BUG_ON(LEA_128_NROUNDS != 24);
		LEA128_4XUNROUND(x0, x1, x2, x3, k, tmp);
		LEA128_4XUNROUND(x0, x1, x2, x3, k, tmp);
		LEA128_4XUNROUND(x0, x1, x2, x3, k, tmp);
		LEA128_4XUNROUND(x0, x1, x2, x3, k, tmp);
		LEA128_4XUNROUND(x0, x1, x2, x3, k, tmp);
		LEA128_4XUNROUND(x0, x1, x2, x3, k, tmp);
	} else {
		for (i = 0; i < ctx->nrounds; i += 4)
			LEA_4XUNROUND(x0, x1, x2, x3, k, tmp);
	}

	put_unaligned_le32(x0, dst + 0);
	put_unaligned_le32(x1, dst + 4);
	put_unaligned_le32(x2, dst + 8);
	put_unaligned_le32(x3, dst + 12);
}
EXPORT_SYMBOL_GPL(crypto_lea_decrypt);

static void lea_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	crypto_lea_decrypt(crypto_tfm_ctx(tfm), dst, src);
}

/* ========== Algorithm definition ========== */

static struct crypto_alg lea_alg = {
	.cra_name		= "lea",
	.cra_driver_name	= "lea-generic",
	.cra_priority		= 100,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= LEA_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct lea_tfm_ctx),
	.cra_module		= THIS_MODULE,
	.cra_u			= {
		.cipher = {
			.cia_min_keysize	= LEA_128_KEY_SIZE,
			.cia_max_keysize	= LEA_256_KEY_SIZE,
			.cia_setkey		= lea_setkey,
			.cia_encrypt		= lea_encrypt,
			.cia_decrypt		= lea_decrypt
		}
	}
};

static int __init lea_module_init(void)
{
	return crypto_register_alg(&lea_alg);
}

static void __exit lea_module_exit(void)
{
	crypto_unregister_alg(&lea_alg);
}

module_init(lea_module_init);
module_exit(lea_module_exit);

MODULE_DESCRIPTION("LEA block cipher (generic)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eric Biggers <ebiggers@google.com>");
MODULE_ALIAS_CRYPTO("lea");
MODULE_ALIAS_CRYPTO("lea-generic");
