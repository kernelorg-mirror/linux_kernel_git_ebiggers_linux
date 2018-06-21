// SPDX-License-Identifier: GPL-2.0+
/*
 * NEON-accelerated implementation of LEA-XTS
 *
 * Copyright (c) 2018 Google, Inc
 */

#include <asm/hwcap.h>
#include <asm/neon.h>
#include <asm/simd.h>
#include <crypto/algapi.h>
#include <crypto/gf128mul.h>
#include <crypto/internal/skcipher.h>
#include <crypto/lea.h>
#include <crypto/xts.h>
#include <linux/kernel.h>
#include <linux/module.h>

/* The assembly functions only handle multiples of 128 bytes */
#define LEA_NEON_CHUNK_SIZE	128

struct lea_xts_tfm_ctx {
	u32 neon_enc_keys[LEA_256_NROUNDS * 6];
	struct lea_tfm_ctx main_key;
	struct lea_tfm_ctx tweak_key;
};

asmlinkage void lea128_xts_encrypt_neon(const u32 *round_keys, int nrounds,
					void *dst, const void *src,
					unsigned int nbytes, void *tweak);

asmlinkage void lea128_xts_decrypt_neon(const u32 *round_keys, int nrounds,
					void *dst, const void *src,
					unsigned int nbytes, void *tweak);

asmlinkage void lea_xts_encrypt_neon(const u32 *round_keys, int nrounds,
				     void *dst, const void *src,
				     unsigned int nbytes, void *tweak);

asmlinkage void lea_xts_decrypt_neon(const u32 *round_keys, int nrounds,
				     void *dst, const void *src,
				     unsigned int nbytes, void *tweak);

typedef void (*lea_crypt_one_t)(const struct lea_tfm_ctx *, u8 *, const u8 *);
typedef void (*lea_xts_crypt_many_t)(const u32 *, int, void *, const void *,
				     unsigned int, void *);

static __always_inline int
__lea_xts_crypt(struct skcipher_request *req, lea_crypt_one_t crypt_one,
		lea_xts_crypt_many_t crypt_many, const u32 *round_keys)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct lea_xts_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	le128 tweak;
	int err;

	err = skcipher_walk_virt(&walk, req, true);

	crypto_lea_encrypt(&ctx->tweak_key, (u8 *)&tweak, walk.iv);

	while (walk.nbytes > 0) {
		unsigned int nbytes = walk.nbytes;
		u8 *dst = walk.dst.virt.addr;
		const u8 *src = walk.src.virt.addr;

		if (nbytes >= LEA_NEON_CHUNK_SIZE && may_use_simd()) {
			unsigned int count;

			count = round_down(nbytes, LEA_NEON_CHUNK_SIZE);
			kernel_neon_begin();
			(*crypt_many)(round_keys, ctx->main_key.nrounds,
				      dst, src, count, &tweak);
			kernel_neon_end();
			dst += count;
			src += count;
			nbytes -= count;
		}

		/* Handle any remainder with generic code */
		while (nbytes >= sizeof(tweak)) {
			le128_xor((le128 *)dst, (const le128 *)src, &tweak);
			(*crypt_one)(&ctx->main_key, dst, dst);
			le128_xor((le128 *)dst, (const le128 *)dst, &tweak);
			gf128mul_x_ble(&tweak, &tweak);

			dst += sizeof(tweak);
			src += sizeof(tweak);
			nbytes -= sizeof(tweak);
		}
		err = skcipher_walk_done(&walk, nbytes);
	}

	return err;
}

static int lea_xts_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct lea_xts_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	lea_xts_crypt_many_t crypt_many;

	if (ctx->main_key.nrounds == LEA_128_NROUNDS)
		crypt_many = lea128_xts_encrypt_neon;
	else
		crypt_many = lea_xts_encrypt_neon;

	return __lea_xts_crypt(req, crypto_lea_encrypt, crypt_many,
			       ctx->neon_enc_keys);
}

static int lea_xts_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct lea_xts_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	lea_xts_crypt_many_t crypt_many;

	if (ctx->main_key.nrounds == LEA_128_NROUNDS)
		crypt_many = lea128_xts_decrypt_neon;
	else
		crypt_many = lea_xts_decrypt_neon;

	return __lea_xts_crypt(req, crypto_lea_decrypt, crypt_many,
			       ctx->main_key.dec_keys);
}

static int lea_xts_setkey(struct crypto_skcipher *tfm, const u8 *key,
			  unsigned int keylen)
{
	struct lea_xts_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	const u32 *enc_keys = ctx->main_key.enc_keys;
	u32 *neon_enc_keys = ctx->neon_enc_keys;
	int err;
	int i;

	err = xts_verify_key(tfm, key, keylen);
	if (err)
		return err;

	keylen /= 2;

	err = crypto_lea_setkey(&ctx->main_key, key, keylen);
	if (err)
		return err;

	/* Rearrange the encryption round keys for the NEON code */
	if (keylen == LEA_128_KEY_SIZE) {
		for (i = 0; i < LEA_128_NROUNDS; i++) {
			*neon_enc_keys++ = enc_keys[3];
			*neon_enc_keys++ = enc_keys[2];
			*neon_enc_keys++ = enc_keys[1];
			*neon_enc_keys++ = enc_keys[0];
			enc_keys += 4;
		}
	} else {
		for (i = 0; i < ctx->main_key.nrounds; i++) {
			*neon_enc_keys++ = enc_keys[3];
			*neon_enc_keys++ = enc_keys[1];
			*neon_enc_keys++ = enc_keys[4];
			*neon_enc_keys++ = enc_keys[2];
			*neon_enc_keys++ = enc_keys[5];
			*neon_enc_keys++ = enc_keys[0];
			enc_keys += 6;
		}
	}

	return crypto_lea_setkey(&ctx->tweak_key, key + keylen, keylen);
}

static struct skcipher_alg lea_xts_alg = {
	.base.cra_name		= "xts(lea)",
	.base.cra_driver_name	= "xts-lea-neon",
	.base.cra_priority	= 300,
	.base.cra_blocksize	= LEA_BLOCK_SIZE,
	.base.cra_ctxsize	= sizeof(struct lea_xts_tfm_ctx),
	.base.cra_alignmask	= 7,
	.base.cra_module	= THIS_MODULE,
	.min_keysize		= 2 * LEA_128_KEY_SIZE,
	.max_keysize		= 2 * LEA_256_KEY_SIZE,
	.ivsize			= LEA_BLOCK_SIZE,
	.walksize		= LEA_NEON_CHUNK_SIZE,
	.setkey			= lea_xts_setkey,
	.encrypt		= lea_xts_encrypt,
	.decrypt		= lea_xts_decrypt,
};

static int __init lea_neon_module_init(void)
{
	if (!(elf_hwcap & HWCAP_NEON))
		return -ENODEV;
	return crypto_register_skcipher(&lea_xts_alg);
}

static void __exit lea_neon_module_exit(void)
{
	crypto_unregister_skcipher(&lea_xts_alg);
}

module_init(lea_neon_module_init);
module_exit(lea_neon_module_exit);

MODULE_DESCRIPTION("LEA block cipher (NEON-accelerated)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eric Biggers <ebiggers@google.com>");
MODULE_ALIAS_CRYPTO("xts(lea)");
MODULE_ALIAS_CRYPTO("xts-lea-neon");
