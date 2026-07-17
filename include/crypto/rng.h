/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * NIST SP800-90A DRBG and jitterentropy
 *
 * Copyright (c) 2008 Neil Horman <nhorman@tuxdriver.com>
 * Copyright (c) 2015 Herbert Xu <herbert@gondor.apana.org.au>
 */

#ifndef _CRYPTO_RNG_H
#define _CRYPTO_RNG_H

#include <linux/fips.h>
#include <linux/random.h>
#include <linux/types.h>

/* drbg */
struct drbg_state;
struct drbg_state *crypto_drbg_alloc(void);
void crypto_drbg_set_entropy(struct drbg_state *drbg, const u8 *data,
			     size_t len);
int crypto_drbg_seed(struct drbg_state *drbg, const u8 *pers, size_t pers_len);
int crypto_drbg_get_bytes(struct drbg_state *drbg, u8 *out, size_t out_len,
			  const u8 *addtl, size_t addtl_len);
void crypto_drbg_free(struct drbg_state *drbg);
int __crypto_stdrng_get_bytes(void *buf, size_t len);

/**
 * crypto_stdrng_get_bytes() - get cryptographically secure random bytes
 * @buf: output buffer holding the random numbers
 * @len: length of the output buffer
 *
 * This function fills the given buffer with random numbers using the normal
 * Linux RNG if fips_enabled=0, or a NIST SP800-90A DRBG if fips_enabled=1.
 *
 * Context: May sleep
 * Return: 0 function was successful; < 0 if an error occurred
 */
static inline int crypto_stdrng_get_bytes(void *buf, size_t len)
{
	might_sleep();
	if (fips_enabled)
		return __crypto_stdrng_get_bytes(buf, len);
	return get_random_bytes_wait(buf, len);
}

int crypto_del_default_rng(void);

/* jitterentropy */
struct jitterentropy;
struct jitterentropy *crypto_jent_alloc(void);
int crypto_jent_get_bytes(struct jitterentropy *rng, u8 *rdata,
			  unsigned int dlen);
void crypto_jent_free(struct jitterentropy *rng);

#endif
