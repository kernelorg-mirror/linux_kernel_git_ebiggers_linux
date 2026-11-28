/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * GHASH and POLYVAL, x86_64 optimized
 *
 * Copyright 2025 Google LLC
 */
#include <asm/fpu/api.h>
#include "gf128hash-cpu.h"

#define NUM_H_POWERS 8

static_assert(sizeof_field(struct gf128hash_key_x86, h_powers) ==
	      NUM_H_POWERS * sizeof(struct polyval_elem));
static_assert(offsetof(struct gf128hash_key_x86, h_powers) == 0);
static_assert(offsetof(struct gf128hash_key_x86, h_powers_xored) == 128);
static_assert(offsetof(struct gf128hash_key_x86, h_times_xm64) == 192);
static_assert(sizeof(struct gf128hash_key_x86) == 208);

static __ro_after_init DEFINE_STATIC_KEY_FALSE(have_pclmul);
static __ro_after_init DEFINE_STATIC_KEY_FALSE(have_pclmul_avx);

void gf128hash_mul_pclmul(struct polyval_elem *acc,
			  const struct gf128hash_key_x86 *key);
void gf128hash_mul_pclmul_avx(struct polyval_elem *acc,
			      const struct gf128hash_key_x86 *key);

void ghash_preparekey_pclmul(struct gf128hash_key_x86 *key,
			     const u8 raw_key[GHASH_BLOCK_SIZE]);
void ghash_preparekey_pclmul_avx(struct gf128hash_key_x86 *key,
				 const u8 raw_key[GHASH_BLOCK_SIZE]);
void polyval_preparekey_pclmul(struct gf128hash_key_x86 *key,
			       const u8 raw_key[POLYVAL_BLOCK_SIZE]);
void polyval_preparekey_pclmul_avx(struct gf128hash_key_x86 *key,
				   const u8 raw_key[POLYVAL_BLOCK_SIZE]);

void ghash_blocks_pclmul(struct polyval_elem *acc,
			 const struct gf128hash_key_x86 *key, const u8 *data,
			 size_t nblocks);
void ghash_blocks_pclmul_avx(struct polyval_elem *acc,
			     const struct gf128hash_key_x86 *key,
			     const u8 *data, size_t nblocks);
void polyval_blocks_pclmul(struct polyval_elem *acc,
			   const struct gf128hash_key_x86 *key, const u8 *data,
			   size_t nblocks);
void polyval_blocks_pclmul_avx(struct polyval_elem *acc,
			       const struct gf128hash_key_x86 *key,
			       const u8 *data, size_t nblocks);

/*
 * Compute *out = *in * x^-64 mod G(x), where
 * x^-64 = x^64 + x^63 + x^62 + x^57 (mod G(x)).
 */
static void polyval_mul_xm64_generic(struct polyval_elem *out,
				     const struct polyval_elem *in)
{
	u64 lo = le64_to_cpu(in->lo);
	u64 hi = le64_to_cpu(in->hi);

	out->lo = cpu_to_le64(hi ^ (lo << 63) ^ (lo << 62) ^ (lo << 57));
	out->hi = cpu_to_le64(lo ^ (lo >> 1) ^ (lo >> 2) ^ (lo >> 7));
}

static void gf128hash_preparekey_fallback(struct gf128hash_key_x86 *key)
{
	polyval_mul_xm64_generic(&key->h_times_xm64,
				 &key->h_powers[NUM_H_POWERS - 1]);
	key->h_powers_xored[NUM_H_POWERS - 1] =
		key->h_powers[NUM_H_POWERS - 1].lo ^
		key->h_powers[NUM_H_POWERS - 1].hi;
	for (int i = NUM_H_POWERS - 2; i >= 0; i--) {
		key->h_powers[i] = key->h_powers[i + 1];
		polyval_mul_generic(&key->h_powers[i],
				    &key->h_powers[NUM_H_POWERS - 1]);
		key->h_powers_xored[i] = key->h_powers[i].lo ^
					 key->h_powers[i].hi;
	}
}

static __always_inline void
gf128hash_preparekey_x86(struct gf128hash_key_x86 *key, const u8 raw_key[16],
			 bool is_ghash)
{
	if (static_branch_likely(&have_pclmul) && likely(irq_fpu_usable())) {
		kernel_fpu_begin_mask(0);
		if (static_branch_likely(&have_pclmul_avx)) {
			if (is_ghash)
				ghash_preparekey_pclmul_avx(key, raw_key);
			else
				polyval_preparekey_pclmul_avx(key, raw_key);
		} else {
			if (is_ghash)
				ghash_preparekey_pclmul(key, raw_key);
			else
				polyval_preparekey_pclmul(key, raw_key);
		}
		kernel_fpu_end();
	} else {
		if (is_ghash)
			ghash_key_to_polyval(raw_key,
					     &key->h_powers[NUM_H_POWERS - 1]);
		else
			memcpy(&key->h_powers[NUM_H_POWERS - 1], raw_key,
			       POLYVAL_BLOCK_SIZE);
		gf128hash_preparekey_fallback(key);
	}
}

#define ghash_preparekey_arch ghash_preparekey_arch
static void ghash_preparekey_arch(struct ghash_key *key,
				  const u8 raw_key[GHASH_BLOCK_SIZE])
{
	gf128hash_preparekey_x86(&key->k, raw_key, true);
}

#define polyval_preparekey_arch polyval_preparekey_arch
static void polyval_preparekey_arch(struct polyval_key *key,
				    const u8 raw_key[POLYVAL_BLOCK_SIZE])
{
	gf128hash_preparekey_x86(&key->k, raw_key, false);
}

static void gf128hash_mul_x86(struct polyval_elem *acc,
			      const struct gf128hash_key_x86 *key)
{
	if (static_branch_likely(&have_pclmul) && likely(irq_fpu_usable())) {
		kernel_fpu_begin_mask(0);
		if (static_branch_likely(&have_pclmul_avx))
			gf128hash_mul_pclmul_avx(acc, key);
		else
			gf128hash_mul_pclmul(acc, key);
		kernel_fpu_end();
	} else {
		polyval_mul_generic(acc, &key->h_powers[NUM_H_POWERS - 1]);
	}
}

#define ghash_mul_arch ghash_mul_arch
static void ghash_mul_arch(struct polyval_elem *acc,
			   const struct ghash_key *key)
{
	gf128hash_mul_x86(acc, &key->k);
}

#define polyval_mul_arch polyval_mul_arch
static void polyval_mul_arch(struct polyval_elem *acc,
			     const struct polyval_key *key)
{
	gf128hash_mul_x86(acc, &key->k);
}

static __always_inline void
gf128hash_blocks_x86(struct polyval_elem *acc,
		     const struct gf128hash_key_x86 *key, const u8 *data,
		     size_t nblocks, bool is_ghash)
{
	if (static_branch_likely(&have_pclmul) && likely(irq_fpu_usable())) {
		do {
			/* Allow rescheduling every 4 KiB. */
			size_t n = min_t(size_t, nblocks,
					 4096 / GHASH_BLOCK_SIZE);

			kernel_fpu_begin_mask(0);
			if (static_branch_likely(&have_pclmul_avx)) {
				if (is_ghash)
					ghash_blocks_pclmul_avx(acc, key, data,
								n);
				else
					polyval_blocks_pclmul_avx(acc, key,
								  data, n);
			} else {
				if (is_ghash)
					ghash_blocks_pclmul(acc, key, data, n);
				else
					polyval_blocks_pclmul(acc, key, data,
							      n);
			}
			kernel_fpu_end();
			data += n * GHASH_BLOCK_SIZE;
			nblocks -= n;
		} while (nblocks);
	} else {
		if (is_ghash)
			ghash_blocks_generic(acc,
					     &key->h_powers[NUM_H_POWERS - 1],
					     data, nblocks);
		else
			polyval_blocks_generic(acc,
					       &key->h_powers[NUM_H_POWERS - 1],
					       data, nblocks);
	}
}

#define ghash_blocks_arch ghash_blocks_arch
static void ghash_blocks_arch(struct polyval_elem *acc,
			      const struct ghash_key *key, const u8 *data,
			      size_t nblocks)
{
	gf128hash_blocks_x86(acc, &key->k, data, nblocks, true);
}

#define polyval_blocks_arch polyval_blocks_arch
static void polyval_blocks_arch(struct polyval_elem *acc,
				const struct polyval_key *key,
				const u8 *data, size_t nblocks)
{
	gf128hash_blocks_x86(acc, &key->k, data, nblocks, false);
}

#define gf128hash_mod_init_arch gf128hash_mod_init_arch
static void gf128hash_mod_init_arch(void)
{
	if (!gf128hash_use_pclmul())
		return;

	if (gf128hash_use_pclmul_avx())
		static_branch_enable(&have_pclmul_avx);
	static_branch_enable(&have_pclmul);
}
