/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Shared x86_64 CPU feature predicates for GHASH, POLYVAL, and AES-GCM.
 *
 * libgf128hash and libaes share struct ghash_key on x86_64, so both must agree
 * on which key layout is active for the running CPU.
 *
 * Copyright 2026 Google LLC
 */
#ifndef _LIB_CRYPTO_X86_GF128HASH_CPU_H
#define _LIB_CRYPTO_X86_GF128HASH_CPU_H

#include <linux/cpufeature.h>

static inline bool gf128hash_use_pclmul(void)
{
	return IS_ENABLED(CONFIG_X86_64) &&
	       cpu_feature_enabled(X86_FEATURE_PCLMULQDQ);
}

static inline bool gf128hash_use_pclmul_avx(void)
{
	return gf128hash_use_pclmul() && cpu_feature_enabled(X86_FEATURE_AVX);
}

static inline bool gf128hash_use_vpclmul_avx2(void)
{
	return gf128hash_use_pclmul_avx() &&
	       cpu_feature_enabled(X86_FEATURE_VAES) &&
	       cpu_feature_enabled(X86_FEATURE_AVX2) &&
	       cpu_feature_enabled(X86_FEATURE_VPCLMULQDQ);
}

#endif /* _LIB_CRYPTO_X86_GF128HASH_CPU_H */
