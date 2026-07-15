/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2003-2004, Instant802 Networks, Inc.
 * Copyright 2006, Devicescape Software, Inc.
 */

#ifndef AES_CCM_H
#define AES_CCM_H

#include <asm/byteorder.h>
#include <crypto/aes-ccm.h>

#define CCM_AAD_LEN	32

static inline int ieee80211_aes_ccm_encrypt(const struct aes_ccm_key *key,
					    const u8 *b_0, const u8 *aad,
					    u8 *data, size_t data_len, u8 *mic)
{
	return aes_ccm_encrypt(data, data, data_len, mic, aad + 2,
			       be16_to_cpup((__be16 *)aad), b_0 + 1, 13, key);
}

static inline int ieee80211_aes_ccm_decrypt(const struct aes_ccm_key *key,
					    const u8 *b_0, const u8 *aad,
					    u8 *data, size_t data_len,
					    const u8 *mic)
{
	return aes_ccm_decrypt(data, data, data_len, mic, aad + 2,
			       be16_to_cpup((__be16 *)aad), b_0 + 1, 13, key);
}

#endif /* AES_CCM_H */
