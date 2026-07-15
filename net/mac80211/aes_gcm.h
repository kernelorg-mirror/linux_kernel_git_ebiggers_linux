/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2014-2015, Qualcomm Atheros, Inc.
 */

#ifndef AES_GCM_H
#define AES_GCM_H

#include <asm/byteorder.h>
#include <crypto/aes-gcm.h>

#define GCM_AAD_LEN	32

static inline void ieee80211_aes_gcm_encrypt(const struct aes_gcm_key *key,
					     const u8 *j_0, const u8 *aad,
					     u8 *data, size_t data_len, u8 *mic)
{
	aes_gcm_encrypt(data, data, data_len, mic, aad + 2,
			be16_to_cpup((__be16 *)aad), j_0, key);
}

static inline int ieee80211_aes_gcm_decrypt(const struct aes_gcm_key *key,
					    const u8 *j_0, const u8 *aad,
					    u8 *data, size_t data_len,
					    const u8 *mic)
{
	return aes_gcm_decrypt(data, data, data_len, mic, aad + 2,
			       be16_to_cpup((__be16 *)aad), j_0, key);
}

#endif /* AES_GCM_H */
