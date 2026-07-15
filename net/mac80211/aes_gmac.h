/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2015, Qualcomm Atheros, Inc.
 */

#ifndef AES_GMAC_H
#define AES_GMAC_H

#include <crypto/aes-gcm.h>

#define GMAC_AAD_LEN	20
#define GMAC_NONCE_LEN	12

int ieee80211_aes_gmac(const struct aes_gcm_key *key, const u8 *aad,
		       const u8 *nonce, const u8 *data, size_t data_len,
		       u8 *mic);

#endif /* AES_GMAC_H */
