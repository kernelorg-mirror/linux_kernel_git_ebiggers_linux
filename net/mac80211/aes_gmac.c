// SPDX-License-Identifier: GPL-2.0-only
/*
 * AES-GMAC for IEEE 802.11 BIP-GMAC-128 and BIP-GMAC-256
 * Copyright 2015, Qualcomm Atheros, Inc.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <crypto/aes-gcm.h>

#include <net/mac80211.h>
#include "aes_gmac.h"

int ieee80211_aes_gmac(const struct aes_gcm_key *key, const u8 *aad,
		       const u8 *nonce, const u8 *data, size_t data_len,
		       u8 *mic)
{
	static const u8 zero[IEEE80211_GMAC_MIC_LEN];
	struct aes_gcm_ctx ctx;
	const __le16 *fc;

	if (data_len < IEEE80211_GMAC_MIC_LEN)
		return -EINVAL;

	aes_gcm_init(&ctx, nonce, key);
	aes_gcm_auth_update(&ctx, aad, GMAC_AAD_LEN);

	fc = (const __le16 *)aad;
	if (ieee80211_is_beacon(*fc)) {
		/* mask Timestamp field to zero */
		aes_gcm_auth_update(&ctx, zero, 8);
		data += 8;
		data_len -= 8;
	}
	aes_gcm_auth_update(&ctx, data, data_len - IEEE80211_GMAC_MIC_LEN);
	aes_gcm_auth_update(&ctx, zero, IEEE80211_GMAC_MIC_LEN);
	aes_gcm_encrypt_final(&ctx, mic);
	return 0;
}
