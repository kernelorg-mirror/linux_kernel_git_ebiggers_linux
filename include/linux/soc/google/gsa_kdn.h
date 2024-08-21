/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2020 Google LLC
 */
#ifndef LINUX_SOC_GOOGLE_GSA_KDN_H
#define LINUX_SOC_GOOGLE_GSA_KDN_H

#include <linux/types.h>

struct device;

/*
 * GSA KDN interface
 *
 * KDN is a hardware block in the UFS storage controller that can be used
 * by GSA to program storage encryption keys. There are 16 individually
 * programmable key slots. The keys programmed in these slots can be used
 * to perform inline data encryption. GSA exclusively controls the sender
 * side of KDN interface and is the only entity that can manage these keys.
 */

#define KDN_NUM_SLOTS	15

/**
 * enum kdn_op_mode - KDN operating mode
 * @KDN_FMP_MODE: legacy FMP mode
 * @KDN_HW_KDF_MODE: HW key derivation mode
 * @KDN_SW_KDF_MODE: SW key derivation mode
 */
enum kdn_op_mode {
	KDN_FMP_MODE = 0,
	KDN_HW_KDF_MODE = 1,
	KDN_SW_KDF_MODE = 2,
};

/**
 * enum kdn_ufs_descr_type - UFS descriptor type
 * @KDN_UFS_DESCR_TYPE_PRDT: use PRDT descriptor
 * @KDN_UFS_DESCR_TYPE_UTRD: use UTRD descriptor
 */
enum kdn_ufs_descr_type {
	KDN_UFS_DESCR_TYPE_PRDT = 0,
	KDN_UFS_DESCR_TYPE_UTRD = 1,
};

#if IS_ENABLED(CONFIG_GOOGLE_SECURITY_ANCHOR)

/**
 * gsa_kdn_set_operating_mode - configure KDN operating mode
 * @dev: pointer to GSA device
 * @mode: &enum kdn_op_mode value to select crypto engine operating mode
 * @descr: one of &enum kdn_ufs_descr_type to select UFS descriptor format
 *
 * Return: 0 on success, negative error code otherwise
 */
int gsa_kdn_set_operating_mode(struct device *dev, enum kdn_op_mode mode,
			       enum kdn_ufs_descr_type descr);

/**
 * gsa_kdn_generate_key - import or generate a storage key
 */
int gsa_kdn_generate_key(struct device *dev,
			 const u8 *raw_key, size_t raw_key_size,
			 u8 *lt_key, size_t max_lt_key_size);

/**
 * gsa_kdn_ephemeral_wrap_key - ephemerally-wrap a storage key
 *
 * Return: 0 on success, negative error code otherwise
 */
int gsa_kdn_ephemeral_wrap_key(struct device *dev,
			       const u8 *lt_key, size_t lt_key_size,
			       u8 *eph_key, size_t max_eph_key_size);

/**
 * gsa_kdn_derive_sw_secret() - derive the "software secret" from a
 *				wrapped inline encryption key
 * @dev: pointer to GSA device
 * @buf: pointer to the buffer to store the derived secret
 * @buf_sz: size of the buffer specified by @buf parameter
 * @key_blob: pointer to the buffer containing ESK wrapped KDN key blob
 * @key_blob_len: number of bytes in @key_blob buffer
 *
 * This routine derives a 256-bit value from specified ESK wrapped GSA KDN key.
 *
 * Return: number of bytes placed into @buf buffer on success or a negative
 * error code otherwise.
 */
int gsa_kdn_derive_sw_secret(struct device *dev,
			     const u8 *lt_key, size_t lt_key_size,
			     u8 *sw_secret, size_t sw_secret_size);

/**
 * gsa_kdn_program_key() - program specified ESK wrapped GSA KDN key
 * @dev: pointer to GSA device
 * @slot: KDN slot to program specified key into
 * @key_blob: pointer to the buffer containing ESK wrapped KDN key blob
 * @key_blob_len: number of bytes in @key_blob buffer
 *
 * This routine modifies the key in the specified KDN slot (0-15 is a valid
 * key slot range). If a new key is specified (@key_blob and @key_blob_len
 * specify a buffer containing a valid ESK wrapped GSA KDN), the new key is
 * programmed. If a new key is not specified (@key_blob is NULL and
 * @key_blob_len is 0), the previously programmed key in the slot (if any) is
 * erased. If the caller specifies an invalid key, the previously programmed key
 * remains unchanged and an error is returned.
 *
 * Return: 0 on success or a negative error code otherwise
 */
int gsa_kdn_program_key(struct device *dev, u32 slot,
			const u8 *eph_key, size_t eph_key_size);

/**
 * gsa_kdn_restore_keys() - reprogram all previously programmed KDN keys
 * @dev: pointer to GSA device
 *
 * This routine can be called to restore the KDN controller state in case the
 * storage controller loses its state due to a power collapse.
 *
 * Return: 0 on success or a negative error code otherwise
 */
int gsa_kdn_restore_keys(struct device *dev);

#else /* CONFIG_GOOGLE_SECURITY_ANCHOR */

static inline int gsa_kdn_set_operating_mode(struct device *dev,
					     enum kdn_op_mode mode,
					     enum kdn_ufs_descr_type descr)
{
	return -EOPNOTSUPP;
}

static inline int gsa_kdn_generate_key(struct device *dev,
				       const u8 *raw_key, size_t raw_key_size,
				       u8 *lt_key, size_t max_lt_key_size)
{
	return -EOPNOTSUPP;
}

static inline int gsa_kdn_ephemeral_wrap_key(struct device *dev,
					     const u8 *lt_key,
					     size_t lt_key_size,
					     u8 *eph_key,
					     size_t max_eph_key_size)
{
	return -EOPNOTSUPP;
}

static inline int gsa_kdn_derive_sw_secret(struct device *dev,
					   const u8 *lt_key, size_t lt_key_size,
					   u8 *sw_secret,
					   size_t sw_secret_size)
{
	return -EOPNOTSUPP;
}

static inline int gsa_kdn_program_key(struct device *dev, u32 slot,
				      const u8 *eph_key, size_t eph_key_size)
{
	return -EOPNOTSUPP;
}

static inline int gsa_kdn_restore_keys(struct device *dev)
{
	return -EOPNOTSUPP;
}
#endif /* !CONFIG_GOOGLE_SECURITY_ANCHOR */

#endif /* LINUX_SOC_GOOGLE_GSA_KDN_H */
