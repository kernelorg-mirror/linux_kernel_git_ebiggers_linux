// SPDX-License-Identifier: GPL-2.0-only
/*
 * Platform device driver for the Google Security Anchor (GSA), also known as
 * the Google Tensor security core
 *
 * Copyright 2020 Google LLC
 */
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/soc/google/gsa_kdn.h>

#include "gsa_mbox.h"

#define GSA_BB_SIZE	PAGE_SIZE

struct gsa_dev_state {
	struct device *dev;
	struct gsa_mbox *mbox;
	dma_addr_t bb_da;
	void *bb_va;
	struct mutex bb_lock; /* protects access to bounce buffer */
};

/*
 *  Internal command interface
 */
static int gsa_send_cmd(struct device *dev, u32 cmd, const u32 *req,
			u32 req_argc, u32 *rsp, u32 rsp_argc)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct gsa_dev_state *s = platform_get_drvdata(pdev);

	return gsa_send_mbox_cmd(s->mbox, cmd, req, req_argc, rsp, rsp_argc);
}

static int send_kdn_cmd_locked(struct gsa_dev_state *s, u32 cmd, u32 opts,
			       const void *src_data, size_t src_data_len,
			       void *dst_buf, size_t max_dst_data_len)
{
	u32 req[5] = {
		/* data_buf_addr_lo= */ lower_32_bits(s->bb_da),
		/* data_buf_addr_hi= */ upper_32_bits(s->bb_da),
		/* data_buf_len= */ GSA_BB_SIZE,
		/* src_data_len= */ src_data_len,
		/* option= */ opts,
	};
	u32 dst_data_len;
	int ret;

	/* copy in data */
	if (src_data_len) {
		if (src_data_len > GSA_BB_SIZE)
			return -EINVAL; /* too much data */
		memcpy(s->bb_va, src_data, src_data_len);
	}

	/* Invoke KDN command */
	ret = gsa_send_mbox_cmd(s->mbox, cmd, req, ARRAY_SIZE(req),
				&dst_data_len, 1);
	if (ret < 0)
		return ret;

	if (ret != 1)
		return -EINVAL; /* unexpected reply */

	/* copy out data */
	if (dst_data_len) {
		if (dst_data_len > max_dst_data_len)
			return -EINVAL; /* buffer too short */
		memcpy(dst_buf, s->bb_va, dst_data_len);
	}
	return dst_data_len;
}

/*
 * Send a Key Distribution Network (KDN) command
 */
static int send_kdn_cmd(struct device *dev, u32 cmd, u32 opts,
			const void *src_data, size_t src_data_len,
			void *dst_buf, size_t max_dst_data_len)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct gsa_dev_state *s = platform_get_drvdata(pdev);
	int ret;

	mutex_lock(&s->bb_lock);
	ret = send_kdn_cmd_locked(s, cmd, opts, src_data, src_data_len,
				  dst_buf, max_dst_data_len);
	mutex_unlock(&s->bb_lock);

	return ret;
}

int gsa_kdn_set_operating_mode(struct device *dev, enum kdn_op_mode mode,
			       enum kdn_ufs_descr_type descr)
{
	u32 req[] = { mode, descr };
	int ret;

	ret = gsa_send_cmd(dev, GSA_MB_CMD_KDN_SET_OP_MODE,
			   req, ARRAY_SIZE(req), NULL, 0);
	if (ret < 0) {
		dev_err(dev,
			"Failed to set KDN operating mode; mode=%d, descr=%d, err=%d\n",
			mode, descr, ret);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(gsa_kdn_set_operating_mode);

int gsa_kdn_generate_key(struct device *dev,
			 const u8 *raw_key, size_t raw_key_size,
			 u8 *lt_key, size_t max_lt_key_size)
{
	int ret;

	ret = send_kdn_cmd(dev, GSA_MB_CMD_KDN_GENERATE_KEY, 0,
			   raw_key, raw_key_size, lt_key, max_lt_key_size);
	if (ret < 0) {
		if (raw_key)
			dev_err(dev, "Failed to import key; err=%d\n", ret);
		else
			dev_err(dev, "Failed to generate key; err=%d\n", ret);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(gsa_kdn_generate_key);

int gsa_kdn_ephemeral_wrap_key(struct device *dev,
			       const u8 *lt_key, size_t lt_key_size,
			       u8 *eph_key, size_t max_eph_key_size)
{
	int ret;

	ret = send_kdn_cmd(dev, GSA_MB_CMD_KDN_EPHEMERAL_WRAP_KEY, 0,
			   lt_key, lt_key_size, eph_key, max_eph_key_size);
	if (ret < 0)
		dev_err(dev, "Failed to ephemerally-wrap key; err=%d\n", ret);
	return ret;
}
EXPORT_SYMBOL_GPL(gsa_kdn_ephemeral_wrap_key);

int gsa_kdn_derive_sw_secret(struct device *dev,
			     const u8 *lt_key, size_t lt_key_size,
			     u8 *sw_secret, size_t sw_secret_size)
{
	int ret;

	ret = send_kdn_cmd(dev, GSA_MB_CMD_KDN_DERIVE_RAW_SECRET, 0,
			   lt_key, lt_key_size, sw_secret, sw_secret_size);
	if (ret < 0) {
		dev_err(dev, "Failed to derive software secret; err=%d\n", ret);
		return ret;
	}
	if (ret != sw_secret_size) {
		dev_err(dev, "GSA returned too-short software secret\n");
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(gsa_kdn_derive_sw_secret);

int gsa_kdn_program_key(struct device *dev, u32 slot,
			const u8 *eph_key, size_t eph_key_size)
{
	int ret;

	ret = send_kdn_cmd(dev, GSA_MB_CMD_KDN_PROGRAM_KEY, slot,
			   eph_key, eph_key_size, NULL, 0);
	if (ret < 0) {
		if (eph_key)
			dev_err(dev, "Failed to program key; err=%d\n", ret);
		else
			dev_err(dev, "Failed to evict key; err=%d\n", ret);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(gsa_kdn_program_key);

int gsa_kdn_restore_keys(struct device *dev)
{
	int ret;

	/* Restore keys is a special no argument command */
	ret = gsa_send_cmd(dev, GSA_MB_CMD_KDN_RESTORE_KEYS, NULL, 0, NULL, 0);
	if (ret < 0) {
		dev_err(dev, "Failed to restore keys; err=%d\n", ret);
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(gsa_kdn_restore_keys);

/********************************************************************/

static int gsa_probe(struct platform_device *pdev)
{
	int err;
	struct gsa_dev_state *s;
	struct device *dev = &pdev->dev;

	s = devm_kzalloc(dev, sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	s->dev = dev;
	mutex_init(&s->bb_lock);
	platform_set_drvdata(pdev, s);

	/*
	 * Set DMA mask and coherent to 36-bit as it is what GSA supports.
	 */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(36));
	if (err) {
		dev_err(dev, "failed (%d) to setup dma mask\n", err);
		return err;
	}

	/* initialize mailbox */
	s->mbox = gsa_mbox_init(pdev);
	if (IS_ERR(s->mbox))
		return PTR_ERR(s->mbox);

	/* add children */
	err = devm_of_platform_populate(dev);
	if (err < 0) {
		dev_err(dev, "populate children failed (%d)\n", err);
		return err;
	}

	/* alloc bounce buffer */
	s->bb_va = dmam_alloc_coherent(dev, GSA_BB_SIZE, &s->bb_da, GFP_KERNEL);
	if (!s->bb_va)
		return -ENOMEM;

	return 0;
}

static void gsa_remove(struct platform_device *pdev)
{
}

static const struct of_device_id gsa_of_match[] = {
	{ .compatible = "google,gs101-gsa", },
	{},
};
MODULE_DEVICE_TABLE(of, gsa_of_match);

static struct platform_driver gsa_driver = {
	.probe = gsa_probe,
	.remove = gsa_remove,
	.driver	= {
		.name = "gsa",
		.of_match_table = gsa_of_match,
	},
};

static int __init gsa_driver_init(void)
{
	return platform_driver_register(&gsa_driver);
}

static void __exit gsa_driver_exit(void)
{
	platform_driver_unregister(&gsa_driver);
}

MODULE_DESCRIPTION("Google Tensor Security Core platform driver");
MODULE_LICENSE("GPL");
module_init(gsa_driver_init);
module_exit(gsa_driver_exit);
