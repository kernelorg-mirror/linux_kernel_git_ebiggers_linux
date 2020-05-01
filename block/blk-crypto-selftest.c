// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */

/*
 * Self-test for inline encryption hardware.
 *
 * For a given encryption algorithm and data unit size, this test decrypts some
 * sectors from the device using inline decryption and compares the result with
 * that gotten with the kernel's crypto API.  Several (key, DUN) combinations
 * are tested.
 *
 * We can't change the data on-disk as we don't know what it is here, so we test
 * decryption only.  This is good enough because there would be lots of obvious
 * data corruption if encryption wasn't the inverse of decryption, so the
 * problem would be noticed without this test.  I.e. the real point of this test
 * is to prevent cases where everything seems to be working but the crypto is
 * actually being done incorrectly.
 *
 * FIXME: this test assumes that the data on disk is not being concurrently
 * modified.
 */

#define pr_fmt(fmt) "blk-crypto-selftest: " fmt

#include <crypto/skcipher.h>
#include <linux/blk-crypto.h>
#include <linux/blkdev.h>
#include <linux/keyslot-manager.h>
#include <linux/random.h>

#include "blk-crypto-internal.h"

#define NUM_PAGES	16
#define START_SECTOR	0

static const u64 duns_to_test[][BLK_CRYPTO_DUN_ARRAY_SIZE] = {
	{ 0 },
	{ 0x1000000000000000 },
	{ 0x0000000000000001 },
	{ 0x0808080808080808 },
	{ 0x6824a1e138577679 },
	{ 0xfffffffffffffff0 },
};

union blk_crypto_iv {
	__le64 dun[BLK_CRYPTO_DUN_ARRAY_SIZE];
	u8 bytes[BLK_CRYPTO_MAX_IV_SIZE];
};

struct blk_crypto_selftest_ctx {
	struct page *raw_pages[NUM_PAGES];
	struct page *decrypted_pages[NUM_PAGES];
	u8 raw_key[BLK_CRYPTO_MAX_KEY_SIZE];
	struct blk_crypto_key blk_key;
};

static int read_data_from_disk(struct block_device *bdev, sector_t sector,
			       const struct blk_crypto_key *blk_key,
			       const u64 dun[BLK_CRYPTO_DUN_ARRAY_SIZE],
			       struct page **dst_pages, int num_pages)
{
	struct bio *bio;
	int i;
	int err;

	bio = bio_alloc(GFP_KERNEL, num_pages);
	bio_set_dev(bio, bdev);
	bio->bi_iter.bi_sector = sector;
	bio->bi_opf = REQ_OP_READ;
	for (i = 0; i < num_pages; i++)
		bio_add_page(bio, dst_pages[i], PAGE_SIZE, 0);
	if (blk_key)
		bio_crypt_set_ctx(bio, blk_key, dun, GFP_KERNEL);
	err = submit_bio_wait(bio);
	if (err)
		pr_err("I/O error while testing inline decryption on %pg [err=%d]\n",
		       bdev, err);
	bio_put(bio);
	return err;
}

static bool pages_equal(struct page *pg1, struct page *pg2)
{
	void *pa, *pb;
	bool equal;

	pa = kmap_atomic(pg1);
	pb = kmap_atomic(pg2);
	equal = (memcmp(pa, pb, PAGE_SIZE) == 0);
	kunmap_atomic(pa);
	kunmap_atomic(pb);

	return equal;
}

static void blk_crypto_dun_to_iv(const u64 dun[BLK_CRYPTO_DUN_ARRAY_SIZE],
				 union blk_crypto_iv *iv)
{
	int i;

	for (i = 0; i < BLK_CRYPTO_DUN_ARRAY_SIZE; i++)
		iv->dun[i] = cpu_to_le64(dun[i]);
}

static int validate_decrypted_data(struct page **raw_pages,
				   struct page **decrypted_pages, int num_pages,
				   const struct blk_crypto_key *blk_key,
				   const u64 dun[BLK_CRYPTO_DUN_ARRAY_SIZE])
{
	const struct blk_crypto_mode *mode =
		&blk_crypto_modes[blk_key->crypto_cfg.crypto_mode];
	const unsigned int data_unit_size = blk_key->crypto_cfg.data_unit_size;
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct page *page = NULL;
	u64 curr_dun[BLK_CRYPTO_DUN_ARRAY_SIZE];
	struct scatterlist src;
	struct scatterlist dst;
	union blk_crypto_iv iv;
	DECLARE_CRYPTO_WAIT(wait);
	int i, j;
	int err;

	/* Set up a crypto API transform with the same algorithm and key. */
	tfm = crypto_alloc_skcipher(mode->cipher_str, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("failed to allocate '%s' from crypto API [err=%ld]\n",
		       mode->cipher_str, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	err = crypto_skcipher_setkey(tfm, blk_key->raw, blk_key->size);
	if (err) {
		pr_err("failed to set key for '%s' [err=%d]\n",
		       mode->cipher_str, err);
		goto out;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP |
				      CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &src, &dst, data_unit_size, iv.bytes);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		err = -ENOMEM;
		goto out;
	}

	memcpy(curr_dun, dun, sizeof(curr_dun));
	sg_init_table(&src, 1);
	sg_init_table(&dst, 1);

	/* Decrypt each page with crypto API and compare with hardware result */
	for (i = 0; i < num_pages; i++) {
		/* Decrypt each data unit in the page */
		for (j = 0; j < PAGE_SIZE; j += data_unit_size) {
			blk_crypto_dun_to_iv(curr_dun, &iv);
			sg_set_page(&src, raw_pages[i], data_unit_size, j);
			sg_set_page(&dst, page, data_unit_size, j);
			err = crypto_wait_req(crypto_skcipher_decrypt(req),
					      &wait);
			if (err) {
				pr_err("'%s' crypto API decryption failure [err=%d]\n",
				       mode->cipher_str, err);
				goto out;
			}
			bio_crypt_dun_increment(curr_dun, 1);
		}
		/* Compare the decrypted pages */
		if (!pages_equal(decrypted_pages[i], page)) {
			blk_crypto_dun_to_iv(dun, &iv);
			pr_err("software and hardware results differ on page %d of %d with key=%*phN, iv=%*phN\n",
			       i + 1, num_pages, blk_key->size, blk_key->raw,
			       (int)mode->ivsize, iv.bytes);
			err = -ELIBBAD;
			goto out;
		}
	}
	err = 0;
out:
	if (page)
		__free_page(page);
	skcipher_request_free(req);
	crypto_free_skcipher(tfm);
	return err;
}

static int run_selftest(struct block_device *bdev,
			enum blk_crypto_mode_num crypto_mode,
			unsigned int data_unit_size)
{
	struct blk_crypto_selftest_ctx *ctx;
	int i;
	int err;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	for (i = 0; i < NUM_PAGES; i++) {
		ctx->raw_pages[i] = alloc_page(GFP_KERNEL);
		ctx->decrypted_pages[i] = alloc_page(GFP_KERNEL);
		if (!ctx->raw_pages[i] || !ctx->decrypted_pages[i]) {
			err = -ENOMEM;
			goto out;
		}
	}

	for (i = 0; i < ARRAY_SIZE(duns_to_test); i++) {

		/* Generate a random key */
		prandom_bytes(ctx->raw_key, sizeof(ctx->raw_key));
		err = blk_crypto_init_key(&ctx->blk_key, ctx->raw_key,
					  crypto_mode, 8, data_unit_size);
		if (err)
			goto out;

		/* Read some raw data from the disk with no decryption */
		err = read_data_from_disk(bdev, START_SECTOR,
					  NULL, duns_to_test[i],
					  ctx->raw_pages, NUM_PAGES);
		if (err)
			goto out;

		/* Read some raw data from the disk with inline decryption */
		err = read_data_from_disk(bdev, START_SECTOR,
					  &ctx->blk_key, duns_to_test[i],
					  ctx->decrypted_pages, NUM_PAGES);
		if (err)
			goto out;

		/* Compare the inline-decrypted data with the expected result */
		err = validate_decrypted_data(ctx->raw_pages,
					      ctx->decrypted_pages, NUM_PAGES,
					      &ctx->blk_key, duns_to_test[i]);
		if (err)
			goto out;

		blk_crypto_evict_key(bdev_get_queue(bdev), &ctx->blk_key);
	}
	err = 0;
out:
	blk_crypto_evict_key(bdev_get_queue(bdev), &ctx->blk_key);
	for (i = 0; i < NUM_PAGES; i++) {
		if (ctx->raw_pages[i])
			__free_page(ctx->raw_pages[i]);
		if (ctx->decrypted_pages[i])
			__free_page(ctx->decrypted_pages[i]);
	}
	kfree(ctx);
	return err;
}

/**
 * blk_crypto_selftest() - run the inline encryption self-test if not already
 *			   done
 * @bdev: the device to use.  Must claim to support inline encryption with the
 *	  specified @cfg.
 * @cfg: the specified crypto configuration to test
 *
 * Return: 0 if test passed (or already passed),
 *	   -errno if test failed (or already failed)
 */
int blk_crypto_selftest(struct block_device *bdev,
			const struct blk_crypto_config *cfg)
{
	struct blk_keyslot_manager *ksm = bdev_get_queue(bdev)->ksm;
	enum blk_crypto_mode_num crypto_mode = cfg->crypto_mode;
	unsigned int data_unit_size = cfg->data_unit_size;
	unsigned int bit = ilog2(data_unit_size);
	int res;

	if (test_and_set_bit(bit,
			     &ksm->crypto_modes_test_started[crypto_mode])) {
		wait_on_bit_io(&ksm->crypto_modes_untested[crypto_mode], bit,
			       TASK_UNINTERRUPTIBLE);
		if (test_bit(bit, &ksm->crypto_modes_supported[crypto_mode]))
			return 0;
		return -ELIBBAD;
	}

	res = run_selftest(bdev, crypto_mode, data_unit_size);
	if (res) {
		pr_err("failed with %s, data_unit_size=%d!  Disabling hardware inline encryption on %pg.\n",
		       blk_crypto_modes[crypto_mode].cipher_str,
		       data_unit_size, bdev);
		clear_bit(bit, &ksm->crypto_modes_supported[crypto_mode]);
	} else {
		pr_info("passed with %s, data_unit_size=%d on %pg\n",
			blk_crypto_modes[crypto_mode].cipher_str,
			data_unit_size, bdev);
	}
	clear_and_wake_up_bit(bit, &ksm->crypto_modes_untested[crypto_mode]);
	return res;
}
