// SPDX-License-Identifier: GPL-2.0-only
/*
 * Crypto algorithm benchmark and testing module
 *
 * Copyright 2018 Google LLC
 */

#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <crypto/skcipher.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>

#undef pr_fmt
#define pr_fmt(fmt) "cryptobench: " fmt

static char cryptobench_results[4096];
static DEFINE_MUTEX(cryptobench_mutex);

static atomic_t cryptobench_async_remaining;
static DECLARE_COMPLETION(cryptobench_async_completion);

#define MAX_KEYSIZE 64

enum cryptobench_result {
	SUCCESS = 0,
	ALG_NOT_FOUND,
	ALG_ALLOCATION_ERROR,
	KEYSIZE_NOT_SUPPORTED,
	CRYPTO_ERROR,
	CRYPTO_INCORRECT,
	BAD_PARAMETERS,
	OUT_OF_MEMORY,
};

static const char *const result_strings[] = {
	[SUCCESS] = "SUCCESS",
	[ALG_NOT_FOUND] = "ALG_NOT_FOUND",
	[ALG_ALLOCATION_ERROR] = "ALG_ALLOCATION_ERROR",
	[KEYSIZE_NOT_SUPPORTED] = "KEYSIZE_NOT_SUPPORTED",
	[CRYPTO_ERROR] = "CRYPTO_ERROR",
	[CRYPTO_INCORRECT] = "CRYPTO_INCORRECT",
	[BAD_PARAMETERS] = "BAD_PARAMETERS",
	[OUT_OF_MEMORY] = "OUT_OF_MEMORY",
};

struct cryptobench_params {
	char *algtype;
	char *algname;
	int keysize;
	unsigned long niter;
	unsigned long datasize;
	unsigned long aadsize;
	bool inplace;
	bool force_ahash;
	bool async;
	unsigned long long random_seed;
};

static u32 rand32(struct cryptobench_params *params)
{
	params->random_seed *= 25214903917;
	params->random_seed += 11;
	params->random_seed &= ((u64)1 << 48) - 1;
	return params->random_seed >> 16;
}

static void rand_bytes(struct cryptobench_params *params, void *buf,
		       size_t size)
{
	u8 *p = buf;

	while (size--)
		*p++ = rand32(params);
}

static u64 measure_buf(const void *buf, size_t size)
{
	union {
		u8 b[SHA256_DIGEST_SIZE];
		__le64 w64;
	} digest;

	sha256(buf, size, digest.b);
	return le64_to_cpu(digest.w64);
}

static void cryptobench_init_async(int count)
{
	atomic_set(&cryptobench_async_remaining, count);
	init_completion(&cryptobench_async_completion);
}

static void cryptobench_dec_async_remaining(void)
{
	if (atomic_dec_and_test(&cryptobench_async_remaining))
		complete(&cryptobench_async_completion);
}

static void cryptobench_cancel(int remaining)
{
	if (atomic_sub_and_test(remaining, &cryptobench_async_remaining))
		complete(&cryptobench_async_completion);
	wait_for_completion(&cryptobench_async_completion);
}

static void cryptobench_skcipher_req_done(void *req, int err)
{
	if (err != -EINPROGRESS && err != -EBUSY) {
		WARN_ON(err);
		cryptobench_dec_async_remaining();
		skcipher_request_free(req);
	}
}

static void cryptobench_ahash_req_done(void *req, int err)
{
	if (err != -EINPROGRESS && err != -EBUSY) {
		WARN_ON(err);
		cryptobench_dec_async_remaining();
		ahash_request_free(req);
	}
}

static ssize_t cryptobench_read(struct file *f, char __user *ubuf, size_t size,
				loff_t *off)
{
	size_t len;
	ssize_t ret = 0;

	mutex_lock(&cryptobench_mutex);
	len = strnlen(cryptobench_results, sizeof(cryptobench_results));

	if (*off >= len)
		goto out;

	len = min_t(size_t, size, len - *off);
	ret = -EFAULT;
	if (copy_to_user(ubuf, &cryptobench_results[*off], len))
		goto out;

	ret = len;
	*off += len;
out:
	mutex_unlock(&cryptobench_mutex);
	return ret;
}

static enum cryptobench_result
benchmark_skcipher(struct cryptobench_params *params)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	const char *driver_name = NULL;
	u8 orig_iv[32];
	u8 iv[32] __aligned(8);
	void *inbuf = NULL, *outbuf = NULL, *orig_data = NULL;
	unsigned long i;
	unsigned long parity = 0;
	struct scatterlist src, dst;
	u64 t1, t2, t3;
	u64 measurement = 0;
	int err;
	DECLARE_CRYPTO_WAIT(wait);
	enum cryptobench_result result;
	u8 key[MAX_KEYSIZE];

	if (params->keysize < 1 || params->keysize > MAX_KEYSIZE) {
		pr_err("bad value for 'keysize' option");
		return BAD_PARAMETERS;
	}

	rand_bytes(params, orig_iv, sizeof(orig_iv));
	rand_bytes(params, key, params->keysize);

	orig_data = kmalloc(params->datasize, GFP_KERNEL);
	inbuf = kzalloc(params->datasize, GFP_KERNEL);
	if (!orig_data || !inbuf) {
		result = OUT_OF_MEMORY;
		goto out;
	}
	sg_init_one(&src, inbuf, params->datasize);
	rand_bytes(params, orig_data, params->datasize);
	memcpy(inbuf, orig_data, params->datasize);

	if (params->inplace) {
		outbuf = inbuf;
		dst = src;
	} else {
		outbuf = kmalloc(params->datasize, GFP_KERNEL);
		if (!outbuf) {
			result = OUT_OF_MEMORY;
			goto out;
		}
		sg_init_one(&dst, outbuf, params->datasize);
	}

	tfm = crypto_alloc_skcipher(params->algname, 0, 0);
	if (IS_ERR(tfm)) {
		if (PTR_ERR(tfm) == -ENOENT) {
			result = ALG_NOT_FOUND;
		} else {
			pr_err("error allocating %s: %ld\n", params->algname,
			       PTR_ERR(tfm));
			result = ALG_ALLOCATION_ERROR;
		}
		tfm = NULL;
		goto out;
	}
	driver_name = crypto_skcipher_driver_name(tfm);

	err = crypto_skcipher_setkey(tfm, key, params->keysize);
	if (err) {
		result = KEYSIZE_NOT_SUPPORTED;
		goto out;
	}

	if (params->async) {
		cryptobench_init_async(params->niter);
		t1 = ktime_get_ns();
		for (i = 0; i < params->niter; i++) {
			struct skcipher_request *req =
				skcipher_request_alloc(tfm, GFP_KERNEL);
			skcipher_request_set_crypt(req, &dst, &src,
						   params->datasize, orig_iv);
			skcipher_request_set_callback(
				req,
				CRYPTO_TFM_REQ_MAY_SLEEP |
					CRYPTO_TFM_REQ_MAY_BACKLOG,
				cryptobench_skcipher_req_done, req);
			err = crypto_skcipher_encrypt(req);
			if (err != -EINPROGRESS && err != -EBUSY) {
				skcipher_request_free(req);
				if (err) {
					pr_err("encryption error w/ alg %s: %d\n",
					       driver_name, err);
					result = CRYPTO_ERROR;
					cryptobench_cancel(params->niter - i);
					goto out;
				}
				cryptobench_dec_async_remaining();
			}
		}
		wait_for_completion(&cryptobench_async_completion);
		t2 = ktime_get_ns();

		cryptobench_init_async(params->niter);
		for (i = 0; i < params->niter; i++) {
			req = skcipher_request_alloc(tfm, GFP_KERNEL);
			skcipher_request_set_crypt(req, &dst, &src,
						   params->datasize, orig_iv);
			skcipher_request_set_callback(
				req,
				CRYPTO_TFM_REQ_MAY_SLEEP |
					CRYPTO_TFM_REQ_MAY_BACKLOG,
				cryptobench_skcipher_req_done, req);
			err = crypto_skcipher_decrypt(req);
			if (err != -EINPROGRESS && err != -EBUSY) {
				skcipher_request_free(req);
				if (err) {
					pr_err("decryption error w/ alg %s: %d\n",
					       driver_name, err);
					result = CRYPTO_ERROR;
					cryptobench_cancel(params->niter - i);
					goto out;
				}
				cryptobench_dec_async_remaining();
			}
		}
		wait_for_completion(&cryptobench_async_completion);
		t3 = ktime_get_ns();
	} else {
		req = skcipher_request_alloc(tfm, GFP_KERNEL);
		if (!req) {
			result = OUT_OF_MEMORY;
			goto out;
		}

		skcipher_request_set_callback(
			req,
			CRYPTO_TFM_REQ_MAY_SLEEP | CRYPTO_TFM_REQ_MAY_BACKLOG,
			crypto_req_done, &wait);

		cond_resched();
		t1 = ktime_get_ns();
		for (i = 0; i < params->niter; i++) {
			memcpy(iv, orig_iv, sizeof(iv));
			*(u64 *)iv += i;
			if (parity++ & 1) {
				skcipher_request_set_crypt(
					req, &dst, &src, params->datasize, iv);
			} else {
				skcipher_request_set_crypt(
					req, &src, &dst, params->datasize, iv);
			}
			err = crypto_wait_req(crypto_skcipher_encrypt(req),
					      &wait);
			if (err) {
				pr_err("encryption error w/ alg %s: %d\n",
				       driver_name, err);
				result = CRYPTO_ERROR;
				skcipher_request_free(req);
				goto out;
			}
		}
		t2 = ktime_get_ns();
		if (params->datasize &&
		    !memcmp(orig_data, (params->niter & 1) ? outbuf : inbuf,
			    params->datasize)) {
			pr_err("encryption w/ alg %s didn't do anything!\n",
			       driver_name);
			result = CRYPTO_INCORRECT;
			skcipher_request_free(req);
			goto out;
		}
		measurement = measure_buf((params->niter & 1) ? outbuf : inbuf,
					  params->datasize);
		cond_resched();
		t2 = ktime_get_ns();
		for (i = 0; i < params->niter; i++) {
			memcpy(iv, orig_iv, sizeof(iv));
			*(u64 *)iv += params->niter - 1 - i;
			if (parity++ & 1) {
				skcipher_request_set_crypt(
					req, &dst, &src, params->datasize, iv);
			} else {
				skcipher_request_set_crypt(
					req, &src, &dst, params->datasize, iv);
			}
			err = crypto_wait_req(crypto_skcipher_decrypt(req),
					      &wait);
			if (err) {
				pr_err("decryption error w/ alg %s: %d\n",
				       driver_name, err);
				result = CRYPTO_ERROR;
				skcipher_request_free(req);
				goto out;
			}
		}
		t3 = ktime_get_ns();
		cond_resched();
		skcipher_request_free(req);

		if (memcmp(orig_data, inbuf, params->datasize)) {
			pr_err("%s decryption didn't invert encryption!\n",
			       driver_name);
			result = CRYPTO_INCORRECT;
			goto out;
		}
	}

	sprintf(cryptobench_results,
		"SUCCESS algname=%s driver_name=%s measurement=%#016llx enc_time=%llu dec_time=%llu\n",
		params->algname, driver_name, measurement, t2 - t1, t3 - t2);
	result = SUCCESS;
out:
	crypto_free_skcipher(tfm);
	kfree(inbuf);
	if (inbuf != outbuf)
		kfree(outbuf);
	kfree(orig_data);
	return result;
}

static enum cryptobench_result benchmark_aead(struct cryptobench_params *params)
{
	struct crypto_aead *tfm;
	const char *driver_name;
	int tagsize;
	struct aead_request *req;
	u8 key[MAX_KEYSIZE];
	u8 orig_iv[32];
	u8 iv[32];
	void *aad = NULL, *orig_data = NULL, *inbuf = NULL, *outbuf = NULL;
	unsigned long i;
	struct scatterlist src[2], _dst[2];
	struct scatterlist *dst;
	u64 t1, t2, t3;
	u64 measurement;
	int err;
	DECLARE_CRYPTO_WAIT(wait);
	enum cryptobench_result result;

	if (params->keysize < 1 || params->keysize > MAX_KEYSIZE) {
		pr_err("bad value for 'keysize' option");
		return BAD_PARAMETERS;
	}

	tfm = crypto_alloc_aead(params->algname, 0, 0);
	if (IS_ERR(tfm)) {
		if (PTR_ERR(tfm) == -ENOENT)
			return ALG_NOT_FOUND;
		pr_err("error allocating %s: %ld\n", params->algname,
		       PTR_ERR(tfm));
		return ALG_ALLOCATION_ERROR;
	}
	driver_name = crypto_aead_driver_name(tfm);
	tagsize = crypto_aead_authsize(tfm);
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		result = OUT_OF_MEMORY;
		goto out;
	}

	rand_bytes(params, key, params->keysize);
	rand_bytes(params, orig_iv, sizeof(orig_iv));

	aad = kmalloc(params->aadsize, GFP_KERNEL);
	orig_data = kmalloc(params->datasize, GFP_KERNEL);
	inbuf = kzalloc(params->datasize + tagsize, GFP_KERNEL);
	if (!aad || !orig_data || !inbuf) {
		result = OUT_OF_MEMORY;
		goto out;
	}
	rand_bytes(params, aad, params->aadsize);
	rand_bytes(params, orig_data, params->datasize);
	memcpy(inbuf, orig_data, params->datasize);

	sg_init_table(src, 2);
	sg_set_buf(&src[0], aad, params->aadsize);
	sg_set_buf(&src[1], inbuf, params->datasize + tagsize);

	if (params->inplace) {
		pr_err("'inplace' option not yet implemented for AEADs");
		return BAD_PARAMETERS;
		/*outbuf = inbuf;*/
		/*dst = src;*/
	} else {
		dst = _dst;
		outbuf = kmalloc(params->datasize + tagsize, GFP_KERNEL);
		if (!outbuf) {
			result = OUT_OF_MEMORY;
			goto out;
		}
		sg_init_table(dst, 2);
		sg_set_buf(&dst[0], aad, params->aadsize);
		sg_set_buf(&dst[1], outbuf, params->datasize + tagsize);
	}

	err = crypto_aead_setkey(tfm, key, params->keysize);
	if (err) {
		result = KEYSIZE_NOT_SUPPORTED;
		goto out;
	}

	aead_request_set_callback(
		req, CRYPTO_TFM_REQ_MAY_SLEEP | CRYPTO_TFM_REQ_MAY_BACKLOG,
		crypto_req_done, &wait);

	cond_resched();
	t1 = ktime_get_ns();
	for (i = 0; i < params->niter; i++) {
		memcpy(iv, orig_iv, sizeof(iv));
		aead_request_set_crypt(req, src, dst, params->datasize, iv);
		aead_request_set_ad(req, params->aadsize);
		err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
		if (err) {
			pr_err("encryption error w/ alg %s: %d\n", driver_name,
			       err);
			result = CRYPTO_ERROR;
			goto out;
		}
	}
	t2 = ktime_get_ns();

	measurement = measure_buf(outbuf, params->datasize + tagsize);
	cond_resched();
	t2 = ktime_get_ns();
	for (i = 0; i < params->niter; i++) {
		memcpy(iv, orig_iv, sizeof(iv));
		aead_request_set_crypt(req, dst, src,
				       params->datasize + tagsize, iv);
		aead_request_set_ad(req, params->aadsize);
		err = crypto_wait_req(crypto_aead_decrypt(req), &wait);
		if (err) {
			pr_err("decryption error w/ alg %s: %d\n", driver_name,
			       err);
			result = CRYPTO_ERROR;
			goto out;
		}
	}
	t3 = ktime_get_ns();
	cond_resched();

	if (memcmp(orig_data, inbuf, params->datasize)) {
		pr_err("%s decryption didn't invert encryption!\n",
		       driver_name);
		result = CRYPTO_INCORRECT;
		goto out;
	}

	sprintf(cryptobench_results,
		"SUCCESS algname=%s driver_name=%s measurement=%#016llx enc_time=%llu dec_time=%llu\n",
		params->algname, driver_name, measurement, t2 - t1, t3 - t2);
	result = SUCCESS;
out:
	aead_request_free(req);
	crypto_free_aead(tfm);
	kfree(inbuf);
	if (inbuf != outbuf)
		kfree(outbuf);
	kfree(orig_data);
	kfree(aad);
	return result;
}

static enum cryptobench_result
benchmark_shash(struct cryptobench_params *params, const void *key,
		const void *inbuf)
{
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, unused);
	const char *driver_name;
	u8 digest[HASH_MAX_DIGESTSIZE];
	unsigned long i;
	u64 t1, t2;
	u64 measurement;
	int err;
	enum cryptobench_result result;

	tfm = crypto_alloc_shash(params->algname, 0, 0);
	if (IS_ERR(tfm)) {
		if (PTR_ERR(tfm) == -ENOENT)
			return ALG_NOT_FOUND;
		pr_err("error allocating %s: %ld\n", params->algname,
		       PTR_ERR(tfm));
		return ALG_ALLOCATION_ERROR;
	}
	desc->tfm = tfm;
	driver_name = crypto_shash_driver_name(tfm);

	if (params->keysize) {
		err = crypto_shash_setkey(tfm, key, params->keysize);
		if (err) {
			result = KEYSIZE_NOT_SUPPORTED;
			goto out;
		}
	}

	cond_resched();
	t1 = ktime_get_ns();
	for (i = 0; i < params->niter; i++) {
		err = crypto_shash_digest(desc, inbuf, params->datasize,
					  digest);
		if (err) {
			pr_err("hash error w/ alg %s: %d\n", driver_name, err);
			result = CRYPTO_ERROR;
			goto out;
		}
	}
	t2 = ktime_get_ns();
	measurement = measure_buf(digest, crypto_shash_digestsize(tfm));

	sprintf(cryptobench_results,
		"SUCCESS algname=%s driver_name=%s measurement=%#016llx time=%llu\n",
		params->algname, driver_name, measurement, t2 - t1);
	result = SUCCESS;
out:
	crypto_free_shash(tfm);
	return result;
}

static enum cryptobench_result
benchmark_ahash(struct cryptobench_params *params, const void *key,
		const void *inbuf)
{
	struct crypto_ahash *tfm;
	struct ahash_request *req;
	const char *driver_name;
	u8 digest[HASH_MAX_DIGESTSIZE];
	unsigned long i;
	struct scatterlist sg;
	u64 t1, t2;
	u64 measurement;
	int err;
	DECLARE_CRYPTO_WAIT(wait);
	enum cryptobench_result result;

	tfm = crypto_alloc_ahash(params->algname, 0, 0);
	if (IS_ERR(tfm)) {
		if (PTR_ERR(tfm) == -ENOENT)
			return ALG_NOT_FOUND;
		pr_err("error allocating %s: %ld\n", params->algname,
		       PTR_ERR(tfm));
		return ALG_ALLOCATION_ERROR;
	}
	driver_name = crypto_ahash_driver_name(tfm);

	if (params->keysize) {
		err = crypto_ahash_setkey(tfm, key, params->keysize);
		if (err) {
			result = KEYSIZE_NOT_SUPPORTED;
			goto out;
		}
	}

	sg_init_one(&sg, inbuf, params->datasize);

	cond_resched();
	t1 = ktime_get_ns();
	cryptobench_init_async(params->niter);
	for (i = 0; i < params->niter; i++) {
		req = ahash_request_alloc(tfm, GFP_KERNEL);
		ahash_request_set_callback(req,
					   CRYPTO_TFM_REQ_MAY_SLEEP |
						   CRYPTO_TFM_REQ_MAY_BACKLOG,
					   cryptobench_ahash_req_done, req);
		ahash_request_set_crypt(req, &sg, digest, params->datasize);
		err = crypto_ahash_digest(req);
		if (err != -EINPROGRESS && err != -EBUSY) {
			ahash_request_free(req);
			if (err) {
				pr_err("hash error w/ alg %s: %d\n",
				       driver_name, err);
				result = CRYPTO_ERROR;
				cryptobench_cancel(params->niter - i);
				goto out;
			}
			cryptobench_dec_async_remaining();
		}
	}

	wait_for_completion(&cryptobench_async_completion);
	t2 = ktime_get_ns();
	measurement = measure_buf(digest, crypto_ahash_digestsize(tfm));

	sprintf(cryptobench_results,
		"SUCCESS algname=%s driver_name=%s measurement=%#016llx time=%llu\n",
		params->algname, driver_name, measurement, t2 - t1);
	result = SUCCESS;
out:
	crypto_free_ahash(tfm);
	return result;
}

static enum cryptobench_result benchmark_hash(struct cryptobench_params *params)
{
	u8 key[MAX_KEYSIZE];
	void *inbuf;
	enum cryptobench_result result;

	if (params->keysize) {
		if (params->keysize > MAX_KEYSIZE) {
			pr_err("bad value for 'keysize' option");
			return BAD_PARAMETERS;
		}
		rand_bytes(params, key, params->keysize);
	}

	inbuf = kzalloc(params->datasize, GFP_KERNEL);
	if (!inbuf)
		return OUT_OF_MEMORY;
	rand_bytes(params, inbuf, params->datasize);

	if (params->force_ahash) {
		result = benchmark_ahash(params, key, inbuf);
	} else {
		result = benchmark_shash(params, key, inbuf);
		if (result == ALG_NOT_FOUND)
			result = benchmark_ahash(params, key, inbuf);
	}
	kfree(inbuf);
	return result;
}

enum {
	Opt_aadsize,
	Opt_algname,
	Opt_algtype,
	Opt_async,
	Opt_datasize,
	Opt_force_ahash,
	Opt_inplace,
	Opt_keysize,
	Opt_niter,
	Opt_random_seed,
	Opt_err,
};

static const match_table_t tokens = {
	{ Opt_aadsize, "aadsize=%s" },
	{ Opt_algname, "algname=%s" },
	{ Opt_algtype, "algtype=%s" },
	{ Opt_async, "async" },
	{ Opt_datasize, "datasize=%s" },
	{ Opt_force_ahash, "force_ahash" },
	{ Opt_inplace, "inplace" },
	{ Opt_keysize, "keysize=%s" },
	{ Opt_niter, "niter=%s" },
	{ Opt_random_seed, "random_seed=%s" },
	{ Opt_err, NULL },
};

static const struct {
	const char *algtype;
	enum cryptobench_result (*f)(struct cryptobench_params *params);
} benchmark_funcs[] = {
	{ "skcipher", benchmark_skcipher },
	{ "aead", benchmark_aead },
	{ "hash", benchmark_hash },
};

static ssize_t cryptobench_write(struct file *f, const char __user *ubuf,
				 size_t size, loff_t *off)
{
	char *optstr = NULL;
	char *opt, *optp;
	struct cryptobench_params params = {
		.algtype = "skcipher",
		.aadsize = 16,
		.datasize = 4096,
	};
	ssize_t ret;
	int i;
	enum cryptobench_result result;

	mutex_lock(&cryptobench_mutex);

	if (size >= 4096 || *off != 0)
		goto bad_params;

	optstr = kmalloc(size + 1, GFP_KERNEL);
	if (!optstr)
		goto bad_params;
	if (copy_from_user(optstr, ubuf, size))
		goto bad_params;
	optstr[size] = '\0';

	optp = optstr;
	while ((opt = strsep(&optp, "\n ")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;

		if (!*opt)
			continue;

		token = match_token(opt, tokens, args);
		switch (token) {
		case Opt_aadsize:
			if (kstrtoul(args[0].from, 10, &params.aadsize)) {
				pr_err("bad value for 'aadsize' option");
				goto bad_params;
			}
			break;
		case Opt_algtype:
			params.algtype = args[0].from;
			break;
		case Opt_algname:
			params.algname = args[0].from;
			break;
		case Opt_async:
			params.async = true;
			break;
		case Opt_datasize:
			if (kstrtoul(args[0].from, 10, &params.datasize)) {
				pr_err("bad value for 'datasize' option");
				goto bad_params;
			}
			break;
		case Opt_force_ahash:
			params.force_ahash = true;
			break;
		case Opt_inplace:
			params.inplace = true;
			break;
		case Opt_keysize:
			if (kstrtoint(args[0].from, 10, &params.keysize)) {
				pr_err("bad value for 'keysize' option");
				goto bad_params;
			}
			break;
		case Opt_niter:
			if (kstrtoul(args[0].from, 10, &params.niter)) {
				pr_err("bad value for 'niter' option");
				goto bad_params;
			}
			break;
		case Opt_random_seed:
			if (kstrtoull(args[0].from, 10, &params.random_seed)) {
				pr_err("bad value for 'random_seed' option");
				goto bad_params;
			}
			break;
		default:
			pr_err("unrecognized option '%s'\n", opt);
			goto bad_params;
		}
	}

	if (!params.algtype) {
		pr_err("'algtype' option is missing");
		goto bad_params;
	}

	if (!params.algname) {
		pr_err("'algname' option is missing");
		goto bad_params;
	}

	if (params.niter == 0) {
		if (strcmp(params.algtype, "aead") == 0)
			params.niter = 16777216 /
				       (params.aadsize + params.datasize ?: 1);
		else
			params.niter = 16777216 / (params.datasize ?: 1);
	}

	for (i = 0; i < ARRAY_SIZE(benchmark_funcs); i++) {
		if (!strcmp(benchmark_funcs[i].algtype, params.algtype)) {
			result = benchmark_funcs[i].f(&params);
			ret = size;
			if (result != SUCCESS)
				goto save_error;
			goto out;
		}
	}

	pr_err("bad value for 'algtype' option");
bad_params:
	ret = -EINVAL;
	result = BAD_PARAMETERS;
save_error:
	sprintf(cryptobench_results, "ERROR %s\n", result_strings[result]);
out:
	mutex_unlock(&cryptobench_mutex);
	kfree(optstr);
	return ret;
}

static const struct proc_ops cryptobench_fops = {
	.proc_write = cryptobench_write,
	.proc_read = cryptobench_read,
	.proc_lseek = noop_llseek,
};

static struct proc_dir_entry *proc_cryptobench;

static int __init cryptobench_init(void)
{
	proc_cryptobench =
		proc_create("cryptobench", 0600, NULL, &cryptobench_fops);
	return PTR_ERR_OR_ZERO(proc_cryptobench);
}

static void __exit cryptobench_exit(void)
{
	proc_remove(proc_cryptobench);
}

module_init(cryptobench_init);
module_exit(cryptobench_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Crypto algorithm benchmark and testing module");
MODULE_AUTHOR("Eric Biggers <ebiggers@google.com>");
