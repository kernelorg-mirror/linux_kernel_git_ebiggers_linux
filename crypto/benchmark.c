// SPDX-License-Identifier: GPL-2.0+
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/siphash.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>

#undef pr_fmt
#define pr_fmt(fmt) "cryptobench: " fmt

static char cryptobench_results[4096];
static DEFINE_MUTEX(cryptobench_mutex);

#define MAX_KEYSIZE	64

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

static const char * const result_strings[] = {
	[SUCCESS]		= "SUCCESS",
	[ALG_NOT_FOUND]		= "ALG_NOT_FOUND",
	[ALG_ALLOCATION_ERROR]	= "ALG_ALLOCATION_ERROR",
	[KEYSIZE_NOT_SUPPORTED]	= "KEYSIZE_NOT_SUPPORTED",
	[CRYPTO_ERROR]		= "CRYPTO_ERROR",
	[CRYPTO_INCORRECT]	= "CRYPTO_INCORRECT",
	[BAD_PARAMETERS]	= "BAD_PARAMETERS",
	[OUT_OF_MEMORY]		= "OUT_OF_MEMORY",
};

struct cryptobench_params {
	char *algtype;
	char *algname;
	int keysize;
	unsigned long niter;
	unsigned long bufsize;
	bool inplace;
	bool sgl_fuzz;
	unsigned long long random_seed;
};

static u32 rand32(struct cryptobench_params *params)
{
	params->random_seed *= 25214903917;
	params->random_seed += 11;
	params->random_seed &= ((u64)1 << 48) - 1;
	return params->random_seed >> 16;
}

static void rand_bytes(struct cryptobench_params *params,
		       void *buf, size_t size)
{
	u8 *p = buf;

	while (size--)
		*p++ = rand32(params);
}

static u64 measure_buf(const void *buf, size_t size)
{
	static const siphash_key_t rand_k = {
		{0xcfc33ef3ebb659e4, 0x474fba075dbfda4e}
	};

	return siphash(buf, size, &rand_k);
}

static ssize_t cryptobench_read(struct file *f, char __user *ubuf,
				size_t size, loff_t *off)
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

#define MAX_NUM_SGS		10
#define MAX_SG_GAP		32

static bool setup_buffer_and_sglist(void **buf_ret, size_t bufsize,
				    struct scatterlist sg[MAX_NUM_SGS],
				    bool sgl_fuzz)
{
	int i;
	void *p;
	int num_sgs;

	if (!sgl_fuzz) {
		*buf_ret = kzalloc(bufsize, GFP_KERNEL);
		if (!*buf_ret)
			return false;
		sg_init_one(&sg[0], *buf_ret, bufsize);
		return true;
	}

	*buf_ret = kzalloc(bufsize + (MAX_NUM_SGS * MAX_SG_GAP), GFP_KERNEL);
	if (!*buf_ret)
		return false;
	p = *buf_ret;

	if (bufsize == 0) {
		sg_init_one(&sg[0], p, 0);
		return true;
	}

	num_sgs = 1 + (get_random_int() % MAX_NUM_SGS);
	sg_init_table(sg, num_sgs);
	i = 0;
	do {
		int r = get_random_int() % 3;
		size_t n;

		if (i == num_sgs - 1 || r == 0)
			n = bufsize;
		else if (r == 1)
			n = 1 + (get_random_long() % 64);
		else
			n = 1 + (get_random_long() % bufsize);
		n = min(n, bufsize);
		p += get_random_int() % (MAX_SG_GAP + 1);
		sg_set_buf(&sg[i], p, n);
		p += n;
		bufsize -= n;
	} while (++i < num_sgs && bufsize != 0);
	sg_mark_end(&sg[i - 1]);
	return true;
}

static void memcpy_to_sgl(struct scatterlist *sg, const void *buf, size_t size)
{
	size_t copied;

	copied = sg_pcopy_from_buffer(sg, sg_nents(sg), buf, size, 0);

	WARN_ON(copied != size);
}

static void memcpy_from_sgl(void *buf, struct scatterlist *sg, size_t size)
{
	size_t copied;

	copied = sg_pcopy_to_buffer(sg, sg_nents(sg), buf, size, 0);

	WARN_ON(copied != size);
}

static enum cryptobench_result
benchmark_skcipher(struct cryptobench_params *params)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	const char *driver_name = NULL;
	u8 orig_iv[16];
	u8 iv[16] __aligned(8);
	void *inbuf = NULL, *outbuf = NULL, *tmpbuf = NULL, *orig_data = NULL;
	unsigned long i;
	unsigned long parity = 0;
	struct scatterlist _src[MAX_NUM_SGS];
	struct scatterlist _dst[MAX_NUM_SGS];
	struct scatterlist *src = _src, *dst = _dst;
	u64 t1, t2, t3;
	u64 measurement;
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

	tmpbuf = kmalloc(params->bufsize, GFP_KERNEL);
	orig_data = kmalloc(params->bufsize, GFP_KERNEL);
	if (!tmpbuf || !orig_data) {
		result = OUT_OF_MEMORY;
		goto out;
	}

	if (!setup_buffer_and_sglist(&inbuf, params->bufsize, src,
				     params->sgl_fuzz)) {
		result = OUT_OF_MEMORY;
		goto out;
	}
	rand_bytes(params, orig_data, params->bufsize);
	memcpy_to_sgl(src, orig_data, params->bufsize);

	if (params->inplace) {
		outbuf = inbuf;
		dst = src;
	} else {
		if (!setup_buffer_and_sglist(&outbuf, params->bufsize, dst,
					     params->sgl_fuzz)) {
			result = OUT_OF_MEMORY;
			goto out;
		}
	}

	tfm = crypto_alloc_skcipher(params->algname, 0, 0);
	if (IS_ERR(tfm)) {
		if (PTR_ERR(tfm) == -ENOENT) {
			result = ALG_NOT_FOUND;
		} else {
			pr_err("error allocating %s: %ld\n",
			       params->algname, PTR_ERR(tfm));
			result = ALG_ALLOCATION_ERROR;
		}
		tfm = NULL;
		goto out;
	}
	driver_name = crypto_skcipher_alg(tfm)->base.cra_driver_name;
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		result = OUT_OF_MEMORY;
		goto out;
	}

	err = crypto_skcipher_setkey(tfm, key, params->keysize);
	if (err) {
		result = KEYSIZE_NOT_SUPPORTED;
		goto out;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP |
				      CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);

	cond_resched();
	t1 = ktime_get_ns();
	for (i = 0; i < params->niter; i++) {
		memcpy(iv, orig_iv, sizeof(iv));
		*(u64 *)iv += i;
		if (parity++ & 1) {
			skcipher_request_set_crypt(req, dst, src,
						   params->bufsize, iv);
		} else {
			skcipher_request_set_crypt(req, src, dst,
						   params->bufsize, iv);
		}
		err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
		if (err) {
			pr_err("encryption error w/ alg %s: %d\n",
			       driver_name, err);
			result = CRYPTO_ERROR;
			goto out;
		}
	}
	t2 = ktime_get_ns();
	memcpy_from_sgl(tmpbuf, (params->niter & 1) ? dst : src,
			params->bufsize);
	if (!memcmp(tmpbuf, orig_data, params->bufsize)) {
		pr_err("encryption w/ alg %s didn't do anything!\n",
		       driver_name);
		result = CRYPTO_INCORRECT;
		goto out;
	}
	measurement = measure_buf(tmpbuf, params->bufsize);
	cond_resched();
	t2 = ktime_get_ns();
	for (i = 0; i < params->niter; i++) {
		memcpy(iv, orig_iv, sizeof(iv));
		*(u64 *)iv += params->niter - 1 - i;
		if (parity++ & 1) {
			skcipher_request_set_crypt(req, dst, src,
						   params->bufsize, iv);
		} else {
			skcipher_request_set_crypt(req, src, dst,
						   params->bufsize, iv);
		}
		err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
		if (err) {
			pr_err("decryption error w/ alg %s: %d\n",
			       driver_name, err);
			result = CRYPTO_ERROR;
			goto out;
		}
	}
	t3 = ktime_get_ns();
	cond_resched();

	memcpy_from_sgl(tmpbuf, src, params->bufsize);
	if (memcmp(tmpbuf, orig_data, params->bufsize)) {
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
	skcipher_request_free(req);
	crypto_free_skcipher(tfm);
	kfree(inbuf);
	if (inbuf != outbuf)
		kfree(outbuf);
	kfree(tmpbuf);
	kfree(orig_data);
	return result;
}

static enum cryptobench_result
benchmark_hash(struct cryptobench_params *params)
{
	struct crypto_ahash *tfm = NULL;
	struct ahash_request *req = NULL;
	const char *driver_name = NULL;
	void *inbuf = NULL, *tmpbuf = NULL;
	u8 *digest = NULL;
	unsigned long i;
	struct scatterlist _sg[MAX_NUM_SGS];
	struct scatterlist *sg = _sg;
	u64 t1, t2;
	u64 measurement;
	int err;
	DECLARE_CRYPTO_WAIT(wait);
	enum cryptobench_result result;
	u8 key[MAX_KEYSIZE];

	if (params->keysize > MAX_KEYSIZE) {
		pr_err("bad value for 'keysize' option");
		return BAD_PARAMETERS;
	}

	if (!setup_buffer_and_sglist(&inbuf, params->bufsize, sg,
				     params->sgl_fuzz)) {
		result = OUT_OF_MEMORY;
		goto out;
	}

	tmpbuf = kmalloc(params->bufsize, GFP_KERNEL);
	if (!tmpbuf) {
		result = OUT_OF_MEMORY;
		goto out;
	}
	rand_bytes(params, tmpbuf, params->bufsize);
	if (params->bufsize)
		((u8 *)tmpbuf)[0] &= 0x7f;
	memcpy_to_sgl(sg, tmpbuf, params->bufsize);

	tfm = crypto_alloc_ahash(params->algname, 0, 0);
	if (IS_ERR(tfm)) {
		if (PTR_ERR(tfm) == -ENOENT) {
			result = ALG_NOT_FOUND;
		} else {
			pr_err("error allocating %s: %ld\n",
			       params->algname, PTR_ERR(tfm));
			result = ALG_ALLOCATION_ERROR;
		}
		tfm = NULL;
		goto out;
	}
	driver_name = crypto_hash_alg_common(tfm)->base.cra_driver_name;
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		result = OUT_OF_MEMORY;
		goto out;
	}

	digest = kmalloc(crypto_ahash_digestsize(tfm), GFP_KERNEL);
	if (!digest) {
		result = OUT_OF_MEMORY;
		goto out;
	}

	if (params->keysize) {
		rand_bytes(params, key, params->keysize);
		err = crypto_ahash_setkey(tfm, key, params->keysize);
		if (err) {
			result = KEYSIZE_NOT_SUPPORTED;
			goto out;
		}
	}

	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP |
				   CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &wait);

	cond_resched();
	t1 = ktime_get_ns();
	for (i = 0; i < params->niter; i++) {
		ahash_request_set_crypt(req, sg, digest, params->bufsize);
		err = crypto_wait_req(crypto_ahash_digest(req), &wait);
		if (err) {
			pr_err("hash error w/ alg %s: %d\n", driver_name, err);
			result = CRYPTO_ERROR;
			goto out;
		}
	}
	t2 = ktime_get_ns();
	measurement = measure_buf(digest, crypto_ahash_digestsize(tfm));

	sprintf(cryptobench_results,
		"SUCCESS algname=%s driver_name=%s measurement=%#016llx time=%llu\n",
		params->algname, driver_name, measurement, t2 - t1);
	result = SUCCESS;
out:
	ahash_request_free(req);
	crypto_free_ahash(tfm);
	kfree(inbuf);
	kfree(tmpbuf);
	kfree(digest);
	return result;
}

enum {
	Opt_algtype,
	Opt_algname,
	Opt_keysize,
	Opt_niter,
	Opt_bufsize,
	Opt_inplace,
	Opt_sgl_fuzz,
	Opt_random_seed,
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_algtype, "algtype=%s"},
	{Opt_algname, "algname=%s"},
	{Opt_keysize, "keysize=%s"},
	{Opt_niter, "niter=%s"},
	{Opt_bufsize, "bufsize=%s"},
	{Opt_inplace, "inplace"},
	{Opt_sgl_fuzz, "sgl_fuzz"},
	{Opt_random_seed, "random_seed=%s"},
	{Opt_err, NULL},
};

static const struct {
	const char *algtype;
	enum cryptobench_result (*f)(struct cryptobench_params *params);
} benchmark_funcs[] = {
	{ "skcipher", benchmark_skcipher },
	{ "hash",     benchmark_hash },
};

static ssize_t cryptobench_write(struct file *f, const char __user *ubuf,
				 size_t size, loff_t *off)
{
	char *optstr = NULL;
	char *opt, *optp;
	struct cryptobench_params params = {
		.algtype = "skcipher",
		.niter = 4096,
		.bufsize = 4096,
	};
	ssize_t ret;
	int i;
	enum cryptobench_result result;

	mutex_lock(&cryptobench_mutex);

	if (size >= 4096 || *off != 0)
		goto bad_params;

	optstr = memdup_user_nul(ubuf, size);
	if (IS_ERR(optstr))
		goto bad_params;

	optp = optstr;
	while ((opt = strsep(&optp, "\n ")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;

		if (!*opt)
			continue;

		token = match_token(opt, tokens, args);
		switch (token) {
		case Opt_algtype:
			params.algtype = args[0].from;
			break;
		case Opt_algname:
			params.algname = args[0].from;
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
		case Opt_bufsize:
			if (kstrtoul(args[0].from, 10, &params.bufsize)) {
				pr_err("bad value for 'bufsize' option");
				goto bad_params;
			}
			break;
		case Opt_inplace:
			params.inplace = true;
			break;
		case Opt_sgl_fuzz:
			params.sgl_fuzz = true;
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

static const struct file_operations cryptobench_fops = {
	.write = cryptobench_write,
	.read = cryptobench_read,
};

static struct proc_dir_entry *proc_cryptobench;

static int __init cryptobench_init(void)
{
	proc_cryptobench = proc_create("cryptobench", 0600, NULL,
				       &cryptobench_fops);
	if (IS_ERR(proc_cryptobench))
		return PTR_ERR(proc_cryptobench);
	return 0;
}

static void __exit cryptobench_exit(void)
{
	proc_remove(proc_cryptobench);
}

module_init(cryptobench_init);
module_exit(cryptobench_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Crypto benchmark module");
