// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Support for AES-NI and VAES instructions.  This file contains glue code.
 * The real AES implementations are in .S files.
 *
 * Copyright (C) 2008, Intel Corp.
 *    Author: Huang Ying <ying.huang@intel.com>
 *
 * Added RFC4106 AES-GCM support for 128-bit keys under the AEAD
 * interface for 64-bit kernels.
 *    Authors: Adrian Hoban <adrian.hoban@intel.com>
 *             Gabriele Paoloni <gabriele.paoloni@intel.com>
 *             Tadeusz Struk (tadeusz.struk@intel.com)
 *             Aidan O'Mahony (aidan.o.mahony@intel.com)
 *    Copyright (c) 2010, Intel Corporation.
 *
 * Copyright 2024 Google LLC
 */

#include <linux/module.h>
#include <linux/err.h>
#include <asm/cpu_device_id.h>

static const struct x86_cpu_id aesni_cpu_id[] = {
	X86_MATCH_FEATURE(X86_FEATURE_AES, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, aesni_cpu_id);

static int __init aesni_init(void)
{
	if (!x86_match_cpu(aesni_cpu_id))
		return -ENODEV;

	return 0;
}

static void __exit aesni_exit(void)
{
}

module_init(aesni_init);
module_exit(aesni_exit);

MODULE_DESCRIPTION("AES-GCM, optimized with AES-NI or VAES instructions");
MODULE_LICENSE("GPL");
