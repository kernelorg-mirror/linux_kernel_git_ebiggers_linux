/* SPDX-License-Identifier: GPL-2.0-or-later */
// Copyright 2025 Google LLC

#include "crc-pclmul-template.S"

DEFINE_CRC_PCLMUL_FUNCS(crc32_lsb, /* bits= */ 32, /* lsb= */ 1)

#ifdef __x86_64__
DEFINE_CRC32C_VPCLMUL_AVX512()
#endif
