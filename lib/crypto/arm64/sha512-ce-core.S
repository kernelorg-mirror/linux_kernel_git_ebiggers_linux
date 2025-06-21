/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sha512-ce-core.S - core SHA-384/SHA-512 transform using v8 Crypto Extensions
 *
 * Copyright (C) 2018 Linaro Ltd <ard.biesheuvel@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

	.irp		b,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
	.set		.Lq\b, \b
	.set		.Lv\b\().2d, \b
	.endr

	.macro		sha512h, rd, rn, rm
	.inst		0xce608000 | .L\rd | (.L\rn << 5) | (.L\rm << 16)
	.endm

	.macro		sha512h2, rd, rn, rm
	.inst		0xce608400 | .L\rd | (.L\rn << 5) | (.L\rm << 16)
	.endm

	.macro		sha512su0, rd, rn
	.inst		0xcec08000 | .L\rd | (.L\rn << 5)
	.endm

	.macro		sha512su1, rd, rn, rm
	.inst		0xce608800 | .L\rd | (.L\rn << 5) | (.L\rm << 16)
	.endm

	.macro		dround, i0, i1, i2, i3, i4, rc0, rc1, in0, in1, in2, in3, in4
	.ifnb		\rc1
	ld1		{v\rc1\().2d}, [x4], #16
	.endif
	add		v5.2d, v\rc0\().2d, v\in0\().2d
	ext		v6.16b, v\i2\().16b, v\i3\().16b, #8
	ext		v5.16b, v5.16b, v5.16b, #8
	ext		v7.16b, v\i1\().16b, v\i2\().16b, #8
	add		v\i3\().2d, v\i3\().2d, v5.2d
	.ifnb		\in1
	ext		v5.16b, v\in3\().16b, v\in4\().16b, #8
	sha512su0	v\in0\().2d, v\in1\().2d
	.endif
	sha512h		q\i3, q6, v7.2d
	.ifnb		\in1
	sha512su1	v\in0\().2d, v\in2\().2d, v5.2d
	.endif
	add		v\i4\().2d, v\i1\().2d, v\i3\().2d
	sha512h2	q\i3, q\i1, v\i0\().2d
	.endm

	/*
	 * size_t __sha512_ce_transform(struct sha512_block_state *state,
	 *				const u8 *data, size_t nblocks);
	 */
	.text
SYM_FUNC_START(__sha512_ce_transform)
	/* load state */
	ld1		{v8.2d-v11.2d}, [x0]

	/* load first 4 round constants */
	adr_l		x3, sha512_K
	ld1		{v20.2d-v23.2d}, [x3], #64

	/* load input */
0:	ld1		{v12.2d-v15.2d}, [x1], #64
	ld1		{v16.2d-v19.2d}, [x1], #64
	sub		x2, x2, #1

CPU_LE(	rev64		v12.16b, v12.16b	)
CPU_LE(	rev64		v13.16b, v13.16b	)
CPU_LE(	rev64		v14.16b, v14.16b	)
CPU_LE(	rev64		v15.16b, v15.16b	)
CPU_LE(	rev64		v16.16b, v16.16b	)
CPU_LE(	rev64		v17.16b, v17.16b	)
CPU_LE(	rev64		v18.16b, v18.16b	)
CPU_LE(	rev64		v19.16b, v19.16b	)

	mov		x4, x3				// rc pointer

	mov		v0.16b, v8.16b
	mov		v1.16b, v9.16b
	mov		v2.16b, v10.16b
	mov		v3.16b, v11.16b

	// v0  ab  cd  --  ef  gh  ab
	// v1  cd  --  ef  gh  ab  cd
	// v2  ef  gh  ab  cd  --  ef
	// v3  gh  ab  cd  --  ef  gh
	// v4  --  ef  gh  ab  cd  --

	dround		0, 1, 2, 3, 4, 20, 24, 12, 13, 19, 16, 17
	dround		3, 0, 4, 2, 1, 21, 25, 13, 14, 12, 17, 18
	dround		2, 3, 1, 4, 0, 22, 26, 14, 15, 13, 18, 19
	dround		4, 2, 0, 1, 3, 23, 27, 15, 16, 14, 19, 12
	dround		1, 4, 3, 0, 2, 24, 28, 16, 17, 15, 12, 13

	dround		0, 1, 2, 3, 4, 25, 29, 17, 18, 16, 13, 14
	dround		3, 0, 4, 2, 1, 26, 30, 18, 19, 17, 14, 15
	dround		2, 3, 1, 4, 0, 27, 31, 19, 12, 18, 15, 16
	dround		4, 2, 0, 1, 3, 28, 24, 12, 13, 19, 16, 17
	dround		1, 4, 3, 0, 2, 29, 25, 13, 14, 12, 17, 18

	dround		0, 1, 2, 3, 4, 30, 26, 14, 15, 13, 18, 19
	dround		3, 0, 4, 2, 1, 31, 27, 15, 16, 14, 19, 12
	dround		2, 3, 1, 4, 0, 24, 28, 16, 17, 15, 12, 13
	dround		4, 2, 0, 1, 3, 25, 29, 17, 18, 16, 13, 14
	dround		1, 4, 3, 0, 2, 26, 30, 18, 19, 17, 14, 15

	dround		0, 1, 2, 3, 4, 27, 31, 19, 12, 18, 15, 16
	dround		3, 0, 4, 2, 1, 28, 24, 12, 13, 19, 16, 17
	dround		2, 3, 1, 4, 0, 29, 25, 13, 14, 12, 17, 18
	dround		4, 2, 0, 1, 3, 30, 26, 14, 15, 13, 18, 19
	dround		1, 4, 3, 0, 2, 31, 27, 15, 16, 14, 19, 12

	dround		0, 1, 2, 3, 4, 24, 28, 16, 17, 15, 12, 13
	dround		3, 0, 4, 2, 1, 25, 29, 17, 18, 16, 13, 14
	dround		2, 3, 1, 4, 0, 26, 30, 18, 19, 17, 14, 15
	dround		4, 2, 0, 1, 3, 27, 31, 19, 12, 18, 15, 16
	dround		1, 4, 3, 0, 2, 28, 24, 12, 13, 19, 16, 17

	dround		0, 1, 2, 3, 4, 29, 25, 13, 14, 12, 17, 18
	dround		3, 0, 4, 2, 1, 30, 26, 14, 15, 13, 18, 19
	dround		2, 3, 1, 4, 0, 31, 27, 15, 16, 14, 19, 12
	dround		4, 2, 0, 1, 3, 24, 28, 16, 17, 15, 12, 13
	dround		1, 4, 3, 0, 2, 25, 29, 17, 18, 16, 13, 14

	dround		0, 1, 2, 3, 4, 26, 30, 18, 19, 17, 14, 15
	dround		3, 0, 4, 2, 1, 27, 31, 19, 12, 18, 15, 16
	dround		2, 3, 1, 4, 0, 28, 24, 12
	dround		4, 2, 0, 1, 3, 29, 25, 13
	dround		1, 4, 3, 0, 2, 30, 26, 14

	dround		0, 1, 2, 3, 4, 31, 27, 15
	dround		3, 0, 4, 2, 1, 24,   , 16
	dround		2, 3, 1, 4, 0, 25,   , 17
	dround		4, 2, 0, 1, 3, 26,   , 18
	dround		1, 4, 3, 0, 2, 27,   , 19

	/* update state */
	add		v8.2d, v8.2d, v0.2d
	add		v9.2d, v9.2d, v1.2d
	add		v10.2d, v10.2d, v2.2d
	add		v11.2d, v11.2d, v3.2d

	cond_yield	3f, x4, x5
	/* handled all input blocks? */
	cbnz		x2, 0b

	/* store new state */
3:	st1		{v8.2d-v11.2d}, [x0]
	mov		x0, x2
	ret
SYM_FUNC_END(__sha512_ce_transform)
