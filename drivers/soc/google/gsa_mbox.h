/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2020 Google LLC
 */
#ifndef DRIVERS_SOC_GOOGLE_GSA_MBOX_H
#define DRIVERS_SOC_GOOGLE_GSA_MBOX_H

#include <linux/types.h>

struct platform_device;

/**
 * enum gsa_mbox_cmd - mailbox commands
 */
enum gsa_mbox_cmd {
	/* KDN */
	GSA_MB_CMD_KDN_GENERATE_KEY = 70,
	GSA_MB_CMD_KDN_EPHEMERAL_WRAP_KEY = 71,
	GSA_MB_CMD_KDN_DERIVE_RAW_SECRET = 72,
	GSA_MB_CMD_KDN_PROGRAM_KEY = 73,
	GSA_MB_CMD_KDN_RESTORE_KEYS = 74,
	GSA_MB_CMD_KDN_SET_OP_MODE = 75,
};

struct gsa_mbox;

struct gsa_mbox *gsa_mbox_init(struct platform_device *pdev);

int gsa_send_mbox_cmd(struct gsa_mbox *mbox, u32 cmd, const u32 *req_args,
		      u32 req_argc, u32 *rsp_args, u32 rsp_argc);

#endif /* DRIVERS_SOC_GOOGLE_GSA_MBOX_H */
