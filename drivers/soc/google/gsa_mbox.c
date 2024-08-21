// SPDX-License-Identifier: GPL-2.0-only
/*
 * Mailbox interface to GSA
 *
 * Copyright 2019 Google LLC
 */
#include <linux/interrupt.h>
#include <linux/platform_device.h>

#include "gsa_mbox.h"

/* Mailbox control Register */
#define MBOX_MCUCTLR_REG 0x0000

/* Interrupt Generation Register */
#define MBOX_INTGR0_REG 0x0020

/* Interrupt Clear Register 0 */
#define MBOX_INTCR0_REG 0x0024

/* Interrupt Mask Register 0 */
#define MBOX_INTMR0_REG 0x0028

/* Interrupt Raw Status Register 0 */
#define MBOX_INTSR0_REG 0x002C

/* Interrupt Masked status register */
#define MBOX_INTMSR0_REG 0x0030

/* Interrupt Generation Register 1 */
#define MBOX_INTGR1_REG 0x0040

/* Interrupt Mask register  */
#define MBOX_INTMR1_REG 0x0048

/* Interrupt Raw status register */
#define MBOX_INTSR1_REG 0x004C

/* Interrupt Masked status register  */
#define MBOX_INTMSR1_REG 0x0050

/* Shared registers */
#define MBOX_SR_BASE_REG 0x0080
#define MBOX_SR_REG(n) (MBOX_SR_BASE_REG + (n) * 4)

/* Number of shared registers  */
#define MBOX_SR_NUM 16

enum mbox_host_irq {
	MBOX_HOST_REQ_IRQ = BIT(0),
};

enum mbox_client_irq {
	MBOX_CLIENT_RSP_IRQ = BIT(0),
};

struct gsa_mbox {
	struct device *dev;
	void __iomem *base;
	int irq;
	spinlock_t slock; /* protects RMW like access to some registers */
	struct mutex mbox_lock; /* protects access to SRs */
	struct completion mbox_cmd_completion;
	u32 exp_intmr0;
};

static void gsa_mbox_mask_irq0(struct gsa_mbox *mbox, u32 mask)
{
	u32 v;
	unsigned long irq_flags;

	spin_lock_irqsave(&mbox->slock, irq_flags);
	v = readl(mbox->base + MBOX_INTMR0_REG);
	v |= mask;
	writel(v, mbox->base + MBOX_INTMR0_REG);
	mbox->exp_intmr0 = v;
	spin_unlock_irqrestore(&mbox->slock, irq_flags);
}

static void gsa_mbox_unmask_irq0(struct gsa_mbox *mbox, u32 mask)
{
	u32 v;
	unsigned long irq_flags;

	spin_lock_irqsave(&mbox->slock, irq_flags);
	v = readl(mbox->base + MBOX_INTMR0_REG);
	v &= ~mask;
	writel(v, mbox->base + MBOX_INTMR0_REG);
	mbox->exp_intmr0 = v;
	spin_unlock_irqrestore(&mbox->slock, irq_flags);
}

static void gsa_mbox_sync_irq0(struct gsa_mbox *mbox)
{
	u32 v;
	unsigned long irq_flags;

	spin_lock_irqsave(&mbox->slock, irq_flags);
	v = readl(mbox->base + MBOX_INTMR0_REG);
	if (v != mbox->exp_intmr0)
		writel(mbox->exp_intmr0, mbox->base + MBOX_INTMR0_REG);
	spin_unlock_irqrestore(&mbox->slock, irq_flags);
}

static void gsa_mbox_clr_irq0(struct gsa_mbox *mbox, u32 mask)
{
	writel(mask, mbox->base + MBOX_INTCR0_REG);
}

static irqreturn_t gsa_mbox_irq_handler(int irq, void *data)
{
	u32 v;
	struct gsa_mbox *mbox = data;

	dev_dbg(mbox->dev, "%s: got irq %d\n", __func__, irq);

	/*
	 * check if somehow we have lost state, like a host resets mailbox
	 * under us
	 */
	gsa_mbox_sync_irq0(mbox);

	v = readl(mbox->base + MBOX_INTMSR0_REG);
	if (v & MBOX_CLIENT_RSP_IRQ) {
		/* response */
		gsa_mbox_mask_irq0(mbox, MBOX_CLIENT_RSP_IRQ);
		complete(&mbox->mbox_cmd_completion);
	}

	return IRQ_HANDLED;
}

struct gsa_mbox *gsa_mbox_init(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct gsa_mbox *mbox;
	struct resource *res;
	int err;

	mbox = devm_kzalloc(dev, sizeof(*mbox), GFP_KERNEL);
	if (!mbox)
		return ERR_PTR(-ENOMEM);

	mbox->dev = dev;
	spin_lock_init(&mbox->slock);
	mutex_init(&mbox->mbox_lock);
	init_completion(&mbox->mbox_cmd_completion);

	/* map mbox registers */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	mbox->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(mbox->base)) {
		dev_err(dev, "ioremap failed (%ld)\n", PTR_ERR(mbox->base));
		return mbox->base;
	}

	/* place hardware into known state */
	mbox->exp_intmr0 = 0xFFFF;
	writel(mbox->exp_intmr0, mbox->base + MBOX_INTMR0_REG);

	/* register mbox interrupt */
	mbox->irq = platform_get_irq(pdev, 0);
	if (mbox->irq < 0)
		return ERR_PTR(mbox->irq);
	err = devm_request_irq(dev, mbox->irq, gsa_mbox_irq_handler, 0,
			       "gsa-mbox-irq", mbox);
	if (err) {
		dev_err(dev, "request_irq failed (%d)\n", err);
		return ERR_PTR(err);
	}

	return mbox;
}

/*
 * GSA specific mailbox protocol support
 */

/* Command response bit */
#define GSA_MBOX_CMD_RSP (1U << 31)

/* Mailbox error codes */
enum gsa_mbox_error {
	/* Defined by GSA ROM */
	GSA_MBOX_OK = 0,
	GSA_MBOX_ERR_INVALID_ARGS = 1,
	GSA_MBOX_ERR_AUTH_FAILED = 2,
	GSA_MBOX_ERR_BUSY = 3,
	GSA_MBOX_ERR_ALREADY_RUNNING = 4,
	GSA_MBOX_ERR_OUT_OF_RESOURCES = 5,
	GSA_MBOX_ERR_BAD_HANDLE = 6,

	/* Extended by GSA firmware */
	GSA_MBOX_ERR_GENERIC = 128,
	GSA_MBOX_ERR_INTERNAL = 129,
	GSA_MBOX_ERR_TIMED_OUT = 130,
	GSA_MBOX_ERR_BAD_STATE = 131,
};

static int gsa_mbox_err_to_errno(u32 rsp_err)
{
	switch (rsp_err) {
	case GSA_MBOX_ERR_BAD_HANDLE:
	case GSA_MBOX_ERR_INVALID_ARGS:
		return -EINVAL;
	case GSA_MBOX_ERR_BUSY:
		return -EBUSY;
	case GSA_MBOX_ERR_AUTH_FAILED:
		return -EACCES;
	case GSA_MBOX_ERR_OUT_OF_RESOURCES:
		return -ENOMEM;
	case GSA_MBOX_ERR_ALREADY_RUNNING:
		return -EEXIST;
	case GSA_MBOX_ERR_TIMED_OUT:
		return -ETIMEDOUT;
	}
	return -EIO;
}

static int gsa_send_mbox_cmd_locked(struct gsa_mbox *mbox, u32 cmd,
				    const u32 *req_args, u32 req_argc,
				    u32 *rsp_args, u32 rsp_max_argc)
{
	u32 i;
	u32 rsp_cmd;
	u32 rsp_err;
	u32 rsp_argc;
	int ret;

	if (req_argc > MBOX_SR_NUM - 2)
		return -EINVAL; /* too many request arguments */

	/* write command */
	writel(cmd, mbox->base + MBOX_SR_REG(0));
	writel(req_argc, mbox->base + MBOX_SR_REG(1));
	for (i = 0; i < req_argc; i++)
		writel(req_args[i], mbox->base + MBOX_SR_REG(i + 2));

	dev_info(mbox->dev, "cmd=%u, req_argc=%u\n", cmd, req_argc);
	for (i = 0; i < req_argc; i++)
		dev_info(mbox->dev, "args[%u]=%u\n", i, req_args[i]);

	/* initiate request */
	reinit_completion(&mbox->mbox_cmd_completion);

	/* unmask response interrupt */
	gsa_mbox_clr_irq0(mbox, MBOX_CLIENT_RSP_IRQ);
	gsa_mbox_unmask_irq0(mbox, MBOX_CLIENT_RSP_IRQ);

	/* raise request interrupt */
	writel(MBOX_HOST_REQ_IRQ, mbox->base + MBOX_INTGR1_REG);

	/* wait for response */
	wait_for_completion(&mbox->mbox_cmd_completion);

	/* read response */
	rsp_cmd = readl(mbox->base + MBOX_SR_REG(0));
	rsp_err = readl(mbox->base + MBOX_SR_REG(1));
	rsp_argc = readl(mbox->base + MBOX_SR_REG(2));

	if (rsp_cmd != (cmd | GSA_MBOX_CMD_RSP)) {
		/* bad response */
		dev_err(mbox->dev,
			"mbox cmd=%u returned rsp_cmd=0x%x\n", cmd, rsp_cmd);
		ret = -EIO;
		goto out;
	}

	if (rsp_err != GSA_MBOX_OK) {
		dev_err(mbox->dev,
			"mbox cmd=%u failed with rsp_err=%u\n", cmd, rsp_err);
		ret = gsa_mbox_err_to_errno(rsp_err);
		goto out;
	}

	/* check argc: first 3 registers are for cmd, err and argc */
	if (WARN_ON(rsp_argc > MBOX_SR_NUM - 3)) {
		/* malformed response */
		ret = -EIO;
		goto out;
	}

	if (WARN_ON(rsp_argc > rsp_max_argc)) {
		/* not enough space to save all returned arguments */
		rsp_argc = rsp_max_argc;
	}

	/* copy response */
	for (i = 0; i < rsp_argc; i++)
		rsp_args[i] = readl(mbox->base + MBOX_SR_REG(i + 3));

	ret = rsp_argc;
out:
	/* clear and mask response interrupts */
	gsa_mbox_clr_irq0(mbox, MBOX_CLIENT_RSP_IRQ);
	gsa_mbox_mask_irq0(mbox, MBOX_CLIENT_RSP_IRQ);

	return ret;
}

int gsa_send_mbox_cmd(struct gsa_mbox *mbox, u32 cmd,
		      const u32 *req_args, u32 req_argc,
		      u32 *rsp_args, u32 rsp_max_argc)
{
	int ret;

	mutex_lock(&mbox->mbox_lock);
	ret = gsa_send_mbox_cmd_locked(mbox, cmd, req_args, req_argc,
				       rsp_args, rsp_max_argc);
	mutex_unlock(&mbox->mbox_lock);
	return ret;
}
