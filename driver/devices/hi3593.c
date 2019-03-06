/*
 * Copyright (C), 2019 CCX Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/spi/spi.h>
#include <linux/of_gpio.h>

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("HOLT Hi-3593 ARINC-429 Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

#define HI3593_MTU	(32*sizeof(__u32)) /* 32 word FIFO */

#define HI3593_OPCODE_RESET		0x04
#define HI3593_OPCODE_RD_TX_STATUS	0x80
#define HI3593_OPCODE_RD_ALCK		0xd4
#define HI3593_OPCODE_WR_ALCK		0x38

#define HI3593_OPCODE_RD_RX1_CNTRL	0x94
#define HI3593_OPCODE_RD_RX2_CNTRL	0xB4
#define HI3593_OPCODE_RD_TX_CNTRL	0x84

#define HI3593_OPCODE_WR_RX1_CNTRL	0x10
#define HI3593_OPCODE_WR_RX2_CNTRL	0x24
#define HI3593_OPCODE_WR_TX_CNTRL	0x08

#define HI3593_OPCODE_RD_RX1_PRIORITY	0x9c
#define HI3593_OPCODE_RD_RX2_PRIORITY	0xbc
#define HI3593_OPCODE_RD_RX1_FILTERS	0x98
#define HI3593_OPCODE_RD_RX2_FILTERS	0xb8

#define HI3593_OPCODE_WR_RX1_PRIORITY	0x18
#define HI3593_OPCODE_WR_RX2_PRIORITY	0x2c
#define HI3593_OPCODE_WR_RX1_FILTERS	0x14
#define HI3593_OPCODE_WR_RX2_FILTERS	0x2c

#define HI3593_NUM_TX	1
#define HI3593_NUM_RX	2

struct hi3593 {
	struct net_device *rx[HI3593_NUM_RX];
	struct net_device *tx[HI3593_NUM_TX];
	int reset_gpio;
	__u32 aclk;
};

struct hi3593_priv {
	struct spi_device *spi;
	int tx_index;
	int rx_index;
};

static int hi3593_set_rate(struct avionics_rate *rate,
			   const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 rd_cmd, wr_cmd[2];
	ssize_t status;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -EINVAL;
	}

	if (priv->tx_index == 0) {
		rd_cmd = HI3593_OPCODE_RD_TX_CNTRL;
		wr_cmd[0] = HI3593_OPCODE_WR_TX_CNTRL;
	} else if (priv->rx_index == 0) {
		rd_cmd = HI3593_OPCODE_RD_RX1_CNTRL;
		wr_cmd[0] = HI3593_OPCODE_WR_RX1_CNTRL;
	} else if (priv->rx_index == 1) {
		rd_cmd = HI3593_OPCODE_RD_RX2_CNTRL;
		wr_cmd[0] = HI3593_OPCODE_WR_RX2_CNTRL;
	} else {
		pr_err("avionics-hi3593: No valid port index\n");
		return -EINVAL;
	}

	status = spi_w8r8(priv->spi, rd_cmd);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get rate: %d\n", status);
		return -ENODEV;
	}

	if(rate->rate_hz == 100000) {
		wr_cmd[1] = status&0x00f7;
	} else if(rate->rate_hz == 12500) {
		wr_cmd[1] = status|0x0001;
	} else {
		pr_warn("avionics-hi3593: speed must be 100000 or 12500 Hz\n");
		return -EINVAL;
	}

	err = spi_write(priv->spi, wr_cmd, sizeof(wr_cmd));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set rate command\n");
		return err;
	}

	status = spi_w8r8(priv->spi, rd_cmd);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get rate: %d\n", status);
		return -ENODEV;
	}

	if (status != wr_cmd[1]) {
		pr_err("avionics-hi3593: Failed to"
		       " set rate to 0x%x: 0x%x\n", wr_cmd[1], status);
		return -ENODEV;
	} else {
		pr_info("avionics-hi3593: Set rate to %d\n", rate->rate_hz);
	}

	return 0;
}

static void hi3593_get_rate(struct avionics_rate *rate,
			     const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 cmd;
	ssize_t status;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}

	if (priv->tx_index == 0) {
		cmd = HI3593_OPCODE_RD_TX_CNTRL;
	} else if (priv->rx_index == 0) {
		cmd = HI3593_OPCODE_RD_RX1_CNTRL;
	} else if (priv->rx_index == 1) {
		cmd = HI3593_OPCODE_RD_RX2_CNTRL;
	} else {
		pr_err("avionics-hi3593: No valid port index\n");
		return;
	}

	status = spi_w8r8(priv->spi, cmd);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get rate: %d\n", status);
	} else if(status&0x0001) {
		rate->rate_hz = 12500;
	} else {
		rate->rate_hz = 100000;
	}
}

static void hi3593_get_arinc429rx(struct avionics_arinc429rx *config,
				   const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 rd_cntrl, rd_priority, rd_filters;
	ssize_t status;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}

	if (priv->rx_index == 0) {
		rd_cntrl = HI3593_OPCODE_RD_RX1_CNTRL;
		rd_priority = HI3593_OPCODE_RD_RX1_PRIORITY;
		rd_filters = HI3593_OPCODE_RD_RX1_FILTERS;
	} else if (priv->rx_index == 1) {
		rd_cntrl = HI3593_OPCODE_RD_RX2_CNTRL;
		rd_priority = HI3593_OPCODE_RD_RX2_PRIORITY;
		rd_filters = HI3593_OPCODE_RD_RX2_FILTERS;
	} else {
		pr_err("avionics-hi3593: No valid rx port index\n");
		return;
	}

	status = spi_w8r8(priv->spi, rd_cntrl);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get rx cntrl: %d\n", status);
	} else {
		config->flags = status;
	}

	err = spi_write_then_read(priv->spi, &rd_priority, sizeof(rd_priority),
				  &config->priority_labels, 3);
	if (err) {
		pr_err("avionics-hi3593: Failed to get rx priorty labels: %d\n",
		       err);
	}

	err = spi_write_then_read(priv->spi, &rd_filters, sizeof(rd_priority),
				  &config->label_filers, 32);
	if (err) {
		pr_err("avionics-hi3593: Failed to get rx label filters: %d\n",
		       err);
	}
}

static int hi3593_set_arinc429rx(struct avionics_arinc429rx *config,
				   const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 rd_cntrl, wr_cntrl[2], wr_priority[4], wr_filters[33];
	ssize_t status;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -ENODEV;
	}

	if (priv->rx_index == 0) {
		rd_cntrl = HI3593_OPCODE_RD_RX1_CNTRL;
		wr_cntrl[0] = HI3593_OPCODE_WR_RX1_CNTRL;
		wr_priority[0] = HI3593_OPCODE_WR_RX1_PRIORITY;
		wr_filters[0] = HI3593_OPCODE_WR_RX1_FILTERS;
	} else if (priv->rx_index == 1) {
		rd_cntrl = HI3593_OPCODE_RD_RX2_CNTRL;
		wr_cntrl[0] = HI3593_OPCODE_WR_RX2_CNTRL;
		wr_priority[0] = HI3593_OPCODE_WR_RX2_PRIORITY;
		wr_filters[0] = HI3593_OPCODE_WR_RX2_FILTERS;
	} else {
		pr_err("avionics-hi3593: No valid rx port index\n");
		return -EINVAL;
	}

	status = spi_w8r8(priv->spi, rd_cntrl);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get rx cntrl: %d\n", status);
		return -ENODEV;
	}

	wr_cntrl[1] = (config->flags&0xfe) | (status&0x01);
	err = spi_write(priv->spi, &wr_cntrl, sizeof(wr_cntrl));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set status.\n");
		return err;
	}

	memcpy(&wr_priority[1], &config->priority_labels, 3);
	err = spi_write(priv->spi, &wr_priority, sizeof(wr_priority));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set priority.\n");
		return err;
	}

	memcpy(&wr_filters[1], &config->label_filers, 32);
	err = spi_write(priv->spi, &wr_filters, sizeof(wr_filters));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set priority.\n");
		return err;
	}

	return 0;
}

static void hi3593_get_arinc429tx(struct avionics_arinc429tx *config,
				   const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 rd_cntrl;
	ssize_t status;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}

	if (priv->tx_index == 0) {
		rd_cntrl = HI3593_OPCODE_RD_TX_CNTRL;
	} else {
		pr_err("avionics-hi3593: No valid tx port index\n");
		return;
	}

	status = spi_w8r8(priv->spi, rd_cntrl);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get tx cntrl: %d\n", status);
	} else {
		config->flags = status;
	}

}

static int hi3593_set_arinc429tx(struct avionics_arinc429tx *config,
				 const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 rd_cntrl, wr_cntrl[2];
	ssize_t status;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -ENODEV;
	}

	if (priv->tx_index == 0) {
		rd_cntrl = HI3593_OPCODE_RD_TX_CNTRL;
		wr_cntrl[0] = HI3593_OPCODE_WR_TX_CNTRL;
	} else {
		pr_err("avionics-hi3593: No valid tx port index\n");
		return -EINVAL;
	}

	status = spi_w8r8(priv->spi, rd_cntrl);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get tx cntrl: %d\n", status);
		return -ENODEV;
	}

	wr_cntrl[1] = (config->flags&0x5c) | (status&0xa1);
	err = spi_write(priv->spi, &wr_cntrl, sizeof(wr_cntrl));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set status.\n");
		return err;
	}

	return 0;
}

static struct avionics_ops hi3593_arinc429rx_ops = {
	.name = "arinc429rx%d",
	.set_rate = hi3593_set_rate,
	.get_rate = hi3593_get_rate,
	.get_arinc429rx = hi3593_get_arinc429rx,
	.set_arinc429rx = hi3593_set_arinc429rx,
};

static struct avionics_ops hi3593_arinc429tx_ops = {
	.name = "arinc429tx%d",
	.set_rate = hi3593_set_rate,
	.get_rate = hi3593_get_rate,
	.get_arinc429tx = hi3593_get_arinc429tx,
	.set_arinc429tx = hi3593_set_arinc429tx,
};

static int hi3593_change_mtu(struct net_device *dev, int mtu)
{
	if (mtu != HI3593_MTU) {
		pr_err("avionics-hi3593: MTU must be %d.\n", HI3593_MTU);
		return -EINVAL;
	}

	return 0;
}

static const struct net_device_ops hi3593_netdev_ops = {
	.ndo_change_mtu = hi3593_change_mtu,
};

static const struct of_device_id hi3593_of_device_id[] = {
	{ .compatible	= "holt,hi3593" },
	{}
};
MODULE_DEVICE_TABLE(of, hi3593_of_device_id);

static const struct spi_device_id hi3593_spi_device_id[] = {
	{
		.name		= "hi3593",
		.driver_data	= (kernel_ulong_t)0,
	},
	{}
};
MODULE_DEVICE_TABLE(spi, hi3593_spi_device_id);

static int hi3593_get_config(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int err;

	hi3593->reset_gpio = of_get_named_gpio(dev->of_node, "reset-gpio", 0);
	if (hi3593->reset_gpio > 0 ) {
		if (!gpio_is_valid(hi3593->reset_gpio)) {
			pr_err("avionics-hi3593: Reset GPIO is not valid\n");
			return -EINVAL;
		}

		err = devm_gpio_request_one(&spi->dev, hi3593->reset_gpio,
					    GPIOF_OUT_INIT_HIGH, "reset");
		if (err) {
			pr_err("avionics-hi3593: Failed to"
			       " register Reset GPIO\n");
			return err;
		}
	}

	err = of_property_read_u32(dev->of_node, "aclk", &hi3593->aclk);
	if (err) {
		pr_err("avionics-hi3593: Failed to get aclk"
		       " frequency from dts: %d\n",err);
		return err;
	}

	return 0;
}

static int hi3593_reset(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	__u8 opcode;
	ssize_t status;
	int err;

	if (hi3593->reset_gpio <= 0 ) {
		pr_err("avionics-hi3593: Reset GPIO Reset missing/malformed,"
		       " will use reset command.\n");
		hi3593->reset_gpio = 0;
		opcode = HI3593_OPCODE_RESET;
		err = spi_write(spi, &opcode, sizeof(opcode));
		if (err < 0) {
			pr_err("avionics-hi3593: Failed to"
			       " send reset command\n");
			return err;
		}

	} else {
		usleep_range(100, 150);
		gpio_set_value(hi3593->reset_gpio, 0);
	}

	status = spi_w8r8(spi, HI3593_OPCODE_RD_TX_STATUS);
	if (status != 0x01) {
		pr_err("avionics-hi3593: TX FIFO is not cleared: %x\n", status);
		return -ENODEV;
	}

	pr_info("avionics-hi3593: Device up\n");
	return 0;
}

static int hi3593_set_aclk(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	int err;
	__u8 cmd[2];
	ssize_t status;

	if ((hi3593->aclk < 1000000) || (hi3593->aclk > 30000000)) {
		pr_err("avionics-hi3593: aclk must be between"
		       " 1000000 and 30000000 (1MHz - 30MHz)\n");
		return -EINVAL;
	}

	if ((hi3593->aclk != 1000000) && (hi3593->aclk % 2000000)) {
		pr_err("avionics-hi3593: aclk must be either 1000000"
		       " or a multiple of 2000000\n");
		return -EINVAL;
	}

	cmd[0] = HI3593_OPCODE_WR_ALCK;
	if (hi3593->aclk == 1000000) {
		cmd[1] = 0x00;
	} else {
		cmd[1] = hi3593->aclk/2000000;
	}

	err = spi_write(spi, &cmd, sizeof(cmd));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to send aclk set command\n");
		return err;
	}

	status = spi_w8r8(spi, HI3593_OPCODE_RD_ALCK);
	if (status != cmd[1]) {
		pr_err("avionics-hi3593: ALCK not set to 0x%x: 0x%x\n",
		       cmd[1], status);
		return -ENODEV;
	}

	pr_info("avionics-hi3593: ALCK set to 0x%x\n", status);

	return 0;
}

static struct avionics_arinc429rx avionics_arinc429rx_default = {
	.flags = (AVIONICS_ARINC429RX_FLIP_LABEL_BITS |
		  AVIONICS_ARINC429RX_PARITY_CHECK),
	.priority_labels = {0,0,0},
	.label_filers = {0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0},
};

static struct avionics_arinc429tx avionics_arinc429tx_default = {
	.flags = (AVIONICS_ARINC429TX_FLIP_LABEL_BITS |
		  AVIONICS_ARINC429TX_PARITY_SET),
};


static int hi3593_create_netdevs(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	struct hi3593_priv *priv;
	int i, err;

	for (i = 0; i < HI3593_NUM_TX; i++) {
		hi3593->tx[i] = avionics_device_alloc(sizeof(*priv),
						      &hi3593_arinc429tx_ops);
		if (!hi3593->tx[i] ) {
			pr_err("avionics-hi3593: Failed to allocate"
			       " TX %d netdev\n", i);
			return -ENOMEM;
		}

		hi3593->tx[i]->netdev_ops = &hi3593_netdev_ops;
		hi3593->tx[i]->mtu = HI3593_MTU;
		priv = avionics_device_priv(hi3593->tx[i]);

		if (!priv) {
			pr_err("avionics-hi3593: Failed to get private data"
			       " for TX %d\n", i);
			return -EINVAL;
		}
		priv->spi = spi;
		priv->tx_index = i;
		priv->rx_index = -1;

		err = avionics_device_register(hi3593->tx[i]);
		if (err) {
			pr_err("avionics-hi3593: Failed to register"
			       " TX %d netdev\n", i);
			avionics_device_free(hi3593->tx[i]);
			return -EINVAL;
		}

		err = hi3593_set_arinc429tx(&avionics_arinc429tx_default,
					    hi3593->tx[i]);
		if (err) {
			pr_err("avionics-hi3593: Failed to set TX %d"
			       " default settings\n", i);
			avionics_device_free(hi3593->tx[i]);
			return -EINVAL;
		}
	}

	for (i = 0; i < HI3593_NUM_RX; i++) {
		hi3593->rx[i] = avionics_device_alloc(sizeof(*priv),
						      &hi3593_arinc429rx_ops);
		if (!hi3593->rx[i] ) {
			pr_err("avionics-hi3593: Failed to allocate"
			       " RX %d netdev\n", i);
			return -ENOMEM;
		}

		hi3593->rx[i]->netdev_ops = &hi3593_netdev_ops;
		hi3593->rx[i]->mtu = HI3593_MTU;
		priv = avionics_device_priv(hi3593->rx[i]);

		if (!priv) {
			pr_err("avionics-hi3593: Failed to get private data"
			       " for RX %d\n", i);
			return -EINVAL;
		}
		priv->spi = spi;
		priv->tx_index = -1;
		priv->rx_index = i;

		err = avionics_device_register(hi3593->rx[i]);
		if (err) {
			pr_err("avionics-hi3593: Failed to register"
			       " RX %d netdev\n", i);
			avionics_device_free(hi3593->rx[i]);
			return -EINVAL;
		}

		err = hi3593_set_arinc429rx(&avionics_arinc429rx_default,
					    hi3593->rx[i]);
		if (err) {
			pr_err("avionics-hi3593: Failed to set RX %d"
			       " default settings\n", i);
			avionics_device_free(hi3593->rx[i]);
			return -EINVAL;
		}
	}

	return 0;
}

static int hi3593_remove(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	int i;

	pr_info("avionics-hi3593: Removing Device\n");

	for (i = 0; i < HI3593_NUM_TX; i++) {
		if (hi3593->tx[i]) {
			avionics_device_unregister(hi3593->tx[i]);
			avionics_device_free(hi3593->tx[i]);
		}
	}

	for (i = 0; i < HI3593_NUM_RX; i++) {
		if (hi3593->rx[i]) {
			avionics_device_unregister(hi3593->rx[i]);
			avionics_device_free(hi3593->rx[i]);
		}
	}

	if (hi3593->reset_gpio > 0) {
		gpio_set_value(hi3593->reset_gpio, 1);
		gpio_free(hi3593->reset_gpio);
	}

	return 0;
}

static int hi3593_probe(struct spi_device *spi)
{
	struct hi3593 *hi3593;
	struct device *dev = &spi->dev;
	int err;

	pr_info("avionics-hi3593: Adding Device\n");

	hi3593 = devm_kzalloc(dev, sizeof(*hi3593), GFP_KERNEL);
	if (!hi3593) {
		pr_err("avionics-hi3593: Failed to allocate hi3593 memory\n");
		return -ENOMEM;
	}
	spi_set_drvdata(spi, hi3593);

	err = hi3593_get_config(spi);
	if (err) {
		pr_err("avionics-hi3593: Failed to get system configuration"
		       " from dts file: %d\n",err);
		hi3593_remove(spi);
		return err;
	}

	err = hi3593_reset(spi);
	if (err) {
		pr_err("avionics-hi3593: Failed to bring device"
		       " out of reset: %d\n",err);
		hi3593_remove(spi);
		return err;
	}

	err = hi3593_set_aclk(spi);
	if (err) {
		pr_err("avionics-hi3593: Failed to set"
		       " aclk divider: %d\n", err);
		hi3593_remove(spi);
		return err;
	}

	err = hi3593_create_netdevs(spi);
	if (err) {
		pr_err("avionics-hi3593: Failed to"
		       " register netdevs: %d\n", err);
		hi3593_remove(spi);
		return err;
	}

	/* TODO: Setup IRQs */

	return 0;
}

static struct spi_driver hi3593_spi_driver = {
	.driver = {
		.name = "hi3593",
		.of_match_table = hi3593_of_device_id,
	},
	.id_table = hi3593_spi_device_id,
	.probe = hi3593_probe,
	.remove = hi3593_remove,
};
module_spi_driver(hi3593_spi_driver);
