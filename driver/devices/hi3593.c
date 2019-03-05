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
	priv = avionics_device_priv(dev);

	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -EINVAL;
	}

	if(rate->rate_hz == 100000) {
		pr_info("avionics-hi3593: high-speed\n");
		/* TODO: Set rate to high */

	} else if(rate->rate_hz == 12500) {
		pr_info("avionics-hi3593: low-speed\n");
		/* TODO: Set rate to low */

	} else {
		pr_warn("avionics-hi3593: speed must be 100000 or 12500 Hz\n");
		return -EINVAL;
	}

	return 0;
}

static void hi3593_get_rate(struct avionics_rate *rate,
			     const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 highspeed;
	priv = avionics_device_priv(dev);

	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}

	/* TODO: Get rate from device */
	highspeed = 0;

	if(highspeed) {
		rate->rate_hz = 100000;
	} else {
		rate->rate_hz = 12500;
	}
}

static struct avionics_ops hi3593_arinc429rx_ops = {
	.name = "arinc429rx%d",
	.set_rate = hi3593_set_rate,
	.get_rate = hi3593_get_rate,
	/* TODO: Add Configuration routines */
};

static struct avionics_ops hi3593_arinc429tx_ops = {
	.name = "arinc429tx%d",
	.set_rate = hi3593_set_rate,
	.get_rate = hi3593_get_rate,
	/* TODO: Add Configuration routines */
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

/* ======================== */

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
		err = spi_write(spi, &opcode, 1);
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
	__u16 cmd;
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

	if (hi3593->aclk == 1000000) {
		cmd = HI3593_OPCODE_WR_ALCK << 8;
	} else {
		cmd = (HI3593_OPCODE_WR_ALCK << 8) + hi3593->aclk/2000000;
	}

	err = spi_write(spi, &cmd, 2);
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to send aclk set command\n");
		return err;
	}

	status = spi_w8r8(spi, HI3593_OPCODE_RD_ALCK);
	if (status != (cmd&0x00ff)) {
		pr_err("avionics-hi3593: ALCK not set to 0x%x: 0x%x\n",
		       (cmd&0x00ff), status);
		return -ENODEV;
	}

	pr_info("avionics-hi3593: ALCK set to 0x%x\n", status);

	return 0;
}

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
			pr_err("avionics-hi3592: Failed to register"
			       " TX %d netdev\n", i);
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
			pr_err("avionics-hi3592: Failed to register"
			       " RX %d netdev\n", i);
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
