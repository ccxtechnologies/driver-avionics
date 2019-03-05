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

struct hi3593 {
	struct net_device *rx[2];
	struct net_device *tx;
	int reset_gpio;
	__u32 aclk;
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

static const struct net_device_ops hi3593_rx_netdev_ops = {
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

static int hi3593_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct hi3593 *hi3593;
	__u8 cmd;
	ssize_t status;
	int err;

	pr_info("avionics-hi3593: Adding Device\n");

	hi3593 = devm_kzalloc(dev, sizeof(*hi3593), GFP_KERNEL);
	if (!hi3593) {
		pr_err("avionics-hi3593: Failed to allocate hi3593 memory\n");
		return -ENOMEM;
	}

	spi_set_drvdata(spi, hi3593);

	hi3593->reset_gpio = of_get_named_gpio(dev->of_node, "reset-gpio", 0);
	if (hi3593->reset_gpio <= 0 ) {
		pr_err("avionics-hi3593: Reset GPIO Reset missing/malformed,"
		       " will use reset command.\n");
		hi3593->reset_gpio = 0;
		cmd = HI3593_OPCODE_RESET;
		err = spi_write(spi, &cmd, 1);
		if (err < 0) {
			pr_err("avionics-hi3593: Failed to"
			       " send reset command\n");
			return err;
		}

	} else {
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

		usleep_range(100, 150);
		gpio_set_value(hi3593->reset_gpio, 0);
	}

	status = spi_w8r8(spi, HI3593_OPCODE_RD_TX_STATUS);
	if (status != 0x01) {
		pr_err("avionics-hi3593: TX FIFO is not cleared: %x\n", status);
		if (hi3593->reset_gpio) {
			gpio_set_value(hi3593->reset_gpio, 0);
			gpio_free(hi3593->reset_gpio);
		}
		return -ENODEV;
	} else {
		pr_info("avionics-hi3593: Device up\n");
	}

	/* TODO: Create net devices */


	/* TODO: Setup IRQs */

	of_property_read_u32(dev->of_node, "aclk", &hi3593->aclk);
	pr_info("avionics-hi3593: Setting ACLK to %dHz\n", hi3593->aclk);
	/* TODO: Configure ACLK */

	return 0;
}

static int hi3593_remove(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);

	pr_info("avionics-hi3593: Removing Device\n");

	if (hi3593->reset_gpio) {
		gpio_set_value(hi3593->reset_gpio, 0);
		gpio_free(hi3593->reset_gpio);
	}

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
