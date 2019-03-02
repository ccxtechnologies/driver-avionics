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

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("Virtual Avionics Example Device");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

struct net_device *example_rx;

struct example_priv {
	__u32 fifo_depth;
	bool highspeed;
};

static int example_set_rate(struct avionics_rate *rate,
			    const struct net_device *dev)
{
	struct example_priv *priv;
	priv = avionics_device_priv(dev);

	if (!priv) {
		pr_err("avionics-example: Failed to get private data\n");
		return -EINVAL;
	}

	if(rate->rate_hz == 100000) {
		pr_info("avionics-example: high-speed\n");
		priv->highspeed = true;
	} else if(rate->rate_hz == 12500) {
		pr_info("avionics-example: low-speed\n");
		priv->highspeed = false;
	} else {
		pr_warn("avionics-example: speed must be 100000 or 12500 Hz\n");
		return -EINVAL;
	}

	return 0;
}

static void example_get_rate(struct avionics_rate *rate,
			     const struct net_device *dev)
{
	struct example_priv *priv;
	priv = avionics_device_priv(dev);

	if (!priv) {
		pr_err("avionics-example: Failed to get private data\n");
		return;
	}

	if(priv->highspeed) {
		rate->rate_hz = 100000;
	} else {
		rate->rate_hz = 12500;
	}
}

static struct avionics_ops example_avionics_ops = {
	.name = "arinc429erx",
	.set_rate = example_set_rate,
	.get_rate = example_get_rate,
};

static int example_change_mtu(struct net_device *dev, int mtu)
{
	struct example_priv * priv;

	if (dev->flags & IFF_UP) {
		pr_err("avionics-example: Can't change MTU when link is up.\n");
		return -EBUSY;
	}

	if (mtu % sizeof(__u32)) {
		pr_err("avionics-example: MTU must be a multiple of 4.\n");
		return -EINVAL;
	}

	pr_info("avionics-example: Setting up device %s MTU to %d\n",
		dev->name, mtu);

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-example: Failed to get private data\n");
		return -EINVAL;
	}
	priv->fifo_depth = mtu / sizeof(__u32);

	dev->mtu = mtu;

	return 0;
}

static const struct net_device_ops example_rx_netdev_ops = {
	.ndo_change_mtu = example_change_mtu,
};

static __init int example_init(void)
{
	struct net_device *net;
	struct example_priv *priv;
	int err;

	pr_info("avionics-example: Initialising Driver\n");

	net = avionics_device_alloc(sizeof(*priv), &example_avionics_ops);
	if (!net) {
		pr_err("avionics-example: Failed to allocate RX ARINC-429\n");
		return -ENOMEM;
	}

	net->netdev_ops = &example_rx_netdev_ops;
	priv = avionics_device_priv(net);

	if (!priv) {
		pr_err("avionics-example: Failed to get private data\n");
		return -EINVAL;
	}
	priv->fifo_depth = 32;
	priv->highspeed = false;

	example_rx = net;
	err = avionics_device_register(example_rx);
	if (err) {
		pr_err("avionics-example: Failed to register RX ARINC-429\n");
		avionics_device_free(example_rx);
		return -EINVAL;
	}

	return 0;
}

static __exit void example_exit(void)
{
	avionics_device_unregister(example_rx);
	avionics_device_free(example_rx);

	pr_info("avionics-example: Exited Driver\n");
}

module_init(example_init);
module_exit(example_exit);
