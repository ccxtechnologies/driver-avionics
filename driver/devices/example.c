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

struct net_device *example_rx0;

struct example_priv {
	int some_config;
	int fifo_depth;
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

	net = avioinics_device_arinc429rx_alloc(sizeof(*priv));
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
	priv->fifo_depth = 32*sizeof(__u32);

	example_rx0 = net;
	err = avionics_device_register(example_rx0);
	if (err) {
		pr_err("avionics-example: Failed to register RX ARINC-429\n");
		avionics_device_free(example_rx0);
		return -EINVAL;
	}

	return 0;
}

static __exit void example_exit(void)
{
	avionics_device_unregister(example_rx0);
	avionics_device_free(example_rx0);

	pr_info("avionics-example: Exited Driver\n");
}

module_init(example_init);
module_exit(example_exit);
