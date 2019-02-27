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

#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include "avionics.h"
#include "protocol.h"
#include "avionics-device.h"

struct device_priv {
	struct net_device *dev;
	struct avionics_rate rate;
	__u8 private[0];
};

static int device_changelink(struct net_device *dev,
			     struct nlattr *tb[], struct nlattr *data[])
{
	struct device_priv *priv = netdev_priv(dev);

	ASSERT_RTNL();

	if (data[IFLA_AVIONICS_RATE]) {
		struct avionics_rate rate;

		if (dev->flags & IFF_UP) {
			return -EBUSY;
		}

		memcpy(&rate, nla_data(data[IFLA_AVIONICS_RATE]),
		       sizeof(rate));

		pr_info("device-device: Setting rate to %d:%d\n",
			rate.tx_rate_hz, rate.rx_rate_hz);

		/* TODO: Call a set rate callback and return error
		 * if there is one */
		memcpy(&priv->rate, &rate, sizeof(rate));

	}

	return 0;
}

static size_t device_get_size(const struct net_device *dev)
{
	size_t size = 0;

	size += nla_total_size(sizeof(struct avionics_rate));

	return size;
}

static int device_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct device_priv *priv = netdev_priv(dev);

	if (
		nla_put(skb, IFLA_AVIONICS_RATE,
			sizeof(priv->rate), &priv->rate)
	) {
		return -EMSGSIZE;
	}

	return 0;
}

static int device_newlink(struct net *src_net, struct net_device *dev,
			    struct nlattr *tb[], struct nlattr *data[])
{
	return -EOPNOTSUPP;
}

static const struct nla_policy device_policy[IFLA_AVIONICS_MAX + 1] = {
	[IFLA_AVIONICS_RATE] = { .len = sizeof(struct avionics_rate) },
};

static void device_setup(struct net_device *dev)
{
	dev->type = ARPHRD_AVIONICS;
	dev->mtu = sizeof(__u32);
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 10;
	dev->flags = IFF_NOARP;
	dev->features = NETIF_F_HW_CSUM;
}

static int device_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (!data) {
		return 0;
	}

	/* TODO: check to make sure the setting is supported
	 * by the interface type, ie. ARINC-429 RX,
	 * return -EOPNOTSUPP; if it isn't */

	return 0;
}

static struct rtnl_link_ops device_link_ops __read_mostly = {
	.kind		= "avionics",
	.maxtype	= IFLA_AVIONICS_MAX,
	.policy		= device_policy,
	.setup		= device_setup,
	.validate	= device_validate,
	.changelink	= device_changelink,
	.get_size	= device_get_size,
	.fill_info	= device_fill_info,
	.newlink	= device_newlink,
};

int device_netlink_register(void)
{
	return rtnl_link_register(&device_link_ops);
}

void device_netlink_unregister(void)
{
	rtnl_link_unregister(&device_link_ops);
}

/* ====================================================== */

struct sk_buff* avionics_device_alloc_skb(struct net_device *dev,
					  unsigned int size)
{
	struct sk_buff *skb;

	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb) {
		pr_err("avionics-device: Unable to allocate skbuff\n");
		return NULL;
	}

	protocol_init_skb(dev, skb);
	skb->len = size;

	return skb;
}
EXPORT_SYMBOL_GPL(avionics_device_alloc_skb);

void * avionics_device_priv(struct net_device *dev)
{
	struct device_priv *priv;

	if (dev->type != ARPHRD_AVIONICS) {
		return NULL;
	}
	priv = netdev_priv(dev);

	return priv->private;
}
EXPORT_SYMBOL_GPL(avionics_device_priv);

int avionics_device_register(struct net_device *dev)
{
	dev->rtnl_link_ops = &device_link_ops;
	return register_netdev(dev);
}
EXPORT_SYMBOL_GPL(avionics_device_register);

void avionics_device_unregister(struct net_device *dev)
{
	unregister_netdev(dev);
}
EXPORT_SYMBOL_GPL(avionics_device_unregister);

static struct net_device *avioinics_device_alloc(int sizeof_priv,
						 const char *name_fmt)
{
	struct net_device *dev;
	struct device_priv *priv;

	dev = alloc_netdev(sizeof(*priv) + sizeof_priv,
			   name_fmt, NET_NAME_UNKNOWN, device_setup);

	if (!dev) {
		pr_err("avionics-device: Failed to allocate netdev\n");
		return NULL;
	}

	priv = netdev_priv(dev);
	priv->dev = dev;

	return dev;
}

struct net_device *avioinics_device_arinc429rx_alloc(int sizeof_priv)
{
	return avioinics_device_alloc(sizeof_priv, "arinc429rx%d");
}
EXPORT_SYMBOL_GPL(avioinics_device_arinc429rx_alloc);

struct net_device *avioinics_device_arinc429tx_alloc(int sizeof_priv)
{
	return avioinics_device_alloc(sizeof_priv, "arinc429tx%d");
}
EXPORT_SYMBOL_GPL(avioinics_device_arinc429tx_alloc);

void avionics_device_free(struct net_device *dev)
{
	free_netdev(dev);
}
EXPORT_SYMBOL_GPL(avionics_device_free);
