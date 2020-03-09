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

#include <linux/version.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include "avionics.h"
#include "protocol.h"
#include "avionics-device.h"

struct device_priv {
	struct net_device *dev;
	struct avionics_ops *ops;
	__u8 private[0];
};

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,13,0)
static int device_changelink(struct net_device *dev,
			     struct nlattr *tb[], struct nlattr *data[])
#else
static int device_changelink(struct net_device *dev,
			     struct nlattr *tb[], struct nlattr *data[],
			     struct netlink_ext_ack *extack)
#endif
{
	struct device_priv *priv = netdev_priv(dev);

	ASSERT_RTNL();

	if (data[IFLA_AVIONICS_RATE] && priv->ops &&
	    priv->ops->set_rate) {
		struct avionics_rate rate;

		memcpy(&rate, nla_data(data[IFLA_AVIONICS_RATE]), sizeof(rate));
		return priv->ops->set_rate(&rate, dev);
	}

	if (data[IFLA_AVIONICS_ARINC429RX] && priv->ops &&
	    priv->ops->set_arinc429rx) {
		struct avionics_arinc429rx arinc429rx;

		memcpy(&arinc429rx, nla_data(data[IFLA_AVIONICS_ARINC429RX]),
		       sizeof(arinc429rx));
		return priv->ops->set_arinc429rx(&arinc429rx, dev);
	}

	if (data[IFLA_AVIONICS_ARINC429TX] && priv->ops &&
	    priv->ops->set_arinc429tx) {
		struct avionics_arinc429tx arinc429tx;

		memcpy(&arinc429tx, nla_data(data[IFLA_AVIONICS_ARINC429TX]),
		       sizeof(arinc429tx));
		return priv->ops->set_arinc429tx(&arinc429tx, dev);
	}

	if (data[IFLA_AVIONICS_ARINC717RX] && priv->ops &&
	    priv->ops->set_arinc717rx) {
		struct avionics_arinc717rx arinc717rx;

		memcpy(&arinc717rx, nla_data(data[IFLA_AVIONICS_ARINC717RX]),
		       sizeof(arinc717rx));
		return priv->ops->set_arinc717rx(&arinc717rx, dev);
	}

	if (data[IFLA_AVIONICS_ARINC717TX] && priv->ops &&
	    priv->ops->set_arinc717tx) {
		struct avionics_arinc717tx arinc717tx;

		memcpy(&arinc717tx, nla_data(data[IFLA_AVIONICS_ARINC717TX]),
		       sizeof(arinc717tx));
		return priv->ops->set_arinc717tx(&arinc717tx, dev);
	}

	return 0;
}

static size_t device_get_size(const struct net_device *dev)
{
	struct device_priv *priv = netdev_priv(dev);
	size_t size = 0;

	if(priv->ops && priv->ops->set_rate) {
		size += nla_total_size(sizeof(struct avionics_rate));
	}

	if(priv->ops && priv->ops->set_arinc429rx) {
		size += nla_total_size(sizeof(struct avionics_arinc429rx));
	}

	if(priv->ops && priv->ops->set_arinc429tx) {
		size += nla_total_size(sizeof(struct avionics_arinc429tx));
	}

	if(priv->ops && priv->ops->set_arinc717rx) {
		size += nla_total_size(sizeof(struct avionics_arinc717rx));
	}

	if(priv->ops && priv->ops->set_arinc717tx) {
		size += nla_total_size(sizeof(struct avionics_arinc717tx));
	}

	return size;
}

static int device_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct device_priv *priv = netdev_priv(dev);
	int err;

	if (priv->ops && priv->ops->get_rate) {
		struct avionics_rate rate;
		priv->ops->get_rate(&rate, dev);

		err = nla_put(skb, IFLA_AVIONICS_RATE, sizeof(rate), &rate);
		if (err) {
			return -EMSGSIZE;
		}
	}

	if (priv->ops && priv->ops->get_arinc429rx) {
		struct avionics_arinc429rx arinc429rx;
		priv->ops->get_arinc429rx(&arinc429rx, dev);

		err = nla_put(skb, IFLA_AVIONICS_ARINC429RX,
			      sizeof(arinc429rx), &arinc429rx);
		if (err) {
			return -EMSGSIZE;
		}
	}

	if (priv->ops && priv->ops->get_arinc429tx) {
		struct avionics_arinc429tx arinc429tx;
		priv->ops->get_arinc429tx(&arinc429tx, dev);

		err = nla_put(skb, IFLA_AVIONICS_ARINC429TX,
			      sizeof(arinc429tx), &arinc429tx);
		if (err) {
			return -EMSGSIZE;
		}

	}

	if (priv->ops && priv->ops->get_arinc717rx) {
		struct avionics_arinc717rx arinc717rx;
		priv->ops->get_arinc717rx(&arinc717rx, dev);

		err = nla_put(skb, IFLA_AVIONICS_ARINC717RX,
			      sizeof(arinc717rx), &arinc717rx);
		if (err) {
			return -EMSGSIZE;
		}
	}

	if (priv->ops && priv->ops->get_arinc717tx) {
		struct avionics_arinc717tx arinc717tx;
		priv->ops->get_arinc717tx(&arinc717tx, dev);

		err = nla_put(skb, IFLA_AVIONICS_ARINC717TX,
			      sizeof(arinc717tx), &arinc717tx);
		if (err) {
			return -EMSGSIZE;
		}

	}

	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,13,0)
static int device_newlink(struct net *src_net, struct net_device *dev,
			    struct nlattr *tb[], struct nlattr *data[])
#else
static int device_newlink(struct net *src_net, struct net_device *dev,
			    struct nlattr *tb[], struct nlattr *data[],
			    struct netlink_ext_ack *extack)
#endif
{
	return -EOPNOTSUPP;
}

static const struct nla_policy device_policy[IFLA_AVIONICS_MAX + 1] = {
	[IFLA_AVIONICS_RATE] = {
		.len = sizeof(struct avionics_rate)
	},
	[IFLA_AVIONICS_ARINC429RX] = {
		.len = sizeof(struct avionics_arinc429rx)
	},
	[IFLA_AVIONICS_ARINC429TX] = {
		.len = sizeof(struct avionics_arinc429tx)
	},
	[IFLA_AVIONICS_ARINC717RX] = {
		.len = sizeof(struct avionics_arinc717rx)
	},
	[IFLA_AVIONICS_ARINC717TX] = {
		.len = sizeof(struct avionics_arinc717tx)
	},
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

static struct rtnl_link_ops device_link_ops __read_mostly = {
	.kind		= "avionics",
	.maxtype	= IFLA_AVIONICS_MAX,
	.policy		= device_policy,
	.setup		= device_setup,
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

void * avionics_device_priv(const struct net_device *dev)
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
	int err;
	err = register_netdev(dev);
	if (err) {
		pr_err("avionics-device: Failed to register netdev\n");
		return err;
	}

	dev->rtnl_link_ops = &device_link_ops;
	return 0;
}
EXPORT_SYMBOL_GPL(avionics_device_register);

void avionics_device_unregister(struct net_device *dev)
{
	if (dev->rtnl_link_ops == &device_link_ops) {
		unregister_netdev(dev);
	} else {
		pr_warn("avionics-device: Device not registered\n");
	}
}
EXPORT_SYMBOL_GPL(avionics_device_unregister);

struct net_device *avionics_device_alloc(int sizeof_priv,
					 struct avionics_ops *ops)
{
	struct net_device *dev;
	struct device_priv *priv;

	if (!ops) {
		pr_err("avionics-device: No ops defined\n");
		return NULL;
	}

	dev = alloc_netdev(sizeof(*priv) + sizeof_priv, ops->name,
			   NET_NAME_UNKNOWN, device_setup);

	if (!dev) {
		pr_err("avionics-device: Failed to allocate netdev\n");
		return NULL;
	}

	priv = netdev_priv(dev);
	priv->dev = dev;
	priv->ops = ops;

	return dev;
}
EXPORT_SYMBOL_GPL(avionics_device_alloc);

void avionics_device_free(struct net_device *dev)
{
	free_netdev(dev);
}
EXPORT_SYMBOL_GPL(avionics_device_free);
