/*
 * Copyright (C) 2015 Marek Vasut <marex@denx.de>
 *
 * Based on the SocketCAN stack.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
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
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include "arinc429.h"
#include "dev.h"
#include "skb.h"
#include "netlink.h"
#include <net/rtnetlink.h>

#define MOD_DESC "ARINC429 device driver interface"

MODULE_DESCRIPTION(MOD_DESC);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marek Vasut <marex@denx.de>");

static void arinc429_setup(struct net_device *dev)
{
	dev->type = ARPHRD_ARINC429;
	dev->mtu = ARINC429_MTU;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 10;

	/* New-style flags. */
	dev->flags = IFF_NOARP;
	dev->features = NETIF_F_HW_CSUM;
}

struct sk_buff *alloc_arinc429_skb(struct net_device *dev,
				   struct arinc429_frame **cf)
{
	struct sk_buff *skb;

	skb = netdev_alloc_skb(dev, sizeof(struct arinc429_skb_priv) +
			       sizeof(struct arinc429_frame));
	if (unlikely(!skb))
		return NULL;

	__net_timestamp(skb);
	skb->protocol = htons(ETH_P_ARINC429);
	skb->pkt_type = PACKET_BROADCAST;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	arinc429_skb_reserve(skb);
	arinc429_skb_prv(skb)->ifindex = dev->ifindex;

	*cf = (struct arinc429_frame *)skb_put(skb,
					       sizeof(struct arinc429_frame));
	memset(*cf, 0, sizeof(struct arinc429_frame));

	return skb;
}
EXPORT_SYMBOL_GPL(alloc_arinc429_skb);

/*
 * Allocate and setup space for the ARINC429 network device
 */
struct net_device *alloc_arinc429dev(int size)
{
	struct net_device *dev;
	struct arinc429_priv *priv;
	int size;

	dev = alloc_netdev(size, "arinc429-%d", NET_NAME_UNKNOWN,
			   arinc429_setup);
	if (!dev)
		return NULL;

	priv = netdev_priv(dev);

	return dev;
}
EXPORT_SYMBOL_GPL(alloc_arinc429dev);

/*
 * Free space of the ARINC429 network device
 */
void free_arinc429dev(struct net_device *dev)
{
	free_netdev(dev);
}
EXPORT_SYMBOL_GPL(free_arinc429dev);

/*
 * changing MTU and control mode for ARINC429 devices
 */
int arinc429_change_mtu(struct net_device *dev, int new_mtu)
{
	/* Do not allow changing the MTU while running */
	if (dev->flags & IFF_UP)
		return -EBUSY;

	if (new_mtu != ARINC429_MTU)
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}
EXPORT_SYMBOL_GPL(arinc429_change_mtu);

/*
 * Common open function when the device gets opened.
 *
 * This function should be called in the open function of the device
 * driver.
 */
int open_arinc429dev(struct net_device *dev)
{
	struct arinc429_priv *priv = netdev_priv(dev);

	if (!priv->rate.rx_rate || !priv->rate.tx_rate) {
		netdev_err(dev, "data rate not yet defined\n");
		return -EINVAL;
	}

	/* Switch carrier on if device was stopped while in bus-off state */
	if (!netif_carrier_ok(dev))
		netif_carrier_on(dev);

	return 0;
}
EXPORT_SYMBOL_GPL(open_arinc429dev);

/*
 * Common close function for cleanup before the device gets closed.
 *
 * This function should be called in the close function of the device
 * driver.
 */
void close_arinc429dev(struct net_device *dev)
{
}
EXPORT_SYMBOL_GPL(close_arinc429dev);

/*
 * ARINC429 netlink interface
 */
static const struct nla_policy arinc429_policy[IFLA_ARINC429_MAX + 1] = {
	[IFLA_ARINC429_RATE]	= { .len = sizeof(struct arinc429_rate) },
	[IFLA_ARINC429_CTRLMODE] = { .len = sizeof(struct arinc429_ctrlmode) },
};

static int arinc429_changelink(struct net_device *dev,
			       struct nlattr *tb[], struct nlattr *data[])
{
	struct arinc429_priv *priv = netdev_priv(dev);
	int err;

	/* We need synchronization with dev->stop() */
	ASSERT_RTNL();

	if (data[IFLA_ARINC429_RATE]) {
		struct arinc429_rate clk;

		/* Do not allow changing clock while running */
		if (dev->flags & IFF_UP)
			return -EBUSY;

		/*
		 * Check if the clock frequency is valid, ARINC429
		 * supports either 12.5kHz bus (Low speed bus mode)
		 * or 100kHz (High speed bus mode). If the speed is
		 * set to 0, do not modify that configuration.
		 */
		memcpy(&clk, nla_data(data[IFLA_ARINC429_RATE]), sizeof(clk));
		if (clk.rx_rate && clk.rx_rate != 12500 &&
		    clk.rx_rate != 100000)
			return -EINVAL;
		if (clk.tx_rate && clk.tx_rate != 12500 &&
		    clk.tx_rate != 100000)
			return -EINVAL;

		memcpy(&priv->rate, &clk, sizeof(clk));

		if (priv->do_set_rate) {
			/* Finally, set the data rate register */
			err = priv->do_set_rate(dev);
			if (err)
				return err;
		}
	}

	if (data[IFLA_ARINC429_CTRLMODE]) {
		struct arinc429_ctrlmode *cm;

		/* Do not allow changing controller mode while running */
		if (dev->flags & IFF_UP)
			return -EBUSY;
		cm = nla_data(data[IFLA_ARINC429_CTRLMODE]);

		/* check whether changed bits are allowed to be modified */
		if (cm->mask & ~priv->ctrlmode_supported)
			return -EOPNOTSUPP;

		/* clear bits to be modified and copy the flag values */
		priv->ctrlmode &= ~cm->mask;
		priv->ctrlmode |= (cm->flags & cm->mask);
	}

	return 0;
}

static size_t arinc429_get_size(const struct net_device *dev)
{
	size_t size = 0;

	/* IFLA_ARINC429_RATE */
	size += nla_total_size(sizeof(struct arinc429_rate));
	/* IFLA_ARINC429_CTRLMODE */
	size += nla_total_size(sizeof(struct arinc429_ctrlmode));

	return size;
}

static int arinc429_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct arinc429_priv *priv = netdev_priv(dev);
	struct arinc429_ctrlmode cm = {.flags = priv->ctrlmode};

	if (
		nla_put(skb, IFLA_ARINC429_RATE, sizeof(priv->rate), &priv->rate) ||
		nla_put(skb, IFLA_ARINC429_CTRLMODE, sizeof(cm), &cm)
	)
		return -EMSGSIZE;

	return 0;
}

static int arinc429_newlink(struct net *src_net, struct net_device *dev,
			    struct nlattr *tb[], struct nlattr *data[])
{
	return -EOPNOTSUPP;
}

static struct rtnl_link_ops arinc429_link_ops __read_mostly = {
	.kind		= "arinc429",
	.maxtype	= IFLA_ARINC429_MAX,
	.policy		= arinc429_policy,
	.setup		= arinc429_setup,
	.newlink	= arinc429_newlink,
	.changelink	= arinc429_changelink,
	.get_size	= arinc429_get_size,
	.fill_info	= arinc429_fill_info,
};

/*
 * Register the ARINC429 network device
 */
int register_arinc429dev(struct net_device *dev)
{
	dev->rtnl_link_ops = &arinc429_link_ops;
	return register_netdev(dev);
}
EXPORT_SYMBOL_GPL(register_arinc429dev);

/*
 * Unregister the ARINC429 network device
 */
void unregister_arinc429dev(struct net_device *dev)
{
	unregister_netdev(dev);
}
EXPORT_SYMBOL_GPL(unregister_arinc429dev);

/*
 * Test if a network device is a arinc429dev based device
 * and return the arinc429_priv* if so.
 */
struct arinc429_priv *safe_arinc429dev_priv(struct net_device *dev)
{
	if ((dev->type != ARPHRD_ARINC429) ||
	    (dev->rtnl_link_ops != &arinc429_link_ops))
		return NULL;

	return netdev_priv(dev);
}
EXPORT_SYMBOL_GPL(safe_arinc429dev_priv);

static __init int arinc429_dev_init(void)
{
	int err;

	err = rtnl_link_register(&arinc429_link_ops);
	if (!err)
		pr_info(MOD_DESC "\n");

	return err;
}
module_init(arinc429_dev_init);

static __exit void arinc429_dev_exit(void)
{
	rtnl_link_unregister(&arinc429_link_ops);
}
module_exit(arinc429_dev_exit);

MODULE_ALIAS_RTNL_LINK("arinc429");
