/*
 * varinc429.c - Virtual ARINC429 interface
 *
 * Copyright (C) 2015 Marek Vasut <marex@denx.de>
 *
 * Based on the SocketCAN stack.
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
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/arinc429.h>
#include <linux/arinc429/dev.h>
#include <linux/arinc429/skb.h>
#include <linux/slab.h>
#include <net/rtnetlink.h>

MODULE_DESCRIPTION("Virtual ARINC429 interface");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marek Vasut <marex@denx.de>");

/*
 * ARINC429 test feature:
 * Enable the echo on driver level for testing the ARINC429 core echo modes.
 */

static bool echo; /* echo testing. Default: 0 (Off) */
module_param(echo, bool, S_IRUGO);
MODULE_PARM_DESC(echo, "Echo sent frames (for testing). Default: 0 (Off)");

static void varinc429_rx(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;

	stats->rx_packets++;
	stats->rx_bytes += ARINC429_MTU;

	skb->pkt_type  = PACKET_BROADCAST;
	skb->dev       = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (!(skb->tstamp.tv64))
		__net_timestamp(skb);

	netif_rx_ni(skb);
}

static netdev_tx_t varinc429_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	int loop;

	if (arinc429_dropped_invalid_skb(dev, skb))
		return NETDEV_TX_OK;

	stats->tx_packets++;
	stats->tx_bytes += ARINC429_MTU;

	/* set flag whether this packet has to be looped back */
	loop = skb->pkt_type == PACKET_LOOPBACK;

	if (!echo) {
		/* no echo handling available inside this driver */

		if (loop) {
			/*
			 * Only count the packets here, because the
			 * ARINC429 core already did the echo for us
			 */
			stats->rx_packets++;
			stats->rx_bytes += ARINC429_MTU;
		}
		consume_skb(skb);
		return NETDEV_TX_OK;
	}

	/* Perform standard echo handling for ARINC429 network interfaces */
	if (loop) {
		skb = arinc429_create_echo_skb(skb);
		if (!skb)
			return NETDEV_TX_OK;

		/* Receive with packet counting */
		varinc429_rx(skb, dev);
	} else {
		/* No looped packets => no counting */
		consume_skb(skb);
	}
	return NETDEV_TX_OK;
}

static int varinc429_change_mtu(struct net_device *dev, int new_mtu)
{
	/* Do not allow changing the MTU while running */
	if (dev->flags & IFF_UP)
		return -EBUSY;

	if (new_mtu != ARINC429_MTU)
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static const struct net_device_ops varinc429_netdev_ops = {
	.ndo_start_xmit = varinc429_tx,
	.ndo_change_mtu = varinc429_change_mtu,
};

static void varinc429_setup(struct net_device *dev)
{
	dev->type		= ARPHRD_ARINC429;
	dev->mtu		= ARINC429_MTU;
	dev->hard_header_len	= 0;
	dev->addr_len		= 0;
	dev->tx_queue_len	= 0;
	dev->flags		= IFF_NOARP;

	/* set flags according to driver capabilities */
	if (echo)
		dev->flags |= IFF_ECHO;

	dev->netdev_ops		= &varinc429_netdev_ops;
	dev->destructor		= free_netdev;
}

static struct rtnl_link_ops varinc429_link_ops __read_mostly = {
	.kind	= "varinc429",
	.setup	= varinc429_setup,
};

static __init int varinc429_init_module(void)
{
	pr_info("varinc429: Virtual ARINC429 interface driver\n");

	if (echo)
		pr_info("varinc429: enabled echo on driver level.\n");

	return rtnl_link_register(&varinc429_link_ops);
}

static __exit void varinc429_cleanup_module(void)
{
	rtnl_link_unregister(&varinc429_link_ops);
}

module_init(varinc429_init_module);
module_exit(varinc429_cleanup_module);
