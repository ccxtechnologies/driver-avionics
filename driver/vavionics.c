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
#include <linux/init.h>

#include "avionics.h"

MODULE_DESCRIPTION("Virtual Avionics Loopback Device");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

static void vavionics_rx(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;

	pr_debug("vavionics: Device rx packet\n");

	stats->rx_packets++;
	stats->rx_bytes += skb->len;

	skb->pkt_type  = PACKET_BROADCAST;
	skb->dev       = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	netif_rx_ni(skb);
}

static netdev_tx_t vavionics_start_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct sk_buff *skb_rx;

	pr_debug("vavionics: Device tx packet\n");

	if (skb->protocol != htons(ETH_P_AVIONICS)) {
	    kfree_skb(skb);
	    dev->stats.tx_dropped++;
	    return NETDEV_TX_OK;
	}

	if (unlikely(skb->len % sizeof(__u32))) {
	    kfree_skb(skb);
	    dev->stats.tx_dropped++;
	    return NETDEV_TX_OK;
	}

	stats->tx_packets++;
	stats->tx_bytes += skb->len;

	skb_rx = skb_clone(skb, GFP_ATOMIC);
	if (!skb_rx) {
		dev->stats.rx_dropped++;
		return NETDEV_TX_OK;
	}

	sock_hold(skb_rx->sk);
	skb_rx->destructor = sock_efree;
	skb_rx->sk = skb->sk;

	vavionics_rx(skb, dev);

	consume_skb(skb);
	return NETDEV_TX_OK;
}

static int vavionics_change_mtu(struct net_device *dev, int mtu)
{
	if (dev->flags & IFF_UP) {
		pr_err("vavionics: Can't change MTU when link is up.\n");
		return -EBUSY;
	}

	if (mtu % sizeof(__u32)) {
		pr_err("vavionics: MTU must be a multiple of 4 bytes.\n");
		return -EINVAL;
	}

	pr_info("vavionics: Setting up device %s MTU to %d\n", dev->name, mtu);

	dev->mtu = mtu;
	return 0;
}

static const struct net_device_ops vavionics_net_device_ops = {
	.ndo_start_xmit = vavionics_start_xmit,
	.ndo_change_mtu = vavionics_change_mtu,
};

static void vavionics_rtnl_link_setup(struct net_device *dev)
{
	pr_info("vavionics: Setting up device\n");

	dev->type		= ARPHRD_AVIONICS;
	dev->mtu		= sizeof(__u32)*32;
	dev->hard_header_len	= 0;
	dev->addr_len		= 0;
	dev->tx_queue_len	= 0;
	dev->flags		= IFF_NOARP;
	dev->netdev_ops		= &vavionics_net_device_ops;
	dev->destructor		= free_netdev;
}

static struct rtnl_link_ops vavionics_rtnl_link_ops __read_mostly = {
	.kind	= "vavionics",
	.setup	= vavionics_rtnl_link_setup,
};

static __init int vavionics_init(void)
{
	int rc;

	pr_info("vavionics: Initialisingr\n");

	rc = rtnl_link_register(&vavionics_rtnl_link_ops);
	if (rc) {
		pr_err("vavionics: Failed to register device: %d\n", rc);
		return rc;
	}

	return 0;
}

static __exit void vavionics_exit(void)
{
	rtnl_link_unregister(&vavionics_rtnl_link_ops);
	pr_info("vavionics: Exited\n");
}

module_init(vavionics_init);
module_exit(vavionics_exit);
