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
#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/init.h>

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("Virtual Avionics Loopback Device");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

static void lb_rx(struct sk_buff *skb_xmit, struct net_device *dev)
{
	struct sk_buff *skb;
	struct net_device_stats *stats = &dev->stats;

	pr_debug("avionics-lb: RX Packet\n");

	skb = avionics_device_alloc_skb(dev, skb_xmit->len);
	if (!skb) {
		pr_err("avionics-lb: Failed ot allocate RX buffer\n");
		return;
	}

	skb_copy_to_linear_data(skb, skb_xmit->data, skb_xmit->len);

	stats->rx_packets++;
	stats->rx_bytes += skb->len;

	netif_rx_ni(skb);
}

static netdev_tx_t lb_start_xmit(struct sk_buff *skb,
				 struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;

	pr_debug("avionics-lb: TX Packet\n");

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

	lb_rx(skb, dev);

	consume_skb(skb);
	return NETDEV_TX_OK;
}

static int lb_change_mtu(struct net_device *dev, int mtu)
{
	if (dev->flags & IFF_UP) {
		pr_err("avionics-lb: Can't change MTU when link is up.\n");
		return -EBUSY;
	}

	pr_info("avionics-lb: Setting up device %s MTU to %d\n", dev->name, mtu);

	dev->mtu = mtu;
	return 0;
}

static const struct net_device_ops lb_net_device_ops = {
	.ndo_start_xmit = lb_start_xmit,
	.ndo_change_mtu = lb_change_mtu,
};

static void lb_rtnl_link_setup(struct net_device *dev)
{
	dev->type		= ARPHRD_AVIONICS;
	dev->mtu		= sizeof(__u32)*32;
	dev->hard_header_len	= 0;
	dev->addr_len		= 0;
	dev->tx_queue_len	= 0;
	dev->flags		= IFF_NOARP;
	dev->netdev_ops		= &lb_net_device_ops;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,11,0)
	dev->destructor		= free_netdev;
#else
	dev->needs_free_netdev	= true;
#endif
}

static struct rtnl_link_ops lb_rtnl_link_ops __read_mostly = {
	.kind	= "avionics-lb",
	.setup	= lb_rtnl_link_setup,
};

static __init int lb_init(void)
{
	int rc;

	pr_info("avionics-lb: Initialising Driver\n");

	rc = rtnl_link_register(&lb_rtnl_link_ops);
	if (rc) {
		pr_err("avionics-lb: Failed to register device: %d\n", rc);
		return rc;
	}

	return 0;
}

static __exit void lb_exit(void)
{
	rtnl_link_unregister(&lb_rtnl_link_ops);
	pr_info("avionics-lb: Exited Driver\n");
}

module_init(lb_init);
module_exit(lb_exit);
