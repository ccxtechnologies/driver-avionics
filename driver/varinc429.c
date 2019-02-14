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

#include "arinc429.h"

MODULE_DESCRIPTION("Virtual ARINC-429 Device");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

static void varinc429_rx(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;

	stats->rx_packets++;
	stats->rx_bytes += skb->len;

	skb->pkt_type  = PACKET_BROADCAST;
	skb->dev       = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	netif_rx_ni(skb);
}

static netdev_tx_t varinc429_start_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct sk_buff *skb_rx;

	if (skb->protocol != htons(ETH_P_ARINC429)) {
	    kfree_skb(skb);
	    dev->stats.tx_dropped++;
	    return NETDEV_TX_OK;
	}

	if (unlikely(skb->len % ARINC429_WORD_SIZE)) {
	    kfree_skb(skb);
	    dev->stats.tx_dropped++;
	    return NETDEV_TX_OK;
	}

	stats->tx_packets++;
	stats->tx_bytes += skb->len;

	skb_rx = skb_clone(skb, GFP_ATOMIC);
	if (!skb) {
		dev->stats.rx_dropped++;
		return NETDEV_TX_OK;
	}

	sock_hold(skb->sk);
	skb_rx->destructor = sock_efree;
	skb_rx->sk = skb->sk;

	varinc429_rx(skb, dev);

	consume_skb(skb);
	return NETDEV_TX_OK;
}

static int varinc429_change_mtu(struct net_device *dev, int mtu)
{
	if (dev->flags & IFF_UP) {
		pr_err("Can't change MTU when link is up.\n");
		return -EBUSY;
	}

	if (mtu % ARINC429_WORD_SIZE) {
		pr_err("MTU must be a multiple of %ld (ARINC-429 word size)\n",
		       ARINC429_WORD_SIZE);
		return -EINVAL;
	}

	pr_info("Setting up device %s MTU to %d\n", dev->name, mtu);

	dev->mtu = mtu;
	return 0;
}

static const struct net_device_ops varinc429_net_device_ops = {
	.ndo_start_xmit = varinc429_start_xmit,
	.ndo_change_mtu = varinc429_change_mtu,
};

static void varinc429_rtnl_link_setup(struct net_device *dev)
{
	pr_info("Setting up Virtial ARINC-429 Device\n");

	dev->type		= ARPHRD_ARINC429;
	dev->mtu		= ARINC429_WORD_SIZE*32;
	dev->hard_header_len	= 0;
	dev->addr_len		= 0;
	dev->tx_queue_len	= 0;
	dev->flags		= IFF_NOARP;
	dev->netdev_ops		= &varinc429_net_device_ops;
	dev->destructor		= free_netdev;
}

static struct rtnl_link_ops varinc429_rtnl_link_ops __read_mostly = {
	.kind	= "varinc429",
	.setup	= varinc429_rtnl_link_setup,
};

static __init int varinc429_init(void)
{
	int rc;

	pr_info("Initialising Virtial ARINC-429 Device Driver\n");

	rc = rtnl_link_register(&varinc429_rtnl_link_ops);
	if (rc) {
		pr_err("Failed to register Virtial ARINC-429 Device: %d\n", rc);
		return rc;
	}

	return 0;
}

static __exit void varinc429_exit(void)
{
	rtnl_link_unregister(&varinc429_rtnl_link_ops);
	pr_info("Exited Virtial ARINC-429 Device Driver\n");
}

module_init(varinc429_init);
module_exit(varinc429_exit);
