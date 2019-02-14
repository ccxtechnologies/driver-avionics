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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/init.h>

#include "arinc429.h"

MODULE_DESCRIPTION("ARINC-429 Socket Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

MODULE_ALIAS_NETPROTO(PF_ARINC429);

static int arinc429_sock_create(struct net *net, struct socket *sock,
				int protocol, int kern)
{
	pr_debug("Creating new ARINC429 socket.\n");
	return 0;
}

static const struct net_proto_family arinc429_net_proto_family = {
	.family	= PF_ARINC429,
	.create	= arinc429_sock_create,
	.owner	= THIS_MODULE,
};

static int arinc429_netdev_notifier(struct notifier_block *nb,
				    unsigned long msg, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	if (dev->type != ARPHRD_ARINC429)
		return NOTIFY_DONE;

	switch (msg) {
	case NETDEV_REGISTER:
		pr_info("Registering new ARINC-429 Device.\n");
		break;

	case NETDEV_UNREGISTER:
		pr_info("Unregistering ARINC-429 Device.\n");
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block arinc429_notifier_block __read_mostly = {
	.notifier_call = arinc429_netdev_notifier,
};

static int arinc429_packet_ingress(struct sk_buff *skb, struct net_device *dev,
				   struct packet_type *pt,
				   struct net_device *orig_dev)
{
	pr_debug("Ingress packet.\n");

	kfree_skb(skb);
	return NET_RX_DROP;
}

static struct packet_type arinc429_packet_type __read_mostly = {
	.type	= cpu_to_be16(ETH_P_ARINC429),
	.func	= arinc429_packet_ingress,
};

static __init int arinc429_init(void)
{
	int rc;

	pr_info("Initialising ARINC-429 Socket Driver\n");

	rc = sock_register(&arinc429_net_proto_family);
	if (rc) {
		pr_err("Failed to register ARINC-429 Socket Type: %d\n", rc);
		return rc;
	}

	rc = register_netdevice_notifier(&arinc429_notifier_block);
	if (rc) {
		pr_err("Failed to register ARINC-429 with NetDev: %d\n", rc);
		sock_unregister(PF_ARINC429);
		return rc;
	}

	dev_add_pack(&arinc429_packet_type);

	return 0;
}

static __exit void arinc429_exit(void)
{
	int rc;

	dev_remove_pack(&arinc429_packet_type);

	rc = unregister_netdevice_notifier(&arinc429_notifier_block);
	if (rc)
		pr_err("Failed to unregister ARINC-429 with NetDev: %d\n", rc);

	sock_unregister(PF_ARINC429);

	pr_info("Exited ARINC-429 Socket Driver\n");
}

module_init(arinc429_init);
module_exit(arinc429_exit);
