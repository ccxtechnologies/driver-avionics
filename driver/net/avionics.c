/*
 * Copyright (C), 2019-2023 CCX Technologies
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
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/init.h>

#include "protocol-raw.h"
#include "protocol-timestamp.h"
#include "protocol-packet.h"
#include "socket-list.h"
#include "avionics.h"
#include "device.h"

MODULE_DESCRIPTION("Avionics Networking Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.1.1");

MODULE_ALIAS_NETPROTO(PF_AVIONICS);

static void avionics_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_receive_queue);
}

static int avionics_sock_create(struct net *net, struct socket *sock,
				int protocol, int kern)
{
	struct sock *sk;
	static const struct proto_ops* popts;
	static struct proto* p;
	int err;

	sock->state = SS_UNCONNECTED;

	if (!net_eq(net, &init_net)) {
		pr_err("avionics: Device not in namespace\n");
		return -EAFNOSUPPORT;
	}

	switch (protocol) {
	case AVIONICS_PROTO_RAW:
		popts = protocol_raw_get_ops();
		p = protocol_raw_get();
		break;

	case AVIONICS_PROTO_TIMESTAMP:
		popts = protocol_timestamp_get_ops();
		p = protocol_timestamp_get();
		break;

	case AVIONICS_PROTO_PACKET:
		popts = protocol_packet_get_ops();
		p = protocol_packet_get();
		break;

	default:
		pr_err("avionics: Invalid protocol %d\n", protocol);
		return -EPROTONOSUPPORT;
	}

	sock->ops = popts;

	sk = sk_alloc(net, PF_AVIONICS, GFP_KERNEL, p, kern);
	if (!sk) {
		pr_err("avionics: Failed to allocate socket.\n");
		return -ENOMEM;
	}

	sock_init_data(sock, sk);
	sk->sk_destruct = avionics_sock_destruct;

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err) {
			pr_err("avionics: Failed to init socket"
			       " protocol %d: %d\n", protocol, err);
			sock_orphan(sk);
			sock_put(sk);
			return err;
		}
	}

	return 0;
}


static const struct net_proto_family avionics_net_proto_family = {
	.family	= PF_AVIONICS,
	.create	= avionics_sock_create,
	.owner	= THIS_MODULE,
};

static int avionics_netdev_notifier(struct notifier_block *nb,
				    unsigned long msg, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	if (dev->type != ARPHRD_AVIONICS)
		return NOTIFY_DONE;

	switch (msg) {
	case NETDEV_REGISTER:
		pr_info("avionics: Registering device %s.\n", dev->name);
		socket_list_add(dev);
		break;

	case NETDEV_UNREGISTER:
		pr_info("avionics: Unregistering device %s.\n", dev->name);
		socket_list_remove(dev);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block avionics_notifier_block __read_mostly = {
	.notifier_call = avionics_netdev_notifier,
};

static int avionics_packet_rx(struct sk_buff *skb, struct net_device *dev,
			      struct packet_type *pt,
			      struct net_device *orig_dev)
{
	int err;

	if (unlikely(!net_eq(dev_net(dev), &init_net))) {
		pr_err("avionics: device not in namespace\n");
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	if(unlikely(dev->type != ARPHRD_AVIONICS)) {
		pr_warn("avionics: dropped invalid skbuf,"
			   " dev type %d, len %d\n", dev->type, skb->len);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	err = socket_list_rx_funcs(dev, skb);
	if (err) {
		pr_err("avionics: Failed to call protocol rx"
		       " functions for %s: %d\n", dev->name, err);
		consume_skb(skb);
		return NET_RX_DROP;
	}

	consume_skb(skb);
	return NET_RX_SUCCESS;
}

static struct packet_type avionics_packet_type __read_mostly = {
	.type	= cpu_to_be16(ETH_P_AVIONICS),
	.func	= avionics_packet_rx,
};

static __init int avionics_init(void)
{
	int rc;

	pr_info("avionics: Initializing Driver\n");

	rc = socket_list_init();
	if (rc) {
		pr_err("avionics: Failed to allocate socket list cache.\n");
		return rc;
	}

	rc = device_netlink_register();
	if (rc) {
		pr_err("avionics: Failed to register device netlink: %d\n", rc);
		socket_list_exit();
		return rc;
	}

	rc = protocol_raw_register();
	if (rc) {
		pr_err("avionics: Failed to register raw protocol: %d\n", rc);
		device_netlink_unregister();
		socket_list_exit();
		return rc;
	}

	rc = sock_register(&avionics_net_proto_family);
	if (rc) {
		pr_err("avionics: Failed to register socket type: %d\n", rc);
		device_netlink_unregister();
		protocol_raw_unregister();
		socket_list_exit();
		return rc;
	}

	rc = register_netdevice_notifier(&avionics_notifier_block);
	if (rc) {
		pr_err("avionics: Failed to register with NetDev: %d\n", rc);
		device_netlink_unregister();
		sock_unregister(PF_AVIONICS);
		protocol_raw_unregister();
		socket_list_exit();
		return rc;
	}

	dev_add_pack(&avionics_packet_type);

	return 0;
}

static __exit void avionics_exit(void)
{
	int err;

	dev_remove_pack(&avionics_packet_type);

	err = unregister_netdevice_notifier(&avionics_notifier_block);
	if (err) {
		pr_err("avionics: Failed to unregister with NetDev: %d\n", err);
	}

	sock_unregister(PF_AVIONICS);

	device_netlink_unregister();
	protocol_raw_unregister();

	socket_list_exit();

	pr_info("avionics: Exited Driver\n");
}

module_init(avionics_init);
module_exit(avionics_exit);
