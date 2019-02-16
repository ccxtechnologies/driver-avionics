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
#include <net/sock.h>
#include <linux/init.h>

#include "arinc429.h"

MODULE_DESCRIPTION("ARINC-429 Socket Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

MODULE_ALIAS_NETPROTO(PF_ARINC429);

/* ====== skbuff Private Data ===== */

struct arinc429_skb_priv {
	int ifindex;
	union arinc429_word word[0];
};

/* ====== Raw Protocol ===== */

struct proto_raw_sock {
	struct sock sk;
	int ifindex;
	int bound;
};

static int proto_raw_bind(struct socket *sock, struct sockaddr *saddr, int len)
{
	DECLARE_SOCKADDR(struct sockaddr_arinc429 *, addr, saddr);
	struct sock *sk = sock->sk;
	struct proto_raw_sock *psk = (struct proto_raw_sock*)sk;
	struct net_device *dev;

	pr_debug("Binding ARINC-429 Raw Socket\n");

	if (len != sizeof(*addr)) {
		pr_err("Socket address length should be %ld.\n", sizeof(*addr));
		return -EINVAL;
	}

	if (!addr->arinc429_ifindex) {
		pr_err("Must specify an interface index in socket address.\n");
		return -EINVAL;
	}

	lock_sock(sk);

	if (psk->bound && (addr->arinc429_ifindex == psk->ifindex)) {
		pr_debug("Socket already bound to %d\n", psk->ifindex);
		release_sock(sk);
		return 0;
	}

	dev = dev_get_by_index(sock_net(sk), addr->arinc429_ifindex);

	if (!dev) {
		pr_err("Can't find device %d.\n", addr->arinc429_ifindex);
		release_sock(sk);
		return -ENODEV;
	}

	if (dev->type != ARPHRD_ARINC429) {
		pr_err("Device %d isn't an ARINC-429 Device.\n",
		       addr->arinc429_ifindex);
		dev_put(dev);
		release_sock(sk);
		return -ENODEV;
	}

	psk->ifindex = dev->ifindex;
	psk->bound = 1;

	release_sock(sk);

	if (!(dev->flags & IFF_UP)) {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD)) {
			sk->sk_error_report(sk);
		}
	}

	dev_put(dev);

	return 0;
}

static int proto_raw_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct proto_raw_sock *psk = (struct proto_raw_sock*)sk;

	if (!sk)
		return 0;

	pr_debug("Releasing ARINC-429 Raw Socket\n");

	lock_sock(sk);

	psk->ifindex = 0;
	psk->bound   = 0;

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static int proto_raw_ioctl(struct socket *sock, unsigned int cmd,
			   unsigned long arg)
{
	struct sock *sk = sock->sk;

	switch (cmd) {
	case SIOCGSTAMP:
		return sock_get_timestamp(sk, (struct timeval __user *)arg);

	default:
		return -ENOIOCTLCMD;
	}
}

static int proto_raw_getname(struct socket *sock, struct sockaddr *saddr,
		       int *len, int peer)
{
	DECLARE_SOCKADDR(struct sockaddr_arinc429 *, addr, saddr);
	struct sock *sk = sock->sk;
	struct proto_raw_sock *psk = (struct proto_raw_sock*)sk;

	if (peer)
		return -EOPNOTSUPP;

	memset(addr, 0, sizeof(*addr));
	addr->arinc429_family  = AF_ARINC429;
	addr->arinc429_ifindex = psk->ifindex;

	*len = sizeof(*addr);

	return 0;
}

static int proto_raw_sendmsg(struct socket *sock, struct msghdr *msg,
			     size_t size)
{
	struct sock *sk = sock->sk;
	struct proto_raw_sock *psk = (struct proto_raw_sock*)sk;
	struct sk_buff *skb;
	struct net_device *dev;
	int ifindex;
	int err;

	pr_debug("Sending a Raw message\n");

	if (unlikely(size % ARINC429_WORD_SIZE)) {
		pr_warn("ARINC-429 Packet must be multiple of word size: %ld\n",
			ARINC429_WORD_SIZE);
		return -EINVAL;
	}

	/* Get the interface index from the message, otherwise from the socket */
	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_arinc429 *, addr,
				 msg->msg_name);

		if (msg->msg_namelen < sizeof(*addr))
			return -EINVAL;

		if (addr->arinc429_family != AF_ARINC429)
			return -EINVAL;

		ifindex = addr->arinc429_ifindex;
		pr_debug("ifindex %d from message.\n", ifindex);

	} else {
		ifindex = psk->ifindex;
		pr_debug("ifindex %d from socket.\n", ifindex);
	}

	/* Make sure the device is valid */
	dev = dev_get_by_index(sock_net(sk), ifindex);
	if (!dev) {
		pr_err("Can't find device %d.\n", ifindex);
		return -ENXIO;
	}

	if (unlikely(dev->type != ARPHRD_ARINC429)) {
		pr_err("Device %d isn't an ARINC-429 Device.\n", ifindex);
		dev_put(dev);
		return -ENODEV;
	}

	if (unlikely(size > dev->mtu)) {
		pr_err("Packet must be less than MTU of %d bytes.\n", dev->mtu);
		dev_put(dev);
		return -EMSGSIZE;
	}

	if (unlikely(!(dev->flags & IFF_UP))) {
		pr_err("Device isn't up\n");
		dev_put(dev);
		return -ENETDOWN;
	}

	/* Allocate and configure the skbuffer */
	skb = sock_alloc_send_skb(sk, size + sizeof(struct arinc429_skb_priv),
				  msg->msg_flags & MSG_DONTWAIT, &err);

	if (!skb) {
		pr_err("Unable to allocate skbuff: %d.\n", err);
		dev_put(dev);
		return err;
	}

	skb_reserve(skb, sizeof(struct arinc429_skb_priv));
	((struct arinc429_skb_priv *)(skb->head))->ifindex = dev->ifindex;

	err = memcpy_from_msg(skb_put(skb, size), msg, size);
	if (err < 0) {
		pr_err("Unable to memcpy from mesg: %d.\n", err);
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}

	sock_tx_timestamp(sk, sk->sk_tsflags, &skb_shinfo(skb)->tx_flags);

	skb->dev = dev;
	skb->sk  = sk;
	skb->priority = sk->sk_priority;
	skb->protocol = htons(ETH_P_ARINC429);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->pkt_type = PACKET_HOST;

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	/* send to netdevice */
	err = dev_queue_xmit(skb);
	if (err > 0) {
		err = net_xmit_errno(err);
	}

	if (err) {
		pr_err("Send to netdevice failed: %d\n", err);
		dev_put(dev);
		return err;
	}

	dev_put(dev);
	return size;
}

static int proto_raw_recvmsg(struct socket *sock,
			     struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int err = 0;
	int noblock;

	pr_debug("Receiving a Raw message\n");

	noblock = flags & MSG_DONTWAIT;
	flags &= ~MSG_DONTWAIT;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb) {
		pr_err("No data in receive message\n");
		return err;
	}

	if (size < skb->len) {
		msg->msg_flags |= MSG_TRUNC;
	} else {
		size = skb->len;
	}

	err = memcpy_to_msg(msg, skb->data, size);
	if (err < 0) {
		pr_err("Failed to copy message data.");
		skb_free_datagram(sk, skb);
		return err;
	}

	sock_recv_ts_and_drops(msg, sk, skb);

	if (msg->msg_name) {
		__sockaddr_check_size(sizeof(struct sockaddr_arinc429));
		msg->msg_namelen = sizeof(struct sockaddr_arinc429);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	skb_free_datagram(sk, skb);

	return size;
}

static const struct proto_ops proto_raw_ops = {
	.owner		= THIS_MODULE,
	.family		= PF_ARINC429,

	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,

	.poll		= datagram_poll,

	.bind		= proto_raw_bind,
	.release	= proto_raw_release,
	.getname	= proto_raw_getname,
	.sendmsg	= proto_raw_sendmsg,
	.recvmsg	= proto_raw_recvmsg,
	.ioctl		= proto_raw_ioctl,
};

static struct proto proto_raw = {
	.name		= "ARINC429_RAW",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct proto_raw_sock),
};

/* ====== Socket Creator ====== */

static void arinc429_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_receive_queue);
}

static int arinc429_sock_create(struct net *net, struct socket *sock,
				int protocol, int kern)
{
	struct sock *sk;
	static const struct proto_ops* _proto_opts;
	static struct proto* _proto;
	int err;

	pr_debug("Creating new ARINC429 socket.\n");

	sock->state = SS_UNCONNECTED;

	if (!net_eq(net, &init_net)) {
		pr_err("Device not in namespace\n");
		return -EAFNOSUPPORT;
	}

	switch (protocol) {
	case ARINC429_PROTO_RAW:
		pr_debug("Configurtion Raw Protocol.\n");

		_proto_opts = &proto_raw_ops;
		_proto = &proto_raw;

		break;

	default:
		pr_err("Invalid protocol %d\n", protocol);
		return -EPROTONOSUPPORT;
	}

	sock->ops = _proto_opts;

	sk = sk_alloc(net, PF_ARINC429, GFP_KERNEL, _proto, kern);
	if (!sk) {
		pr_err("Failed to allocate socket.\n");
		return -ENOMEM;
	}

	sock_init_data(sock, sk);
	sk->sk_destruct = arinc429_sock_destruct;

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err) {
			pr_err("Failed to initialize socket protocol: %d\n",
			       err);
			sock_orphan(sk);
			sock_put(sk);
			return err;
		}
	}

	return 0;
}


static const struct net_proto_family arinc429_net_proto_family = {
	.family	= PF_ARINC429,
	.create	= arinc429_sock_create,
	.owner	= THIS_MODULE,
};

/* ====== NetDev Notifier ====== */

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

/* ====== Ingress Packet Processing ====== */

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

/* ====== Module Init/Exit ====== */

static __init int arinc429_init(void)
{
	int rc;

	pr_info("Initialising ARINC-429 Socket Driver\n");

	rc = proto_register(&proto_raw, ARINC429_PROTO_RAW);
	if (rc) {
		pr_err("Failed to register ARINC-429 Raw Protocol: %d\n", rc);
		return rc;
	}

	rc = sock_register(&arinc429_net_proto_family);
	if (rc) {
		pr_err("Failed to register ARINC-429 Socket Type: %d\n", rc);
		proto_unregister(&proto_raw);
		return rc;
	}

	rc = register_netdevice_notifier(&arinc429_notifier_block);
	if (rc) {
		pr_err("Failed to register ARINC-429 with NetDev: %d\n", rc);
		sock_unregister(PF_ARINC429);
		proto_unregister(&proto_raw);
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

	proto_unregister(&proto_raw);

	pr_info("Exited ARINC-429 Socket Driver\n");
}

module_init(arinc429_init);
module_exit(arinc429_exit);
