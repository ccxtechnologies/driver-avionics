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

#include "protocol.h"
#include "socket-list.h"
#include "avionics.h"

void protocol_init_skb(struct net_device *dev, struct sk_buff *skb)
{
	skb->dev = dev;
	skb->protocol = htons(ETH_P_AVIONICS);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->pkt_type = PACKET_HOST;

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
}

struct sk_buff* protocol_alloc_send_skb(struct net_device *dev,
					int flags, struct sock *sk,
					size_t size)
{
	struct sk_buff *skb;
	int err;

	skb = sock_alloc_send_skb(sk, size, flags, &err);
	if (!skb) {
		pr_err("avionics-device: Unable to allocate send skbuff: %d.\n",
		       err);
		return NULL;
	}

	protocol_init_skb(dev, skb);

	sock_tx_timestamp(sk, sk->sk_tsflags, &skb_shinfo(skb)->tx_flags);

	skb->sk  = sk;
	skb->priority = sk->sk_priority;

	return skb;
}


int protocol_get_dev_from_msg(struct protocol_sock *psk,
			      struct msghdr *msg, size_t size,
			      struct net_device **dev)
{
	int ifindex;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_avionics *, addr,
				 msg->msg_name);

		if (msg->msg_namelen < sizeof(*addr)) {
			pr_err("avionics-protocol: Message name wrong length: %d"
			       " should be %zu\n", msg->msg_namelen,
			       sizeof(*addr));
			return -EINVAL;
		}

		if (addr->avionics_family != AF_AVIONICS) {
			pr_err("avionics-protocol: Message in wrong family: %u"
			       " should be %u\n", addr->avionics_family,
			       AF_AVIONICS);
			return -EINVAL;
		}

		ifindex = addr->ifindex;
	} else {
		ifindex = psk->ifindex;
	}

	/* Make sure the device is valid */
	*dev = dev_get_by_index(sock_net(&psk->sk), ifindex);
	if (!*dev) {
		pr_err("avionics-protocol: Can't find device %d.\n", ifindex);
		return -ENXIO;
	}

	if (unlikely((*dev)->type != ARPHRD_AVIONICS)) {
		pr_err("avionics-protocol: Device %s is wrong type: %d.\n",
		       (*dev)->name, (*dev)->type);
		dev_put(*dev);
		return -ENODEV;
	}

	if (unlikely(!((*dev)->flags & IFF_UP))) {
		pr_err("avionics-protocol: Device %s is down.\n", (*dev)->name);
		dev_put(*dev);
		return -ENETDOWN;
	}

	if (unlikely(size > (*dev)->mtu)) {
		pr_err("avionics-protocol: %zu bytes too large for MTU of"
		       " %d bytes.\n", size, (*dev)->mtu);
		dev_put(*dev);
		return -EMSGSIZE;
	}


	return 0;
}


int protocol_send_to_netdev(struct net_device *dev, struct sk_buff *skb)
{
	int err;

	if (!dev->netdev_ops->ndo_start_xmit) {
		pr_err("avionics-protocol: device doesn't support transmit\n");
		return -ENODEV;
	}

	/* send to netdevice */
	err = dev_queue_xmit(skb);
	if (err > 0) {
		err = net_xmit_errno(err);
	}

	if (err) {
		pr_err("avionics-protocol: Send to netdevice failed: %d\n",
		       err);
		dev_put(dev);
		return err;
	}

	dev_put(dev);
	return 0;
}

int protocol_getname(struct socket *sock, struct sockaddr *saddr,
		     int *len, int peer)
{
	DECLARE_SOCKADDR(struct sockaddr_avionics *, addr, saddr);
	struct sock *sk = sock->sk;
	struct protocol_sock *psk = (struct protocol_sock*)sk;

	if (peer) {
		return -EOPNOTSUPP;
	}

	memset(addr, 0, sizeof(*addr));
	addr->avionics_family  = AF_AVIONICS;
	addr->ifindex = psk->ifindex;

	*len = sizeof(*addr);

	return 0;
}

int protocol_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;

	switch (cmd) {
	case SIOCGSTAMP:
		return sock_get_timestamp(sk, (struct timeval __user *)arg);

	default:
		return -ENOIOCTLCMD;
	}
}

static void protocol_rx(struct sk_buff *oskb, struct sock *sk)
{
	struct sk_buff *skb;
	struct sockaddr_avionics *addr;

	/* clone the given skb to be able to enqueue it into the rcv queue */
	skb = skb_clone(oskb, GFP_ATOMIC);
	if (!skb) {
		pr_err("avionics-protocol: Failed to allocate skbuff clone.\n");
		return;
	}

	sock_skb_cb_check_size(sizeof(struct sockaddr_avionics));
	addr = (struct sockaddr_avionics *)skb->cb;
	memset(addr, 0, sizeof(*addr));
	addr->avionics_family  = AF_AVIONICS;
	addr->ifindex = skb->dev->ifindex;

	if (sock_queue_rcv_skb(sk, skb) < 0) {
		pr_err("avionics-protocol: Failed to queue rx message.\n");
		kfree_skb(skb);
	}
}

int protocol_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct protocol_sock *psk = (struct protocol_sock*)sk;
	struct net_device *dev = NULL;

	if (!sk) {
		return 1;
	}

	dev = dev_get_by_index(sock_net(sk), psk->ifindex);
	if (dev) {
		socket_list_remove_socket(dev, protocol_rx, sk);
		dev_put(dev);
	}

	lock_sock(sk);

	psk->ifindex = 0;
	psk->bound   = 0;

	sock_orphan(sk);
	sock->sk = NULL;


	release_sock(sk);
	sock_put(sk);

	return 0;
}

int protocol_bind(struct socket *sock, struct sockaddr *saddr, int len)
{
	DECLARE_SOCKADDR(struct sockaddr_avionics *, addr, saddr);
	struct sock *sk = sock->sk;
	struct protocol_sock *psk = (struct protocol_sock*)sk;
	struct net_device *dev;
	int err;

	if (len != sizeof(*addr)) {
		pr_err("avionics-protocol: Address length should"
		       " be %zu not %d.\n", sizeof(*addr), len);
		return -EINVAL;
	}

	if (!addr->ifindex) {
		pr_err("avionics-protocol: Must specify ifindex in Address.\n");
		return -EINVAL;
	}

	lock_sock(sk);

	if (psk->bound && (addr->ifindex == psk->ifindex)) {
		pr_debug("avionics-protocol: Socket already bound to %d.\n",
			 psk->ifindex);
		release_sock(sk);
		return 0;
	}

	dev = dev_get_by_index(sock_net(sk), addr->ifindex);

	if (!dev) {
		pr_err("avionics-protocol: Can't find device %d.\n",
		       addr->ifindex);
		release_sock(sk);
		return -ENODEV;
	}

	if (dev->type != ARPHRD_AVIONICS) {
		pr_err("avionics-protocol: Device %d isn't type avionics.\n",
		       addr->ifindex);
		dev_put(dev);
		release_sock(sk);
		return -ENODEV;
	}

	err = socket_list_add_socket(dev, protocol_rx, sk);
	if (err) {
		pr_err("avionics-protocol: Failed to register socket with"
		       " device %s: %d\n", dev->name, err);
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
