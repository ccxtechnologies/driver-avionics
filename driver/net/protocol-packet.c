/*
 * Copyright (C), 2023 CCX Technologies
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

#include "protocol-packet.h"
#include "protocol.h"
#include "avionics.h"
#include "avionics-device.h"

/* ====== Packet Protocol ===== */

static int protocol_packet_sendmsg(struct socket *sock, struct msghdr *msg,
		size_t size)
{
	struct sock *sk = sock->sk;
	struct protocol_sock *psk = (struct protocol_sock*)sk;
	struct sk_buff *skb;
	struct net_device *dev;
	avionics_data *data;
	int err;

	err = protocol_get_dev_from_msg(psk, msg, size, &dev);
	if (err) {
		pr_err("avionics-protocol-packet: Can't find device: %d.\n", err);
		return err;
	}

	skb = protocol_alloc_send_skb(dev, msg->msg_flags&MSG_DONTWAIT,
				      sk, size, &err);
	if (!skb) {
		pr_err("avionics-protocol-packet: Unable to allocate skbuff: %d\n", err);
		dev_put(dev);
		return err;
	}

	err = memcpy_from_msg(skb_put(skb, size), msg, size);
	if (err < 0) {
		pr_err("avionics-protocol-packet: Can't memcpy from msg: %d.\n",
		       err);
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}

	data = (avionics_data *)skb->data;
    if (data->length < (skb->len - sizeof(avionics_data))) {
        skb_trim(skb, data->length + sizeof(avionics_data));
    } else if (data->length > (skb->len - sizeof(avionics_data))) {
		pr_err("avionics-protocol-packet: sendmsg data length mismatch: %d %ld.\n",
                data->length, skb->len - sizeof(avionics_data));
		kfree_skb(skb);
		dev_put(dev);
        return -EAFNOSUPPORT;
    }

	err = protocol_send_to_netdev(dev, skb);
	if (err) {
		pr_err("avionics-protocol-packet: Failed to send packet: %d.\n",
		       err);
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}

	return size;
}

static int protocol_packet_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	avionics_data *data;
	int err = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,8)
	int noblock;

	noblock = flags & MSG_DONTWAIT;
	flags &= ~MSG_DONTWAIT;
	skb = skb_recv_datagram(sk, flags, noblock, &err);
#else
	skb = skb_recv_datagram(sk, flags, &err);
#endif
	if (!skb) {
		pr_debug("avionics-protocol-packet: No data in receive message\n");
		return err;
	}

	data = (avionics_data *)skb->data;

	if (data->length != (skb->len - sizeof(avionics_data))) {
		pr_err("avionics-protocol-packet: recvmsg data length mismatch: %d %ld.\n",
                data->length, skb->len - sizeof(avionics_data));
		return -EAFNOSUPPORT;
	}

	if (size < skb->len) {
		msg->msg_flags |= MSG_TRUNC;
	} else {
		size = skb->len;
	}

	err = memcpy_to_msg(msg, skb->data, size);
	if (err < 0) {
		pr_err("avionics-protocol-packet: Failed to copy message data.\n");
		skb_free_datagram(sk, skb);
		return err;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
	sock_recv_ts_and_drops(msg, sk, skb);
#else
	sock_recv_cmsgs(msg, sk, skb);
#endif

	if (msg->msg_name) {
		__sockaddr_check_size(sizeof(struct sockaddr_avionics));
		msg->msg_namelen = sizeof(struct sockaddr_avionics);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	skb_free_datagram(sk, skb);

	return size;
}

static const struct proto_ops protocol_packet_ops = {
	.owner		= THIS_MODULE,
	.family		= PF_AVIONICS,

	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
#endif
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,

	.poll		= datagram_poll,

	.sendmsg	= protocol_packet_sendmsg,
	.recvmsg	= protocol_packet_recvmsg,

	.bind		= protocol_bind,
	.release	= protocol_release,
	.getname	= protocol_getname,
	.ioctl		= protocol_ioctl,
};

static struct proto protocol_packet = {
	.name		= "AVIONICS_PACKET",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct protocol_sock),
};

const struct proto_ops* protocol_packet_get_ops(void)
{
	return &protocol_packet_ops;
}

struct proto * protocol_packet_get(void)
{
	return &protocol_packet;
}

int protocol_packet_register(void)
{
	int err;

	err = proto_register(&protocol_packet, 1);
	if (err) {
		pr_err("avionics-protocol-packet: Failed to register"
		       " Packet Protocol: %d\n", err);
		return err;
	}
	return 0;
}

void protocol_packet_unregister(void)
{
	proto_unregister(&protocol_packet);
}
