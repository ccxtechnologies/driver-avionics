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

#include "protocol-raw.h"
#include "protocol.h"
#include "avionics.h"
#include "avionics-device.h"

/* ====== Raw Protocol ===== */

static int protocol_raw_sendmsg(struct socket *sock, struct msghdr *msg,
				size_t size)
{
	struct sock *sk = sock->sk;
	struct protocol_raw_sock *psk = (struct protocol_raw_sock*)sk;
	struct sk_buff *skb;
	struct net_device *dev;
	avionics_data *data;
	int err = 0, buffer_size, num_samples, i;

	err = protocol_get_dev_from_msg((struct protocol_sock*)psk,
					msg, size, &dev);
	if (err) {
		pr_err("avionics-protocol-raw: Can't find device: %d.\n", err);
		return err;
	}

	num_samples = size/sizeof(data->value);
	buffer_size = num_samples * sizeof(data[0]);
	skb = protocol_alloc_send_skb(dev, msg->msg_flags&MSG_DONTWAIT,
				      sk, buffer_size);

	if (!skb) {
		pr_err("avionics-protocol-raw: Unable to allocate skbuff\n");
		dev_put(dev);
		return -ENOMEM;
	}

	err = memcpy_from_msg(skb_put(skb, buffer_size), msg, size);
	if (err < 0) {
		pr_err("avionics-protocol-raw: Can't memcpy from msg: %d.\n", err);
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}

	data = (avionics_data*)skb->data;
	for (i = num_samples - 1; i >= 0; i--) {
		memcpy(&(data[i].value),
		       &(skb->data[i*sizeof(data->value)]),
		       sizeof(data->value));
		data[i].time_msecs = 0;
	}

	err = protocol_send_to_netdev(dev, skb);
	if (err) {
		pr_err("avionics-protocol-raw: Failed to send packet: %d.\n", err);
		return err;
	}

	return size;
}

static int protocol_raw_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	struct avionics_proto_raw_data *buffer;
	avionics_data *data;
	int err = 0, i, num_samples, buffer_size;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,8)
	int noblock;

	noblock = flags & MSG_DONTWAIT;
	flags &= ~MSG_DONTWAIT;
	skb = skb_recv_datagram(sk, flags, noblock, &err);
#else
	skb = skb_recv_datagram(sk, flags, &err);
#endif
	if (!skb) {
		pr_debug("avionics-protocol-raw: No data in receive message\n");
		return err;
	}

	if (size < skb->len) {
		msg->msg_flags |= MSG_TRUNC;
	} else {
		size = skb->len;
	}

	num_samples = size / sizeof(avionics_data);
	buffer_size = num_samples * sizeof(buffer[0]);

	data = (avionics_data *)skb->data;
	buffer = kmalloc(buffer_size, GFP_KERNEL);
	for(i = 0; i < num_samples; i++) {
		memcpy(&buffer[i], &(data[i].value), sizeof(buffer[0]));
	}

	err = memcpy_to_msg(msg, buffer, buffer_size);
	if (err < 0) {
		pr_err("avionics-protocol-raw: Failed to copy message data.\n");
		skb_free_datagram(sk, skb);
		kfree(buffer);
		return err;
	}

	sock_recv_ts_and_drops(msg, sk, skb);

	if (msg->msg_name) {
		__sockaddr_check_size(sizeof(struct sockaddr_avionics));
		msg->msg_namelen = sizeof(struct sockaddr_avionics);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	skb_free_datagram(sk, skb);
	kfree(buffer);

	return buffer_size;
}

static const struct proto_ops protocol_raw_ops = {
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

	.sendmsg	= protocol_raw_sendmsg,
	.recvmsg	= protocol_raw_recvmsg,

	.bind		= protocol_bind,
	.release	= protocol_release,
	.getname	= protocol_getname,
	.ioctl		= protocol_ioctl,
};

static struct proto protocol_raw = {
	.name		= "AVIONICS_RAW",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct protocol_sock),
};

const struct proto_ops* protocol_raw_get_ops(void)
{
	return &protocol_raw_ops;
}

struct proto * protocol_raw_get(void)
{
	return &protocol_raw;
}

int protocol_raw_register(void)
{
	int err;

	err = proto_register(&protocol_raw, AVIONICS_PROTO_RAW);
	if (err) {
		pr_err("avionics-protocol-raw: Failed to register"
		       " Raw Protocol: %d\n", err);
		return err;
	}
	return 0;
}

void protocol_raw_unregister(void)
{
	proto_unregister(&protocol_raw);
}
