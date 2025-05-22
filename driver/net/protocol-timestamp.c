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

#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include "protocol-timestamp.h"
#include "protocol.h"
#include "avionics.h"
#include "avionics-device.h"

/* ====== Timestamp Protocol ===== */

static int protocol_timestamp_sendmsg(struct socket *sock, struct msghdr *msg,
				size_t size)
{
	struct sock *sk = sock->sk;
	struct protocol_sock *psk = (struct protocol_sock*)sk;
	struct sk_buff *skb;
	struct net_device *dev;
	avionics_data *data;
	struct avionics_proto_timestamp_data *buffer;
	int err, i=0, num_bytes, num_words;
    __u32 vbuffer;

	err = protocol_get_dev_from_msg(psk, msg, size, &dev);
	if (err) {
		pr_err("avionics-protocol-timestamp: Can't find device: %d.\n", err);
		return err;
	}

	num_words = size/sizeof(struct avionics_proto_timestamp_data);
	num_bytes = num_words*sizeof(__u32);

	buffer = kzalloc(size, GFP_KERNEL);
	if (buffer == NULL) {
		pr_err("avionics-protocol-timestamp: Failed to allocate buffer.\n");
		return -ENOMEM;
	}

    err = memcpy_from_msg(buffer, msg, size);
    if (err < 0) {
        pr_err("avionics-protocol-timestamp: Can't memcpy from msg: %d.\n", err);
        kfree(buffer);
        dev_put(dev);
        return err;
    }

	while(i < num_words) {

		skb = protocol_alloc_send_skb(dev, msg->msg_flags&MSG_DONTWAIT, sk,
				num_bytes + sizeof(avionics_data), &err);
		if (!skb) {
			pr_err("avionics-protocol-timestamp: Unable to allocate skbuff: %d\n", err);
            kfree(buffer);
			dev_put(dev);
			return err;
		}

        data = (avionics_data *)skb->head;
        data->time_msecs = buffer[i].time_msecs;
        data->status = 0;
        data->count = i;
        data->width = 4;
        data->length = 4;

		vbuffer = cpu_to_be32(buffer[i].value);
        memcpy(&data->data[0], &vbuffer, 4);

        for (i++ ; (i < num_words) && (buffer[i-1].time_msecs == buffer[i].time_msecs); i++) {
		    vbuffer = cpu_to_be32(buffer[i].value);
            memcpy(&data->data[data->length], &vbuffer, 4);
            data->length += 4;
        }

		skb_put(skb, data->length + sizeof(avionics_data));

		err = protocol_send_to_netdev(dev, skb);
		if (err) {
			pr_err("avionics-protocol-timestamp: Failed to send packet: %d.\n", err);
            kfree(buffer);
            kfree_skb(skb);
            dev_put(dev);
			return err;
		}

	}

	kfree(buffer);

	return size;
}

static int protocol_timestamp_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	avionics_data *data;
	struct avionics_proto_timestamp_data *buffer;
	int err = 0, num_words, num_bytes, i;
    __u32 vbuffer;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,8)
	int noblock;

	noblock = flags & MSG_DONTWAIT;
	flags &= ~MSG_DONTWAIT;
	skb = skb_recv_datagram(sk, flags, noblock, &err);
#else
	skb = skb_recv_datagram(sk, flags, &err);
#endif
	if (!skb) {
		pr_debug("avionics-protocol-timestamp: No data in receive message\n");
		return err;
	}

	data = (avionics_data *)skb->data;

	if (data->length != (skb->len - sizeof(avionics_data))) {
		return -EAFNOSUPPORT;
	}

	if(data->width == 0) {
		data->width = 4;
	}

	num_words = data->length/data->width;
	num_bytes = sizeof(struct avionics_proto_timestamp_data)*num_words;

	if (size < num_bytes) {
		msg->msg_flags |= MSG_TRUNC;
	} else {
		size = num_bytes;
	}

	buffer = kzalloc(num_bytes, GFP_KERNEL);
	if (buffer == NULL) {
		pr_err("avionics-protocol-timestamp: Failed to allocate buffer.\n");
		return -ENOMEM;
	}

	for(i = 0; i < num_words; i++) {
		buffer[i].time_msecs = data->time_msecs;
		memcpy(&vbuffer, &data->data[i*data->width], data->width);
        buffer[i].value = be32_to_cpu(vbuffer);
	}

	err = memcpy_to_msg(msg, buffer, num_bytes);
	if (err < 0) {
		pr_err("avionics-protocol-timestamp: Failed to copy message data.\n");
		skb_free_datagram(sk, skb);
		return err;
	}

	kfree(buffer);

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

static const struct proto_ops protocol_timestamp_ops = {
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

	.sendmsg	= protocol_timestamp_sendmsg,
	.recvmsg	= protocol_timestamp_recvmsg,

	.bind		= protocol_bind,
	.release	= protocol_release,
	.getname	= protocol_getname,
	.ioctl		= protocol_ioctl,
};

static struct proto protocol_timestamp = {
	.name		= "AVIONICS_TIMESTAMP",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct protocol_sock),
};

const struct proto_ops* protocol_timestamp_get_ops(void)
{
	return &protocol_timestamp_ops;
}

struct proto * protocol_timestamp_get(void)
{
	return &protocol_timestamp;
}

int protocol_timestamp_register(void)
{
	int err;

	err = proto_register(&protocol_timestamp, 1);
	if (err) {
		pr_err("avionics-protocol-timestamp: Failed to register"
			   " Timestamp Protocol: %d\n", err);
		return err;
	}
	return 0;
}

void protocol_timestamp_unregister(void)
{
	proto_unregister(&protocol_timestamp);
}
