/*
 * raw.c - Raw sockets for protocol family ARINC429
 *
 * Copyright (C) 2015 Marek Vasut <marex@denx.de>
 *
 * Based on the SocketCAN stack.
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
#include <linux/init.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/arinc429.h>
#include <linux/arinc429/core.h>
#include <linux/arinc429/skb.h>
#include <linux/arinc429/raw.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#define ARINC429_RAW_VERSION ARINC429_VERSION

MODULE_DESCRIPTION("PF_ARINC429 raw protocol");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marek Vasut <marex@denx.de>");
MODULE_ALIAS("arinc429-proto-1");

/*
 * A raw socket has a list of arinc429_filters attached to it, each receiving
 * the ARINC429 frames matching that filter.  If the filter list is empty,
 * no ARINC429 frames will be received by the socket.  The default after
 * opening the socket, is to have one filter which receives all frames.
 * The filter list is allocated dynamically with the exception of the
 * list containing only one item.  This common case is optimized by
 * storing the single filter in dfilter, to avoid using dynamic memory.
 */

struct uniqframe {
	ktime_t tstamp;
	const struct sk_buff *skb;
	unsigned int join_rx_count;
};

struct raw_sock {
	struct sock sk;
	int bound;
	int ifindex;
	struct notifier_block notifier;
	int loopback;
	int recv_own_msgs;
	int join_filters;
	int count;                 /* number of active filters */
	struct arinc429_filter dfilter; /* default/single filter */
	struct arinc429_filter *filter; /* pointer to filter(s) */
	struct uniqframe __percpu *uniq;
};

/*
 * Return pointer to store the extra msg flags for raw_recvmsg().
 * We use the space of one unsigned int beyond the 'struct sockaddr_arinc429'
 * in skb->cb.
 */
static inline unsigned int *raw_flags(struct sk_buff *skb)
{
	sock_skb_cb_check_size(sizeof(struct sockaddr_arinc429) +
			       sizeof(unsigned int));

	/* return pointer after struct sockaddr_arinc429 */
	return (unsigned int *)(&((struct sockaddr_arinc429 *)skb->cb)[1]);
}

static inline struct raw_sock *raw_sk(const struct sock *sk)
{
	return (struct raw_sock *)sk;
}

static void raw_rcv(struct sk_buff *oskb, void *data)
{
	struct sock *sk = (struct sock *)data;
	struct raw_sock *ro = raw_sk(sk);
	struct sockaddr_arinc429 *addr;
	struct sk_buff *skb;
	unsigned int *pflags;

	/* check the received tx sock reference */
	if (!ro->recv_own_msgs && oskb->sk == sk)
		return;

	/* do not pass non-ARINC429 frames to a socket */
	if (oskb->len != ARINC429_MTU)
		return;

	/* eliminate multiple filter matches for the same skb */
	if (this_cpu_ptr(ro->uniq)->skb == oskb &&
	    ktime_equal(this_cpu_ptr(ro->uniq)->tstamp, oskb->tstamp)) {
		if (ro->join_filters) {
			this_cpu_inc(ro->uniq->join_rx_count);
			/* drop frame until all enabled filters matched */
			if (this_cpu_ptr(ro->uniq)->join_rx_count < ro->count)
				return;
		} else {
			return;
		}
	} else {
		this_cpu_ptr(ro->uniq)->skb = oskb;
		this_cpu_ptr(ro->uniq)->tstamp = oskb->tstamp;
		this_cpu_ptr(ro->uniq)->join_rx_count = 1;
		/* drop first frame to check all enabled filters? */
		if (ro->join_filters && ro->count > 1)
			return;
	}

	/* clone the given skb to be able to enqueue it into the rcv queue */
	skb = skb_clone(oskb, GFP_ATOMIC);
	if (!skb)
		return;

	/*
	 *  Put the datagram to the queue so that raw_recvmsg() can
	 *  get it from there.  We need to pass the interface index to
	 *  raw_recvmsg().  We pass a whole struct sockaddr_arinc429 in skb->cb
	 *  containing the interface index.
	 */

	sock_skb_cb_check_size(sizeof(struct sockaddr_arinc429));
	addr = (struct sockaddr_arinc429 *)skb->cb;
	memset(addr, 0, sizeof(*addr));
	addr->arinc429_family  = AF_ARINC429;
	addr->arinc429_ifindex = skb->dev->ifindex;

	/* add ARINC429 specific message flags for raw_recvmsg() */
	pflags = raw_flags(skb);
	*pflags = 0;
	if (oskb->sk)
		*pflags |= MSG_DONTROUTE;
	if (oskb->sk == sk)
		*pflags |= MSG_CONFIRM;

	if (sock_queue_rcv_skb(sk, skb) < 0)
		kfree_skb(skb);
}

static int raw_enable_filters(struct net_device *dev, struct sock *sk,
			      struct arinc429_filter *filter, int count)
{
	int err = 0;
	int i;

	for (i = 0; i < count; i++) {
		err = arinc429_rx_register(dev, &filter[i], raw_rcv, sk, "raw");
		if (err) {
			/* clean up successfully registered filters */
			while (--i >= 0)
				arinc429_rx_unregister(dev, &filter[i],
						       raw_rcv, sk);
			break;
		}
	}

	return err;
}

static void raw_disable_filters(struct net_device *dev, struct sock *sk,
				struct arinc429_filter *filter, int count)
{
	int i;

	for (i = 0; i < count; i++)
		arinc429_rx_unregister(dev, &filter[i], raw_rcv, sk);
}

static inline void raw_disable_allfilters(struct net_device *dev,
					  struct sock *sk)
{
	struct raw_sock *ro = raw_sk(sk);

	raw_disable_filters(dev, sk, ro->filter, ro->count);
}

static int raw_enable_allfilters(struct net_device *dev, struct sock *sk)
{
	struct raw_sock *ro = raw_sk(sk);
	int err;

	err = raw_enable_filters(dev, sk, ro->filter, ro->count);

	return err;
}

static int raw_notifier(struct notifier_block *nb,
			unsigned long msg, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct raw_sock *ro = container_of(nb, struct raw_sock, notifier);
	struct sock *sk = &ro->sk;

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	if (dev->type != ARPHRD_ARINC429)
		return NOTIFY_DONE;

	if (ro->ifindex != dev->ifindex)
		return NOTIFY_DONE;

	switch (msg) {
	case NETDEV_UNREGISTER:
		lock_sock(sk);
		/* remove current filters & unregister */
		if (ro->bound)
			raw_disable_allfilters(dev, sk);

		if (ro->count > 1)
			kfree(ro->filter);

		ro->ifindex = 0;
		ro->bound   = 0;
		ro->count   = 0;
		release_sock(sk);

		sk->sk_err = ENODEV;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;

	case NETDEV_DOWN:
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;
	}

	return NOTIFY_DONE;
}

static int raw_init(struct sock *sk)
{
	struct raw_sock *ro = raw_sk(sk);

	ro->bound            = 0;
	ro->ifindex          = 0;

	/* set default filter to single entry dfilter */
	ro->dfilter.label    = 0;
	ro->dfilter.mask     = 0;
	ro->filter           = &ro->dfilter;
	ro->count            = 1;

	/* set default loopback behaviour */
	ro->loopback         = 1;
	ro->recv_own_msgs    = 0;
	ro->join_filters     = 0;

	/* alloc_percpu provides zero'ed memory */
	ro->uniq = alloc_percpu(struct uniqframe);
	if (unlikely(!ro->uniq))
		return -ENOMEM;

	/* set notifier */
	ro->notifier.notifier_call = raw_notifier;

	register_netdevice_notifier(&ro->notifier);

	return 0;
}

static int raw_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct raw_sock *ro;

	if (!sk)
		return 0;

	ro = raw_sk(sk);

	unregister_netdevice_notifier(&ro->notifier);

	lock_sock(sk);

	/* remove current filters & unregister */
	if (ro->bound) {
		if (ro->ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(&init_net, ro->ifindex);
			if (dev) {
				raw_disable_allfilters(dev, sk);
				dev_put(dev);
			}
		} else {
			raw_disable_allfilters(NULL, sk);
		}
	}

	if (ro->count > 1)
		kfree(ro->filter);

	ro->ifindex = 0;
	ro->bound   = 0;
	ro->count   = 0;
	free_percpu(ro->uniq);

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static int raw_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sockaddr_arinc429 *addr = (struct sockaddr_arinc429 *)uaddr;
	struct sock *sk = sock->sk;
	struct raw_sock *ro = raw_sk(sk);
	int ifindex;
	int err = 0;
	int notify_enetdown = 0;

	if (len < sizeof(*addr))
		return -EINVAL;

	lock_sock(sk);

	if (ro->bound && addr->arinc429_ifindex == ro->ifindex)
		goto out;

	if (addr->arinc429_ifindex) {
		struct net_device *dev;

		dev = dev_get_by_index(&init_net, addr->arinc429_ifindex);
		if (!dev) {
			err = -ENODEV;
			goto out;
		}
		if (dev->type != ARPHRD_ARINC429) {
			dev_put(dev);
			err = -ENODEV;
			goto out;
		}
		if (!(dev->flags & IFF_UP))
			notify_enetdown = 1;

		ifindex = dev->ifindex;

		/* filters set by default/setsockopt */
		err = raw_enable_allfilters(dev, sk);
		dev_put(dev);
	} else {
		ifindex = 0;

		/* filters set by default/setsockopt */
		err = raw_enable_allfilters(NULL, sk);
	}

	if (!err) {
		if (ro->bound) {
			/* unregister old filters */
			if (ro->ifindex) {
				struct net_device *dev;

				dev = dev_get_by_index(&init_net, ro->ifindex);
				if (dev) {
					raw_disable_allfilters(dev, sk);
					dev_put(dev);
				}
			} else {
				raw_disable_allfilters(NULL, sk);
			}
		}
		ro->ifindex = ifindex;
		ro->bound = 1;
	}

 out:
	release_sock(sk);

	if (notify_enetdown) {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
	}

	return err;
}

static int raw_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *len, int peer)
{
	struct sockaddr_arinc429 *addr = (struct sockaddr_arinc429 *)uaddr;
	struct sock *sk = sock->sk;
	struct raw_sock *ro = raw_sk(sk);

	if (peer)
		return -EOPNOTSUPP;

	memset(addr, 0, sizeof(*addr));
	addr->arinc429_family  = AF_ARINC429;
	addr->arinc429_ifindex = ro->ifindex;

	*len = sizeof(*addr);

	return 0;
}

static int raw_setsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct raw_sock *ro = raw_sk(sk);
	struct arinc429_filter *filter = NULL;  /* dyn. alloc'ed filters */
	struct arinc429_filter sfilter;         /* single filter */
	struct net_device *dev = NULL;
	int count = 0;
	int err = 0;

	if (level != SOL_ARINC429_RAW)
		return -EINVAL;

	switch (optname) {
	case ARINC429_RAW_FILTER:
		if (optlen % sizeof(struct arinc429_filter) != 0)
			return -EINVAL;

		count = optlen / sizeof(struct arinc429_filter);

		if (count > 1) {
			/* filter does not fit into dfilter => alloc space */
			filter = memdup_user(optval, optlen);
			if (IS_ERR(filter))
				return PTR_ERR(filter);
		} else if (count == 1) {
			if (copy_from_user(&sfilter, optval, sizeof(sfilter)))
				return -EFAULT;
		}

		lock_sock(sk);

		if (ro->bound && ro->ifindex)
			dev = dev_get_by_index(&init_net, ro->ifindex);

		if (ro->bound) {
			/* (try to) register the new filters */
			if (count == 1)
				err = raw_enable_filters(dev, sk, &sfilter, 1);
			else
				err = raw_enable_filters(dev, sk, filter,
							 count);
			if (err) {
				if (count > 1)
					kfree(filter);
				goto out_fil;
			}

			/* remove old filter registrations */
			raw_disable_filters(dev, sk, ro->filter, ro->count);
		}

		/* remove old filter space */
		if (ro->count > 1)
			kfree(ro->filter);

		/* link new filters to the socket */
		if (count == 1) {
			/* copy filter data for single filter */
			ro->dfilter = sfilter;
			filter = &ro->dfilter;
		}
		ro->filter = filter;
		ro->count  = count;

 out_fil:
		if (dev)
			dev_put(dev);

		release_sock(sk);

		break;

	case ARINC429_RAW_LOOPBACK:
		if (optlen != sizeof(ro->loopback))
			return -EINVAL;

		if (copy_from_user(&ro->loopback, optval, optlen))
			return -EFAULT;

		break;

	case ARINC429_RAW_RECV_OWN_MSGS:
		if (optlen != sizeof(ro->recv_own_msgs))
			return -EINVAL;

		if (copy_from_user(&ro->recv_own_msgs, optval, optlen))
			return -EFAULT;

		break;

	case ARINC429_RAW_JOIN_FILTERS:
		if (optlen != sizeof(ro->join_filters))
			return -EINVAL;

		if (copy_from_user(&ro->join_filters, optval, optlen))
			return -EFAULT;

		break;

	default:
		return -ENOPROTOOPT;
	}
	return err;
}

static int raw_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct raw_sock *ro = raw_sk(sk);
	int len;
	void *val;
	int err = 0;

	if (level != SOL_ARINC429_RAW)
		return -EINVAL;
	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case ARINC429_RAW_FILTER:
		lock_sock(sk);
		if (ro->count > 0) {
			int fsize = ro->count * sizeof(struct arinc429_filter);

			if (len > fsize)
				len = fsize;
			if (copy_to_user(optval, ro->filter, len))
				err = -EFAULT;
		} else {
			len = 0;
		}
		release_sock(sk);

		if (!err)
			err = put_user(len, optlen);
		return err;

	case ARINC429_RAW_LOOPBACK:
		if (len > sizeof(int))
			len = sizeof(int);
		val = &ro->loopback;
		break;

	case ARINC429_RAW_RECV_OWN_MSGS:
		if (len > sizeof(int))
			len = sizeof(int);
		val = &ro->recv_own_msgs;
		break;

	case ARINC429_RAW_JOIN_FILTERS:
		if (len > sizeof(int))
			len = sizeof(int);
		val = &ro->join_filters;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, val, len))
		return -EFAULT;
	return 0;
}

static int raw_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct raw_sock *ro = raw_sk(sk);
	struct sk_buff *skb;
	struct net_device *dev;
	int ifindex;
	int err;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_arinc429 *, addr,
				 msg->msg_name);

		if (msg->msg_namelen < sizeof(*addr))
			return -EINVAL;

		if (addr->arinc429_family != AF_ARINC429)
			return -EINVAL;

		ifindex = addr->arinc429_ifindex;
	} else {
		ifindex = ro->ifindex;
	}

	if (unlikely(size != ARINC429_MTU))
		return -EINVAL;

	dev = dev_get_by_index(&init_net, ifindex);
	if (!dev)
		return -ENXIO;

	skb = sock_alloc_send_skb(sk, size + sizeof(struct arinc429_skb_priv),
				  msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto put_dev;

	arinc429_skb_reserve(skb);
	arinc429_skb_prv(skb)->ifindex = dev->ifindex;

	err = memcpy_from_msg(skb_put(skb, size), msg, size);
	if (err < 0)
		goto free_skb;

	sock_tx_timestamp(sk, &skb_shinfo(skb)->tx_flags);

	skb->dev = dev;
	skb->sk  = sk;
	skb->priority = sk->sk_priority;

	err = arinc429_send(skb, ro->loopback);

	dev_put(dev);

	if (err)
		goto send_failed;

	return size;

free_skb:
	kfree_skb(skb);
put_dev:
	dev_put(dev);
send_failed:
	return err;
}

static int raw_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		       int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int err = 0;
	int noblock;

	noblock =  flags & MSG_DONTWAIT;
	flags   &= ~MSG_DONTWAIT;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		return err;

	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;

	err = memcpy_to_msg(msg, skb->data, size);
	if (err < 0) {
		skb_free_datagram(sk, skb);
		return err;
	}

	sock_recv_ts_and_drops(msg, sk, skb);

	if (msg->msg_name) {
		__sockaddr_check_size(sizeof(struct sockaddr_arinc429));
		msg->msg_namelen = sizeof(struct sockaddr_arinc429);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	/* assign the flags that have been recorded in raw_rcv() */
	msg->msg_flags |= *(raw_flags(skb));

	skb_free_datagram(sk, skb);

	return size;
}

static const struct proto_ops raw_ops = {
	.family        = PF_ARINC429,
	.release       = raw_release,
	.bind          = raw_bind,
	.connect       = sock_no_connect,
	.socketpair    = sock_no_socketpair,
	.accept        = sock_no_accept,
	.getname       = raw_getname,
	.poll          = datagram_poll,
	/* use arinc429_ioctl() from af_arinc429.c */
	.ioctl         = arinc429_ioctl,
	.listen        = sock_no_listen,
	.shutdown      = sock_no_shutdown,
	.setsockopt    = raw_setsockopt,
	.getsockopt    = raw_getsockopt,
	.sendmsg       = raw_sendmsg,
	.recvmsg       = raw_recvmsg,
	.mmap          = sock_no_mmap,
	.sendpage      = sock_no_sendpage,
};

static struct proto raw_proto __read_mostly = {
	.name       = "ARINC429_RAW",
	.owner      = THIS_MODULE,
	.obj_size   = sizeof(struct raw_sock),
	.init       = raw_init,
};

static const struct arinc429_proto raw_arinc429_proto = {
	.type       = SOCK_RAW,
	.protocol   = ARINC429_RAW,
	.ops        = &raw_ops,
	.prot       = &raw_proto,
};

static __init int raw_module_init(void)
{
	int err;

	pr_info("arinc429: raw protocol (rev " ARINC429_RAW_VERSION ")\n");

	err = arinc429_proto_register(&raw_arinc429_proto);
	if (err < 0)
		pr_err("arinc429: registration of raw protocol failed\n");

	return err;
}

static __exit void raw_module_exit(void)
{
	arinc429_proto_unregister(&raw_arinc429_proto);
}

module_init(raw_module_init);
module_exit(raw_module_exit);
