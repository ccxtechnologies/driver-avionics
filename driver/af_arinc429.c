/*
 * af_arinc429.c - Protocol family ARINC429 core module
 *                 (used by different ARINC429 protocol modules)
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
#include <linux/stddef.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/arinc429.h>
#include <linux/arinc429/core.h>
#include <linux/arinc429/skb.h>
#include <linux/ratelimit.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "af_arinc429.h"

MODULE_DESCRIPTION("ARINC429 PF_ARINC429 core");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marek Vasut <marex@denx.de>");

MODULE_ALIAS_NETPROTO(PF_ARINC429);

/* receive filters subscribed for 'all' ARINC429 devices */
struct dev_rcv_lists arinc429_rx_alldev_list;
static DEFINE_SPINLOCK(arinc429_rcvlists_lock);

static struct kmem_cache *rcv_cache __read_mostly;

/* table of registered ARINC429 protocols */
static const struct arinc429_proto *proto_tab[ARINC429_NPROTO] __read_mostly;
static DEFINE_MUTEX(proto_tab_lock);

struct timer_list arinc429_stattimer;   /* timer for statistics update */
struct s_stats    arinc429_stats;       /* packet statistics */
struct s_pstats   arinc429_pstats;      /* receive list statistics */

/*
 * af_arinc429 socket functions
 */

int arinc429_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;

	switch (cmd) {
	case SIOCGSTAMP:
		return sock_get_timestamp(sk, (struct timeval __user *)arg);

	default:
		return -ENOIOCTLCMD;
	}
}
EXPORT_SYMBOL(arinc429_ioctl);

static void arinc429_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_receive_queue);
}

static const struct arinc429_proto *arinc429_get_proto(int protocol)
{
	const struct arinc429_proto *cp;

	rcu_read_lock();
	cp = rcu_dereference(proto_tab[protocol]);
	if (cp && !try_module_get(cp->prot->owner))
		cp = NULL;
	rcu_read_unlock();

	return cp;
}

static inline void arinc429_put_proto(const struct arinc429_proto *cp)
{
	module_put(cp->prot->owner);
}

static int arinc429_create(struct net *net, struct socket *sock, int protocol,
			   int kern)
{
	struct sock *sk;
	const struct arinc429_proto *cp;
	int err = 0;

	sock->state = SS_UNCONNECTED;

	if (protocol < 0 || protocol >= ARINC429_NPROTO)
		return -EINVAL;

	if (!net_eq(net, &init_net))
		return -EAFNOSUPPORT;

	cp = arinc429_get_proto(protocol);

#ifdef CONFIG_MODULES
	if (!cp) {
		/* Try to load protocol module if kernel is modular */
		err = request_module("arinc429-proto-%d", protocol);

		/*
		 * In case of error we only print a message but don't
		 * return the error code immediately.  Below we will
		 * return -EPROTONOSUPPORT
		 */
		if (err) {
			pr_err_ratelimited(
				"arinc429: request_module (arinc429-proto-%d) failed.\n",
				protocol);
		}

		cp = arinc429_get_proto(protocol);
	}
#endif

	/* Check for available protocol and correct usage */
	if (!cp)
		return -EPROTONOSUPPORT;

	if (cp->type != sock->type) {
		err = -EPROTOTYPE;
		goto errout;
	}

	sock->ops = cp->ops;

	sk = sk_alloc(net, PF_ARINC429, GFP_KERNEL, cp->prot, kern);
	if (!sk) {
		err = -ENOMEM;
		goto errout;
	}

	sock_init_data(sock, sk);
	sk->sk_destruct = arinc429_sock_destruct;

	if (sk->sk_prot->init)
		err = sk->sk_prot->init(sk);

	if (err) {
		/* release sk on errors */
		sock_orphan(sk);
		sock_put(sk);
	}

 errout:
	arinc429_put_proto(cp);
	return err;
}

/*
 * af_arinc429 tx path
 */

/**
 * arinc429_send - transmit a ARINC429 frame (optional with local loopback)
 * @skb: pointer to socket buffer with ARINC429 frame in data section
 * @loop: loopback for listeners on local ARINC429 sockets
 *        (recommended default!)
 *
 * Due to the loopback this routine must not be called from hardirq context.
 *
 * Return:
 *  0 on success
 *  -ENETDOWN when the selected interface is down
 *  -ENOBUFS on full driver queue (see net_xmit_errno())
 *  -ENOMEM when local loopback failed at calling skb_clone()
 *  -EPERM when trying to send on a non-ARINC429 interface
 *  -EMSGSIZE ARINC429 frame size is bigger than ARINC429 interface MTU
 *  -EINVAL when the skb->data does not contain a valid ARINC429 frame
 */
int arinc429_send(struct sk_buff *skb, int loop)
{
	struct sk_buff *newskb = NULL;
	int err = -EINVAL;

	if (skb->len == ARINC429_MTU)
		skb->protocol = htons(ETH_P_ARINC429);
	else
		goto inval_skb;

	/*
	 * Make sure the ARINC429 frame can pass the selected
	 * ARINC429 netdevice.
	 */
	if (unlikely(skb->len > skb->dev->mtu)) {
		err = -EMSGSIZE;
		goto inval_skb;
	}

	if (unlikely(skb->dev->type != ARPHRD_ARINC429)) {
		err = -EPERM;
		goto inval_skb;
	}

	if (unlikely(!(skb->dev->flags & IFF_UP))) {
		err = -ENETDOWN;
		goto inval_skb;
	}

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	if (loop) {
		/* local loopback of sent ARINC429 frames */

		/* indication for the ARINC429 driver: do loopback */
		skb->pkt_type = PACKET_LOOPBACK;

		/*
		 * The reference to the originating sock may be required
		 * by the receiving socket to check whether the frame is
		 * its own.
		 * Example: arinc429_raw sockopt ARINC429_RAW_RECV_OWN_MSGS
		 * Therefore we have to ensure that skb->sk remains the
		 * reference to the originating sock by restoring skb->sk
		 * after each skb_clone() or skb_orphan() usage.
		 */

		if (!(skb->dev->flags & IFF_ECHO)) {
			/*
			 * If the interface is not capable to do loopback
			 * itself, we do it here.
			 */
			newskb = skb_clone(skb, GFP_ATOMIC);
			if (!newskb) {
				kfree_skb(skb);
				return -ENOMEM;
			}

			arinc429_skb_set_owner(newskb, skb->sk);
			newskb->ip_summed = CHECKSUM_UNNECESSARY;
			newskb->pkt_type = PACKET_BROADCAST;
		}
	} else {
		/* indication for the ARINC429 driver: no loopback required */
		skb->pkt_type = PACKET_HOST;
	}

	/* send to netdevice */
	err = dev_queue_xmit(skb);
	if (err > 0)
		err = net_xmit_errno(err);

	if (err) {
		kfree_skb(newskb);
		return err;
	}

	if (newskb) {
		if (!(newskb->tstamp.tv64))
			__net_timestamp(newskb);

		netif_rx_ni(newskb);
	}

	/* update statistics */
	arinc429_stats.tx_frames++;
	arinc429_stats.tx_frames_delta++;

	return 0;

inval_skb:
	kfree_skb(skb);
	return err;
}
EXPORT_SYMBOL(arinc429_send);

/*
 * af_arinc429 rx path
 */

static struct dev_rcv_lists *find_dev_rcv_lists(struct net_device *dev)
{
	if (!dev)
		return &arinc429_rx_alldev_list;
	else
		return (struct dev_rcv_lists *)dev->ml_priv;
}

/**
 * find_rcv_list - determine optimal filterlist inside device filter struct
 * @label: pointer to ARINC429 identifier of a given arinc429_filter
 * @mask: pointer to ARINC429 mask of a given arinc429_filter
 * @inv: filter is inverted
 * @d: pointer to the device filter struct
 *
 * Description:
 *  Returns the optimal filterlist to reduce the filter handling in the
 *  receive path. This function is called by service functions that need
 *  to register or unregister a arinc429_filter in the filter lists.
 *
 *  A filter matches in general, when
 *
 *          <received_label> & mask == label & mask
 *
 *  The filter can be inverted (ARINC429_INV_FILTER bit set in label).
 *
 * Return:
 *  Pointer to optimal filterlist for the given label/mask pair.
 *  Constistency checked mask.
 *  Reduced label to have a preprocessed filter compare value.
 */
static struct hlist_head *find_rcv_list(u8 *label, u8 *mask, const bool inv,
					struct dev_rcv_lists *d)
{
	/* reduce condition testing at receive time */
	*label &= *mask;

	/* inverse label/can_mask filter */
	if (inv)
		return &d->rx[RX_INV];

	/* mask == 0 => no condition testing at receive time */
	if (!(*mask))
		return &d->rx[RX_ALL];

	/* default: filter via label/can_mask */
	return &d->rx[RX_FIL];
}

/**
 * arinc429_rx_register - subscribe ARINC429 frames from a specific interface
 * @dev: pointer to netdevice (NULL => subscribe from 'all' devices list)
 * @filter: ARINC429 filter (see description)
 * @func: callback function on filter match
 * @data: returned parameter for callback function
 * @ident: string for calling module identification
 *
 * Description:
 *  Invokes the callback function with the received sk_buff and the given
 *  parameter 'data' on a matching receive filter. A filter matches, when
 *
 *          <received_arinc429_id> & mask == arinc429_id & mask
 *
 *  The filter can be inverted (ARINC429_INV_FILTER bit set in arinc429_id)
 *  or it can filter for error message frames (ARINC429_ERR_FLAG bit set in
 *  mask).
 *
 *  The provided pointer to the sk_buff is guaranteed to be valid as long as
 *  the callback function is running. The callback function must *not* free
 *  the given sk_buff while processing it's task. When the given sk_buff is
 *  needed after the end of the callback function it must be cloned inside
 *  the callback function with skb_clone().
 *
 * Return:
 *  0 on success
 *  -ENOMEM on missing cache mem to create subscription entry
 *  -ENODEV unknown device
 */
int arinc429_rx_register(struct net_device *dev,
			 struct arinc429_filter *filter,
			 void (*func)(struct sk_buff *, void *), void *data,
			 char *ident)
{
	struct receiver *r;
	struct hlist_head *rl;
	struct dev_rcv_lists *d;
	int err = 0;
	u8 label = filter->label;
	u8 mask = filter->mask;
	const bool inv = filter->flags & ARINC429_INV_FILTER;

	/* insert new receiver  (dev,label,mask) -> (func,data) */

	if (dev && dev->type != ARPHRD_ARINC429)
		return -ENODEV;

	r = kmem_cache_alloc(rcv_cache, GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	spin_lock(&arinc429_rcvlists_lock);

	d = find_dev_rcv_lists(dev);
	if (d) {
		rl = find_rcv_list(&label, &mask, inv, d);

		r->label   = label;
		r->mask    = mask;
		r->matches = 0;
		r->func    = func;
		r->data    = data;
		r->ident   = ident;

		hlist_add_head_rcu(&r->list, rl);
		d->entries++;

		arinc429_pstats.rcv_entries++;
		if (arinc429_pstats.rcv_entries_max < arinc429_pstats.rcv_entries)
			arinc429_pstats.rcv_entries_max = arinc429_pstats.rcv_entries;
	} else {
		kmem_cache_free(rcv_cache, r);
		err = -ENODEV;
	}

	spin_unlock(&arinc429_rcvlists_lock);

	return err;
}
EXPORT_SYMBOL(arinc429_rx_register);

/*
 * arinc429_rx_delete_receiver - rcu callback for single receiver entry removal
 */
static void arinc429_rx_delete_receiver(struct rcu_head *rp)
{
	struct receiver *r = container_of(rp, struct receiver, rcu);

	kmem_cache_free(rcv_cache, r);
}

/**
 * arinc429_rx_unregister - unsubscribe ARINC429 frames from specific interface
 * @dev: pointer to netdevice (NULL => unsubscribe from 'all' devices list)
 * @filter: ARINC429 filter
 * @func: callback function on filter match
 * @data: returned parameter for callback function
 *
 * Description:
 *  Removes subscription entry depending on given (subscription) values.
 */
void arinc429_rx_unregister(struct net_device *dev,
			    struct arinc429_filter *filter,
			    void (*func)(struct sk_buff *, void *),
			    void *data)
{
	struct receiver *r = NULL;
	struct hlist_head *rl;
	struct dev_rcv_lists *d;
	u8 label = filter->label;
	u8 mask = filter->mask;
	const bool inv = filter->flags & ARINC429_INV_FILTER;

	if (dev && dev->type != ARPHRD_ARINC429)
		return;

	spin_lock(&arinc429_rcvlists_lock);

	d = find_dev_rcv_lists(dev);
	if (!d) {
		pr_err("BUG: receive list not found for dev %s, label %02X, mask %02X\n",
		       DNAME(dev), label, mask);
		goto out;
	}

	rl = find_rcv_list(&label, &mask, inv, d);

	/*
	 * Search the receiver list for the item to delete.  This should
	 * exist, since no receiver may be unregistered that hasn't
	 * been registered before.
	 */

	hlist_for_each_entry_rcu(r, rl, list) {
		if (r->label == label && r->mask == mask &&
		    r->func == func && r->data == data)
			break;
	}

	/*
	 * Check for bugs in ARINC429 protocol implementations using af_arinc429.c:
	 * 'r' will be NULL if no matching list item was found for removal.
	 */

	if (!r) {
		WARN(1, "BUG: receive list entry not found for dev %s, id %02X, mask %02X\n",
		     DNAME(dev), label, mask);
		goto out;
	}

	hlist_del_rcu(&r->list);
	d->entries--;

	if (arinc429_pstats.rcv_entries > 0)
		arinc429_pstats.rcv_entries--;

	/* remove device structure requested by NETDEV_UNREGISTER */
	if (d->remove_on_zero_entries && !d->entries) {
		kfree(d);
		dev->ml_priv = NULL;
	}

 out:
	spin_unlock(&arinc429_rcvlists_lock);

	/* schedule the receiver item for deletion */
	if (r)
		call_rcu(&r->rcu, arinc429_rx_delete_receiver);
}
EXPORT_SYMBOL(arinc429_rx_unregister);

static inline void deliver(struct sk_buff *skb, struct receiver *r)
{
	r->func(skb, r->data);
	r->matches++;
}

static unsigned int arinc429_rcv_filter(struct dev_rcv_lists *d,
					struct sk_buff *skb)
{
	struct receiver *r;
	unsigned int matches = 0;
	struct arinc429_frame *af = (struct arinc429_frame *)skb->data;
	__u8 label = af->label;

	if (d->entries == 0)
		return 0;

	/* check for unfiltered entries */
	hlist_for_each_entry_rcu(r, &d->rx[RX_ALL], list) {
		deliver(skb, r);
		matches++;
	}

	/* check for label/mask entries */
	hlist_for_each_entry_rcu(r, &d->rx[RX_FIL], list) {
		if ((label & r->mask) == r->label) {
			deliver(skb, r);
			matches++;
		}
	}

	/* check for inverted label/mask entries */
	hlist_for_each_entry_rcu(r, &d->rx[RX_INV], list) {
		if ((label & r->mask) != r->label) {
			deliver(skb, r);
			matches++;
		}
	}

	return matches;
}

static void arinc429_receive(struct sk_buff *skb, struct net_device *dev)
{
	struct dev_rcv_lists *d;
	unsigned int matches;

	/* update statistics */
	arinc429_stats.rx_frames++;
	arinc429_stats.rx_frames_delta++;

	rcu_read_lock();

	/* deliver the packet to sockets listening on all devices */
	matches = arinc429_rcv_filter(&arinc429_rx_alldev_list, skb);

	/* find receive list for this device */
	d = find_dev_rcv_lists(dev);
	if (d)
		matches += arinc429_rcv_filter(d, skb);

	rcu_read_unlock();

	/* consume the skbuff allocated by the netdevice driver */
	consume_skb(skb);

	if (matches > 0) {
		arinc429_stats.matches++;
		arinc429_stats.matches_delta++;
	}
}

static int arinc429_rcv(struct sk_buff *skb, struct net_device *dev,
			struct packet_type *pt, struct net_device *orig_dev)
{
	int ret;

	if (unlikely(!net_eq(dev_net(dev), &init_net)))
		goto drop;

	ret = WARN_ONCE(dev->type != ARPHRD_ARINC429 ||
			skb->len != ARINC429_MTU,
			"PF_ARINC429: dropped non conform ARINC429 skbuf: dev type %d, len %d\n",
			dev->type, skb->len);
	if (ret)
		goto drop;

	arinc429_receive(skb, dev);
	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 * af_arinc429 protocol functions
 */

/**
 * arinc429_proto_register - register ARINC429 transport protocol
 * @cp: pointer to ARINC429 protocol structure
 *
 * Return:
 *  0 on success
 *  -EINVAL invalid (out of range) protocol number
 *  -EBUSY  protocol already in use
 *  -ENOBUF if proto_register() fails
 */
int arinc429_proto_register(const struct arinc429_proto *cp)
{
	int proto = cp->protocol;
	int err = 0;

	if (proto < 0 || proto >= ARINC429_NPROTO) {
		pr_err("arinc429: protocol number %d out of range\n", proto);
		return -EINVAL;
	}

	err = proto_register(cp->prot, 0);
	if (err < 0)
		return err;

	mutex_lock(&proto_tab_lock);

	if (proto_tab[proto]) {
		pr_err("arinc429: protocol %d already registered\n", proto);
		err = -EBUSY;
	} else {
		RCU_INIT_POINTER(proto_tab[proto], cp);
	}

	mutex_unlock(&proto_tab_lock);

	if (err < 0)
		proto_unregister(cp->prot);

	return err;
}
EXPORT_SYMBOL(arinc429_proto_register);

/**
 * arinc429_proto_unregister - unregister ARINC429 transport protocol
 * @cp: pointer to ARINC429 protocol structure
 */
void arinc429_proto_unregister(const struct arinc429_proto *cp)
{
	int proto = cp->protocol;

	mutex_lock(&proto_tab_lock);
	BUG_ON(proto_tab[proto] != cp);
	RCU_INIT_POINTER(proto_tab[proto], NULL);
	mutex_unlock(&proto_tab_lock);

	synchronize_rcu();

	proto_unregister(cp->prot);
}
EXPORT_SYMBOL(arinc429_proto_unregister);

/*
 * af_arinc429 notifier to create/remove ARINC429 netdevice specific structs
 */
static int arinc429_notifier(struct notifier_block *nb, unsigned long msg,
			     void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct dev_rcv_lists *d;

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	if (dev->type != ARPHRD_ARINC429)
		return NOTIFY_DONE;

	switch (msg) {
	case NETDEV_REGISTER:

		/* create new dev_rcv_lists for this device */
		d = kzalloc(sizeof(*d), GFP_KERNEL);
		if (!d)
			return NOTIFY_DONE;
		BUG_ON(dev->ml_priv);
		dev->ml_priv = d;

		break;

	case NETDEV_UNREGISTER:
		spin_lock(&arinc429_rcvlists_lock);

		d = dev->ml_priv;
		if (d) {
			if (d->entries)
				d->remove_on_zero_entries = 1;
			else {
				kfree(d);
				dev->ml_priv = NULL;
			}
		} else {
			pr_err("arinc429: notifier: receive list not found for dev %s\n",
			       dev->name);
		}

		spin_unlock(&arinc429_rcvlists_lock);

		break;
	}

	return NOTIFY_DONE;
}

/*
 * af_arinc429 module init/exit functions
 */
static struct packet_type arinc429_packet __read_mostly = {
	.type	= cpu_to_be16(ETH_P_ARINC429),
	.func	= arinc429_rcv,
};

static const struct net_proto_family arinc429_family_ops = {
	.family	= PF_ARINC429,
	.create	= arinc429_create,
	.owner	= THIS_MODULE,
};

/* notifier block for netdevice event */
static struct notifier_block arinc429_netdev_notifier __read_mostly = {
	.notifier_call = arinc429_notifier,
};

static __init int arinc429_init(void)
{
	pr_info("arinc429: ARINC429 core (" ARINC429_VERSION_STRING ")\n");

	memset(&arinc429_rx_alldev_list, 0, sizeof(arinc429_rx_alldev_list));

	rcv_cache = kmem_cache_create("arinc429_receiver",
				      sizeof(struct receiver),
				      0, 0, NULL);
	if (!rcv_cache)
		return -ENOMEM;

	/* the statistics are updated every second (timer triggered) */
	setup_timer(&arinc429_stattimer, arinc429_stat_update, 0);
	mod_timer(&arinc429_stattimer, round_jiffies(jiffies + HZ));

	arinc429_init_proc();

	/* protocol register */
	sock_register(&arinc429_family_ops);
	register_netdevice_notifier(&arinc429_netdev_notifier);
	dev_add_pack(&arinc429_packet);

	return 0;
}

static __exit void arinc429_exit(void)
{
	struct net_device *dev;

	del_timer_sync(&arinc429_stattimer);

	arinc429_remove_proc();

	/* protocol unregister */
	dev_remove_pack(&arinc429_packet);
	unregister_netdevice_notifier(&arinc429_netdev_notifier);
	sock_unregister(PF_ARINC429);

	/* remove created dev_rcv_lists from still registered devices */
	rcu_read_lock();
	for_each_netdev_rcu(&init_net, dev) {
		if (dev->type == ARPHRD_ARINC429 && dev->ml_priv) {
			struct dev_rcv_lists *d = dev->ml_priv;

			BUG_ON(d->entries);
			kfree(d);
			dev->ml_priv = NULL;
		}
	}
	rcu_read_unlock();

	rcu_barrier(); /* Wait for completion of call_rcu()'s */

	kmem_cache_destroy(rcv_cache);
}

module_init(arinc429_init);
module_exit(arinc429_exit);
