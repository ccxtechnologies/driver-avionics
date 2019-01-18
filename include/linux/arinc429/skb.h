/*
 * linux/arinc429/skb.h
 *
 * Definitions for the ARINC429 network socket buffer
 *
 * Copyright (C) 2015 Marek Vasut <marex@denx.de>
 *
 * Based on the SocketCAN stack.
 */

#ifndef __ARINC429_SKB_H__
#define __ARINC429_SKB_H__

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/arinc429.h>
#include <net/sock.h>

/*
 * The struct arinc429_skb_priv is used to transport additional information
 * along with the stored struct arinc429(fd)_frame that arinc429 not be
 * contained in existing struct sk_buff elements.
 * N.B. that this information must not be modified in cloned ARINC429 sk_buffs.
 * To modify the ARINC429 frame content or the struct arinc429_skb_priv content
 * skb_copy() needs to be used instead of skb_clone().
 */

/**
 * struct arinc429_skb_priv - private additional data inside ARINC429 sk_buffs
 * @ifindex:	ifindex of the first interface the ARINC429 frame appeared on
 * @cf:		align to the following ARINC429 frame at skb->data
 */
struct arinc429_skb_priv {
	int			ifindex;
	struct arinc429_frame	af[0];
};

static inline struct arinc429_skb_priv *arinc429_skb_prv(struct sk_buff *skb)
{
	return (struct arinc429_skb_priv *)(skb->head);
}

static inline void arinc429_skb_reserve(struct sk_buff *skb)
{
	skb_reserve(skb, sizeof(struct arinc429_skb_priv));
}

static inline void arinc429_skb_set_owner(struct sk_buff *skb, struct sock *sk)
{
	if (sk) {
		sock_hold(sk);
		skb->destructor = sock_efree;
		skb->sk = sk;
	}
}

/*
 * returns an unshared skb owned by the original sock to be echo'ed back
 */
static inline struct sk_buff *arinc429_create_echo_skb(struct sk_buff *skb)
{
	if (skb_shared(skb)) {
		struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);

		if (likely(nskb)) {
			arinc429_skb_set_owner(nskb, skb->sk);
			consume_skb(skb);
			return nskb;
		}

		kfree_skb(skb);
		return NULL;
	}

	/* we can assume to have an unshared skb with proper owner */
	return skb;
}

#endif /* __ARINC429_SKB_H__ */
