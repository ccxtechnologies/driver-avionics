/*
 * Copyright (C) 2019, CCX Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __AVIONICS_PROTOCOL_H__
#define __AVIONICS_PROTOCOL_H__

#include <net/sock.h>
#include <linux/version.h>

struct protocol_sock {
	struct sock sk; /* must be first */
	int ifindex;
	int bound;
};

void protocol_init_skb(struct net_device *dev, struct sk_buff *skb);
struct sk_buff* protocol_alloc_send_skb(struct net_device *dev,
					int flags, struct sock *sk,
					size_t size, int *err);

int protocol_get_dev_from_msg(struct protocol_sock *psk,
			      struct msghdr *msg, size_t size,
			      struct net_device **dev);
int protocol_send_to_netdev(struct net_device *dev, struct sk_buff *skb);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,17,0)
int protocol_getname(struct socket *sock, struct sockaddr *saddr,
		     int *len, int peer);
#else
int protocol_getname(struct socket *sock, struct sockaddr *saddr,
		     int peer);
#endif
int protocol_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);
int protocol_release(struct socket *sock);
int protocol_bind(struct socket *sock, struct sockaddr *saddr, int len);

#endif /* __AVIONICS_PROTOCOL_H__ */
