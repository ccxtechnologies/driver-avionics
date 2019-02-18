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

#ifndef __PROTO_H__
#define __PROTO_H__

#include <net/sock.h>

struct proto_sock {
	struct sock sk; /* must be first */
	int ifindex;
	int bound;
};

int proto_get_dev_from_msg(struct proto_sock *psk,
			   struct msghdr *msg, size_t size,
			   struct net_device **dev);
struct sk_buff* proto_alloc_send_skb(struct net_device *dev,
					 int flags,
					 struct sock *sk,
					 size_t size);
int proto_send_to_netdev(struct net_device *dev, struct sk_buff *skb);

int proto_getname(struct socket *sock, struct sockaddr *saddr,
		  int *len, int peer);
int proto_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);
int proto_release(struct socket *sock);
int proto_bind(struct socket *sock, struct sockaddr *saddr, int len);

#endif /* __AVIONICS_H__ */
