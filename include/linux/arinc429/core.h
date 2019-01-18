/*
 * linux/arinc429/core.h
 *
 * Protoypes and definitions for ARINC429 protocol modules
 * using the PF_ARINC429 core.
 *
 * Copyright (C) 2015 Marek Vasut <marex@denx.de>
 *
 * Based on the SocketCAN stack.
 */

#ifndef __ARINC429_CORE_H__
#define __ARINC429_CORE_H__

#include <linux/arinc429.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#define ARINC429_VERSION "20151101"

/* Increment this number each time you change some user-space interface */
#define ARINC429_ABI_VERSION "1"

#define ARINC429_VERSION_STRING		\
	"rev " ARINC429_VERSION " abi " ARINC429_ABI_VERSION

#define DNAME(dev) ((dev) ? (dev)->name : "any")

/**
 * struct arinc429_proto - ARINC429 protocol structure
 * @type:       type argument in socket() syscall, e.g. SOCK_DGRAM.
 * @protocol:   protocol number in socket() syscall.
 * @ops:        pointer to struct proto_ops for sock->ops.
 * @prot:       pointer to struct proto structure.
 */
struct arinc429_proto {
	int			type;
	int			protocol;
	const struct proto_ops	*ops;
	struct proto		*prot;
};

/* Function prototypes for the ARINC429 network layer core (af_arinc429.c) */
extern int  arinc429_proto_register(const struct arinc429_proto *cp);
extern void arinc429_proto_unregister(const struct arinc429_proto *cp);

extern int  arinc429_rx_register(struct net_device *dev,
				 struct arinc429_filter *filter,
				 void (*func)(struct sk_buff *, void *),
				 void *data, char *ident);

extern void arinc429_rx_unregister(struct net_device *dev,
				   struct arinc429_filter *filter,
				   void (*func)(struct sk_buff *, void *),
				   void *data);

extern int arinc429_send(struct sk_buff *skb, int loop);
extern int arinc429_ioctl(struct socket *sock, unsigned int cmd,
			  unsigned long arg);

#endif /* __ARINC429_CORE_H__ */
