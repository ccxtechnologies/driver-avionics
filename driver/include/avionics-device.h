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

#ifndef __AVIONICS_DEVICE_H__
#define __AVIONICS_DEVICE_H__

#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include "avionics.h"

typedef struct avionics_proto_header_data avionics_data;

struct avionics_ops {
	const char *name;

	int (*set_rate)(struct avionics_rate *rate,
			const struct net_device *dev);
	void (*get_rate)(struct avionics_rate *rate,
			 const struct net_device *dev);

	int (*set_arinc429rx)(struct avionics_arinc429rx *config,
			      const struct net_device *dev);
	void (*get_arinc429rx)(struct avionics_arinc429rx *config,
			       const struct net_device *dev);

	int (*set_arinc429tx)(struct avionics_arinc429tx *config,
			      const struct net_device *dev);
	void (*get_arinc429tx)(struct avionics_arinc429tx *config,
			       const struct net_device *dev);

	int (*set_arinc717rx)(struct avionics_arinc717rx *config,
			      const struct net_device *dev);
	void (*get_arinc717rx)(struct avionics_arinc717rx *config,
			       const struct net_device *dev);

	int (*set_arinc717tx)(struct avionics_arinc717tx *config,
			      const struct net_device *dev);
	void (*get_arinc717tx)(struct avionics_arinc717tx *config,
			       const struct net_device *dev);

	int (*set_mil1553bm)(struct avionics_mil1553bm *config,
			     const struct net_device *dev);
	void (*get_mil1553bm)(struct avionics_mil1553bm *config,
			      const struct net_device *dev);
};

struct sk_buff* avionics_device_alloc_skb(struct net_device *dev,
					  unsigned int size);

void * avionics_device_priv(const struct net_device *dev);

int avionics_device_register(struct net_device *dev);
void avionics_device_unregister(struct net_device *dev);

struct net_device *avionics_device_alloc(int sizeof_priv,
					 struct avionics_ops *ops);

void avionics_device_free(struct net_device *dev);

#endif /* __AVIONICS_DEVICE_H__ */
