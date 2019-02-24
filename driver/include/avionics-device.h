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

struct sk_buff* avionics_device_alloc_skb(struct net_device *dev,
					  unsigned int size);

void * avionics_device_priv(struct net_device *dev);

int avionics_device_register(struct net_device *dev);
void avionics_device_unregister(struct net_device *dev);

struct net_device *avioinics_device_arinc429rx_alloc(int sizeof_priv);
struct net_device *avioinics_device_arinc429tx_alloc(int sizeof_priv);

void avionics_device_free(struct net_device *dev);

#endif /* __AVIONICS_DEVICE_H__ */
