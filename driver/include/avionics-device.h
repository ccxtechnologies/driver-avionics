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

#endif /* __AVIONICS_DEVICE_H__ */
