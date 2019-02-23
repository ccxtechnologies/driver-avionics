/*
 * Copyright (C), 2019 CCX Technologies
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

#include <linux/skbuff.h>

#include "protocol.h"
#include "avionics-device.h"

struct sk_buff* avionics_device_alloc_skb(struct net_device *dev,
					  unsigned int size)
{
	return protocol_alloc_skb(dev, size);
}
EXPORT_SYMBOL(avionics_device_alloc_skb);
