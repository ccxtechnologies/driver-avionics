/*
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

#ifndef AF_ARINC429_H
#define AF_ARINC429_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include "arinc429.h"

/* af_arinc429 rx dispatcher structures */

struct receiver {
	struct hlist_node	list;
	struct rcu_head		rcu;
	__u8			label;
	__u8			mask;
	unsigned long		matches;
	void			(*func)(struct sk_buff *, void *);
	void			*data;
	char			*ident;
};

enum { RX_ALL, RX_FIL, RX_INV, RX_MAX };

/* per device receive filters linked at dev->ml_priv */
struct dev_rcv_lists {
	struct hlist_head	rx[RX_MAX];
	int			remove_on_zero_entries;
	int			entries;
};

/* receive filters subscribed for 'all' ARINC429 devices */
extern struct dev_rcv_lists arinc429_rx_alldev_list;

#endif /* AF_ARINC429_H */
