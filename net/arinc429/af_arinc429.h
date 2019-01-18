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
#include <linux/arinc429.h>

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

/* statistic structures */

/* can be reset e.g. by arinc429_init_stats() */
struct s_stats {
	unsigned long jiffies_init;

	unsigned long rx_frames;
	unsigned long tx_frames;
	unsigned long matches;

	unsigned long total_rx_rate;
	unsigned long total_tx_rate;
	unsigned long total_rx_match_ratio;

	unsigned long current_rx_rate;
	unsigned long current_tx_rate;
	unsigned long current_rx_match_ratio;

	unsigned long max_rx_rate;
	unsigned long max_tx_rate;
	unsigned long max_rx_match_ratio;

	unsigned long rx_frames_delta;
	unsigned long tx_frames_delta;
	unsigned long matches_delta;
};

/* persistent statistics */
struct s_pstats {
	unsigned long stats_reset;
	unsigned long user_reset;
	unsigned long rcv_entries;
	unsigned long rcv_entries_max;
};

/* receive filters subscribed for 'all' ARINC429 devices */
extern struct dev_rcv_lists arinc429_rx_alldev_list;

/* function prototypes for the ARINC429 networklayer procfs (proc.c) */
void arinc429_init_proc(void);
void arinc429_remove_proc(void);
void arinc429_stat_update(unsigned long data);

/* structures and variables from af_arinc429.c needed in proc.c for reading */
extern struct timer_list arinc429_stattimer;    /* timer for stats update */
extern struct s_stats    arinc429_stats;        /* packet statistics */
extern struct s_pstats   arinc429_pstats;       /* receive list statistics */
extern struct hlist_head arinc429_rx_dev_list;  /* rx dispatcher structures */

#endif /* AF_ARINC429_H */
