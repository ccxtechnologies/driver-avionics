/*
 * proc.c - procfs support for Protocol family ARINC429 core module
 *
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

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/if_arp.h>
#include <linux/arinc429/core.h>

#include "af_arinc429.h"

/*
 * proc filenames for the PF_ARINC429 core
 */

#define ARINC429_PROC_VERSION     "version"
#define ARINC429_PROC_STATS       "stats"
#define ARINC429_PROC_RESET_STATS "reset_stats"
#define ARINC429_PROC_RCVLIST_ALL "rcvlist_all"
#define ARINC429_PROC_RCVLIST_FIL "rcvlist_fil"
#define ARINC429_PROC_RCVLIST_INV "rcvlist_inv"

static struct proc_dir_entry *arinc429_dir;
static struct proc_dir_entry *pde_version;
static struct proc_dir_entry *pde_stats;
static struct proc_dir_entry *pde_reset_stats;
static struct proc_dir_entry *pde_rcvlist_all;
static struct proc_dir_entry *pde_rcvlist_fil;
static struct proc_dir_entry *pde_rcvlist_inv;

static int user_reset;

static const char rx_list_name[][8] = {
	[RX_ALL] = "rx_all",
	[RX_FIL] = "rx_fil",
	[RX_INV] = "rx_inv",
};

/*
 * af_arinc429 statistics stuff
 */

static void arinc429_init_stats(void)
{
	/*
	 * This memset function is called from a timer context (when
	 * arinc429_stattimer is active which is the default) OR in a process
	 * context (reading the proc_fs when arinc429_stattimer is disabled).
	 */
	memset(&arinc429_stats, 0, sizeof(arinc429_stats));
	arinc429_stats.jiffies_init = jiffies;

	arinc429_pstats.stats_reset++;

	if (user_reset) {
		user_reset = 0;
		arinc429_pstats.user_reset++;
	}
}

static unsigned long calc_rate(unsigned long oldjif, unsigned long newjif,
			       unsigned long count)
{
	unsigned long rate;

	if (oldjif == newjif)
		return 0;

	/* see arinc429_stat_update() - this should NEVER happen! */
	if (count > (ULONG_MAX / HZ)) {
		pr_err("arinc429: calc_rate: count exceeded! %ld\n", count);
		return 99999999;
	}

	rate = (count * HZ) / (newjif - oldjif);

	return rate;
}

void arinc429_stat_update(unsigned long data)
{
	unsigned long j = jiffies; /* snapshot */

	/* restart counting in timer context on user request */
	if (user_reset)
		arinc429_init_stats();

	/* restart counting on jiffies overflow */
	if (j < arinc429_stats.jiffies_init)
		arinc429_init_stats();

	/* prevent overflow in calc_rate() */
	if (arinc429_stats.rx_frames > (ULONG_MAX / HZ))
		arinc429_init_stats();

	/* prevent overflow in calc_rate() */
	if (arinc429_stats.tx_frames > (ULONG_MAX / HZ))
		arinc429_init_stats();

	/* matches overflow - very improbable */
	if (arinc429_stats.matches > (ULONG_MAX / 100))
		arinc429_init_stats();

	/* calc total values */
	if (arinc429_stats.rx_frames)
		arinc429_stats.total_rx_match_ratio =
			(arinc429_stats.matches * 100) /
			arinc429_stats.rx_frames;

	arinc429_stats.total_tx_rate = calc_rate(arinc429_stats.jiffies_init,
						 j, arinc429_stats.tx_frames);
	arinc429_stats.total_rx_rate = calc_rate(arinc429_stats.jiffies_init,
						 j, arinc429_stats.rx_frames);

	/* calc current values */
	if (arinc429_stats.rx_frames_delta)
		arinc429_stats.current_rx_match_ratio =
			(arinc429_stats.matches_delta * 100) /
			arinc429_stats.rx_frames_delta;

	arinc429_stats.current_tx_rate =
		calc_rate(0, HZ, arinc429_stats.tx_frames_delta);
	arinc429_stats.current_rx_rate =
		calc_rate(0, HZ, arinc429_stats.rx_frames_delta);

	/* check / update maximum values */
	if (arinc429_stats.max_tx_rate < arinc429_stats.current_tx_rate)
		arinc429_stats.max_tx_rate = arinc429_stats.current_tx_rate;

	if (arinc429_stats.max_rx_rate < arinc429_stats.current_rx_rate)
		arinc429_stats.max_rx_rate = arinc429_stats.current_rx_rate;

	if (arinc429_stats.max_rx_match_ratio < arinc429_stats.current_rx_match_ratio)
		arinc429_stats.max_rx_match_ratio = arinc429_stats.current_rx_match_ratio;

	/* clear values for 'current rate' calculation */
	arinc429_stats.tx_frames_delta = 0;
	arinc429_stats.rx_frames_delta = 0;
	arinc429_stats.matches_delta   = 0;

	/* restart timer (one second) */
	mod_timer(&arinc429_stattimer, round_jiffies(jiffies + HZ));
}

/*
 * proc read functions
 */

static void arinc429_print_rcvlist(struct seq_file *m,
				   struct hlist_head *rx_list,
				   struct net_device *dev)
{
	struct receiver *r;

	seq_puts(m, "  device      label  mask  function  userdata   matches  ident\n");

	hlist_for_each_entry_rcu(r, rx_list, list) {
		char *fmt = "   %-5s     %02x     %02x   %pK  %pK  %8ld  %s\n";

		seq_printf(m, fmt, DNAME(dev), r->label, r->mask,
			   r->func, r->data, r->matches, r->ident);
	}
}

static int arinc429_stats_proc_show(struct seq_file *m, void *v)
{
	seq_putc(m, '\n');
	seq_printf(m, " %8ld transmitted frames (TXF)\n",
		   arinc429_stats.tx_frames);
	seq_printf(m, " %8ld received frames (RXF)\n",
		   arinc429_stats.rx_frames);
	seq_printf(m, " %8ld matched frames (RXMF)\n",
		   arinc429_stats.matches);

	seq_putc(m, '\n');

	if (arinc429_stattimer.function == arinc429_stat_update) {
		seq_printf(m, " %8ld %% total match ratio (RXMR)\n",
			   arinc429_stats.total_rx_match_ratio);

		seq_printf(m, " %8ld frames/s total tx rate (TXR)\n",
			   arinc429_stats.total_tx_rate);
		seq_printf(m, " %8ld frames/s total rx rate (RXR)\n",
			   arinc429_stats.total_rx_rate);

		seq_putc(m, '\n');

		seq_printf(m, " %8ld %% current match ratio (CRXMR)\n",
			   arinc429_stats.current_rx_match_ratio);

		seq_printf(m, " %8ld frames/s current tx rate (CTXR)\n",
			   arinc429_stats.current_tx_rate);
		seq_printf(m, " %8ld frames/s current rx rate (CRXR)\n",
			   arinc429_stats.current_rx_rate);

		seq_putc(m, '\n');

		seq_printf(m, " %8ld %% max match ratio (MRXMR)\n",
			   arinc429_stats.max_rx_match_ratio);

		seq_printf(m, " %8ld frames/s max tx rate (MTXR)\n",
			   arinc429_stats.max_tx_rate);
		seq_printf(m, " %8ld frames/s max rx rate (MRXR)\n",
			   arinc429_stats.max_rx_rate);

		seq_putc(m, '\n');
	}

	seq_printf(m, " %8ld current receive list entries (CRCV)\n",
		   arinc429_pstats.rcv_entries);
	seq_printf(m, " %8ld maximum receive list entries (MRCV)\n",
		   arinc429_pstats.rcv_entries_max);

	if (arinc429_pstats.stats_reset)
		seq_printf(m, "\n %8ld statistic resets (STR)\n",
			   arinc429_pstats.stats_reset);

	if (arinc429_pstats.user_reset)
		seq_printf(m, " %8ld user statistic resets (USTR)\n",
			   arinc429_pstats.user_reset);

	seq_putc(m, '\n');
	return 0;
}

static int arinc429_stats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, arinc429_stats_proc_show, NULL);
}

static const struct file_operations arinc429_stats_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= arinc429_stats_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int arinc429_reset_stats_proc_show(struct seq_file *m, void *v)
{
	user_reset = 1;

	if (arinc429_stattimer.function == arinc429_stat_update) {
		seq_printf(m, "Scheduled statistic reset #%ld.\n",
			   arinc429_pstats.stats_reset + 1);

	} else {
		if (arinc429_stats.jiffies_init != jiffies)
			arinc429_init_stats();

		seq_printf(m, "Performed statistic reset #%ld.\n",
			   arinc429_pstats.stats_reset);
	}
	return 0;
}

static int arinc429_reset_stats_proc_open(struct inode *inode,
					  struct file *file)
{
	return single_open(file, arinc429_reset_stats_proc_show, NULL);
}

static const struct file_operations arinc429_reset_stats_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= arinc429_reset_stats_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int arinc429_version_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", ARINC429_VERSION_STRING);
	return 0;
}

static int arinc429_version_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, arinc429_version_proc_show, NULL);
}

static const struct file_operations arinc429_version_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= arinc429_version_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static inline void arinc429_rcvlist_proc_show_one(struct seq_file *m, int idx,
						  struct net_device *dev,
						  struct dev_rcv_lists *d)
{
	if (!hlist_empty(&d->rx[idx]))
		arinc429_print_rcvlist(m, &d->rx[idx], dev);
	else
		seq_printf(m, "  (%s: no entry)\n", DNAME(dev));
}

static int arinc429_rcvlist_proc_show(struct seq_file *m, void *v)
{
	/* double cast to prevent GCC warning */
	int idx = (int)(long)m->private;
	struct net_device *dev;
	struct dev_rcv_lists *d;

	seq_printf(m, "\nreceive list '%s':\n", rx_list_name[idx]);

	rcu_read_lock();

	/* receive list for 'all' ARINC429 devices (dev == NULL) */
	d = &arinc429_rx_alldev_list;
	arinc429_rcvlist_proc_show_one(m, idx, NULL, d);

	/* receive list for registered ARINC429 devices */
	for_each_netdev_rcu(&init_net, dev) {
		if (dev->type == ARPHRD_ARINC429 && dev->ml_priv)
			arinc429_rcvlist_proc_show_one(m, idx, dev,
						       dev->ml_priv);
	}

	rcu_read_unlock();

	seq_putc(m, '\n');
	return 0;
}

static int arinc429_rcvlist_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, arinc429_rcvlist_proc_show, PDE_DATA(inode));
}

static const struct file_operations arinc429_rcvlist_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= arinc429_rcvlist_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*
 * proc utility functions
 */

static void arinc429_remove_proc_readentry(const char *name)
{
	if (arinc429_dir)
		remove_proc_entry(name, arinc429_dir);
}

/*
 * arinc429_init_proc - create main ARINC429 proc directory and procfs entries
 */
void arinc429_init_proc(void)
{
	/* create /proc/net/arinc429 directory */
	arinc429_dir = proc_mkdir("arinc429", init_net.proc_net);

	if (!arinc429_dir) {
		pr_info("arinc429: failed to create /proc/net/arinc429 . CONFIG_PROC_FS missing?\n");
		return;
	}

	/* own procfs entries from the AF_ARINC429 core */
	pde_version     = proc_create(ARINC429_PROC_VERSION, 0644,
				      arinc429_dir,
				      &arinc429_version_proc_fops);
	pde_stats       = proc_create(ARINC429_PROC_STATS, 0644,
				      arinc429_dir,
				      &arinc429_stats_proc_fops);
	pde_reset_stats = proc_create(ARINC429_PROC_RESET_STATS, 0644,
				      arinc429_dir,
				      &arinc429_reset_stats_proc_fops);
	pde_rcvlist_all = proc_create_data(ARINC429_PROC_RCVLIST_ALL, 0644,
					   arinc429_dir,
					   &arinc429_rcvlist_proc_fops,
					   (void *)RX_ALL);
	pde_rcvlist_fil = proc_create_data(ARINC429_PROC_RCVLIST_FIL, 0644,
					   arinc429_dir,
					   &arinc429_rcvlist_proc_fops,
					   (void *)RX_FIL);
	pde_rcvlist_inv = proc_create_data(ARINC429_PROC_RCVLIST_INV, 0644,
					   arinc429_dir,
					   &arinc429_rcvlist_proc_fops,
					   (void *)RX_INV);
}

/*
 * arinc429_remove_proc - remove procfs entries and main ARINC429 proc directory
 */
void arinc429_remove_proc(void)
{
	if (pde_version)
		arinc429_remove_proc_readentry(ARINC429_PROC_VERSION);

	if (pde_stats)
		arinc429_remove_proc_readentry(ARINC429_PROC_STATS);

	if (pde_reset_stats)
		arinc429_remove_proc_readentry(ARINC429_PROC_RESET_STATS);

	if (pde_rcvlist_all)
		arinc429_remove_proc_readentry(ARINC429_PROC_RCVLIST_ALL);

	if (pde_rcvlist_fil)
		arinc429_remove_proc_readentry(ARINC429_PROC_RCVLIST_FIL);

	if (pde_rcvlist_inv)
		arinc429_remove_proc_readentry(ARINC429_PROC_RCVLIST_INV);

	if (arinc429_dir)
		remove_proc_entry("arinc429", init_net.proc_net);
}
