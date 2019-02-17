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

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <net/sock.h>

#include "avionics.h"
#include "socket-list.h"

struct socket_info {
	struct hlist_node node;
	struct sock *sk;
	void (*rx_func)(struct sk_buff*, struct sock *);
};

struct socket_list {
	struct hlist_head head;
	int remove_on_zero_entries;
	int entries;
};

static DEFINE_SPINLOCK(socket_list_lock);
static struct kmem_cache *socket_list_cache __read_mostly;

void socket_list_remove_socket(struct net_device *dev,
			 void (*rx_func)(struct sk_buff *, struct sock *),
			 struct sock *sk)
{
	struct socket_list *sk_list;
	struct socket_info *sk_info;

	pr_debug("socket-list: Unregistering socket with %s\n", dev->name);

	if (!dev) {
		pr_err("socket-list: Not a valid device.\n");
		return;
	}

	if (dev->type != ARPHRD_AVIONICS) {
		pr_err("socket-list: %s is not a valid device.\n", dev->name);
		return;
	}

	if (!dev->ml_priv) {
		pr_err("socket-list: %s has no registerd socket list.\n",
		       dev->name);
		return;
	}

	spin_lock(&socket_list_lock);

	sk_list = (struct socket_list *)dev->ml_priv;

	rcu_read_lock();
	hlist_for_each_entry_rcu(sk_info, &sk_list->head, node) {
		if ((sk_info->rx_func == rx_func)
		    && (sk_info->sk == sk)) {
			break;
		}
	}
	rcu_read_unlock();

	if (!sk_info) {
		pr_err("socket-list: failed to find socket in device %s.\n",
		       dev->name);
		spin_unlock(&socket_list_lock);
		return;
	}

	hlist_del_rcu(&sk_info->node);
	sk_list->entries--;

	if (sk_list->remove_on_zero_entries && (sk_list->entries <= 0)) {
		pr_debug("socket-list: Removing socket list from %s.\n",
			 dev->name);
		kfree(sk_list);
		dev->ml_priv = NULL;
	}

	spin_unlock(&socket_list_lock);

	kmem_cache_free(socket_list_cache, sk_info);

}

int socket_list_add_socket(struct net_device *dev,
			void (*rx_func)(struct sk_buff *, struct sock *),
			struct sock *sk)
{
	struct socket_list *sk_list;
	struct socket_info *sk_info;

	pr_debug("socket-list: Registering socket with %s\n", dev->name);

	if (!dev) {
		pr_err("socket-list: Not a valid device.\n");
		return -ENODEV;
	}

	if (dev->type != ARPHRD_AVIONICS) {
		pr_err("socket-list: %s is not a valid device.\n", dev->name);
		return -ENODEV;
	}

	if (!dev->ml_priv) {
		pr_err("socket-list: %s has no registerd socket list.\n",
		       dev->name);
		return -ENODEV;
	}
	spin_lock(&socket_list_lock);

	sk_list = (struct socket_list *)dev->ml_priv;

	rcu_read_lock();
	hlist_for_each_entry_rcu(sk_info, &sk_list->head, node) {
		if (sk_info->rx_func == rx_func
		    && sk_info->sk == sk) {
			pr_info("Socket already attached to %s\n", dev->name);
			rcu_read_unlock();
			spin_unlock(&socket_list_lock);
			return 0;
		}
	}
	rcu_read_unlock();

	sk_info = kmem_cache_alloc(socket_list_cache, GFP_KERNEL);
	if (!sk_info) {
		pr_info("Failed to allocate socket info\n");
		return -ENOMEM;
	}

	sk_info->sk = sk;
	sk_info->rx_func = rx_func;

	hlist_add_head_rcu(&sk_info->node, &sk_list->head);
	sk_list->entries++;

	spin_unlock(&socket_list_lock);

	return 0;
}

void socket_list_remove(struct net_device *dev)
{
	struct socket_list *sk_list;

	pr_debug("socket-list: Removing socket list from %s\n",dev->name);

	spin_lock(&socket_list_lock);

	sk_list = (struct socket_list *)dev->ml_priv;
	if (sk_list) {
		sk_list->remove_on_zero_entries = 1;
		if (!sk_list->entries)
			kfree(sk_list);
		dev->ml_priv = NULL;
	} else {
		pr_err("socket-list: receive list not found for device %s\n",
		       dev->name);
	}

	spin_unlock(&socket_list_lock);
}

int socket_list_add(struct net_device *dev)
{
	struct socket_list *sk_list;

	pr_debug("socket-list: Adding socket list to %s\n",dev->name);

	if (dev->ml_priv) {
		pr_err("socket-list: Device %s already has a socket list.\n",
		       dev->name);
		return -EINVAL;
	}

	sk_list = kzalloc(sizeof(*sk_list), GFP_KERNEL);
	if (!sk_list) {
		pr_err("socket-list: Failed to allocate socket list.\n");
		return -ENOMEM;
	}

	dev->ml_priv = sk_list;

	return 0;
}

void socket_list_exit(void)
{
	struct socket_list *sk_list;
	struct net_device *dev;

	/* remove created dev_rcv_lists from still registered devices */
	rcu_read_lock();
	for_each_netdev_rcu(&init_net, dev) {
		if (dev->type == ARPHRD_AVIONICS && dev->ml_priv) {
			sk_list = (struct socket_list *)dev->ml_priv;
			if (sk_list->entries) {
				pr_err("socket-list: %s had sockets attached\n",
				       dev->name);
			}
			kfree(sk_list);
			dev->ml_priv = NULL;
		}
	}
	rcu_read_unlock();
	rcu_barrier();

	kmem_cache_destroy(socket_list_cache);
}

int socket_list_init(void)
{
	socket_list_cache = kmem_cache_create("avionics_socket_list",
					     sizeof(struct socket_info),
					     0, 0, NULL);
	if (!socket_list_cache) {
		pr_err("socket-list: Failed to allocate device socket cache.\n");
		return -ENOMEM;
	}

	return 0;
}
