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

#ifndef __SOCKET_LIST_H__
#define __SOCKET_LIST_H__

/* Socket lists are used to track a list of sockets that are
 * attached to a specific device. This is used to determine
 * where to send any incoming packets. */

void socket_list_remove_socket(struct net_device *dev,
			 void (*rx_func)(struct sk_buff *, struct sock *),
			 struct sock *sk);
int socket_list_add_socket(struct net_device *dev,
			void (*rx_func)(struct sk_buff *, struct sock *),
			struct sock *sk);

void socket_list_remove(struct net_device *dev);
int socket_list_add(struct net_device *dev);

void socket_list_exit(void);
int socket_list_init(void);

#endif /* __SOCKET_LIST_H__ */
