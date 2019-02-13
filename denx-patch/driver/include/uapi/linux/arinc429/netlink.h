/*
 * linux/arinc429/netlink.h
 *
 * Definitions for the ARINC429 netlink interface
 *
 * Copyright (C) 2015 Marek Vasut <marex@denx.de>
 *
 * Based on the SocketARINC429 stack.
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

#ifndef _UAPI_ARINC429_NETLINK_H
#define _UAPI_ARINC429_NETLINK_H

#include <linux/types.h>

/*
 * ARINC429 data rate parameters
 */
struct arinc429_rate {
	__u32 rx_rate;		/* ARINC429 bus RX rate [Hz] */
	__u32 tx_rate;		/* ARINC429 bus TX rate [Hz] */
};

/*
 * ARINC429 controller mode
 */
struct arinc429_ctrlmode {
	__u32 mask;
	__u32 flags;
};

#define ARINC429_CTRLMODE_LOOPBACK	0x01	/* Loopback mode */

/*
 * ARINC429 netlink interface
 */
enum {
	IFLA_ARINC429_UNSPEC,
	IFLA_ARINC429_RATE,
	IFLA_ARINC429_CTRLMODE,
	__IFLA_ARINC429_MAX
};

#define IFLA_ARINC429_MAX	(__IFLA_ARINC429_MAX - 1)

#endif /* !_UAPI_ARINC429_NETLINK_H */
