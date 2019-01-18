/*
 * linux/arinc429/raw.h
 *
 * Definitions for raw ARINC429 sockets
 *
 * Copyright (C) 2015 Marek Vasut <marex@denx.de>
 *
 * Based on the SocketCAN stack.
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

#ifndef _UAPI_ARINC429_RAW_H
#define _UAPI_ARINC429_RAW_H

#include <linux/arinc429.h>

#define SOL_ARINC429_RAW (SOL_ARINC429_BASE + ARINC429_RAW)

/* for socket options affecting the socket (not the global system) */

enum {
	ARINC429_RAW_FILTER = 1,	/* set 0 .. n arinc429_filter(s)     */
	ARINC429_RAW_LOOPBACK,		/* local loopback (default:on)       */
	ARINC429_RAW_RECV_OWN_MSGS,	/* receive my own msgs (default:off) */
	ARINC429_RAW_JOIN_FILTERS,	/* all filters must match to trigger */
};

#endif /* !_UAPI_ARINC429_RAW_H */
