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

#ifndef __AVIONICS_H__
#define __AVIONICS_H__

#include <linux/types.h>
#include <linux/socket.h>

/************************************************************************
 * CCX: This is an ugly hack so that we can build this out of tree without
 * patching the kernel, delete it and create new definions in the propper
 * place if this is ever pulled into your kernel. */

/* should be in include/linux/socket.h, and should have it's own
 * index, not stealing from Ash (which is unused) */
#ifndef AF_AVIONICS
#define AF_AVIONICS	AF_ASH
#endif

/* should be in include/linux/socket.h, and should have it's own
 * index, not stealing from Ash (which is unused) */
#ifndef PF_AVIONICS
#define PF_AVIONICS	AF_AVIONICS
#endif

/* should be in include/uapi/linux/if_arp.h */
#ifndef ARPHRD_AVIONICS
#define ARPHRD_AVIONICS	281
#endif

/* should be in include/uapi/linux/if_ether.h */
#ifndef ETH_P_AVIONICS
#define ETH_P_AVIONICS	0x001D
#endif

/************************************************************************/


/* ================= Defintions for Socket Interface =================== */

#define AVIONICS_PROTO_RAW	1

struct sockaddr_avionics {
	__kernel_sa_family_t avionics_family;
	int ifindex;
	union {
		/* reserved for future prototcols */
	} avionics_addr;
};

/* ============= Defintions for Netlink (RNTL) Interface =============== */

struct avionics_rate {
	__u32 rx_rate_hz;
	__u32 tx_rate_hz;
};

enum {
	IFLA_AVIONICS_UNSPEC,
	IFLA_AVIONICS_RATE,
	__IFLA_AVIONICS_MAX
};

#define IFLA_AVIONICS_MAX	(__IFLA_AVIONICS_MAX - 1)

#endif /* __AVIONICS_H__ */
