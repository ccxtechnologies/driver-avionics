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
	__u32 rate_hz;
};

#define AVIONICS_ARINC429RX_FLIP_LABEL_BITS		(1<<7)
#define AVIONICS_ARINC429RX_SD9_MASK			(1<<6)
#define AVIONICS_ARINC429RX_SD10_MASK			(1<<5)
#define AVIONICS_ARINC429RX_SD_MASK_ENABLE		(1<<4)
#define AVIONICS_ARINC429RX_PARITY_CHECK		(1<<3)
#define AVIONICS_ARINC429RX_LABEL_FILTER_ENABLE		(1<<2)
#define AVIONICS_ARINC429RX_PRIORITY_LABEL_ENABLE	(1<<1)
#define AVIONICS_ARINC429RX_EVEN_PARITY			(1<<0)

struct avionics_arinc429rx {
	__u8 flags;
	__u8 padding;
	__u8 priority_labels[3];
	__u8 label_filters[32]; /* one bit per label, starting at 0xFF */
};

#define AVIONICS_ARINC429TX_FLIP_LABEL_BITS	(1<<6)
#define AVIONICS_ARINC429TX_SELF_TEST		(1<<4)
#define AVIONICS_ARINC429TX_EVEN_PARITY		(1<<3)
#define AVIONICS_ARINC429TX_PARITY_SET		(1<<2)

struct avionics_arinc429tx {
	__u8 flags;
	__u8 padding[3];
};

enum {
	IFLA_AVIONICS_UNSPEC,
	IFLA_AVIONICS_RATE,
	IFLA_AVIONICS_ARINC429RX,
	IFLA_AVIONICS_ARINC429TX,
	__IFLA_AVIONICS_MAX
};

#define IFLA_AVIONICS_MAX	(__IFLA_AVIONICS_MAX - 1)

#endif /* __AVIONICS_H__ */
