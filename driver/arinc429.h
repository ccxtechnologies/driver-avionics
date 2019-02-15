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

#ifndef __ARINC429_H__
#define __ARINC429_H__

#include <linux/types.h>
#include <linux/socket.h>

/************************************************************************
 * CCX: This is an ugly hack so that we can build this out of tree without
 * patching the kernel, delete it and create new definions in the propper
 * place if this is ever pulled into your kernel. */

/* should be in include/linux/socket.h, and should have it's own
 * index, not stealing from Ash (which is unused) */
#ifndef AF_ARINC429
#define AF_ARINC429	AF_ASH
#endif

/* should be in include/linux/socket.h, and should have it's own
 * index, not stealing from Ash (which is unused) */
#ifndef PF_ARINC429
#define PF_ARINC429	AF_ARINC429
#endif

/* should be in include/uapi/linux/if_arp.h */
#ifndef ARPHRD_ARINC429
#define ARPHRD_ARINC429	281
#endif

/* should be in include/uapi/linux/if_ether.h */
#ifndef ETH_P_ARINC429
#define ETH_P_ARINC429	0x001D
#endif

/************************************************************************/

#define ARINC429_PROTO_RAW	1

union arinc429_word {
	__u32 raw;
	struct {
		__u32 label:8;
		__u32 sdi:2;
		__u32 data:21;
		__u32 parity:1;
	} fmt;
};

#define ARINC429_WORD_SIZE	(sizeof(union arinc429_word))

struct sockaddr_arinc429 {
	__kernel_sa_family_t arinc429_family;
	int arinc429_ifindex;
	union {
		/* reserved for future prototcols */
	} arinc429_addr;
};

#endif /* __ARINC429_H__ */
