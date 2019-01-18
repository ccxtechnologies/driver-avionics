/*
 * linux/arinc429.h
 *
 * Definitions for ARINC429 network layer
 * (socket addr / ARINC429 frame / ARINC429 filter)
 *
 * * Copyright (C) 2015 Marek Vasut <marex@denx.de>
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

#ifndef __UAPI_ARINC429_H__
#define __UAPI_ARINC429_H__

#include <linux/types.h>
#include <linux/socket.h>

/* ARINC429 kernel definitions */

/*
 * ARINC packet:
 *
 * .-.---.------.---.-----.
 * |P|SSM| Data |SDI|Label|
 * '-'---'------'---'-----'
 *  3 3 2 2....1 1 9 8...0
 *  1 0 9 8    1 0
 */

/**
 * struct arinc429_frame - basic ARINC429 frame structure
 * @label:	ARINC429 label
 * @data:	ARINC429 P, SSM, DATA and SDI
 */
struct arinc429_frame {
	__u8	label;		/* 8 bit label */
	__u8	data[3];	/* Up-to 23 bits are valid. */
};

#define ARINC429_MTU		(sizeof(struct arinc429_frame))

/* particular protocols of the protocol family PF_ARINC429 */
#define ARINC429_RAW		1 /* RAW sockets */
#define ARINC429_NPROTO		2

#define SOL_ARINC429_BASE	100

/**
 * struct sockaddr_arinc429 - the sockaddr structure for ARINC429 sockets
 * @arinc429_family:	address family number AF_ARINC429.
 * @arinc429_ifindex:	ARINC429 network interface index.
 * @arinc429_addr:	protocol specific address information
 */
struct sockaddr_arinc429 {
	__kernel_sa_family_t arinc429_family;
	int         arinc429_ifindex;
	union {
		/* reserved for future ARINC429 protocols address information */
	} arinc429_addr;
};

/**
 * struct arinc429_filter - ARINC429 ID based filter in arinc429_register().
 * @arinc429_label: relevant bits of ARINC429 ID which are not masked out.
 * @arinc429_mask:  ARINC429 mask (see description)
 *
 * Description:
 * A filter matches, when
 *
 *          <received_arinc429_id> & mask == arinc429_id & mask
 */
struct arinc429_filter {
	__u8	label;		/* 8 bit label */
	__u8	mask;		/* 8 bit label mask */
#define ARINC429_INV_FILTER	0x00000001
	__u32	flags;		/* Flags */
};

#endif /* __UAPI_ARINC429_H__ */
