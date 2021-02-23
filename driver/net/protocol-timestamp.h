/*
 * Copyright (C) 2020, CCX Technologies
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

#ifndef __AVIONICS_PROTOCOL_TIMESTAMP_H__
#define __AVIONICS_PROTOCOL_TIMESTAMP_H__

const struct proto_ops* protocol_timestamp_get_ops(void);
struct proto* protocol_timestamp_get(void);

int protocol_timestamp_register(void);
void protocol_timestamp_unregister(void);

#endif /* __AVIONICS_PROTOCOL_TIMESTAMP_H__ */
