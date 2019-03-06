#!/usr/bin/python
# Copyright: 2019, CCX Technologies

import socket
import ctypes
import ctypes.util
import struct
import fcntl
import collections

import os
import errno
import sys

AF_AVIONICS = 18
PF_AVIONICS = 18
AVIONICS_RAW = 1

SIOCGIFINDEX = 0x8933

# from include/uapi/linux/rtnetlink.h.
RTM_NEWLINK = 16
RTM_GETLINK = 18

# from include/uapi/linux/netlink.h.
NLM_F_REQUEST = 1
NLMSG_DONE = 3

IFLA_LINKINFO = 18

# from include/uapi/linux/if_link.h
IFLA_INFO_DATA = 2

# from avionics.h
IFLA_AVIONICS_RATE = 1
IFLA_AVIONICS_ARINC429RX = 2
IFLA_AVIONICS_ARINC429TX = 3

AVIONICS_ARINC429RX_FLIP_LABEL_BITS = (1<<7)
AVIONICS_ARINC429RX_SD9_MASK = (1<<6)
AVIONICS_ARINC429RX_SD10_MASK = (1<<5)
AVIONICS_ARINC429RX_SD_MASK_ENABLE = (1<<4)
AVIONICS_ARINC429RX_PARITY_CHECK = (1<<3)
AVIONICS_ARINC429RX_LABEL_FILTER_ENABLE = (1<<2)
AVIONICS_ARINC429RX_PRIORITY_LABEL_ENABLE = (1<<1)

device = sys.argv[1]

def get_index(device):
    with socket.socket(PF_AVIONICS, socket.SOCK_RAW, AVIONICS_RAW) as sock:
        data = struct.pack("16si", device.encode(), 0)
        res = fcntl.ioctl(sock, SIOCGIFINDEX, data)
        index, = struct.unpack("16xi", res)
        return index

class CStruct:
    def __init__(self, name, pack, fields):
        self.struct = struct.Struct(pack)
        self.args = collections.namedtuple(name, fields)

    def __len__(self):
        return self.struct.size

    def pack(self, *args, **kwargs):
        _args = self.args(*args, **kwargs)
        return self.struct.pack(*_args)

    def unpack(self, data):
        return self.args._make(self.struct.unpack(data))

    def consume(self, data):
        return data[len(self):], self.unpack(data[:len(self)])

nlmsghdr = CStruct("nlmsghdr", "=LHHLL", ("nlmsg_len", "nlmsg_type", "nlmsg_flags", "nlmsg_seq", "nlmsg_pid"))
ifinfomsg = CStruct("ifinfomsg", "=BxHiII", ("ifi_family", "ifi_type","ifi_index", "ifi_flags", "ifi_change"))
rattr = CStruct("rattr", "=HH", ("rta_len", "rta_type"))

avionics_rate = CStruct("avionics_rate", "=L", ("rate_hz"))
avionics_arinc429rx = CStruct("avionics_arinc429rx", "=Bx3s32s", ("flags", "priority_labels", "label_filters"))

def parse_rtattr(msg):
    attrs = {}
    while msg:
        msg, msgrattr = rattr.consume(msg)

        if msgrattr.rta_len < 4:
            print(f"Invalid rta length {msgrattr.rta_len}")
            break

        increment = ((msgrattr.rta_len + 4 - 1) & ~(4 - 1)) - len(rattr)

        attrs[msgrattr.rta_type] = msg[:msgrattr.rta_len-len(rattr)]

        msg = msg[increment:]

    return attrs

def getlink():
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.bind((os.getpid(), 0))

        index = get_index(device)

        msg = (nlmsghdr.pack(len(nlmsghdr) + len(ifinfomsg), RTM_GETLINK, NLM_F_REQUEST, 0, 0) +
                ifinfomsg.pack(socket.AF_PACKET, 0, index, 0, 0))

        sock.send(msg)

        while True:
            msg = sock.recv(65535)
            msg_len = len(msg)

            msg, msghdr = nlmsghdr.consume(msg)

            if msghdr.nlmsg_len != msg_len:
                print(f"Message truncated! {msghdr.nlmsg_len} != {len(msg)}")
                return

            if msghdr.nlmsg_type != RTM_NEWLINK:
                print(f"Unexpected message type {msghdr.nlmsg_type}")
                return

            msg, msgifinfo = ifinfomsg.consume(msg)

            if msgifinfo.ifi_index != index:
                print(f"Wrong device index: {msgifinfo.ifi_index}")
                return

            return msg

if __name__ == "__main__":

    msg = getlink()

    link_attrs = parse_rtattr(msg)
    link_info = parse_rtattr(link_attrs[IFLA_LINKINFO])
    link_data = parse_rtattr(link_info[IFLA_INFO_DATA])

    rate = avionics_rate.unpack(link_data[IFLA_AVIONICS_RATE])
    print(f"Rate = {rate.rate_hz} Hz")

    config = avionics_arinc429rx.unpack(link_data[IFLA_AVIONICS_ARINC429RX])
    print(f"Flip Label Bits = {bool(config.flags&AVIONICS_ARINC429RX_FLIP_LABEL_BITS)}")
    print(f"SD9 Mask = {bool(config.flags&AVIONICS_ARINC429RX_SD9_MASK)}")
    print(f"SD10 Mask = {bool(config.flags&AVIONICS_ARINC429RX_SD10_MASK)}")
    print(f"SD Mask Enable = {bool(config.flags&AVIONICS_ARINC429RX_SD_MASK_ENABLE)}")
    print(f"Parity Check Enabled = {bool(config.flags&AVIONICS_ARINC429RX_PARITY_CHECK)}")
    print(f"Label Filter Enabled = {bool(config.flags&AVIONICS_ARINC429RX_LABEL_FILTER_ENABLE)}")
    print(f"Priority Labels Enabled = {bool(config.flags&AVIONICS_ARINC429RX_PRIORITY_LABEL_ENABLE)}")
