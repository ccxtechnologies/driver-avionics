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
NLM_F_ACK = 4

NLMSG_ERROR = 2
NLMSG_DONE = 3

IFLA_LINKINFO = 18

# from include/uapi/linux/if_link.h
IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2

# from avionics.h
IFLA_AVIONICS_RATE = 1

# from include/uapi/linux/if.h
IFF_UP = 1

device = sys.argv[1]

def get_index(device):
    with socket.socket(PF_AVIONICS, socket.SOCK_RAW, AVIONICS_RAW) as sock:
        data = struct.pack("16si", device.encode(), 0)
        res = fcntl.ioctl(sock, SIOCGIFINDEX, data)
        index, = struct.unpack("16xi", res)
        print(f"Device {device} index is {index}.")
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
nlmsgerr = CStruct("nlmsgerr", "=i", ("error"))
ifinfomsg = CStruct("ifinfomsg", "=BBHiII", ("ifi_family", "ifi_padding", "ifi_type","ifi_index", "ifi_flags", "ifi_change"))
rattr = CStruct("rattr", "=HH", ("rta_len", "rta_type"))

avionics_rate = CStruct("avionics_rate", "=L", ("rate_hz"))

def setlink(rate):
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.bind((os.getpid(), 0))

        index = get_index(device)

        kind = b"avionics\x00\x00\x00\x00"

        set_rate = rattr.pack(len(rattr) + len(avionics_rate), IFLA_AVIONICS_RATE) + avionics_rate.pack(rate)
        info_data = rattr.pack(len(rattr) + len(set_rate), IFLA_INFO_DATA) + set_rate

        info_kind = rattr.pack(len(rattr) + len(kind), IFLA_INFO_KIND) + kind

        command = rattr.pack(len(rattr) + len(info_kind) + len(info_data), IFLA_LINKINFO) + info_kind + info_data

        msg = (nlmsghdr.pack(len(nlmsghdr) + len(ifinfomsg) + len(command), RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 0, 0) +
                ifinfomsg.pack(0, 0, 0, index, IFF_UP, IFF_UP) + command)

        sock.send(msg)

        while True:
            msg = sock.recv(65535)
            msg_len = len(msg)

            msg, msghdr = nlmsghdr.consume(msg)

            print(msghdr)

            if msghdr.nlmsg_len != msg_len:
                print(f"Message truncated! {msghdr.nlmsg_len} != {len(msg)}")
                return

            if msghdr.nlmsg_type == NLMSG_ERROR:
                msg, msgerr = nlmsgerr.consume(msg)
                msg, msgerrhdr = nlmsghdr.consume(msg)

                print(f"Error: {msgerr} from {msgerrhdr}")

                return

            msg, msgifinfo = ifinfomsg.consume(msg)

            print(msgifinfo)

            return msg

if __name__ == "__main__":

    msg = setlink(int(sys.argv[2]))

    print(msg)
