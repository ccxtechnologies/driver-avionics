#!/usr/bin/python
# Copyright: 2019, CCX Technologies

import socket
import ctypes
import ctypes.util
import struct
import fcntl

import os
import errno

AF_ARINC429 = 18
PF_ARINC429 = 18
ARINC429_RAW = 1

SIOCGIFINDEX = 0x8933

def get_addr(sock, channel):
    data = struct.pack("16si", channel.encode(), 0)
    res = fcntl.ioctl(sock, SIOCGIFINDEX, data)
    idx, = struct.unpack("16xi", res)
    return struct.pack("HiLL", AF_ARINC429, idx, 0, 0)

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# == create socket ==
sock = socket.socket(PF_ARINC429, socket.SOCK_RAW, ARINC429_RAW)

# == bind to interface ==
# Python doesn't know about PF_ARINC so directly use libc
addr = get_addr(sock, "varinc0")
libc.bind(sock.fileno(), addr, len(addr))

# == receive data example ==
recv = sock.recv(4)
print(recv)

sock.close()
