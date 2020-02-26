#!/usr/bin/python
# Copyright: 2018, CCX Technologies

import socket
import ctypes
import ctypes.util
import struct
import fcntl

import sys
import os
import errno

AF_AVIONICS = 18
PF_AVIONICS = 18
AVIONICS_RAW = 1

SIOCGIFINDEX = 0x8933

device = sys.argv[1]

# ARINC-717 Word Format (32 bits)
# 0000yyyy yyyyyyyy xxxxxxxx xxxxx0zz
#   where y is the word to write (12 bits)
#   where x is the word count
#   and z if the frame
a717_data = (
    ((1<<16)+(3<<3)+0).to_bytes(4, 'little') +
    ((2<<16)+(3<<3)+1).to_bytes(4, 'little') +
    ((3<<16)+(3<<3)+2).to_bytes(4, 'little')
    )

# ARINC-429 Word Format (32 bits)
# pyyyyyyy yyyyyyyy yyyyyyzz xxxxxxxx
#   where p is the parityh bit
#   where y is the word (21 bit)
#   where z are the SD bits
#   and y are the label bits (bit order dependant on the flip bits setting)
a429_data = (
        (0x01020304).to_bytes(4, 'little')
        )

def error_code_to_str(code):
    try:
        name = errno.errorcode[code]
    except KeyError:
        name = "UNKNOWN"

    try:
        description = os.strerror(code)
    except ValueError:
        description = "no description available"

    return "{} (errno {}): {}".format(name, code, description)


def get_addr(sock, channel):
    data = struct.pack("16si", channel.encode(), 0)
    res = fcntl.ioctl(sock, SIOCGIFINDEX, data)
    idx, = struct.unpack("16xi", res)
    return struct.pack("Hi", AF_AVIONICS, idx)


libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# == create socket ==
with socket.socket(PF_AVIONICS, socket.SOCK_RAW, AVIONICS_RAW) as sock:

    # == bind to interface ==
    # Python doesn't know about PF_ARINC so directly use libc
    addr = get_addr(sock, device)
    err = libc.bind(sock.fileno(), addr, len(addr))
    if err:
        raise OSError(err, "Failed to bind to socket")

    sent = sock.send(a429_data)

    if sent < 0:
        print("Send failed {error_code_to_str(-sent)}")
        if sent == -1:
            print("Is interface up?")
    else:
        print("Sent {sent} bytes.")
