#!/usr/bin/python
# Copyright: 2018-2021, CCX Technologies

import socket
import ctypes
import ctypes.util
import struct
import fcntl
import time

import sys
import os
import errno

AF_AVIONICS = 18
PF_AVIONICS = 18
AVIONICS_RAW = 1
AVIONICS_TIMESTAMP = 2

SIOCGIFINDEX = 0x8933

device = sys.argv[1]
proto = (AVIONICS_TIMESTAMP if ((len(sys.argv) >= 3) and (sys.argv[2] == "timestamp")) else AVIONICS_RAW)

# ARINC-717 Word Format (32 bits)
# 0000yyyy yyyyyyyy xxxxxxxx xxxxx0zz
#   where y is the word to write (12 bits)
#   where x is the word count
#   and z if the frame
a717_data_raw = (
    ((1<<16)+(2<<3)+0).to_bytes(4, 'little') +
    ((5<<16)+(3<<3)+0).to_bytes(4, 'little') +
    ((7<<16)+(4<<3)+0).to_bytes(4, 'little')
    )

# ARINC-429 Word Format (32 bits)
# pyyyyyyy yyyyyyyy yyyyyyzz xxxxxxxx
#   where p is the parityh bit
#   where y is the word (21 bit)
#   where z are the SD bits
#   and y are the label bits (bit order dependant on the flip bits setting)
a429_data_raw = (
        (0x01020304).to_bytes(4, 'little') +
        (0x80000008).to_bytes(4, 'little') +
        (0xffffffff).to_bytes(4, 'little') +
        (0x00000000).to_bytes(4, 'little')
        )

time_msecs = int((time.time()+2)*1000)
a429_data_timestamp = (
        (time_msecs).to_bytes(8, 'little') +
        (0xf1020304).to_bytes(4, 'little') +
        (time_msecs+100).to_bytes(8, 'little') +
        (0xf0000008).to_bytes(4, 'little') +
        (time_msecs+2100).to_bytes(8, 'little') +
        (0x0fffffff).to_bytes(4, 'little') +
        (time_msecs+4101).to_bytes(8, 'little') +
        (0xf0000000).to_bytes(4, 'little')
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
with socket.socket(PF_AVIONICS, socket.SOCK_RAW, proto) as sock:

    # == bind to interface ==
    # Python doesn't know about PF_ARINC so directly use libc
    addr = get_addr(sock, device)
    err = libc.bind(sock.fileno(), addr, len(addr))
    if err:
        raise OSError(err, "Failed to bind to socket")

    if proto == AVIONICS_RAW:
        if "arinc429" in device:
            sent = sock.send(a429_data_raw)
        elif "arinc717" in device:
            sent = sock.send(a717_data_raw)

    elif proto == AVIONICS_TIMESTAMP:
        print(time_msecs)
        sent = sock.send(a429_data_timestamp)

    if sent < 0:
        print(f"Send failed {error_code_to_str(-sent)}")
        if sent == -1:
            print("Is interface up?")
    else:
        print(f"Sent {sent} bytes.")
