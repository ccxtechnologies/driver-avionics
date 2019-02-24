#!/usr/bin/python
# Copyright: 2018, CCX Technologies

import socket
import ctypes
import ctypes.util
import struct
import fcntl

import os
import errno

AF_AVIONICS = 18
PF_AVIONICS = 18
AVIONICS_RAW = 1

SIOCGIFINDEX = 0x8933

device = "avionics-lb0"

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
sock = socket.socket(PF_AVIONICS, socket.SOCK_RAW, AVIONICS_RAW)

# == bind to interface ==
# Python doesn't know about PF_ARINC so directly use libc
addr = get_addr(sock, device)
err = libc.bind(sock.fileno(), addr, len(addr))
if err:
    raise OSError(err, "Failed to bind to socket")

# == send data example ==
sent = sock.send(bytes((0x01,0x02,0x03,0x04)))
if sent < 0:
    print(f"Send failed {error_code_to_str(-sent)}")
    if sent == -1:
        print("Is interface up?")
else:
    print(f"Sent {sent} bytes.")

sock.close()
