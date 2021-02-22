#!/usr/bin/python
# Copyright: 2019-2021, CCX Technologies

import socket
import ctypes
import ctypes.util
import struct
import fcntl
import sys
import datetime

AF_AVIONICS = 18
PF_AVIONICS = 18
AVIONICS_RAW = 1
AVIONICS_TIMESTAMP = 2

SIOCGIFINDEX = 0x8933

device = sys.argv[1]
proto = (AVIONICS_TIMESTAMP if ((len(sys.argv) >= 3) and (sys.argv[2] == "timestamp")) else AVIONICS_RAW)

def get_addr(sock, channel):
    data = struct.pack("16si", channel.encode(), 0)
    res = fcntl.ioctl(sock, SIOCGIFINDEX, data)
    idx, = struct.unpack("16xi", res)
    return struct.pack("Hi", AF_AVIONICS, idx)


libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

last_word = 0
last_count = 0
last_frame = 0


def print_a717(value):
    # ARINC-717 Word Format
    # 0000yyyy yyyyyyyy xxxxxxxx xxxxx0zz
    #   where y is the word to write (12 bits)
    #   where x is the word count
    #   and z if the frame

    global last_count
    global last_frame
    global last_word

    word = (value & 0x0fff0000) >> 16
    count = (value & 0x0000fff8) >> 3
    frame = (value & 0x3)

    if (count != last_count + 1) and (frame != (last_frame + 1) % 4):
        print(f"==> 0x{last_word:03X} -- {last_count} -- {last_frame}")
        print(f"--> 0x{word:03X} -- {count} -- {frame}")

    last_word = word
    last_count = count
    last_frame = frame

    if word:
        print(f"~~> 0x{word:03X} -- {count} -- {frame}")


# == create socket ==
with socket.socket(PF_AVIONICS, socket.SOCK_RAW, proto) as sock:

    # == bind to interface ==
    # Python doesn't know about PF_ARINC so directly use libc
    addr = get_addr(sock, device)
    err = libc.bind(sock.fileno(), addr, len(addr))

    if err:
        raise OSError(err, "Failed to bind to socket")

    # == receive data example ==
    print(f"Receiver started: {datetime.datetime.utcnow()}")
    while True:
        recv = sock.recv(4096)
        print(f"Received: {len(recv)} bytes")
        if proto == AVIONICS_RAW:
            data = [
                    int.from_bytes(recv[i:i + 4], "little")
                    for i in range(0, len(recv), 4)
            ]

            for d in data:
                print(f"0x{d:08X}")

        elif proto == AVIONICS_TIMESTAMP:
            data = [
                    (int.from_bytes(recv[i:i + 8], "little"),
                    int.from_bytes(recv[i+8:i + 12], "little"))
                    for i in range(0, len(recv), 12)
            ]

            for ts, d in data:
                timestamp = datetime.datetime.fromtimestamp(ts/1000)
                print(f"{timestamp.isoformat()}: 0x{d:08X}")
