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
    """Get sockaddr for a channel."""
    if channel:
        data = struct.pack("16si", channel.encode(), 0)
        res = fcntl.ioctl(sock, SIOCGIFINDEX, data)
        idx, = struct.unpack("16xi", res)
    else:
        # All channels
        idx = 0
    return struct.pack("HiLL", AF_ARINC429, idx, 0, 0)

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# == create socket ==
sock = socket.socket(PF_ARINC429, socket.SOCK_RAW, ARINC429_RAW)

# == bind to interface ==
# Python doesn't know about PF_ARINC so directly use libc
addr = get_addr(sock, "varinc0")
libc.bind(sock.fileno(), addr, len(addr))

# == send data example ==
sent = sock.send(bytes(4))
if sent < 0:
    print(f"Send failed {error_code_to_str(-sent)}")
    if sent == -1:
        print("Is interface up?")
else:
    print(f"Sent {sent} bytes.")

sock.close()
