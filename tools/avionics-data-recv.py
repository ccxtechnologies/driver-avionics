#!/usr/bin/python
# Copyright: 2023, CCX Technologies

import sys
import os

import socket
import ctypes.util
import ctypes
import struct
import fcntl

# ===== from linux/socket.h =====

AF_ASH = 18

# ===== from linux/sockios.h ====

SIOCGIFINDEX = 0x8933

# ===== from avionics.h =========

AF_AVIONICS = AF_ASH
PF_AVIONICS = AF_AVIONICS

AVIONICS_PROTO_RAW = 1
AVIONICS_PROTO_TIMESTAMP = 2
AVIONICS_PROTO_PACKET = 3


class avionics_proto_timestamp_data(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
            ('time_msecs', ctypes.c_int64),
            ('value', ctypes.c_uint32),
    ]


class avionics_proto_packet_data(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
            ('time_msecs', ctypes.c_int64),
            ('status', ctypes.c_uint32),
            ('count', ctypes.c_uint64),
            ('width', ctypes.c_uint8),
            ('length', ctypes.c_uint8),
    ]


# ===============================


def net_device_set_up(ifname):
    result = os.system(f"ip link set dev {ifname}")

    if (result == 256) and ("lb" in ifname):
        print(f"-- loop-back device {ifname} doesn't exists, creating")
        if os.system(f"ip link add dev {ifname} type avionics-lb"):
            print(f"Error: failed to create avionics-lb device {ifname}")
            exit(result)
        else:
            if os.system(f"ip link set dev {ifname}"):
                print(f"Error: failed to set avionics-lb {ifname} up")
                exit(1)
            else:
                print(f"-- set avionics-lb device {ifname} up")
    elif result:
        print(f"Error: failed to set {ifname} up")
        exit(result)

    else:
        print(f"-- set device {ifname} up")


def avionics_protcol_get(pname):
    if pname == "raw8":
        return AVIONICS_PROTO_RAW
    elif pname == "raw16":
        return AVIONICS_PROTO_RAW
    elif pname == "raw32":
        return AVIONICS_PROTO_RAW
    elif pname == "timestamp":
        return AVIONICS_PROTO_TIMESTAMP
    elif pname == "packet":
        return AVIONICS_PROTO_PACKET
    else:
        print(f"Error: invalid protocol name {pname}")
        print("must be: raw8, raw16, raw32, timestamp, or packet")
        exit(1)


def avionics_addr(sock, ifname):
    # get device index from ifname using ioctl call
    idx, = struct.unpack(
            "16xi",
            fcntl.ioctl(
                    sock, SIOCGIFINDEX,
                    struct.pack("16si", ifname.encode(), 0)
            )
    )

    return struct.pack("Hi", AF_AVIONICS, idx)


def exit_help():
    print("==== avionics-data-recv.py ====")
    print("Error: invalid command line arguments")
    print(
            "== requires three command line arguments, protocol,"
            " device name and output file"
    )
    print("== example: avionics-data-recv.py raw16 avionics-lb0 data.bin")
    exit(1)


# ===========================

if __name__ == "__main__":

    if len(sys.argv) != 4:
        exit_help()

    protocol_name = sys.argv[1]
    device_name = sys.argv[2]
    file_name = sys.argv[3]

    print("==== avionics-data-recv.py ====")

    net_device_set_up(device_name)

    with socket.socket(
            PF_AVIONICS, socket.SOCK_RAW, avionics_protcol_get(protocol_name)
    ) as sk:

        # Python doesn't support PF_AVIONICS so directly use libc
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        addr = avionics_addr(sk, device_name)
        err = libc.bind(sk.fileno(), addr, len(addr))

        if err:
            print(f"Error: failed to bind to socket: {err}")
            exit(err)

        print(
                f"-- Starting Receiver on {device_name}"
                f" with protocol {protocol_name} --"
        )

        with open(file_name, 'wb') as fo:
            while True:
                data = sk.recv(4096)
                print(f"+++ Received: {len(data)} bytes +++")
                fo.write(data)

                if protocol_name == "raw8":
                    for i in range(0, len(data), 1):
                        d = int.from_bytes(data[i:i + 1], "little")
                        print(f"{i:08d}: 0x{d:02x}")

                elif protocol_name == "raw16":
                    for i in range(0, len(data), 2):
                        d = int.from_bytes(data[i:i + 2], "little")
                        print(f"{i:08d}: 0x{d:04x}")

                elif protocol_name == "raw32":
                    for i in range(0, len(data), 4):
                        d = int.from_bytes(data[i:i + 4], "little")
                        print(f"{i:08d}: 0x{d:08x}")

                elif protocol_name == "timestamp":
                    data_size = ctypes.sizeof(avionics_proto_timestamp_data)
                    print(data_size)
                    for i in range(0, len(data), data_size):
                        d = avionics_proto_timestamp_data.from_buffer_copy(
                                data[i:i + data_size]
                        )
                        print(f"{i:08d}: {d.time_msecs} 0x{d.value:08x}")

    print("===============================")
