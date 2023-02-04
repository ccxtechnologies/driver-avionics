#!/usr/bin/python
# Copyright: 2023, CCX Technologies

import sys
import os

import socket
import ctypes
import struct
import fcntl

# ===== from linux/rtnetlink.h ========
RTM_NEWLINK = 16
RTM_GETLINK = 18


class ifinfomsg(ctypes.Structure):
    _fields_ = [
            ('ifi_family', ctypes.c_ubyte),
            ('__ifi_pad', ctypes.c_ubyte),
            ('ifi_type', ctypes.c_ushort),
            ('ifi_index', ctypes.c_int),
            ('ifi_flags', ctypes.c_uint),
            ('ifi_change', ctypes.c_uint),
    ]


class rtattr(ctypes.Structure):
    _fields_ = [
            ('rta_len', ctypes.c_ushort),
            ('rta_type', ctypes.c_ushort),
    ]


# ===== from linux/netlink.h ==========

NLM_F_REQUEST = 1
NLM_F_ACK = 4

NLMSG_ERROR = 2
NLMSG_DONE = 3

IFLA_LINKINFO = 18


class nlmsghdr(ctypes.Structure):
    _fields_ = [
            ('nlmsg_len', ctypes.c_uint32),
            ('nlmsg_type', ctypes.c_uint16),
            ('nlmsg_flags', ctypes.c_uint16),
            ('nlmsg_seq', ctypes.c_uint32),
            ('nlmsg_pid', ctypes.c_uint32),
    ]


class nlmsgerr(ctypes.Structure):
    _fields_ = [
            ('error', ctypes.c_int),
            ('msg', nlmsghdr),
    ]


# ===== from linux/if_link.h ==========

IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2

# ===== from linux/if.h ===============

IFF_UP = 1

# ===== from linux/socket.h ===========

AF_ASH = 18

# ===== from linux/sockios.h ==========

SIOCGIFINDEX = 0x8933

# ===== from avionics.h ===============

AF_AVIONICS = AF_ASH
PF_AVIONICS = AF_AVIONICS

AVIONICS_PROTO_RAW = 1
AVIONICS_PROTO_TIMESTAMP = 2
AVIONICS_PROTO_PACKET = 3

AVIONICS_ARINC429RX_FLIP_LABEL_BITS = (1 << 7)
AVIONICS_ARINC429RX_SD9_MASK = (1 << 6)
AVIONICS_ARINC429RX_SD10_MASK = (1 << 5)
AVIONICS_ARINC429RX_SD_MASK_ENABLE = (1 << 4)
AVIONICS_ARINC429RX_PARITY_CHECK = (1 << 3)
AVIONICS_ARINC429RX_LABEL_FILTER_ENABLE = (1 << 2)
AVIONICS_ARINC429RX_PRIORITY_LABEL_ENABLE = (1 << 1)
AVIONICS_ARINC429RX_EVEN_PARITY = (1 << 0)

AVIONICS_ARINC429TX_FLIP_LABEL_BITS = (1 << 6)
AVIONICS_ARINC429TX_SELF_TEST = (1 << 4)
AVIONICS_ARINC429TX_EVEN_PARITY = (1 << 3)
AVIONICS_ARINC429TX_PARITY_SET = (1 << 2)

AVIONICS_ARINC717RX_BPRZ = (1 << 0)
AVIONICS_ARINC717RX_NOSYNC = (1 << 1)
AVIONICS_ARINC717RX_SFTSYNC = (1 << 2)

AVIONICS_ARINC717TX_SLEW = (3 << 1)
AVIONICS_ARINC717TX_SELF_TEST = (1 << 0)

IFLA_AVIONICS_RATE = 1
IFLA_AVIONICS_ARINC429RX = 2
IFLA_AVIONICS_ARINC429TX = 3
IFLA_AVIONICS_ARINC717RX = 4
IFLA_AVIONICS_ARINC717TX = 5
IFLA_AVIONICS_MIL1553MB = 5


class avionics_rate(ctypes.Structure):
    _fields_ = [
            ('rate_hz', ctypes.c_uint32),
    ]


class avionics_arinc429rx(ctypes.Structure):
    _fields_ = [
            ('flags', ctypes.c_uint8),
            ('padding', ctypes.c_uint8),
            ('priority_labels', ctypes.c_uint8 * 3),
            ('label_filters', ctypes.c_uint8 * 32),
    ]


class avionics_arinc429tx(ctypes.Structure):
    _fields_ = [
            ('flags', ctypes.c_uint8),
            ('padding', ctypes.c_uint8 * 3),
    ]


# =====================================


def net_device_get_index(sock, ifname):
    # get device index from ifname using ioctl call
    idx, = struct.unpack(
            "16xi",
            fcntl.ioctl(
                    sock, SIOCGIFINDEX,
                    struct.pack("16si", ifname.encode(), 0)
            )
    )

    return idx


def _parse_rtattr(message):
    attrs = {}
    while message:
        rta = rtattr.from_buffer_copy(message[:ctypes.sizeof(rtattr)])
        message = message[ctypes.sizeof(rtattr):]

        if rta.rta_len < 4:
            print(f"Error: Invalid rta length {rta.rta_len}")
            exit(1)

        increment = ((rta.rta_len + 4 - 1) & ~(4 - 1)) - ctypes.sizeof(rtattr)

        attrs[rta.rta_type] = message[:rta.rta_len - ctypes.sizeof(rtattr)]

        message = message[increment:]

    return attrs


def link_data_from_msg(message):
    link_attrs = _parse_rtattr(message)
    link_info = _parse_rtattr(link_attrs[IFLA_LINKINFO])
    link_data = _parse_rtattr(link_info[IFLA_INFO_DATA])

    return link_data


# =====================================


def exit_help():
    print("==== avionics-config-get.py ====")
    print("Error: invalid command line arguments")
    print("== requires two command line arguments, device type, device name")
    print("== example: avionics-config-get.py a429rx arinc429rx0")
    exit(1)


if __name__ == "__main__":

    if len(sys.argv) != 3:
        exit_help()

    device_type = sys.argv[1]
    device_name = sys.argv[2]

    print("==== avionics-config-get.py ====")
    print(f"-- getting {device_type} config from {device_name}")

    with socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE
    ) as sk:
        sk.bind((os.getpid(), 0))

        device_index = net_device_get_index(sk, device_name)

        header = nlmsghdr(
                ctypes.sizeof(nlmsghdr) + ctypes.sizeof(ifinfomsg),
                RTM_GETLINK, NLM_F_REQUEST, 0, os.getpid()
        )

        packet = ifinfomsg(socket.AF_PACKET, 0, 0, device_index, 0, 0)

        sk.send(bytes(header) + bytes(packet))
        msg = sk.recv(65535)

        header = nlmsghdr.from_buffer_copy(msg[:ctypes.sizeof(nlmsghdr)])

        if (header.nlmsg_len != len(msg)):
            print(
                    "Error: incorrect message"
                    f" length {header.nlmsg_len}, {len(msg)}"
            )
            exit(1)

        msg = msg[ctypes.sizeof(nlmsghdr):]

        if header.nlmsg_type != RTM_NEWLINK:
            print(f"Error: Unexpected message type {header.nlmsg_type}")
            exit(1)

        ifinfo = ifinfomsg.from_buffer_copy(msg[:ctypes.sizeof(ifinfomsg)])
        msg = msg[ctypes.sizeof(ifinfomsg):]

        if ifinfo.ifi_index != device_index:
            print(f"Error: Wrong device index: {ifinfo.ifi_index}")
            exit(1)

        data = link_data_from_msg(msg)

        rate = avionics_rate.from_buffer_copy(data[IFLA_AVIONICS_RATE])
        print(f"Rate = {rate.rate_hz} Hz")

        if device_type == "a429rx":
            if IFLA_AVIONICS_ARINC429RX not in data:
                print(
                        "Error: a429rx configuration info not returned,"
                        " device type may be wrong"
                )
                exit(1)

            config = avionics_arinc429rx.from_buffer_copy(
                    data[IFLA_AVIONICS_ARINC429RX]
            )

            flip_label = config.flags & AVIONICS_ARINC429RX_FLIP_LABEL_BITS
            sd9_mask = config.flags & AVIONICS_ARINC429RX_FLIP_LABEL_BITS
            sd10_mask = config.flags & AVIONICS_ARINC429RX_SD10_MASK
            sd_mask_enable = config.flags & AVIONICS_ARINC429RX_SD_MASK_ENABLE
            parity_check = config.flags & AVIONICS_ARINC429RX_PARITY_CHECK
            even_parity = config.flags & AVIONICS_ARINC429RX_EVEN_PARITY
            filter_enabled = \
                config.flags & AVIONICS_ARINC429RX_LABEL_FILTER_ENABLE
            priority_enabled = \
                config.flags & AVIONICS_ARINC429RX_PRIORITY_LABEL_ENABLE
            priority_labels = list(bytes(config.priority_labels))
            label_filters = list(bytes(config.label_filters))

            print(f"Flip Label Bits = {bool(flip_label)}")

            print(f"SD9 Mask = {bool(sd9_mask)}")
            print(f"SD10 Mask = {bool(sd10_mask)}")
            print(f"SD Mask Enable = {bool(sd_mask_enable)}")
            print(f"Parity Check Enabled = {bool(parity_check)}")
            print(f"Even Parity = {bool(even_parity)}")
            print(f"Label Filter Enabled = {bool(filter_enabled)}")
            print(f"Priority Labels Enabled = {bool(priority_enabled)}")
            print(f"Priority Labels = {priority_labels}")
            print(f"Label Filters = {label_filters}")

        elif device_type == "a429tx":
            if IFLA_AVIONICS_ARINC429TX not in data:
                print(
                        "Error: a429tx configuration info not returned,"
                        " device type may be wrong"
                )
                exit(1)

            config = avionics_arinc429tx.from_buffer_copy(
                    data[IFLA_AVIONICS_ARINC429TX]
            )

            flip_label = config.flags & AVIONICS_ARINC429TX_FLIP_LABEL_BITS
            self_test = config.flags & AVIONICS_ARINC429TX_SELF_TEST
            even_parity = config.flags & AVIONICS_ARINC429TX_EVEN_PARITY
            set_parity = config.flags & AVIONICS_ARINC429TX_PARITY_SET

            print(f"Flip Label Bits = {bool(flip_label)}")
            print(f"Self Test = {bool(self_test)}")
            print(f"Even Parity = {bool(even_parity)}")
            print(f"Set Parity = {bool(set_parity)}")

        elif device_type == "m1553mb":
            if IFLA_AVIONICS_MIL1553MB not in data:
                print(
                        "Error: m1553mb configuration info not returned,"
                        " device type may be wrong"
                )
                exit(1)

        else:
            print(
                    f"Error: unknown device type {device_type},"
                    " expecting a429rx, a429tx, or m1553mb"
            )
            exit(1)

    print("===============================")
