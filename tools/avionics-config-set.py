#!/usr/bin/python
# Copyright: 2023, CCX Technologies

import sys
import os

import socket
import ctypes
import struct
import fcntl

import json

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


def get_device_config(ifname):
    with socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE
    ) as sk:
        sk.bind((os.getpid(), 0))

        device_index = net_device_get_index(sk, ifname)

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

        return link_data_from_msg(msg)


def set_device_config(ifname, config):
    with socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE
    ) as sk:
        sk.bind((os.getpid(), 0))

        index = net_device_get_index(sk, ifname)

        info_data = bytes(
                rtattr(ctypes.sizeof(rtattr) + len(config), IFLA_INFO_DATA)
        ) + config

        kind = b"avionics\x00\x00\x00\x00"
        info_kind = bytes(
                rtattr(ctypes.sizeof(rtattr) + len(kind), IFLA_INFO_KIND)
        ) + kind

        command = bytes(
                rtattr(
                        ctypes.sizeof(rtattr) + len(info_kind) +
                        len(info_data), IFLA_LINKINFO
                )
        ) + info_kind + info_data

        sk.send(
                bytes(
                        nlmsghdr(
                                ctypes.sizeof(nlmsghdr) +
                                ctypes.sizeof(ifinfomsg) +
                                len(command), RTM_NEWLINK, NLM_F_REQUEST
                                | NLM_F_ACK, 0, 0
                        )
                ) + bytes(ifinfomsg(0, 0, 0, index, IFF_UP, IFF_UP)) + command
        )

        msg = sk.recv(65535)

        header = nlmsghdr.from_buffer_copy(msg[:ctypes.sizeof(nlmsghdr)])

        if (header.nlmsg_len != len(msg)):
            print(
                    "Error: incorrect message"
                    f" length {header.nlmsg_len}, {len(msg)}"
            )
            exit(1)

        msg = msg[ctypes.sizeof(nlmsghdr):]

        if header.nlmsg_type == NLMSG_ERROR:
            msgerr = nlmsgerr.from_buffer_copy(msg[:ctypes.sizeof(nlmsgerr)])

            if msgerr.error:
                print(f"Error: {msgerr.error} from {msgerr.msg.nlmsg_type}")

            exit(1)


def str_to_flag(string, flg, mask):
    if string in ("true", "True", "1", "yes", "enable"):
        return flg | mask
    return flg & ~(mask)


# =====================================


def exit_help():
    print("==== avionics-config-get.py ====")
    print("Error: invalid command line arguments")
    print(
            "== requires three command line arguments, device name,"
            " setting name, setting value"
    )
    print("== example: avionics-config-set.py arinc429rx0 flip-label true")
    exit(1)


if __name__ == "__main__":

    if len(sys.argv) != 4:
        exit_help()

    device_name = sys.argv[1]
    setting_name = sys.argv[2]
    setting_value = sys.argv[3]

    print("==== avionics-config-set.py ====")
    print(
            f"-- setting config in {device_name}:"
            f" {setting_name} to {setting_value}"
    )

    data = get_device_config(device_name)

    if setting_name == "rate-hz":
        rate = avionics_rate.from_buffer_copy(data[IFLA_AVIONICS_RATE])
        if rate.rate_hz == int(setting_value):
            exit(0)

        cfg = bytes(
                rtattr(
                        ctypes.sizeof(rtattr) + ctypes.sizeof(avionics_rate),
                        IFLA_AVIONICS_RATE
                )
        ) + bytes(avionics_rate(int(setting_value)))

    elif IFLA_AVIONICS_ARINC429RX in data:
        rx_config = avionics_arinc429rx.from_buffer_copy(
                data[IFLA_AVIONICS_ARINC429RX]
        )

        flags = rx_config.flags
        priority_labels = rx_config.priority_labels
        label_filters = rx_config.label_filters

        if setting_name == "flip-label":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429RX_FLIP_LABEL_BITS
            )

        elif setting_name == "sd9-mask":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429RX_SD9_MASK
            )
        elif setting_name == "sd10-mask":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429RX_SD10_MASK
            )
        elif setting_name == "sd-mask-enabled":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429RX_SD_MASK_ENABLE
            )
        elif setting_name == "parity-check-enabled":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429RX_PARITY_CHECK
            )
        elif setting_name == "even-parity":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429RX_EVEN_PARITY
            )
        elif setting_name == "filters-enabled":
            flags = str_to_flag(
                    setting_value, flags,
                    AVIONICS_ARINC429RX_LABEL_FILTER_ENABLE
            )
        elif setting_name == "priority-enabled":
            flags = str_to_flag(
                    setting_value, flags,
                    AVIONICS_ARINC429RX_PRIORITY_LABEL_ENABLE
            )
        elif setting_name == "priority-labels":
            label_def = ctypes.c_uint8 * 3
            priority_labels = label_def.from_buffer_copy(
                    bytes(json.loads(setting_value))
            )
        elif setting_name == "label-filters":
            label_def = ctypes.c_uint8 * 32
            label_filters = label_def.from_buffer_copy(
                    bytes(json.loads(setting_value))
            )
        else:
            print(
                    f"Error: {setting_name} is not a valid"
                    " setting for an ARINC-429 RX interface"
            )
            exit(1)

        cfg = bytes(
                rtattr(
                        ctypes.sizeof(rtattr) +
                        ctypes.sizeof(avionics_arinc429rx),
                        IFLA_AVIONICS_ARINC429RX
                )
        ) + bytes(
                avionics_arinc429rx(flags, 0, priority_labels, label_filters)
        )

    elif IFLA_AVIONICS_ARINC429TX in data:
        tx_config = avionics_arinc429tx.from_buffer_copy(
                data[IFLA_AVIONICS_ARINC429TX]
        )

        flags = tx_config.flags

        if setting_name == "flip-label":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429TX_FLIP_LABEL_BITS
            )
        elif setting_name == "self-test":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429TX_SELF_TEST
            )
        elif setting_name == "even-parity":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429TX_EVEN_PARITY
            )
        elif setting_name == "set-parity":
            flags = str_to_flag(
                    setting_value, flags, AVIONICS_ARINC429TX_PARITY_SET
            )
        else:
            print(
                    f"Error: {setting_name} is not a valid"
                    " setting for an ARINC-429 TX interface"
            )
            exit(1)

        padding_def = ctypes.c_uint8 * 3
        cfg = bytes(
                rtattr(
                        ctypes.sizeof(rtattr) +
                        ctypes.sizeof(avionics_arinc429tx),
                        IFLA_AVIONICS_ARINC429TX
                )
        ) + bytes(avionics_arinc429tx(flags, padding_def()))

    elif IFLA_AVIONICS_MIL1553MB in data:
        print(
                f"Error: {setting_name} is not a valid"
                " setting for an MIL-1553 MB interface"
        )
        exit(1)

    set_device_config(device_name, cfg)

    print("===============================")
