#!/usr/bin/python
# Copyright: 2019-2021, CCX Technologies

import socket
import struct
import fcntl
import collections

import os

AF_AVIONICS = 18
PF_AVIONICS = 18
AVIONICS_RAW = 1
AVIONICS_TIMESTAMP = 2

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
IFLA_AVIONICS_ARINC429RX = 2
IFLA_AVIONICS_ARINC429TX = 3
IFLA_AVIONICS_ARINC717RX = 4
IFLA_AVIONICS_ARINC717TX = 5

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

# from include/uapi/linux/if.h
IFF_UP = 1


def get_index(device):
    with socket.socket(PF_AVIONICS, socket.SOCK_RAW, AVIONICS_RAW) as sock:
        data = struct.pack("16si", device.encode(), 0)
        res = fcntl.ioctl(sock, SIOCGIFINDEX, data)
        index, = struct.unpack("16xi", res)
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


nlmsghdr = CStruct(
        "nlmsghdr", "=LHHLL",
        ("nlmsg_len", "nlmsg_type", "nlmsg_flags", "nlmsg_seq", "nlmsg_pid")
)
nlmsgerr = CStruct("nlmsgerr", "=i", ("error"))
ifinfomsg = CStruct(
        "ifinfomsg", "=BxHiII",
        ("ifi_family", "ifi_type", "ifi_index", "ifi_flags", "ifi_change")
)
rattr = CStruct("rattr", "=HH", ("rta_len", "rta_type"))

avionics_rate = CStruct("avionics_rate", "=L", ("rate_hz"))
avionics_arinc429rx = CStruct(
        "avionics_arinc429rx", "=Bx3s32s",
        ("flags", "priority_labels", "label_filters")
)
avionics_arinc429tx = CStruct("avionics_arinc429tx", "=Bxxx", ("flags"))
avionics_arinc717rx = CStruct("avionics_arinc717rx", "=Bxxx", ("flags"))
avionics_arinc717tx = CStruct("avionics_arinc717tx", "=Bxxx", ("flags"))

# =============================================================================


def set_avionics_config(device, set_packet):
    with socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE
    ) as sock:
        sock.bind((os.getpid(), 0))

        index = get_index(device)

        kind = b"avionics\x00\x00\x00\x00"

        info_data = rattr.pack(
                len(rattr) + len(set_packet), IFLA_INFO_DATA
        ) + set_packet

        info_kind = rattr.pack(len(rattr) + len(kind), IFLA_INFO_KIND) + kind

        command = rattr.pack(
                len(rattr) + len(info_kind) + len(info_data), IFLA_LINKINFO
        ) + info_kind + info_data

        msg = (
                nlmsghdr.pack(
                        len(nlmsghdr) + len(ifinfomsg) + len(command),
                        RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 0, 0
                ) + ifinfomsg.pack(0, 0, index, IFF_UP, IFF_UP) + command
        )

        sock.send(msg)

        while True:
            msg = sock.recv(65535)
            msg_len = len(msg)

            msg, msghdr = nlmsghdr.consume(msg)

            if msghdr.nlmsg_len != msg_len:
                print(f"Message truncated! {msghdr.nlmsg_len} != {len(msg)}")
                return

            if msghdr.nlmsg_type == NLMSG_ERROR:
                msg, msgerr = nlmsgerr.consume(msg)
                msg, msgerrhdr = nlmsghdr.consume(msg)
                if msgerr.error:
                    print(f"Error: {msgerr} from {msgerrhdr}")
                return


def set_arinc429tx(device, flags):
    set_avionics_config(
            device,
            rattr.pack(
                    len(rattr) + len(avionics_arinc429tx),
                    IFLA_AVIONICS_ARINC429TX
            ) + avionics_arinc429tx.pack(flags)
    )


def set_arinc429rx(
        device, flags, priority_labels=bytes(3), label_filters=bytes(32)
):
    set_avionics_config(
            device,
            rattr.pack(
                    len(rattr) + len(avionics_arinc429rx),
                    IFLA_AVIONICS_ARINC429RX
            ) +
            avionics_arinc429rx.pack(flags, priority_labels, label_filters)
    )


def set_arinc717tx(device, flags):
    set_avionics_config(
            device,
            rattr.pack(
                    len(rattr) + len(avionics_arinc717tx),
                    IFLA_AVIONICS_ARINC717TX
            ) + avionics_arinc717tx.pack(flags)
    )


def set_arinc717rx(device, flags):
    set_avionics_config(
            device,
            rattr.pack(
                    len(rattr) + len(avionics_arinc717rx),
                    IFLA_AVIONICS_ARINC717RX
            ) + avionics_arinc717rx.pack(flags)
    )


# =============================================================================


def parse_rtattr(msg):
    attrs = {}
    while msg:
        msg, msgrattr = rattr.consume(msg)

        if msgrattr.rta_len < 4:
            print(f"Invalid rta length {msgrattr.rta_len}")
            break

        increment = ((msgrattr.rta_len + 4 - 1) & ~(4 - 1)) - len(rattr)

        attrs[msgrattr.rta_type] = msg[:msgrattr.rta_len - len(rattr)]

        msg = msg[increment:]

    return attrs


def getlink(device):
    with socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE
    ) as sock:
        sock.bind((os.getpid(), 0))

        index = get_index(device)

        msg = (
                nlmsghdr.pack(
                        len(nlmsghdr) + len(ifinfomsg), RTM_GETLINK,
                        NLM_F_REQUEST, 0, 0
                ) + ifinfomsg.pack(socket.AF_PACKET, 0, index, 0, 0)
        )

        sock.send(msg)

        while True:
            msg = sock.recv(65535)
            msg_len = len(msg)

            msg, msghdr = nlmsghdr.consume(msg)

            if msghdr.nlmsg_len != msg_len:
                print(f"Message truncated! {msghdr.nlmsg_len} != {len(msg)}")
                return

            if msghdr.nlmsg_type != RTM_NEWLINK:
                print(f"Unexpected message type {msghdr.nlmsg_type}")
                return

            msg, msgifinfo = ifinfomsg.consume(msg)

            if msgifinfo.ifi_index != index:
                print(f"Wrong device index: {msgifinfo.ifi_index}")
                return

            return msg


def get_arinc429tx(device):
    msg = getlink(device)

    link_attrs = parse_rtattr(msg)
    link_info = parse_rtattr(link_attrs[IFLA_LINKINFO])
    link_data = parse_rtattr(link_info[IFLA_INFO_DATA])

    rate = avionics_rate.unpack(link_data[IFLA_AVIONICS_RATE])
    print(f"Rate = {rate.rate_hz} Hz")

    config = avionics_arinc429tx.unpack(link_data[IFLA_AVIONICS_ARINC429TX])
    print(config)
    print(
            f"Flip Label Bits ="
            f" {bool(config.flags&AVIONICS_ARINC429TX_FLIP_LABEL_BITS)}"
    )
    print(f"Self Test = {bool(config.flags&AVIONICS_ARINC429TX_SELF_TEST)}")
    print(
            f"Even Parity ="
            f" {bool(config.flags&AVIONICS_ARINC429TX_EVEN_PARITY)}"
    )
    print(f"Set Parity = {bool(config.flags&AVIONICS_ARINC429TX_PARITY_SET)}")


def get_arinc429rx(device):
    msg = getlink(device)

    link_attrs = parse_rtattr(msg)
    link_info = parse_rtattr(link_attrs[IFLA_LINKINFO])
    link_data = parse_rtattr(link_info[IFLA_INFO_DATA])

    rate = avionics_rate.unpack(link_data[IFLA_AVIONICS_RATE])
    print(f"Rate = {rate.rate_hz} Hz")

    config = avionics_arinc429rx.unpack(link_data[IFLA_AVIONICS_ARINC429RX])
    print(
            "Flip Label Bits = "
            f"{bool(config.flags&AVIONICS_ARINC429RX_FLIP_LABEL_BITS)}"
    )
    print(f"SD9 Mask = {bool(config.flags&AVIONICS_ARINC429RX_SD9_MASK)}")
    print(f"SD10 Mask = {bool(config.flags&AVIONICS_ARINC429RX_SD10_MASK)}")
    print(
            "SD Mask Enable = "
            f"{bool(config.flags&AVIONICS_ARINC429RX_SD_MASK_ENABLE)}"
    )
    print(
            "Parity Check Enabled = "
            f"{bool(config.flags&AVIONICS_ARINC429RX_PARITY_CHECK)}"
    )
    print(
            "Even Parity = "
            f"{bool(config.flags&AVIONICS_ARINC429RX_EVEN_PARITY)}"
    )
    print(
            "Label Filter Enabled = "
            f"{bool(config.flags&AVIONICS_ARINC429RX_LABEL_FILTER_ENABLE)}"
    )
    print(
            "Priority Labels Enabled = "
            f"{bool(config.flags&AVIONICS_ARINC429RX_PRIORITY_LABEL_ENABLE)}"
    )
    print(f"Priority Labels = {config.priority_labels}")
    print(f"Label Filters = {config.label_filters}")


def get_arinc717tx(device):
    msg = getlink(device)

    link_attrs = parse_rtattr(msg)
    link_info = parse_rtattr(link_attrs[IFLA_LINKINFO])
    link_data = parse_rtattr(link_info[IFLA_INFO_DATA])

    rate = avionics_rate.unpack(link_data[IFLA_AVIONICS_RATE])
    print(f"Rate = {rate.rate_hz} Hz")

    config = avionics_arinc717tx.unpack(link_data[IFLA_AVIONICS_ARINC717TX])
    print(config)
    print(f"Slew Rate =" f" {int((config.flags&AVIONICS_ARINC717TX_SLEW)>>1)}")
    print(f"Self Test = {bool(config.flags&AVIONICS_ARINC717TX_SELF_TEST)}")


def get_arinc717rx(device):
    msg = getlink(device)

    link_attrs = parse_rtattr(msg)
    link_info = parse_rtattr(link_attrs[IFLA_LINKINFO])
    link_data = parse_rtattr(link_info[IFLA_INFO_DATA])

    rate = avionics_rate.unpack(link_data[IFLA_AVIONICS_RATE])
    print(f"Rate = {rate.rate_hz} Hz")

    config = avionics_arinc717tx.unpack(link_data[IFLA_AVIONICS_ARINC717RX])
    print(config)
    print(f"BPRZ = {bool(config.flags&AVIONICS_ARINC717RX_BPRZ)}")
    print(f"No Sync = {bool(config.flags&AVIONICS_ARINC717RX_NOSYNC)}")
    print(f"Soft Sync = {bool(config.flags&AVIONICS_ARINC717RX_SFTSYNC)}")


# =============================================================================


def test_arinc429tx():
    print("==> Testing ARINC-429 TX Config <==")
    set_arinc429tx(
            "arinc429tx0", 0
    )
    get_arinc429tx("arinc429tx0")


def test_arinc429rx():
    print("==> Testing ARINC-429 RX 0 Config <==")
    set_arinc429rx(
            "arinc429rx0", 0
    )
    get_arinc429rx("arinc429rx0")

    print("==> Testing ARINC-429 RX 1 Config <==")
    set_arinc429rx(
            "arinc429rx1", 0
    )
    get_arinc429rx("arinc429rx1")


def test_arinc717tx():
    print("==> Testing ARINC-717 TX Config <==")
    set_arinc717tx("arinc717tx0", 0)
    get_arinc717tx("arinc717tx0")


def test_arinc717rx():
    print("==> Testing ARINC-717 RX Config <==")
    set_arinc717rx("arinc717rx0", AVIONICS_ARINC717RX_BPRZ)
    get_arinc717rx("arinc717rx0")
    # AVIONICS_ARINC717RX_BPRZ = (1 << 0)
    # AVIONICS_ARINC717RX_NOSYNC = (1 << 1)
    # AVIONICS_ARINC717RX_SFTSYNC = (1 << 2)


if __name__ == "__main__":

    #test_arinc429rx()
    #test_arinc429tx()

    test_arinc717tx()
    test_arinc717rx()
