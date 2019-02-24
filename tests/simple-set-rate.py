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

device = "arinc428rx0"

sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
sock.close()
