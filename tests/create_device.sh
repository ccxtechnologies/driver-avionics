#!/bin/sh

DEVICE=vavionics0

echo Loading Drivers
modprobe avionics
modprobe vavionics

echo Creating $DEVICE
ip link add dev $DEVICE type vavionics
ip link set dev $DEVICE up


