#!/bin/sh

DEVICE=avionics-lb0

echo Loading Drivers
modprobe avionics
modprobe avionics-lb

echo Creating $DEVICE
ip link add dev $DEVICE type avionics-lb
ip link set dev $DEVICE up


