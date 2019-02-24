#!/bin/sh

echo Unloading Drivers
modprobe -r avionics-example
modprobe -r avionics-lb
modprobe -r avionics

