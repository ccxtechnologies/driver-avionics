# driver-avionics
Socket based Avionics Networking Driver for Linux

Includes ARINC-429 and ARINC-717 interfaces, can be expanded to include new protocols like MIL-1553, etc.

__NOTE: The linux kernel must be configured for 1000 ticks per second (CONFIG_HZ_1000) for the higher ARINC-717 rates__

## Notes on Kernel Header Files

In order to create a socket device with a configurable interface we would technically have to add a socket
AF\_index and PF\_index to socket.h, an ARPHRD\_index to if\_arp.h, and an ETH\_P\_index to if\_ether.h but
since we want to build this as an out-of-tree dirver we can't do that. So we stole the unused indexes from Ash.
Refer to arinc429.h for more details on this ugly hack.

If this driver ever get's upstreamed, or if you want to create a patch for it and pull it into your kernel you should
create new, unique socket indexes.

# Interfacing with the Driver

These drivers use netlink for configuration and raw sockets for data transfers. Refer to the Python test scripts
for examples.

You will have to include the avionics.h header file in your user space applications that interface with this driver
to get the protocol indexes and data formats.

These drivers support a raw protcol and a timestamp protocol which utalize different base datatypes.

## Raw Protocol

The raw protocol transmits and receives a set of 32-bit words. All transmit data will be immediatly written, receive
data may be buffered internally for some time so the receive time may vary from the capture time.

## Timestamp Protocol

The timestamp protocol transmits and receives a set of 32-bit words plus a milli-second epoch time counter.

The time counter on all received data will be set to the processor's capture time, this may vary somewhat from the
time the data was received from the databus but shoud lbe within 3 ms.

If the time counter on transmit data will be used to delay the data until the epoch time that is set. If the setting
is less than the current time, or greater than 6 minutes in the future the data will be sent immediatly.


# Kernel Version

All development and testing was done on kernel versions 4.9 to 5.6, this driver will probably work on
different kernels but may require some updates.



