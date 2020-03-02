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

# Kernel Version

All development and testing was done on kernel versions 4.9 to 5.2, this driver will probably work on
different kernels but may require some updates.
