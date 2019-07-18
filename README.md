# driver-avionics
Socket based Avionics Networking Driver for Linux

Includes ARINC-429 interfaces, but can be expanded to include new protocols like ARINC-717, MIL-1553, etc.

## Notes on Kernel Header Files

In order to create a socket device with a configurable interface we need to add a socket
AF\_index and PF\_index to socket.h, an ARPHRD\_index to if\_arp.h, and an ETH\_P\_index to if\_ether.h.

Since we would prefer this to be an out-of-tree driver (at least for now) we reuse existing but
unused indexes for Ash. Refer to arinc429.h for more details on this ugly hack.

# Kernel Version

All development and testing was done on kernel versions 4.9 to 5.2, this driver will probably work on
different kernels but may require some updates.
