# driver-arinc429
Socket based ARINC-429 Driver for Linux

## Notes on Kernel Header Files

In order to create a socket device with a configurable interface we need to add a socket
AF\_index and PF\_index to socket.h, an ARPHRD\_index to if\_arp.h, and an ETH\_P\_index to if\_ether.h.

Since we would prefer this to be an out-of-tree driver (at least for now) we reuse existing but
unused indexes for Ash. Refer to arinc429.h for more details on this ugly hack.

# Kernel Version

All development and testing was done on 4.9, this can probably work on an different
kernels but it will probably require some updates.
