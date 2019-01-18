#
#  Makefile for the Linux Controller Area Network drivers.
#

obj-$(CONFIG_ARINC429_VARINC429)	+= varinc429.o

obj-$(CONFIG_ARINC429_DEV)		+= arinc429-dev.o
arinc429-dev-y				:= dev.o

subdir-ccflags-y += -D__CHECK_ENDIAN__
subdir-ccflags-$(CONFIG_ARINC429_DEBUG_DEVICES) += -DDEBUG
