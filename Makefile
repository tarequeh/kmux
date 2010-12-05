obj-m	:= kmux.o

INCLUDE	:= -I/usr/include/asm/mach-default/
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD		:= $(shell pwd)

all::
	make -C $(KDIR) $(INCLUDE) SUBDIRS=$(PWD) modules


build::
	insmod kmux.ko
