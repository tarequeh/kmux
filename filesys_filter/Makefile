obj-m	:= fsfilter.o
fsfilter-objs := filesys_filter.o

KDIR    := /lib/modules/$(shell uname -r)/build
INCLUDE	:= -I/usr/include/asm/mach-default/
PWD		:= $(shell pwd)

CC=gcc
EXTRA_CFLAGS=-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -ggdb3

all:
	make -C $(KDIR) $(INCLUDE) SUBDIRS=$(PWD) modules

clean:
	make -i remove-module
	make remove-files

remove-files:
	rm -rf *.ko *.mod.c *.o *.mod.o .*.cmd .tmp_versions modules.order Module.symvers

remove-module:
	rmmod fsfilter.ko

install:
	insmod fsfilter.ko
