obj-m	:= kmux.o
kmux-objs := kern_entry.o kern_mux.o

KDIR    := /lib/modules/$(shell uname -r)/build
INCLUDE	:= -I/usr/include/asm/mach-default/
PWD		:= $(shell pwd)

CC=gcc
EXTRA_CFLAGS=-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -ggdb3

all:
	make -C $(KDIR) $(INCLUDE) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.ko *.mod.c *.o *.mod.o .*.cmd .tmp_versions modules.order Module.symvers

build:
	insmod kmux.ko
