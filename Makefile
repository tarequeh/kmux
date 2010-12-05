obj-m	:= kmux.o
cos-objs := kern_entry.o

INCLUDE	:= -I/usr/include/asm/mach-default/
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD		:= $(shell pwd)

all::
	make -C $(KDIR) $(INCLUDE) SUBDIRS=$(PWD) modules

clean::
	rm -rf *.ko *.mod.c *.o *.mod.o .*.cmd .tmp_versions

build::
	insmod kmux.ko
