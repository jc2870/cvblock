# SPDX-License-Identifier: GPL-2.0

sblkdev-y := main.o device.o
obj-m += sblkdev.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
