# SPDX-License-Identifier: GPL-2.0

# Configuration and compile options for standalone module version in a separate
# file. The upstream version should contains the configuration in the Kconfig
# file, and should be free from all branches of conditional compilation.

ccflags-y += $(shell 							\
	grep -qw "*bi_bdev;" $(srctree)/include/linux/blk_types.h &&		\
		echo -D HAVE_BI_BDEV)

ccflags-y += $(shell test -f $(srctree)/include/linux/genhd.h &&		\
	grep -qw "int add_disk" $(srctree)/include/linux/genhd.h &&		\
		echo -D HAVE_ADD_DISK_RESULT)
ccflags-y += $(shell test -f $(srctree)/include/linux/blkdev.h &&		\
	grep -qw "int add_disk" $(srctree)/include/linux/blkdev.h &&		\
		echo -D HAVE_ADD_DISK_RESULT)
ccflags-y += $(shell test -f $(srctree)/include/linux/genhd.h &&		\
	grep -qw "int __must_check add_disk" $(srctree)/include/linux/genhd.h && \
		echo -D HAVE_ADD_DISK_RESULT)
ccflags-y += $(shell test -f $(srctree)/include/linux/blkdev.h &&		\
	grep -qw "int __must_check add_disk" $(srctree)/include/linux/blkdev.h && \
		echo -D HAVE_ADD_DISK_RESULT)

ccflags-y += $(shell test -f $(srctree)/include/linux/genhd.h &&		\
	grep -qw "void blk_cleanup_disk" $(srctree)/include/linux/genhd.h &&	\
		echo -D HAVE_BLK_CLEANUP_DISK)
ccflags-y += $(shell test -f $(srctree)/include/linux/blkdev.h &&		\
	grep -qw "void blk_cleanup_disk" $(srctree)/include/linux/blkdev.h &&	\
		echo -D HAVE_BLK_CLEANUP_DISK)

ccflags-y += $(shell test -f $(srctree)/include/linux/genhd.h &&		\
		echo -D HAVE_GENHD_H)

sblkdev-y := main.o
obj-m += sblkdev.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
