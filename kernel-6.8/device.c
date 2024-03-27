// SPDX-License-Identifier: GPL-2.0

#include "linux/bio.h"
#include "linux/blk_types.h"
#include "linux/blkdev.h"
#include "linux/err.h"
#include "linux/gfp_types.h"
#include "linux/printk.h"
#include <linux/hdreg.h> /* for HDIO_GETGEO */
#include <linux/cdrom.h> /* for CDROM_GET_CAPABILITY */
#include "device.h"
#include "test.h"
#include <linux/workqueue_types.h>
#include <linux/delay.h>

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

struct zspace_vdev_private {
	struct bio *bio_bak;
	struct bio *bio;
	bio_end_io_t *end_io_bak;
	void *private_bak;
	struct work_struct work;
};

#define DEFAULT_BLOCK_SIZE 4096
static unsigned long start_time;


static void zspace_decrypt_bio(struct work_struct *work)
{
	struct zspace_vdev_private *ctx =
		container_of(work, struct zspace_vdev_private, work);
	struct bio_vec bvec;
	struct bvec_iter iter;
	struct bio* biobak = ctx->bio_bak;
	struct bio* bio= ctx->bio;

	bio_for_each_segment(bvec, biobak, iter) {
		unsigned int len = bvec.bv_len;
		void *buf = page_address(bvec.bv_page) + bvec.bv_offset;

		crypt_set_data(buf, len);
		decrypt_process();
	}
	bio_end_io_acct(bio, start_time);
	bio->bi_end_io(ctx->bio);
	kfree(ctx);
}

static void end_io(struct bio* bio)
{
	struct zspace_vdev_private *private = bio->bi_private;

	bio->bi_private = private->private_bak;
	bio->bi_end_io = private->end_io_bak;

	// pr_info("%s %pK\n", __func__, bio);
	if (bio_data_dir(bio) == READ) {
		// pr_info("1\n");
		INIT_WORK(&private->work, zspace_decrypt_bio);
		queue_work(zspace_crypto_wq, &private->work);
		// zspace_decrypt_bio(&private->work);
	} else {
		bio_end_io_acct(bio, start_time);
		kfree(private);
		bio->bi_end_io(bio);
	}
}

extern void resubmit_bio(struct bio* bio);
void resubmit_bio(struct bio* bio)
{
	struct zspace_vdev_private *private = kmalloc(sizeof(*private), GFP_KERNEL);
	BUG_ON(!private);
	private->bio_bak = kmalloc(sizeof(struct bio), GFP_KERNEL);
	BUG_ON(!private->bio_bak);

	bio_init_clone(zspace_bdev_handle->bdev, private->bio_bak, bio , GFP_KERNEL);
	// pr_info("%s %pK\n", __func__, bio);
	private->private_bak = bio->bi_private;
	private->end_io_bak = bio->bi_end_io;
	private->bio = bio;
	bio->bi_end_io = end_io;
	bio->bi_private = private;
	bio_set_dev(bio, zspace_bdev_handle->bdev);
	submit_bio_noacct(bio);
}

static inline void process_bio(struct sblkdev_device *dev, struct bio *bio)
{
	struct bio_vec bvec;
	struct bvec_iter iter;
	loff_t pos = bio->bi_iter.bi_sector << SECTOR_SHIFT;
	loff_t dev_size = (dev->capacity << SECTOR_SHIFT);

	start_time = bio_start_io_acct(bio);

	if (bio_data_dir(bio) == READ) {
		resubmit_bio(bio);
		return;
	}

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		void *buf = page_address(bvec.bv_page) + bvec.bv_offset;

		if ((pos + len) > dev_size) {
			/* len = (unsigned long)(dev_size - pos);*/
			bio->bi_status = BLK_STS_IOERR;
			break;
		}

		crypt_set_data(buf, len);
		encrypt_process();

		pos += len;
	}
	resubmit_bio(bio);
}

static void _submit_bio(struct bio *bio)
{
	struct sblkdev_device *dev = bio->bi_bdev->bd_disk->private_data;

	might_sleep();
	//cant_sleep(); /* cannot use any locks that make the thread sleep */
	process_bio(dev, bio);
}

static int _open(struct gendisk *bd_disk, fmode_t mode)
{
	struct sblkdev_device *dev = bd_disk->private_data;

	if (!dev) {
		pr_err("Invalid disk private_data\n");
		return -ENXIO;
	}

	pr_debug("Device was opened\n");

	return 0;
}

static void _release(struct gendisk *disk)
{
	struct sblkdev_device *dev = disk->private_data;

	if (!dev) {
		pr_err("Invalid disk private_data\n");
		return;
	}

	pr_debug("Device was closed\n");
}

static const struct block_device_operations fops = {
	.owner = THIS_MODULE,
	.open = _open,
	.release = _release,
	.submit_bio = _submit_bio,
};

/*
 * sblkdev_remove() - Remove simple block device
 */
void sblkdev_remove(struct sblkdev_device *dev)
{
	del_gendisk(dev->disk);

	put_disk(dev->disk);

	vfree(dev->data);

	kfree(dev);

	pr_info("simple block device was removed\n");
}

/*
 * sblkdev_add() - Add simple block device
 */
struct sblkdev_device *sblkdev_add(int major, int minor, char *name,
				  sector_t capacity)
{
	struct sblkdev_device *dev = NULL;
	int ret = 0;
	struct gendisk *disk;

	pr_info("add device '%s' capacity %llu sectors\n", name, capacity);

	dev = kzalloc(sizeof(struct sblkdev_device), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto fail;
	}

	INIT_LIST_HEAD(&dev->link);
	dev->capacity = capacity;
	dev->data = __vmalloc(capacity << SECTOR_SHIFT, GFP_NOIO | __GFP_ZERO);
	// dev->data = kmalloc(capacity << SECTOR_SHIFT, GFP_KERNEL);
	if (!dev->data) {
		ret = -ENOMEM;
		goto fail_kfree;
	}

	disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk) {
		pr_err("Failed to allocate disk\n");
		ret = -ENOMEM;
		goto fail_vfree;
	}
	dev->disk = disk;

	/* only one partition */
#ifdef GENHD_FL_NO_PART_SCAN
	disk->flags |= GENHD_FL_NO_PART_SCAN;
#else
	disk->flags |= GENHD_FL_NO_PART;
#endif

	/* removable device */
	/* disk->flags |= GENHD_FL_REMOVABLE; */

	disk->major = major;
	disk->first_minor = minor;
	disk->minors = 1;

	disk->fops = &fops;

	disk->private_data = dev;

	sprintf(disk->disk_name, name);
	set_capacity(disk, dev->capacity);

	blk_queue_physical_block_size(disk->queue, DEFAULT_BLOCK_SIZE);
	blk_queue_logical_block_size(disk->queue, DEFAULT_BLOCK_SIZE);
	blk_queue_max_hw_sectors(disk->queue, BLK_SAFE_MAX_SECTORS);
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, disk->queue);


	ret = add_disk(disk);
	if (ret) {
		pr_err("Failed to add disk '%s'\n", disk->disk_name);
		goto fail_put_disk;
	}

	pr_info("Simple block device [%d:%d] was added\n", major, minor);

	return dev;

// #ifdef HAVE_ADD_DISK_RESULT
fail_put_disk:
	put_disk(dev->disk);
// #endif /* HAVE_ADD_DISK_RESULT */

fail_vfree:
	vfree(dev->data);
fail_kfree:
	kfree(dev);
fail:
	pr_err("Failed to add block device\n");

	return ERR_PTR(ret);
}
