// SPDX-License-Identifier: GPL-2.0

#include "linux/blkdev.h"
#include "linux/fs.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <crypto/internal/skcipher.h> 
#include <linux/crypto.h> 

#include "test.h"

struct sblkdev_device {
	struct list_head link;

	sector_t capacity;		/* Device size in sectors */
	u8 *data;			/* The data in virtual memory */
	struct gendisk *disk;
};

static char *device_path = "/dev/loop0";
#pragma message("Bio-based scheme selected.")

#ifdef HAVE_BI_BDEV
#pragma message("The struct bio have pointer to struct block_device.")
#endif
#ifdef HAVE_ADD_DISK_RESULT
#pragma message("The function add_disk() has a return code.")
#endif
#ifdef HAVE_BDEV_BIO_ALLOC
#pragma message("The function bio_alloc_bioset() has a parameter bdev.")
#endif
#ifdef HAVE_BLK_CLEANUP_DISK
#pragma message("The function blk_cleanup_disk() was found.")
#endif
#ifdef HAVE_GENHD_H
#pragma message("The header file 'genhd.h' was found.")
#endif

/*
 * A module can create more than one block device.
 * The configuration of block devices is implemented in the simplest way:
 * using the module parameter, which is passed when the module is loaded.
 * Example:
 *    modprobe sblkdev catalog="sblkdev1,2048;sblkdev2,4096"
 */

static int sblkdev_major;
static LIST_HEAD(sblkdev_device_list);
static char *sblk_devname = "zspace_vdev";
static u32 capacity = 2097152;
static struct sblkdev_device *dev = NULL;

static const size_t ivsize = 16;
static const size_t keysize = 16;
static struct crypto_skcipher *tfm = NULL;
static struct workqueue_struct *zspace_crypto_wq;
static struct crypto_dev crypto;


struct block_device *zspace_bdev_handle = NULL;
#define DEFAULT_BLOCK_SIZE SECTOR_SIZE

static unsigned long start_time;

struct zspace_vdev_private {
	struct bio *bio_bak;
	struct bio *bio;
	bio_end_io_t *end_io_bak;
	void *private_bak;
	struct work_struct work;
};

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
    if (!private) {
        pr_err("no memory\n");
        return;
    }
	private->bio_bak = kmalloc(sizeof(struct bio), GFP_KERNEL);
    if (!private->bio_bak) {
        pr_err("no memory\n");
        return;
    }

    memcpy(private->bio_bak, bio, sizeof(*bio));
	// pr_info("%s %pK\n", __func__, bio);
	private->private_bak = bio->bi_private;
	private->end_io_bak = bio->bi_end_io;
	private->bio = bio;
	bio->bi_end_io = end_io;
	bio->bi_private = private;
	bio_set_dev(bio, zspace_bdev_handle);
    generic_make_request(bio);
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

static blk_qc_t _submit_bio(struct request_queue *q, struct bio *bio)
{
    struct sblkdev_device *dev = q->queuedata;

	might_sleep();
	//cant_sleep(); /* cannot use any locks that make the thread sleep */
	process_bio(dev, bio);

    return BLK_QC_T_NONE;
}

static int _open(struct block_device *bd_disk, fmode_t mode)
{
	struct sblkdev_device *dev = bd_disk->bd_disk->private_data;

	if (!dev) {
		pr_err("Invalid disk private_data\n");
		return -ENXIO;
	}

	pr_debug("Device was opened\n");

	return 0;
}

static void _release(struct gendisk *disk, fmode_t mode)
{
	struct sblkdev_device *dev = disk->private_data;

	if (!dev) {
		pr_err("Invalid disk private_data\n");
		return;
	}

	pr_debug("Device was closed\n");
}

static const struct block_device_operations sblkdev_fops = {
	.owner = THIS_MODULE,
    .open = _open,
    .release = _release,
};

/*
 * sblkdev_remove() - Remove simple block device
 */
static void sblkdev_remove(struct sblkdev_device *dev)
{
	del_gendisk(dev->disk);

	blk_cleanup_queue(dev->disk->queue);
	put_disk(dev->disk);

	vfree(dev->data);

	kfree(dev);

	pr_info("simple block device was removed\n");
}

static struct gendisk *blk_alloc_disk(int numa_node)
{
    struct request_queue *q = NULL;
    struct gendisk *disk = NULL;

    q = blk_alloc_queue(_submit_bio, numa_node);
    if (!q) {
        pr_err("no memory\n");
        return ERR_PTR(ENOMEM);
    }
    disk = alloc_disk_node(1, numa_node);
    if (!disk) {
        pr_err("no memory\n");
        disk = ERR_PTR(ENOMEM);
        goto failed_alloc_disk;
    }

    disk->queue = q;

    return disk;

failed_alloc_disk:
    blk_cleanup_queue(q);
    return disk;
}

/*
 * sblkdev_add() - Add simple block device
 */
static struct sblkdev_device *sblkdev_add(int major, int minor, char *name,
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
    disk->queue->queuedata = dev;

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

	disk->fops = &sblkdev_fops;

	disk->private_data = dev;

	sprintf(disk->disk_name, name);
	set_capacity(disk, dev->capacity);

	blk_queue_physical_block_size(disk->queue, DEFAULT_BLOCK_SIZE);
	blk_queue_logical_block_size(disk->queue, DEFAULT_BLOCK_SIZE);
	blk_queue_max_hw_sectors(disk->queue, BLK_SAFE_MAX_SECTORS);
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, disk->queue);

	add_disk(disk);

	pr_info("Simple block device [%d:%d] was added\n", major, minor);

	return dev;

fail_vfree:
	vfree(dev->data);
fail_kfree:
	kfree(dev);
fail:
	pr_err("Failed to add block device\n");

	return ERR_PTR(ret);
}

static int crypt_init(void)
{
    const char *cipher_name = "xts(aes)";
    crypto.iv = kmalloc(ivsize, GFP_KERNEL);
    crypto.key = kmalloc(keysize, GFP_KERNEL);

    BUG_ON(!crypto.iv || !crypto.key);

    tfm = crypto_alloc_skcipher(cipher_name, 0, 0);
    if (IS_ERR(tfm)) {
	    pr_err("Error allocating %s handle: %ld\n", cipher_name, PTR_ERR(tfm));
	    return PTR_ERR(tfm);
    }

    return 0;
}

static void crypt_uninit(void)
{
    kfree(crypto.iv);
    kfree(crypto.key);
    crypto_free_skcipher(tfm);
}

int decrypt_process()
{
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    char *data = crypto.data;
    char *iv = crypto.iv; 
    int err;
    struct skcipher_request *req = NULL;

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_info("no memory\n");
	    return -ENOMEM;
    }
    err = crypto_skcipher_setkey(tfm, (const u8*)crypto.key, keysize);
    if (err) {
	    pr_err("Error setting key: %d\n", err);
	    goto out;
    }
    sg_init_one(&sg, data, crypto.data_len);
    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				       CRYPTO_TFM_REQ_MAY_SLEEP,
				  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, crypto.data_len, iv);

    err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    if (err) {
	    pr_err("Error encrypting data: %d\n", err);
    }

out:
    skcipher_request_free(req);
    return err;
}

int encrypt_process()
{
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    char *data = crypto.data;
    char *iv = crypto.iv; 
    int err;
    struct skcipher_request *req = NULL;

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_info("no memory\n");
	    return -ENOMEM;
    }
    err = crypto_skcipher_setkey(tfm, (const u8*)crypto.key, keysize);
    if (err) {
	    pr_err("Error setting key: %d\n", err);
	    goto out;
    }

    sg_init_one(&sg, data, crypto.data_len);
    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				       CRYPTO_TFM_REQ_MAY_SLEEP,
				  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, crypto.data_len, iv);
    err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (err) {
	    pr_err("Error encrypting data: %d\n", err);
    }

out:
    skcipher_request_free(req);
    return err;
}

void crypt_set_data(char *data, size_t len)
{
    memcpy(crypto.key, KEY_DATA, keysize);
    memcpy(crypto.iv, IV_DATA, ivsize);
	crypto.data = data;
	crypto.data_len = len;
}

int crypt_selftest(void)
{
    int datalen = 16;
    u8 *data = kmalloc(datalen, GFP_KERNEL);
    if (!data) {
        return -ENOMEM;
    }

    memcpy(data, TEST_DATA, datalen);

    crypt_set_data((char*)data, datalen);
    encrypt_process();
    crypt_set_data((char*)data, datalen);
    decrypt_process();

    if (memcmp(data, TEST_DATA, datalen)) {
        return -EINVAL;
    }

    return 0;
}

/*
 * sblkdev_init() - Entry point 'init'.
 *
 * Executed when the module is loaded. Parses the catalog parameter and
 * creates block devices.
 */
static int __init sblkdev_init(void)
{
	int ret = 0;
	int inx = 0;

	ret = crypt_init();
	if (ret) {
		pr_info("unable to init crypt\n");
		return -EINVAL;
	}

    ret = crypt_selftest();
    if (ret) {
        pr_info("self test failed\n");
        crypt_uninit();
        return -EINVAL;
    }

    zspace_bdev_handle = blkdev_get_by_path(device_path, FMODE_READ|FMODE_WRITE, NULL);
    if (!zspace_bdev_handle) {
        return -EINVAL;
    }

    zspace_crypto_wq = alloc_workqueue("zspace_crypto_wq",
					WQ_UNBOUND | WQ_HIGHPRI |
					WQ_MEM_RECLAIM, num_online_cpus());
    if (!zspace_crypto_wq) {
        return -EINVAL;
    }

	// @TODO: memleak here
	sblkdev_major = register_blkdev(0, KBUILD_MODNAME);
	if (sblkdev_major <= 0) {
		pr_info("Unable to get major number\n");
        ret = sblkdev_major;
		goto fail_register;
	}

    dev = sblkdev_add(sblkdev_major, inx, sblk_devname, capacity);
    if (IS_ERR(dev)) {
        ret = PTR_ERR(dev);
        goto fail_unregister;
    }
    return ret;

fail_unregister:
	unregister_blkdev(sblkdev_major, KBUILD_MODNAME);
fail_register:
	return ret;
}

/*
 * sblkdev_exit() - Entry point 'exit'.
 *
 * Executed when the module is unloaded. Remove all block devices and cleanup
 * all resources.
 */
static void __exit sblkdev_exit(void)
{

    sblkdev_remove(dev);

	if (sblkdev_major > 0) {
		unregister_blkdev(sblkdev_major, KBUILD_MODNAME);
	}

	blkdev_put(zspace_bdev_handle, FMODE_READ | FMODE_WRITE);
    crypt_uninit();
}

module_init(sblkdev_init);
module_exit(sblkdev_exit);

module_param_named(device_path, device_path, charp, 0644);
MODULE_PARM_DESC(device_path, "New block devices catalog in format '<name>,<capacity sectors>;...'");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Junchao Sun");
