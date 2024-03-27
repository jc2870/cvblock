// SPDX-License-Identifier: GPL-2.0

#include "linux/blk_types.h"
#include "linux/gfp_types.h"
#include "linux/log2.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include "device.h"
#include <crypto/internal/skcipher.h> 
#include <linux/crypto.h> 
#include <linux/blk-crypto.h>

#include "test.h"

/*
 * A module can create more than one block device.
 * The configuration of block devices is implemented in the simplest way:
 * using the module parameter, which is passed when the module is loaded.
 * Example:
 *    modprobe sblkdev catalog="sblkdev1,2048;sblkdev2,4096"
 */

static int sblkdev_major;
static LIST_HEAD(sblkdev_device_list);
static char *sblkdev_catalog = "zspace_vdev,2097152";
static const size_t ivsize = 16;
static const size_t keysize = 32;
static struct crypto_skcipher *tfm = NULL;

struct bdev_handle *zspace_bdev_handle = NULL;
struct workqueue_struct *zspace_crypto_wq;

static struct crypto_dev crypto;


static void crypt_uninit(void)
{
    crypto_free_skcipher(tfm);
}

static int crypt_init(void)
{
    crypto.iv = kmalloc(ivsize, GFP_KERNEL);
    crypto.key = kmalloc(keysize, GFP_KERNEL);
    int err;

    BUG_ON(!crypto.iv || !crypto.key);

    memcpy(crypto.iv, IV_DATA, ivsize);
    memcpy(crypto.key, KEY_DATA, keysize);

    tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(tfm)) {
	    pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
	    return PTR_ERR(tfm);
    }

    // get_random_bytes(key, sizeof(key));
    err = crypto_skcipher_setkey(tfm, (const u8*)crypto.key, keysize);
    if (err) {
	    pr_err("Error setting key: %d\n", err);
	    goto out;
    }

out:
    return err;
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

    sg_init_one(&sg, data, crypto.data_len);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				       CRYPTO_TFM_REQ_MAY_SLEEP,
				  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, crypto.data_len, iv);

    err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    if (err) {
	    pr_err("Error encrypting data: %d\n", err);
    }
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

    sg_init_one(&sg, data, crypto.data_len);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				       CRYPTO_TFM_REQ_MAY_SLEEP,
				  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, crypto.data_len, iv);
    err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (err) {
	    pr_err("Error encrypting data: %d\n", err);
    }

    skcipher_request_free(req);
    return err;
}


void crypt_set_data(char *data, size_t len)
{
	crypto.data = data;
	crypto.data_len = len;
	if (!is_power_of_2(len)) {
		pr_info("len is %zu\n", len);
		BUG();
	}
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
	char *catalog;
	char *next_token;
	char *token;
	size_t length;

	ret = crypt_init();
	if (ret) {
		pr_info("unable to init crypt\n");
		return -EINVAL;
	}

	zspace_crypto_wq = alloc_workqueue("zspace_crypto_wq",
					WQ_UNBOUND | WQ_HIGHPRI |
					WQ_MEM_RECLAIM, num_online_cpus());
	BUG_ON(!zspace_crypto_wq);

	zspace_bdev_handle = bdev_open_by_path("/dev/loop0", BLK_OPEN_READ | BLK_OPEN_WRITE , NULL, NULL);
	if (IS_ERR_OR_NULL(zspace_bdev_handle)) {
		return -EINVAL;
	}


	// @TODO: memleak here
	sblkdev_major = register_blkdev(sblkdev_major, KBUILD_MODNAME);
	if (sblkdev_major <= 0) {
		pr_info("Unable to get major number\n");
		return -EBUSY;
	}

	length = strlen(sblkdev_catalog);
	if ((length < 1) || (length > PAGE_SIZE)) {
		pr_info("Invalid module parameter 'catalog'\n");
		ret = -EINVAL;
		goto fail_unregister;
	}

	catalog = kzalloc(length + 1, GFP_KERNEL);
	if (!catalog) {
		ret = -ENOMEM;
		goto fail_unregister;
	}
	strcpy(catalog, sblkdev_catalog);

	next_token = catalog;
	while ((token = strsep(&next_token, ";"))) {
		struct sblkdev_device *dev;
		char *name;
		char *capacity;
		sector_t capacity_value;

		name = strsep(&token, ",");
		if (!name)
			continue;
		capacity = strsep(&token, ",");
		if (!capacity)
			continue;

		ret = kstrtoull(capacity, 10, &capacity_value);
		if (ret)
			break;

		dev = sblkdev_add(sblkdev_major, inx, name, capacity_value);
		if (IS_ERR(dev)) {
			ret = PTR_ERR(dev);
			break;
		}

		list_add(&dev->link, &sblkdev_device_list);
		inx++;
	}
	kfree(catalog);

	if (ret == 0)
		return 0;

fail_unregister:
	unregister_blkdev(sblkdev_major, KBUILD_MODNAME);
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
	struct sblkdev_device *dev;

	while ((dev = list_first_entry_or_null(&sblkdev_device_list,
					       struct sblkdev_device, link))) {
		list_del(&dev->link);
		sblkdev_remove(dev);
	}

	if (sblkdev_major > 0) {
		unregister_blkdev(sblkdev_major, KBUILD_MODNAME);
	}

	crypt_uninit();
	bdev_release(zspace_bdev_handle);
}

module_init(sblkdev_init);
module_exit(sblkdev_exit);

module_param_named(catalog, sblkdev_catalog, charp, 0644);
MODULE_PARM_DESC(catalog, "New block devices catalog in format '<name>,<capacity sectors>;...'");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Junchao Sun");
