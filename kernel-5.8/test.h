#ifndef __TEST_H 
#define __TEST_H
#include "linux/blk_types.h"
#include "linux/blkdev.h"
#include <linux/types.h>
#include <linux/blk-crypto.h>


#define TEST_DATA "\x00\x01\x02\x03\x04\x05\x06\x07" \
			  "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" \
			  "\x10\x11\x12\x13\x14\x15\x16\x17" \
			  "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" \
			  "\x20\x21\x22\x23\x24\x25\x26\x27" \
			  "\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f" \
			  "\x30\x31\x32\x33\x34\x35\x36\x37" \
			  "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f" \
			  "\x40\x41\x42\x43\x44\x45\x46\x47" \
			  "\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f" \
			  "\x50\x51\x52\x53\x54\x55\x56\x57" \
			  "\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f" \
			  "\x60\x61\x62\x63\x64\x65\x66\x67" \
			  "\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f" \
			  "\x70\x71\x72\x73\x74\x75\x76\x77" \
			  "\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f" \
			  "\x80\x81\x82\x83\x84\x85\x86\x87" \
			  "\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f" \
			  "\x90\x91\x92\x93\x94\x95\x96\x97" \
			  "\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f" \
			  "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7" \
			  "\xa8\xa9\xaa\xab\xac\xad\xae\xaf" \
			  "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7" \
			  "\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf" \
			  "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7" \
			  "\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf" \
			  "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7" \
			  "\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf" \
			  "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7" \
			  "\xe8\xe9\xea\xeb\xec\xed\xee\xef" \
			  "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7" \
			  "\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" \
			  "\x00\x01\x02\x03\x04\x05\x06\x07" \
			  "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" \
			  "\x10\x11\x12\x13\x14\x15\x16\x17" \
			  "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" \
			  "\x20\x21\x22\x23\x24\x25\x26\x27" \
			  "\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f" \
			  "\x30\x31\x32\x33\x34\x35\x36\x37" \
			  "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f" \
			  "\x40\x41\x42\x43\x44\x45\x46\x47" \
			  "\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f" \
			  "\x50\x51\x52\x53\x54\x55\x56\x57" \
			  "\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f" \
			  "\x60\x61\x62\x63\x64\x65\x66\x67" \
			  "\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f" \
			  "\x70\x71\x72\x73\x74\x75\x76\x77" \
			  "\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f" \
			  "\x80\x81\x82\x83\x84\x85\x86\x87" \
			  "\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f" \
			  "\x90\x91\x92\x93\x94\x95\x96\x97" \
			  "\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f" \
			  "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7" \
			  "\xa8\xa9\xaa\xab\xac\xad\xae\xaf" \
			  "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7" \
			  "\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf" \
			  "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7" \
			  "\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf" \
			  "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7" \
			  "\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf" \
			  "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7" \
			  "\xe8\xe9\xea\xeb\xec\xed\xee\xef" \
			  "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7" \
			  "\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
#define RESULT_DATA  "\x1c\x3b\x3a\x10\x2f\x77\x03\x86"      \
			  "\xe4\x83\x6c\x99\xe3\x70\xcf\x9b" \
			  "\xea\x00\x80\x3f\x5e\x48\x23\x57" \
			  "\xa4\xae\x12\xd4\x14\xa3\xe6\x3b" \
			  "\x5d\x31\xe2\x76\xf8\xfe\x4a\x8d" \
			  "\x66\xb3\x17\xf9\xac\x68\x3f\x44" \
			  "\x68\x0a\x86\xac\x35\xad\xfc\x33" \
			  "\x45\xbe\xfe\xcb\x4b\xb1\x88\xfd" \
			  "\x57\x76\x92\x6c\x49\xa3\x09\x5e" \
			  "\xb1\x08\xfd\x10\x98\xba\xec\x70" \
			  "\xaa\xa6\x69\x99\xa7\x2a\x82\xf2" \
			  "\x7d\x84\x8b\x21\xd4\xa7\x41\xb0" \
			  "\xc5\xcd\x4d\x5f\xff\x9d\xac\x89" \
			  "\xae\xba\x12\x29\x61\xd0\x3a\x75" \
			  "\x71\x23\xe9\x87\x0f\x8a\xcf\x10" \
			  "\x00\x02\x08\x87\x89\x14\x29\xca" \
			  "\x2a\x3e\x7a\x7d\x7d\xf7\xb1\x03" \
			  "\x55\x16\x5c\x8b\x9a\x6d\x0a\x7d" \
			  "\xe8\xb0\x62\xc4\x50\x0d\xc4\xcd" \
			  "\x12\x0c\x0f\x74\x18\xda\xe3\xd0" \
			  "\xb5\x78\x1c\x34\x80\x3f\xa7\x54" \
			  "\x21\xc7\x90\xdf\xe1\xde\x18\x34" \
			  "\xf2\x80\xd7\x66\x7b\x32\x7f\x6c" \
			  "\x8c\xd7\x55\x7e\x12\xac\x3a\x0f" \
			  "\x93\xec\x05\xc5\x2e\x04\x93\xef" \
			  "\x31\xa1\x2d\x3d\x92\x60\xf7\x9a" \
			  "\x28\x9d\x6a\x37\x9b\xc7\x0c\x50" \
			  "\x84\x14\x73\xd1\xa8\xcc\x81\xec" \
			  "\x58\x3e\x96\x45\xe0\x7b\x8d\x96" \
			  "\x70\x65\x5b\xa5\xbb\xcf\xec\xc6" \
			  "\xdc\x39\x66\x38\x0a\xd8\xfe\xcb" \
			  "\x17\xb6\xba\x02\x46\x9a\x02\x0a" \
			  "\x84\xe1\x8e\x8f\x84\x25\x20\x70" \
			  "\xc1\x3e\x9f\x1f\x28\x9b\xe5\x4f" \
			  "\xbc\x48\x14\x57\x77\x8f\x61\x60" \
			  "\x15\xe1\x32\x7a\x02\xb1\x40\xf1" \
			  "\x50\x5e\xb3\x09\x32\x6d\x68\x37" \
			  "\x8f\x83\x74\x59\x5c\x84\x9d\x84" \
			  "\xf4\xc3\x33\xec\x44\x23\x88\x51" \
			  "\x43\xcb\x47\xbd\x71\xc5\xed\xae" \
			  "\x9b\xe6\x9a\x2f\xfe\xce\xb1\xbe" \
			  "\xc9\xde\x24\x4f\xbe\x15\x99\x2b" \
			  "\x11\xb7\x7c\x04\x0f\x12\xbd\x8f" \
			  "\x6a\x97\x5a\x44\xa0\xf9\x0c\x29" \
			  "\xa9\xab\xc3\xd4\xd8\x93\x92\x72" \
			  "\x84\xc5\x87\x54\xcc\xe2\x94\x52" \
			  "\x9f\x86\x14\xdc\xd2\xab\xa9\x91" \
			  "\x92\x5f\xed\xc4\xae\x74\xff\xac" \
			  "\x6e\x33\x3b\x93\xeb\x4a\xff\x04" \
			  "\x79\xda\x9a\x41\x0e\x44\x50\xe0" \
			  "\xdd\x7a\xe4\xc6\xe2\x91\x09\x00" \
			  "\x57\x5d\xa4\x01\xfc\x07\x05\x9f" \
			  "\x64\x5e\x8b\x7e\x9b\xfd\xef\x33" \
			  "\x94\x30\x54\xff\x84\x01\x14\x93" \
			  "\xc2\x7b\x34\x29\xea\xed\xb4\xed" \
			  "\x53\x76\x44\x1a\x77\xed\x43\x85" \
			  "\x1a\xd7\x7f\x16\xf5\x41\xdf\xd2" \
			  "\x69\xd5\x0d\x6a\x5f\x14\xfb\x0a" \
			  "\xab\x1c\xbb\x4c\x15\x50\xbe\x97" \
			  "\xf7\xab\x40\x66\x19\x3c\x4c\xaa" \
			  "\x77\x3d\xad\x38\x01\x4b\xd2\x09" \
			  "\x2f\xa7\x55\xc8\x24\xbb\x5e\x54" \
			  "\xc4\xf3\x6f\xfd\xa9\xfc\xea\x70" \
			  "\xb9\xc6\xe6\x93\xe1\x48\xc1\x51"
			
#define KEY_DATA "\x27\x18\x28\x18\x28\x45\x90\x45"\
		"\x23\x53\x60\x28\x74\x71\x35\x26"               \
		"\x62\x49\x77\x57\x24\x70\x93\x69"               \
		"\x99\x59\x57\x49\x66\x96\x76\x27"               \
		"\x31\x41\x59\x26\x53\x58\x97\x93"               \
		"\x23\x84\x62\x64\x33\x83\x27\x95"               \
		"\x02\x88\x41\x97\x16\x93\x99\x37"               \
		"\x51\x05\x82\x09\x74\x94\x45\x92"

#define IV_DATA "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#define CBC_KEY_DATA "\x06\xa9\x21\x40\x36\xb8\xa1\x5b" \
			  "\x51\x2e\x03\xd5\x34\x12\x00\x06"
#define CBC_IV_DATA "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30" \
			  "\xb4\x22\xda\x80\x2c\x9f\xac\x41"
#define CBC_TEST_DATA "Single block msg"
#define CBC_RESULT_DATA "\xe3\x53\x77\x9c\x10\x79\xae\xb8" \
			  "\x27\x08\x94\x2d\xbe\x77\x18\x1a"

struct crypto_dev {
	char *data;
	char *iv;
	char *key;

	size_t data_len;
};

extern void crypt_set_data(char *data, size_t len);
extern int encrypt_process(void);
extern int decrypt_process(void);
extern struct block_device *zspace_bdev_handle;

#endif //  __TEST_H