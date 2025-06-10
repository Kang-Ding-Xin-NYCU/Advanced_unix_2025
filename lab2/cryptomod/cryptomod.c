/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include "cryptomod.h"

#define BUFFER_SIZE 16384
#define AES_BLOCK_SIZE 16

struct crypto_device {
    char key[CM_KEY_MAX_LEN];
    int key_len;
    enum IOMode io_mode;
    enum CryptoMode c_mode;
    size_t data_len_in_enc;
	size_t data_len_out_enc;
	size_t data_len_in_dec;
	size_t data_len_out_dec;
    char *buffer_in_enc;
	char *buffer_out_enc;
	char *buffer_in_dec;
	char *buffer_out_dec;
    struct crypto_skcipher *tfm;
	bool finalize;
};

DEFINE_MUTEX(my_lock);
static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
static unsigned long total_bytes_read = 0;
static unsigned long total_bytes_written = 0;
static unsigned long byte_freq[256] = {0};

static int apply_pkcs7_padding(char *buffer, size_t *len) {
    size_t pad_len = CM_BLOCK_SIZE - (*len % CM_BLOCK_SIZE);
	if (pad_len == 0) pad_len = CM_BLOCK_SIZE;
    if (*len + pad_len > BUFFER_SIZE) return -ENOMEM;

    memset(buffer + *len, pad_len, pad_len);
    *len += pad_len;
    return 0;
}

static int remove_pkcs7_padding(char *buffer, size_t *len) {
    size_t pad_len = buffer[*len - 1];
    if (pad_len > CM_BLOCK_SIZE || pad_len > *len) return -EINVAL;
    *len -= pad_len;
    return 0;
}

static int aes_process(struct crypto_device *dev, int encrypt) {
    struct scatterlist sg_in, sg_out;
    struct skcipher_request *req;
    struct crypto_skcipher *tfm = dev->tfm;
    int ret;
	size_t process_len;

    if (encrypt) {
        if (!dev->buffer_in_enc || !dev->buffer_out_enc)
            return -EINVAL;
    } 
	else {
        if (!dev->buffer_in_dec || !dev->buffer_out_dec)
            return -EINVAL;
    }

	if (dev->io_mode == BASIC) {
		if (encrypt) {
			process_len = dev->data_len_in_enc - (dev->data_len_in_enc % AES_BLOCK_SIZE);
		}
		else {
			process_len = dev->data_len_in_dec - (dev->data_len_in_dec % AES_BLOCK_SIZE);
		}
	}
	else {
		if (encrypt) {
			process_len = dev->data_len_in_enc - (dev->data_len_in_enc % AES_BLOCK_SIZE);
		}
		else {
			if (dev->data_len_in_dec > AES_BLOCK_SIZE) {
				process_len = dev->data_len_in_dec - (dev->data_len_in_dec % AES_BLOCK_SIZE) - AES_BLOCK_SIZE;
			}
			else {
				process_len = 0;
			}
			
		}
	}

	if (process_len == 0) {
		return 0;
	}

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) return -ENOMEM;

    if (encrypt) {
        sg_init_one(&sg_in, dev->buffer_in_enc, process_len);
		if (dev->buffer_out_enc + dev->data_len_out_enc > dev->buffer_out_enc + BUFFER_SIZE) {
			return -EINVAL;
		}			
        sg_init_one(&sg_out, dev->buffer_out_enc + dev->data_len_out_enc, process_len);
        skcipher_request_set_crypt(req, &sg_in, &sg_out, process_len, NULL);
    } 
	else {
        sg_init_one(&sg_in, dev->buffer_in_dec, process_len);
		if (dev->buffer_out_dec + dev->data_len_out_dec > dev->buffer_out_dec + BUFFER_SIZE) {
			return -EINVAL;
		}		
        sg_init_one(&sg_out, dev->buffer_out_dec + dev->data_len_out_dec, process_len);
        skcipher_request_set_crypt(req, &sg_in, &sg_out, process_len, NULL);
    }

    ret = encrypt ? crypto_skcipher_encrypt(req) : crypto_skcipher_decrypt(req);
    skcipher_request_free(req);

    if (ret) {
		printk(KERN_ERR "AES process error: %d\n", ret);
		return ret;
	}
	

    if (encrypt) {
        dev->data_len_out_enc += process_len;
        memset(dev->buffer_in_enc, 0, process_len);
        memmove(dev->buffer_in_enc, dev->buffer_in_enc + process_len,
                dev->data_len_in_enc - process_len);
        dev->data_len_in_enc -= process_len;
    }
    else {
        dev->data_len_out_dec += process_len;
        memset(dev->buffer_in_dec, 0, process_len);
        memmove(dev->buffer_in_dec, dev->buffer_in_dec + process_len,
                dev->data_len_in_dec - process_len);
        dev->data_len_in_dec -= process_len;
    }

    return 0;
}

static int cryptomod_open(struct inode *inode, struct file *file) {
    struct crypto_device *dev;

    dev = kmalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;

    dev->buffer_in_enc = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	dev->buffer_in_dec = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	dev->buffer_out_enc = kmalloc(BUFFER_SIZE, GFP_KERNEL);
	dev->buffer_out_dec = kmalloc(BUFFER_SIZE, GFP_KERNEL);

    if (!dev->buffer_in_enc || !dev->buffer_in_dec || !dev->buffer_out_dec || !dev->buffer_out_enc) {
        printk(KERN_ERR "cryptomod_open: kmalloc failed\n");
		kfree(dev->buffer_in_enc);
    	kfree(dev->buffer_in_dec);
    	kfree(dev->buffer_out_enc);
    	kfree(dev->buffer_out_dec);
    	kfree(dev);
        return -ENOMEM;
    }

    dev->data_len_in_enc = 0;
	dev->data_len_in_dec = 0;
	dev->data_len_out_enc = 0;
	dev->data_len_out_dec = 0;
	dev->key_len = 0;
	dev->finalize = false;

    dev->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);

    if (IS_ERR(dev->tfm)) {
        kfree(dev->buffer_in_enc);
		kfree(dev->buffer_in_dec);
		kfree(dev->buffer_out_enc);
		kfree(dev->buffer_out_dec);
        kfree(dev);
        return -EINVAL;
    }

    file->private_data = dev;
    return 0;
}

static int cryptomod_release(struct inode *inode, struct file *file) {
    struct crypto_device *dev = file->private_data;
    if (dev) {
        crypto_free_skcipher(dev->tfm);
        kfree(dev->buffer_in_enc);
		kfree(dev->buffer_in_dec);
		kfree(dev->buffer_out_enc);
		kfree(dev->buffer_out_dec);
        kfree(dev);
		file->private_data = NULL;
    }
    return 0;
}

static ssize_t cryptomod_read(struct file *file, char __user *user_buf, size_t count, loff_t *pos) {
    struct crypto_device *dev = file->private_data;
    ssize_t retval = 0;

    if (!dev || !dev->buffer_out_dec || !dev->buffer_out_enc) {
		return -EINVAL;
	}

	if ((dev->key_len != 16 && dev->key_len != 24 && dev->key_len != 32) || (dev->io_mode != BASIC && dev->io_mode != ADV) || (dev->c_mode != ENC && dev->c_mode != DEC)) {
		return -EINVAL;
	}

    if (dev->c_mode == ENC && count > dev->data_len_out_enc) {
		count = dev->data_len_out_enc;
	}
	else if (dev->c_mode == DEC && count > dev->data_len_out_dec) {
		count = dev->data_len_out_dec;
	}
	
	if (dev->io_mode == BASIC) {
		if (dev->c_mode == ENC) {
			if (copy_to_user(user_buf, dev->buffer_out_enc, count)) {
				retval = -EBUSY;
				goto out;
			}
			for (size_t i = 0; i < count; i++) {
				mutex_lock(&my_lock);
				byte_freq[(unsigned char)dev->buffer_out_enc[i]]++;
				mutex_unlock(&my_lock);
			}
			memmove(dev->buffer_out_enc, dev->buffer_out_enc + count, dev->data_len_out_enc - count);
			dev->data_len_out_enc -= count;
		}
		else if (dev->c_mode == DEC) {
			if (copy_to_user(user_buf, dev->buffer_out_dec, count)) {
				retval = -EBUSY;
				goto out;
			}
			memmove(dev->buffer_out_dec, dev->buffer_out_dec + count, dev->data_len_out_dec - count);
			dev->data_len_out_dec -= count;
		}
		mutex_lock(&my_lock);
		total_bytes_read += count;
		mutex_unlock(&my_lock);
		
		retval = count;
	}
	else if (dev->io_mode == ADV) {
		if (dev->c_mode == ENC) {
			if (copy_to_user(user_buf, dev->buffer_out_enc, count)) {
				retval = -EBUSY;
				goto out;
			}			
			for (size_t i = 0; i < count; i++) {
				mutex_lock(&my_lock);
				byte_freq[(unsigned char)dev->buffer_out_enc[i]]++;
				mutex_unlock(&my_lock);
			}
			memmove(dev->buffer_out_enc, dev->buffer_out_enc + count, dev->data_len_out_enc - count);
			dev->data_len_out_enc -= count;
		}
		else if (dev->c_mode == DEC) {
			if (copy_to_user(user_buf, dev->buffer_out_dec, count)) {
				retval = -EBUSY;
				goto out;
			}
			memmove(dev->buffer_out_dec, dev->buffer_out_dec + count, dev->data_len_out_dec - count);
			dev->data_len_out_dec -= count;
		}
		mutex_lock(&my_lock);
		total_bytes_read += count;
		mutex_unlock(&my_lock);
		
		retval = count;
	}

out:
    return retval;
}

static ssize_t cryptomod_write(struct file *file, const char __user *user_buf, size_t count, loff_t *pos) {

    struct crypto_device *dev = file->private_data;
    ssize_t retval = 0;

    if (!dev || !dev->buffer_in_enc || !dev->buffer_in_dec) {
		return -EINVAL;
	}

	if ((dev->key_len != 16 && dev->key_len != 24 && dev->key_len != 32) || (dev->io_mode != BASIC && dev->io_mode != ADV) || (dev->c_mode != ENC && dev->c_mode != DEC)) {
		return -EINVAL;
	}

	if (dev->finalize == true) {
		return -EINVAL;
	}

	size_t remaining;
	
	if (dev->io_mode == BASIC) {
		if (dev->c_mode == ENC) {
			remaining = BUFFER_SIZE - dev->data_len_in_enc;
			if (count > remaining) {
				count = remaining;
			}
			if (copy_from_user(dev->buffer_in_enc + dev->data_len_in_enc, user_buf, count)) {
				retval = -EBUSY;
				goto out;
			}
			dev->data_len_in_enc += count;
		}
		else if (dev->c_mode == DEC) {
			remaining = BUFFER_SIZE - dev->data_len_in_dec;
			if (count > remaining) {
				count = remaining;
			}
			if (copy_from_user(dev->buffer_in_dec + dev->data_len_in_dec, user_buf, count)) {
				retval = -EBUSY;
				goto out;
			}
			dev->data_len_in_dec += count;
		}
	}
	else if (dev->io_mode == ADV) {
		if (dev->c_mode == ENC) {
			remaining = BUFFER_SIZE - dev->data_len_in_enc;
			if (count > remaining) {
				count = remaining;
			}
			if (copy_from_user(dev->buffer_in_enc + dev->data_len_in_enc, user_buf, count)) {
				retval = -EBUSY;
				goto out;
			}
			dev->data_len_in_enc += count;
			aes_process(dev, 1);
		}
		else if (dev->c_mode == DEC) {
			remaining = BUFFER_SIZE - dev->data_len_in_dec;
			if (count > remaining) {
				count = remaining;
			}
			if (copy_from_user(dev->buffer_in_dec + dev->data_len_in_dec, user_buf, count)) {
				retval = -EBUSY;
				goto out;
			}
			dev->data_len_in_dec += count;
			if (dev->data_len_in_dec > AES_BLOCK_SIZE) {
				aes_process(dev, 0);
			}
		}
	}
	mutex_lock(&my_lock);
	total_bytes_written += count;
	mutex_unlock(&my_lock);
    
    retval = count;

out:
    return retval;
}


static long cryptomod_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct crypto_device *dev = file->private_data;
    struct CryptoSetup setup;
    int ret = 0;

    if (!dev) {
		return -EINVAL;
	}

    switch (cmd) {
        case CM_IOC_SETUP:
            if (copy_from_user(&setup, (struct CryptoSetup __user *)arg, sizeof(setup))) {
                ret = -EINVAL;
                goto out;
            }

            if (setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32) {
                ret = -EINVAL;
                goto out;
            }

            if (setup.io_mode != BASIC && setup.io_mode != ADV) {
                ret = -EINVAL;
                goto out;
            }

            if (setup.c_mode != ENC && setup.c_mode != DEC) {
                ret = -EINVAL;
                goto out;
            }

            memcpy(dev->key, setup.key, setup.key_len);
            dev->key_len = setup.key_len;
            dev->io_mode = setup.io_mode;
            dev->c_mode = setup.c_mode;

			ret = crypto_skcipher_setkey(dev->tfm, dev->key, dev->key_len);
            if (ret) {
                goto out;
            }
            break;

		case CM_IOC_FINALIZE:

			if ((dev->key_len != 16 && dev->key_len != 24 && dev->key_len != 32) || (dev->io_mode != BASIC && dev->io_mode != ADV) || (dev->c_mode != ENC && dev->c_mode != DEC)) {
				return -EINVAL;
			}
			
			if (dev->io_mode == BASIC) {
				if (dev->c_mode == ENC) {
					ret = apply_pkcs7_padding(dev->buffer_in_enc, &dev->data_len_in_enc);
					if (ret) goto out;
					ret = aes_process(dev, 1);
					if (ret) goto out;
				}				
				else if (dev->c_mode == DEC) {
					ret = aes_process(dev, 0);
					if (ret) goto out;
					ret = remove_pkcs7_padding(dev->buffer_out_dec, &dev->data_len_out_dec);
					if (ret) goto out;
				}
			}
			else if (dev->io_mode == ADV) {
				if (dev->c_mode == ENC) {
					ret = apply_pkcs7_padding(dev->buffer_in_enc, &dev->data_len_in_enc);
					if (ret) goto out;
					ret = aes_process(dev, 1);
					if (ret) goto out;
				}				
				else if (dev->c_mode == DEC) {
					ret = aes_process(dev, 0);
					if (ret) goto out;
				}
			}

			dev->finalize = true;

			if (ret) {
			}
			break;
		

        case CM_IOC_CLEANUP:
            memset(dev->buffer_in_enc, 0, dev->data_len_in_enc);
			memset(dev->buffer_in_dec, 0, dev->data_len_in_dec);
			memset(dev->buffer_out_enc, 0, dev->data_len_out_enc);
			memset(dev->buffer_out_dec, 0, dev->data_len_out_dec);
            dev->data_len_in_enc = 0;
			dev->data_len_in_dec = 0;
			dev->data_len_out_enc = 0;
			dev->data_len_out_dec = 0;
            break;

        case CM_IOC_CNT_RST:
			mutex_lock(&my_lock);
			total_bytes_read = 0;
            total_bytes_written = 0;
            memset(byte_freq, 0, sizeof(byte_freq));
			mutex_unlock(&my_lock);
            break;

        default:
            ret = -EINVAL;
            break;
    }

out:
    return ret;
}


static const struct file_operations cryptodev_fops = {
    .owner = THIS_MODULE,
    .open = cryptomod_open,
    .read = cryptomod_read,
    .write = cryptomod_write,
    .unlocked_ioctl = cryptomod_ioctl,
    .release = cryptomod_release
};
 
static int cryptomod_proc_read(struct seq_file *m, void *v) {
    int i, j;

	mutex_lock(&my_lock);
	seq_printf(m, "%lu %lu\n", total_bytes_read, total_bytes_written);
	mutex_unlock(&my_lock);

    for (i = 0; i < 256; i += 16) {
        for (j = 0; j < 16; j++) {
			mutex_lock(&my_lock);
			seq_printf(m, "%lu ", byte_freq[i + j]);
			mutex_unlock(&my_lock);
        }
        seq_printf(m, "\n");
    }

    return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, cryptomod_proc_read, NULL);
}
 
static const struct proc_ops cryptomod_proc_fops = {
	.proc_open = cryptomod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *cryptodevnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init cryptomod_init(void) {
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = cryptodevnode;
	if(device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL)
		goto release_class;
	cdev_init(&c_dev, &cryptodev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;
	
	proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);
 
	return 0;
 
release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}
 
static void __exit cryptomod_cleanup(void){
	remove_proc_entry("cryptomod", NULL);
 
	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);
}
 
module_init(cryptomod_init);
module_exit(cryptomod_cleanup);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");