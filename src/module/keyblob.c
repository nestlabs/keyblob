/*
 * Copyright (C) 2017 Google Inc.

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *      
 *      You should have received a copy of the GNU General Public License along
 *      with this program; if not, write to the Free Software Foundation, Inc.,
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 *    Description:
 *      This is a Linux kernel module for producing keys wrapped with CAAM Blob
 *      protocol and injecting them into kernel keyring service.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <keys/user-type.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/key-type.h>
#include <linux/key.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <caam/intern.h>
#include <caam/snvsregs.h>
#include <caam/sm.h>

#include "error.h"
#include "keyblob.h"

MODULE_LICENSE("Dual BSD/GPL");

/* Used to prevent multiple access to device */
static DEFINE_SEMAPHORE(s_sem);

/* Buffer to hold request sent from user space */
static u8 s_request_buf[REQUEST_BUF_LEN];

/*
 * s_keymod is used to generate derived keys used with blob. The following value
 * was randomly generated for KeyBlob driver. This is not a secret.
 */
static u8 s_keymod[] = {
    0xe2, 0x01, 0x06, 0x50, 0x57, 0x74, 0x52, 0x4d,
    0x1e, 0xb2, 0x35, 0x5d, 0x30, 0x05, 0x2b, 0xf2,
};

/*
 * Structure to hold response data and internal data to handle read().
 */
static struct result_data_t
{
    u16 length;     /* Bytes actually occupied in buffer */
    u8 buffer[RESPONSE_BUF_LEN];
} s_result_data;

static inline void set_result(struct result_data_t *rd, u8 type, void *data,
                              u16 datalen)
{
    struct response_t *res;

    memset(rd->buffer, 0, RESPONSE_BUF_LEN);
    res  = (struct response_t *)rd->buffer;

    if (datalen > (RESPONSE_BUF_LEN
                    - member_sizeof(struct response_t, length)
                    - member_sizeof(struct response_t, type)))
    {
        u8 error = ERROR_CODE_RESPONSE_TOO_LARGE;

        // Insufficient buffer size to encode response
        res->type = RESULT_CODE_ERROR;
        res->length = sizeof(error);
        memcpy(res->data, &error, sizeof(error));
    }
    else
    {
        res->type = type;
        res->length = datalen;
        if (data && datalen)
            memcpy(res->data, data, datalen);
    }

    rd->length = sizeof(struct response_t) + res->length;
}

static inline void set_result_success(struct result_data_t *rd)
{
    set_result(rd, RESULT_CODE_SUCCESS, NULL, 0);
}

static inline void set_result_error(struct result_data_t *rd, int error)
{
    set_result(rd, RESULT_CODE_ERROR, &error, sizeof(error));
}

static int insert_key_in_user_keyring(uid_t uid, const char *description,
                                      const void *payload, size_t plen)
{
    int rc = 0;
    struct key *keyring;
    key_ref_t key_ref;
    char keyringname[20];
    const char user_type[] = "user";
    const int perm = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH
                     | KEY_USR_VIEW;

    snprintf(keyringname, sizeof(keyringname), "_uid.%d", uid);

    /* Look up user's keyring */
    keyring = request_key(&key_type_keyring, keyringname, NULL);
    if (IS_ERR(keyring))
    {
        rc = PTR_ERR(keyring);
        pr_err("request_key() for user keyring %s failed with %d\n",
               keyringname, rc);
        goto exit;
    }

    /* Make sure specified key is not in keyring already */
    key_ref = keyring_search(make_key_ref(keyring, 1), &key_type_user,
                             description);
    if (!IS_ERR(key_ref))
    {
        pr_warning("Key %s is already in user keyring %s\n", description,
                   keyringname);
        key_ref_put(key_ref);
        goto release_keyring;
    }
    else if (PTR_ERR(key_ref) != -EAGAIN)
    {
        rc = PTR_ERR(key_ref);
        pr_err("keyring_search() for user keyring %s with description %s"
               " failed with %d\n", keyringname, description, rc);
        goto release_keyring;
    }

    /* Create a new key.
     *
     * key_create_or_update() creates a new key if it cannot be found in the
     * provided keyring, or updates an existing key. While the above search in
     * the keyring prevents us from calling key_create_or_update(), we also set
     * permission mask such that a key cannot be modified after it is created.
     *
     * Few important notes with this call:
     *  - Key is created with owner UID and group access ID from current task
     *    credential's FSUID and FSGID. These values are equivalent to the
     *    effective UID/GID of the process accessing this driver.
     *  - Key has a notion of a possessor, which in this context is the owner of
     *    the user keyring.
     *  - Based on above, we set the permission mask such that only the
     *    possessor can search and read the key. The owner may view the
     *    attributes of the key but cannot search or read the content. As the
     *    key must not be changed after set, write permission is not granted to
     *    any.
     *  - Finally, this key does not count toward user's quota.
     */
    key_ref = key_create_or_update(make_key_ref(keyring, 1),
                                   user_type, description, payload, plen,
                                   perm, KEY_ALLOC_NOT_IN_QUOTA);
    if (IS_ERR(key_ref))
    {
        rc = PTR_ERR(key_ref);
        pr_err("key_create_or_update() for user keyring %s with description %s"
               " failed with %d\n", keyringname, description, rc);
        goto release_keyring;
    }

    /* Success! */
    pr_notice("Loaded key %s in keyring %s\n",
              key_ref_to_ptr(key_ref)->description, keyringname);
    key_ref_put(key_ref);

release_keyring:
    key_put(keyring);
exit:
    return rc;
}

static int keyblob_dev_open(struct inode *inode, struct file *file)
{
    pr_debug("%s\n", __FUNCTION__);

    if (down_trylock(&s_sem))
        return -EBUSY;

    try_module_get(THIS_MODULE);

    return 0;
}

static int keyblob_dev_release(struct inode *inode, struct file *file)
{
    pr_debug("%s\n", __FUNCTION__);

    /*
     * Decrement the usage count, or else once you opened the file, you'll
     * never get rid of the module.
     */
    module_put(THIS_MODULE);
    up(&s_sem);

    return 0;
}

static ssize_t keyblob_dev_read(struct file *filp, char __user *buffer,
                                size_t length, loff_t *offset)
{
    pr_debug("%s\n", __FUNCTION__);

    if (*offset >= s_result_data.length)
        return 0;

    if (*offset + length > s_result_data.length)
        length = s_result_data.length - *offset;

    if (copy_to_user(buffer, s_result_data.buffer + *offset, length))
        return -EFAULT;

    *offset += length;

    return length;
}

/*
 * Get CAAM's device node.
 *
 * On a successful return, caller must call of_node_put() on returned device
 * node.
 */
static int get_caam_device_node(struct device_node **dev_node,
                                struct platform_device **pdev)
{
    if (!dev_node || !pdev)
        return -EINVAL;

    *dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");
    if (!*dev_node)
    {
        *dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
        if (!*dev_node)
            return -ENODEV;
    }

    *pdev = of_find_device_by_node(*dev_node);
    if (!*pdev)
        return -ENODEV;

    /* Retain the device, caller is suppose to call of_node_put() */
    of_node_get(*dev_node);

    return 0;
}

/*
 * Get CAAM's Secure Memory device.
 */
static int get_sm_device(struct platform_device *pdev, struct device **smdev)
{
    struct device *ctrldev;
    struct caam_drv_private *ctrlpriv;

    if (!pdev || !smdev)
        return -EINVAL;

    ctrldev = &pdev->dev;
    if (!ctrldev)
        return -ENODEV;

    ctrlpriv = dev_get_drvdata(ctrldev);
    if (!ctrlpriv)
        return -ENODEV;

    *smdev = ctrlpriv->smdev;
    if (!(*smdev))
        return -ENODEV;

    return 0;
}

/*
 * Encapsulate (export) or decapsulate (import) key in Blob protocol.
 */
static int sm_keyblob_operation(u8 __iomem *key, u32 keylen, u8 __iomem *blob,
                                u32 bloblen, bool import)
{
    int rc;
    struct device_node *np;
    struct platform_device *pdev;
    struct device *smdev;
    u32 units, unit, keyslot;

    if (!key || !blob)
        return -EINVAL;

    if (GET_BLOB_SIZE(keylen) != bloblen)
    {
        pr_err("bloblen does not match expected length\n");
        return -EINVAL;
    }

    rc = get_caam_device_node(&np, &pdev);
    if (rc < 0)
    {
        pr_err("Failed to get caam device node");
        return rc;
    }

    rc = get_sm_device(pdev, &smdev);
    if (rc < 0)
    {
        pr_err("Failed to get secure memory device");
        goto release_of;
    }

    units = sm_detect_keystore_units(smdev);
    if (!units)
    {
        pr_err("No keystore units available\n");
        rc = -ENODEV;
        goto release_of;
    }
    else if (units < 2)
    {
        pr_err("Insufficient keystore units\n");
        rc = -ENODEV;
        goto release_of;
    }

    /*
     * MX6 bootloader stores some stuff in unit0, so we use 1 or above.
     */
    unit = 1;

    rc = sm_establish_keystore(smdev, unit);
    if (rc)
    {
        pr_err("sm_establish_keystore() failed with %d\n", rc);
        goto release_of;
    }

    rc = sm_keystore_slot_alloc(smdev, unit, AES_BLOCK_PAD(keylen), &keyslot);
    if (rc)
    {
        pr_err("sm_keystore_slot_alloc() failed with %d\n", rc);
        goto release_keystore;
    }

    if (import)
    {
        rc = sm_keystore_slot_import(smdev, unit, keyslot, RED_KEY,
                                     KEY_COVER_ECB, blob, keylen, s_keymod);
        if (rc)
        {
            pr_err("sm_keystore_slot_import() failed with %d\n", rc);
            goto release_keystore_slot;
        }
        rc = sm_keystore_slot_read(smdev, unit, keyslot, keylen, key);
        if (rc)
        {
            pr_err("sm_keystore_slot_read() failed with %d\n", rc);
            goto release_keystore_slot;
        }
    }
    else
    {
        rc = sm_keystore_slot_load(smdev, unit, keyslot, key, keylen);
        if (rc)
        {
            pr_err("sm_keystore_slot_load() failed with %d\n", rc);
            goto release_keystore_slot;
        }
        rc = sm_keystore_slot_export(smdev, unit, keyslot, RED_KEY,
                                     KEY_COVER_ECB, blob, keylen, s_keymod);
        if (rc)
        {
            pr_err("sm_keystore_slot_export() failed with %d\n", rc);
            goto release_keystore_slot;
        }
    }

release_keystore_slot:
    /* We can't really do anything when failed to deallocate a slot */
    (void)sm_keystore_slot_dealloc(smdev, unit, keyslot);
release_keystore:
    sm_release_keystore(smdev, unit);
release_of:
    of_node_put(np);
    return rc;
}

/*
 * Unpack a single variable from provided buffer. Endianness is
 * platform-defined.
 */
static inline int unpack_var(void *var, size_t varsize,
                             const u8 **buffer, size_t *length)
{
    if (*length < varsize)
    {
        pr_err("Insufficient data in buffer.");
        return -1;
    }

    memcpy(var, *buffer, varsize);
    *buffer += varsize;
    *length -= varsize;
    return 0;
}

/*
 * Unpack an array from provided buffer. Array has a length field followed by
 * the array data. arr points to the data in buffer and data is not copied.
 * Length field must be 2-byte.
 */
static inline int unpack_array(const u8 **arr, u16 *arrlen,
                               const u8 **buffer, size_t *length)
{
    int rc = unpack_var(arrlen, sizeof(*arrlen), buffer, length);
    if (rc != 0)
        return rc;

    if (*length < *arrlen)
    {
        pr_err("Insufficient data in buffer.");
        return -1;
    }

    if (*arrlen == 0)
    {
        pr_err("Buffer contains zero-length array.");
        return -1;
    }

    *arr = *buffer;
    *buffer += *arrlen;
    *length -= *arrlen;
    return 0;
}

/*
 * Unpack a string from provided buffer. This function internally uses
 * unpack_array to get an array and check that the string is NULL terminated
 * and is a non-zero length. strlen is the number of characters in str
 * excluding the NULL character.
 */
static inline int unpack_string(const char **str, u16 *strlen,
                                const u8 **buffer, size_t *length)
{
    int rc = unpack_array((const u8 **)str, strlen, buffer, length);
    if (rc != 0)
        return rc;

    /* Make sure there's a valid buffer. */
    if (*strlen <= 1)
    {
        pr_err("Buffer contains zero-length string.");
        return -1;
    }

    /* Make sure string is null terminated. */
    if ((*str)[*strlen-1] != '\0')
    {
        pr_err("String in buffer is not NULL terminated.");
        return -1;
    }

    /* Return length of string excluding the NULL character. */
    (*strlen)--;

    return 0;
}

/*
 * GenRandKey command formats the request as:
 *
 *   type        description
 *   ----------------------------------------------
 *   u8          Length of key to generate.
 */
static int keyblob_command_gen_rand_key(const u8 *buffer, size_t length)
{
    int rc;
    u8 keylen;
    u8 __iomem *key = NULL;
    u8 __iomem *keyblob = NULL;
    u16 keybloblen;

    pr_debug("%s\n", __FUNCTION__);

    rc = unpack_var(&keylen, sizeof(keylen), &buffer, &length);
    if (rc == -1)
        return -ERROR_CODE_INVALID_FORMAT;

    pr_debug("Generating key size %u\n", keylen);

    key = kzalloc(keylen, GFP_KERNEL | GFP_DMA);
    if (!key)
    {
        pr_err("kmalloc() failed\n");
        rc = -ERR_INTERNAL_ERROR(ENOMEM);
        goto exit;
    }

#ifdef FIXED_KEY
#error FIXED_KEY must not be enabled!
    {
        static const u8 fixedkey[256] = {
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            /* Remainder are zero */
        };

        pr_alert("!! Using a fixed key !!\n");
        memcpy(key, fixedkey, keylen);
    }
#else
    get_random_bytes(key, keylen);
#endif

    keybloblen = GET_BLOB_SIZE(keylen);
    keyblob = kzalloc(keybloblen, GFP_KERNEL | GFP_DMA);
    if (!keyblob)
    {
        pr_err("kmalloc() failed\n");
        rc = -ERR_INTERNAL_ERROR(ENOMEM);
        goto exit;
    }

    rc = sm_keyblob_operation(key, keylen, keyblob, keybloblen,
                              /*import=*/false);
    if (rc < 0)
    {
        rc = -ERR_INTERNAL_ERROR(-rc);
        pr_err("keyblob export failed\n");
        goto exit;
    }

    set_result(&s_result_data, RESULT_CODE_KEYBLOB, keyblob, keybloblen);
    rc = 0;

exit:
    if (key)
        kfree(key);
    if (keyblob)
        kfree(keyblob);

    return rc;
}

/*
 * LoadDirect command formats the request as:
 *
 *   type        description
 *   ----------------------------------------------
 *   uid_t       UID used for the keyring
 *   u8          Length of key
 *   u16         Length of key description string
 *   <variable>  Key description string
 *   u16         Length of KeyBlob data
 *   <variable>  KeyBlob data
 */
static int keyblob_command_load_direct(const u8 *buffer, size_t length)
{
    int rc;
    uid_t uid;
    u8 keylen;
    u16 keydesclen;
    const char *keydesc;
    u16 keybloblen;
    const u8 *keyblobtmp;
    u8 __iomem *key = NULL;
    u8 __iomem *keyblob = NULL;

    pr_debug("%s\n", __FUNCTION__);

    /* Unpack all the fields */
    rc = unpack_var(&uid, sizeof(uid), &buffer, &length);
    if (rc != 0)
        return -ERROR_CODE_INVALID_FORMAT;
    rc = unpack_var(&keylen, sizeof(keylen), &buffer, &length);
    if (rc != 0)
        return -ERROR_CODE_INVALID_FORMAT;
    rc = unpack_string(&keydesc, &keydesclen, &buffer, &length);
    if (rc != 0)
        return -ERROR_CODE_INVALID_FORMAT;
    rc = unpack_array(&keyblobtmp, &keybloblen, &buffer, &length);
    if (rc != 0)
        return -ERROR_CODE_INVALID_FORMAT;

    /* Make sure blob length matches specified keylen */
    if (GET_BLOB_SIZE(keylen) != keybloblen)
    {
        pr_err("keyblob size does not match keylen: "
               "%u (expected) != %u (actual)\n",
               GET_BLOB_SIZE(keylen), keybloblen);
        rc = -ERROR_CODE_INVALID_FORMAT;
        goto exit;
    }

    /* Key needs to be large enough to hold the overhead of AES block. */
    key = kzalloc(AES_BLOCK_PAD(keylen), GFP_KERNEL | GFP_DMA);
    if (!key)
    {
        pr_err("kmalloc() failed\n");
        rc = -ERR_INTERNAL_ERROR(ENOMEM);
        goto exit;
    }

    /* Allocate DMA friendly memory for keyblob */
    keyblob = kzalloc(keybloblen, GFP_KERNEL | GFP_DMA);
    if (!keyblob)
    {
        pr_err("kmalloc() failed\n");
        rc = -ERR_INTERNAL_ERROR(ENOMEM);
        goto exit;
    }
    memcpy(keyblob, keyblobtmp, keybloblen);

    rc = sm_keyblob_operation(key, keylen, keyblob, keybloblen,
                              /*import=*/true);
    if (rc < 0)
    {
        rc = -ERR_INTERNAL_ERROR(-rc);
        pr_err("keyblob import failed\n");
        goto exit;
    }

    /* Finally put the key into a keyring */
    rc = insert_key_in_user_keyring(uid, keydesc, key, keylen);
    if (rc)
    {
        rc = -ERR_INTERNAL_ERROR(-rc);
        goto exit;
    }

    set_result_success(&s_result_data);
    rc = 0;

exit:
    if (key)
        kfree(key);
    if (keyblob)
        kfree(keyblob);

    return rc;
}

/*
 * EncryptKey command formats the request as:
 *
 *   type        description
 *   ----------------------------------------------
 *   uint16_t    Length of key
 *   <variable>  Key
 */
static int keyblob_command_encrypt_key(const u8 *buffer, size_t length)
{
    int rc;
    u16 keylen;
    const char *inkey;
    u16 keybloblen;
    u8 __iomem *key = NULL;
    u8 __iomem *keyblob = NULL;

    pr_debug("%s\n", __FUNCTION__);

    /* Unpack all the fields */
    rc = unpack_array(&inkey, &keylen, &buffer, &length);
    if (rc != 0)
        return -ERROR_CODE_INVALID_FORMAT;

    /* Key needs to be large enough to hold the overhead of AES block. */
    key = kzalloc(AES_BLOCK_PAD(keylen), GFP_KERNEL | GFP_DMA);
    if (!key)
    {
        pr_err("kmalloc() failed\n");
        rc = -ERR_INTERNAL_ERROR(ENOMEM);
        goto exit;
    }
    memcpy(key, inkey, keylen);

    /* Allocate DMA friendly memory for keyblob */
    keybloblen = GET_BLOB_SIZE(keylen);
    keyblob = kzalloc(keybloblen, GFP_KERNEL | GFP_DMA);
    if (!keyblob)
    {
        pr_err("kmalloc() failed\n");
        rc = -ERR_INTERNAL_ERROR(ENOMEM);
        goto exit;
    }

    rc = sm_keyblob_operation(key, keylen, keyblob, keybloblen,
                              /*import=*/false);
    if (rc < 0)
    {
        rc = -ERR_INTERNAL_ERROR(-rc);
        pr_err("keyblob export failed\n");
        goto exit;
    }

    set_result(&s_result_data, RESULT_CODE_KEYBLOB, keyblob, keybloblen);
    rc = 0;

exit:
    if (key)
        kfree(key);
    if (keyblob)
        kfree(keyblob);

    return rc;
}

/*
 * Dispatch KeyBlob request to matching command funcitons.
 *
 * Request is formatted as
 *
 *   type        description
 *   ----------------------------------------------
 *   u16         Length of request
 *   u8          Command type
 *   <variable>  Command data (size is <length of request> - 1)
 */
static int keyblob_dispatch_command(const u8 *buffer, size_t length)
{
    int rc;
    u16 len = 0;
    u8 command;

    pr_debug("%s\n", __FUNCTION__);

    rc = unpack_var(&len, sizeof(len), &buffer, &length);
    if (rc != 0)
    {
        return -ERROR_CODE_INVALID_FORMAT;
    }
    else if (len != length)
    {
        pr_err("Length mismatch: %u (in request) != %zu (received)\n",
               len, length);
        return -ERROR_CODE_INVALID_FORMAT;
    }

    rc = unpack_var(&command, sizeof(command), &buffer, &length);
    if (rc != 0)
        return -ERROR_CODE_INVALID_FORMAT;

    switch (command) {
        case COMMAND_GENRANDKEY:
            rc = keyblob_command_gen_rand_key(buffer, length);
            break;

        case COMMAND_LOADDIRECT:
            rc = keyblob_command_load_direct(buffer, length);
            break;

        case COMMAND_ENCRYPTKEY:
            rc = keyblob_command_encrypt_key(buffer, length);
            break;

        default:
            pr_warning("Unknown command: %d\n", command);
            rc = ERROR_CODE_UNKNOWN_COMMAND;
            break;
    }

    return rc;
}

static ssize_t keyblob_dev_write(struct file *filp, const char __user *buffer,
                                 size_t length, loff_t *offset)
{
    int rc;

    pr_debug("%s\n", __FUNCTION__);

    /* Clear previous result */
    memset(&s_result_data, 0, sizeof(struct result_data_t));
    memset(s_request_buf, 0, sizeof(s_request_buf));

    if (length > sizeof(s_request_buf))
        return -EINVAL;

    if (copy_from_user(s_request_buf, buffer, length))
        return -EFAULT;

    rc = keyblob_dispatch_command(s_request_buf, length);
    if (rc < 0)
        set_result_error(&s_result_data, -rc);

    return length;
}

static struct file_operations keyblob_dev_operations =
{
    .read = keyblob_dev_read,
    .write = keyblob_dev_write,
    .open = keyblob_dev_open,
    .release = keyblob_dev_release,

    /* Don't support seek for this device. */
    .llseek = noop_llseek,
};

/*
 * Check SoC's Secure Non-Volatile Storage (SNVS) Security Monitor state to
 * make sure that we are in Trusted State.
 */
static int check_trusted_state(void)
{
    int rc = 0;
    struct device_node *dev_node, *np;
    struct platform_device *pdev;
    struct snvs_full __iomem *snvsregs;
    u32 statusreg;
    u32 smstate;

    dev_node = of_find_compatible_node(NULL, NULL, "fsl,imx6q-caam-snvs");
    if (!dev_node)
    {
        pr_err("Failed to get CAAM SNVS device node");
        return -ENODEV;
    }

    pdev = of_find_device_by_node(dev_node);
    if (!pdev)
    {
        pr_err("Failed to get CAAM SNVS platform device");
        rc = -ENODEV;
        goto release_of;
    }

    np = pdev->dev.of_node;
    snvsregs = of_iomap(np, 0);
    statusreg = ioread32(&(snvsregs->hp.status));
    smstate = (statusreg & HP_STATUS_SSM_ST_MASK) >> HP_STATUS_SSM_ST_SHIFT;

    if (smstate != HP_STATUS_SSM_ST_TRUSTED)
    {
        pr_warn("Secure Monitor state is %d\n", smstate);
#if !defined(ALLOW_NONSECURE_SECURITY_STATE)
        pr_alert("Secure Monitor state must be in Trusted State!\n");
        rc = -EACCES;
#endif
    }

release_of:
    of_node_put(dev_node);

    return rc;
}

static struct miscdevice keyblob_miscdevice =
{
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &keyblob_dev_operations,
};

static int __init keyblob_init(void)
{
    int rc;
    struct device_node *np;
    struct platform_device *pdev;

    pr_debug("%s\n", __FUNCTION__);

    rc = get_caam_device_node(&np, &pdev);
    if (rc < 0)
    {
        pr_err("CAAM driver not loaded\n");
        return rc;
    }
    of_node_put(np);

    rc = check_trusted_state();
    if (rc < 0)
        return rc;

    rc = misc_register(&keyblob_miscdevice);
    if (rc < 0)
    {
        pr_err("Registering misc device failed with %d\n", rc);
        return rc;
    }

    memset(&s_result_data, 0, sizeof(struct result_data_t));

    return rc;
}

static void __exit keyblob_exit(void)
{
    pr_debug("%s\n", __FUNCTION__);
    misc_deregister(&keyblob_miscdevice);
}

module_init(keyblob_init);
module_exit(keyblob_exit);
