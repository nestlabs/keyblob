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
 *      This is file defines common code between /dev/keyblob kernel module and
 *      command-line interface.
 *
 */
#ifndef _KEYBLOB_H_
#define _KEYBLOB_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define DEVICE_NAME                     "keyblob"
#define DEVICE_PATH                     "/dev/" DEVICE_NAME

/*
 * Define Command Types
 */
#define COMMAND_GENRANDKEY              1
#define COMMAND_LOADDIRECT              2
#define COMMAND_ENCRYPTKEY              3

/*
 * Define Result Code
 */
#define RESULT_CODE_SUCCESS             0
#define RESULT_CODE_ERROR               1
#define RESULT_CODE_KEYBLOB             2

/*
 * Define Error Code
 */
#define ERROR_CODE_INTERNAL_ERROR       0
#define ERROR_CODE_REQUEST_TOO_LARGE    1
#define ERROR_CODE_RESPONSE_TOO_LARGE   2
#define ERROR_CODE_INVALID_FORMAT       3
#define ERROR_CODE_UNKNOWN_COMMAND      4

/*
 * Maximum message size for all requests
 */
#define REQUEST_BUF_LEN                 400

/*
 * Maximum response length
 */
#define RESPONSE_BUF_LEN                400

/*
 * Return value that rounds up to the nearest AES block size.
 */
#ifndef AES_BLOCK_PAD
#define AES_BLOCK_PAD(n)                ((n & 15) ? ((n & ~15) + 16) : n)
#endif

/* 
 * Blob has a 256-bit key and 16-byte MAC. This does not account the AES block
 * padding if underlying data is not exactly multiple of AES block size..
 */
#ifndef BLOB_OVERHEAD
#define BLOB_OVERHEAD                   (32 + 16)
#endif

/*
 * Calculate the blob size given the size of data to encapsulate. This macro
 * takes into account the AES block padding when datalen is not multiple of AES
 * block size.
 */
#define GET_BLOB_SIZE(datalen)          (BLOB_OVERHEAD + AES_BLOCK_PAD(datalen))

struct response_t
{
    uint8_t type;
    uint16_t length;
    uint8_t data[];
} __attribute__((packed));

#ifndef member_sizeof
#define member_sizeof(type, member) sizeof(((type *)0)->member)
#endif

#endif /* _KEYBLOB_H_ */
