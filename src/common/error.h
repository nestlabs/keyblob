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
 *    Description:
 *      This is file defines functions for dealing with error in response.
 *
 */
#ifndef _ERROR_H_
#define _ERROR_H_

#include "keyblob.h"

/*
 * Macros for encoding errno with ERROR_CODE_INTERNAL_ERROR.
 *
 * In order to conveniently return results from a command, we encode errno and
 * an internal error code into a 32-bit integer. The resulting value is always
 * positive. The lower 8-bit has the value of ERROR_CODE_INTERNAL_ERROR while
 * the next 23-bit encodes the errno value. This assumes that errno fits within
 * 23-bits width. While this does not seem to be a problem on Linux for the
 * values used in this project, future maintainer should be aware.
 */
#define _ERROR_CODE_WIDTH           (8)
#define _ERROR_CODE_MASK            ((1 << _ERROR_CODE_WIDTH) - 1)
#define _ERRNO_SHIFT                (_ERROR_CODE_WIDTH)
#define _ERRNO_WIDTH                (23)
#define _ERRNO_MASK                 ((1 << _ERRNO_WIDTH) - 1)

#define _ENCODE_ERROR_RESULT(code, errno)                   \
    (int)((code & _ERROR_CODE_MASK)                         \
            | ((errno & _ERRNO_MASK) << _ERRNO_SHIFT))

/*
 * Macro for setting errno.
 */
#define ERR_INTERNAL_ERROR(errno) \
    _ENCODE_ERROR_RESULT(ERROR_CODE_INTERNAL_ERROR, errno)

/*
 * Get Errno value.
 */
#define GET_ERRNO(val)              ((val >> _ERRNO_SHIFT) & _ERRNO_MASK)

/*
 * Get Error Code.
 */
#define GET_ERROR_CODE(val)         (val & _ERROR_CODE_MASK)

#ifndef __KERNEL__

/*
 * Returns the error code in response. For non-error response, returns -1.
 */
const int error_from_response(const struct response_t *res);

/*
 * Returns a string matching the error code.
 */
const char *error_code_string(int code);

#endif /* ! __KERNEL__ */

#endif /* _ERROR_H_ */
