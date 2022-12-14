/* Copyright (C) 1996-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#if !defined _SYS_UIO_H && !defined _FCNTL_H
#error "Never include <bits/uio.h> directly; use <sys/uio.h> instead."
#endif

#ifndef _BITS_UIO_H
#define _BITS_UIO_H 1

#include <sgx/sys/types.h>

/* We should normally use the Linux kernel header file to define this
   type and macros but this calls for trouble because of the header
   includes other kernel headers.  */

/* Size of object which can be written atomically.

   This macro has different values in different kernel versions.  The
   latest versions of the kernel use 1024 and this is good choice.  Since
   the C library implementation of readv/writev is able to emulate the
   functionality even if the currently running kernel does not support
   this large value the readv/writev call will not fail because of this.  */
#define UIO_MAXIOV 1024

/* Structure for scatter/gather I/O.  */
#ifndef __iovec_defined 
#define __iovec_defined 1
struct iovec
{
   void *iov_base; /* Pointer to data.  */
   size_t iov_len; /* Length of data.  */
};
#endif

#endif

#ifdef __USE_GNU
#if defined _SYS_UIO_H && !defined _BITS_UIO_H_FOR_SYS_UIO_H
#define _BITS_UIO_H_FOR_SYS_UIO_H 1

#endif
#endif
