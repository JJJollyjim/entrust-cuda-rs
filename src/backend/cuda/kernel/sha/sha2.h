/*
---------------------------------------------------------------------------
Copyright (c) 1998-2010, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007
*/

#ifndef _SHA2_H
#define _SHA2_H

#include <stdlib.h>

/* define for bit or byte oriented SHA   */
#if 1
#  define SHA2_BITS 0   /* byte oriented */
#else
#  define SHA2_BITS 1   /* bit oriented  */
#endif

/* define the hash functions that you need  */
/* define for 64-bit SHA384 and SHA512      */
#define SHA_64BIT
#define SHA_2   /* for dynamic hash length  */
#define SHA_224
#define SHA_256
#ifdef SHA_64BIT
#  define SHA_384
#  define SHA_512
#  define NEED_uint64_t
#endif

#define SHA2_MAX_DIGEST_SIZE   64
#define SHA2_MAX_BLOCK_SIZE   128

#include "brg_types.h"

/* Note that the following function prototypes are the same */
/* for both the bit and byte oriented implementations.  But */
/* the length fields are in bytes or bits as is appropriate */
/* for the version used.  Bit sequences are arrays of bytes */
/* in which bit sequence indexes increase from the most to  */
/* the least significant end of each byte.  The value 'len' */
/* in sha<nnn>_hash for the byte oriented versions of SHA2  */
/* is limited to 2^29 bytes, but multiple calls will handle */
/* longer data blocks.                                      */

#define SHA224_DIGEST_SIZE  28
#define SHA224_BLOCK_SIZE   64

#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

/* type to hold the SHA256 (and SHA224) context */

typedef struct
{   uint32_t count[2];
    uint32_t hash[SHA256_DIGEST_SIZE >> 2];
    uint32_t wbuf[SHA256_BLOCK_SIZE >> 2];
} sha256_ctx;

typedef sha256_ctx  sha224_ctx;

__device__ VOID_RETURN sha256_compile(sha256_ctx ctx[1]);

__device__ VOID_RETURN sha224_begin(sha224_ctx ctx[1]);
#define sha224_hash sha256_hash
__device__ VOID_RETURN sha224_end(unsigned char hval[], sha224_ctx ctx[1]);
__device__ VOID_RETURN sha224(unsigned char hval[], const unsigned char data[], unsigned long len);

__device__ VOID_RETURN sha256_begin(sha256_ctx ctx[1]);
__device__ VOID_RETURN sha256_hash(const unsigned char data[], unsigned long len, sha256_ctx ctx[1]);
__device__ VOID_RETURN sha256_end(unsigned char hval[], sha256_ctx ctx[1]);
__device__ VOID_RETURN sha256(unsigned char hval[], const unsigned char data[], unsigned long len);


#endif
