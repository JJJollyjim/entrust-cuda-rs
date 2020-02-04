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

This is an implementation of HMAC, the FIPS standard keyed hash function
*/

#include "hmac.h"

#if defined(__cplusplus)
extern "C"
{
#endif

/* initialise the HMAC context to zero */
__device__ int hmac_sha_begin(hmac_ctx cx[1]) {
  memset(cx, 0, sizeof(hmac_ctx));
  return SHA256_DIGEST_SIZE;
}

/* input the HMAC key (can be called multiple times)    */
__device__ int hmac_sha_key(const unsigned char key[], unsigned long key_len,
                            hmac_ctx cx[1]) {
  if (cx->klen == HMAC_IN_DATA) /* error if further key input   */
    return EXIT_FAILURE;        /* is attempted in data mode    */

  if (cx->klen + key_len > SHA256_BLOCK_SIZE) /* if the key has to be hashed  */
  {
    if (cx->klen <= SHA256_BLOCK_SIZE) /* if the hash has not yet been */
    {                                  /* started, initialise it and   */
      sha256_begin(cx->sha_ctx);       /* hash stored key characters   */
      sha256_hash(cx->key, cx->klen, cx->sha_ctx);
    }

    sha256_hash(key, key_len, cx->sha_ctx); /* hash long key data into hash */
  } else                                    /* otherwise store key data     */
    memcpy(cx->key + cx->klen, key, key_len);

  cx->klen += key_len; /* update the key length count  */
  return EXIT_SUCCESS;
}

/* input the HMAC data (can be called multiple times) - */
/* note that this call terminates the key input phase   */
__device__ void hmac_sha_data(const unsigned char data[],
                              unsigned long data_len, hmac_ctx cx[1]) {
  unsigned int i;

  if (cx->klen != HMAC_IN_DATA) /* if not yet in data phase */
  {
    if (cx->klen > SHA256_BLOCK_SIZE)   /* if key is being hashed   */
    {                                   /* complete the hash and    */
      sha256_end(cx->key, cx->sha_ctx); /* store the result as the  */
      cx->klen = SHA256_DIGEST_SIZE;    /* key and set new length   */
    }

    /* pad the key if necessary */
    memset(cx->key + cx->klen, 0, SHA256_BLOCK_SIZE - cx->klen);

    /* xor ipad into key value  */
    for (i = 0; i < (SHA256_BLOCK_SIZE >> 2); ++i)
      ((uint32_t *)cx->key)[i] ^= 0x36363636;

    /* and start hash operation */
    sha256_begin(cx->sha_ctx);
    sha256_hash(cx->key, SHA256_BLOCK_SIZE, cx->sha_ctx);

    /* mark as now in data mode */
    cx->klen = HMAC_IN_DATA;
  }

  /* hash the data (if any)       */
  if (data_len)
    sha256_hash(data, data_len, cx->sha_ctx);
}

/* compute and output the MAC value */
__device__ void hmac_sha_end(unsigned char mac[], unsigned long mac_len,
                             hmac_ctx cx[1]) {
  unsigned char dig[HMAC_MAX_OUTPUT_SIZE];
  unsigned int i;

  /* if no data has been entered perform a null data phase        */
  if (cx->klen != HMAC_IN_DATA)
    hmac_sha_data((const unsigned char *)0, 0, cx);

  sha256_end(dig, cx->sha_ctx); /* complete the inner hash       */

  /* set outer key value using opad and removing ipad */
  for (i = 0; i < (SHA256_BLOCK_SIZE >> 2); ++i)
    ((uint32_t *)cx->key)[i] ^= 0x36363636 ^ 0x5c5c5c5c;

  /* perform the outer hash operation */
  sha256_begin(cx->sha_ctx);
  sha256_hash(cx->key, SHA256_BLOCK_SIZE, cx->sha_ctx);
  sha256_hash(dig, SHA256_DIGEST_SIZE, cx->sha_ctx);
  sha256_end(dig, cx->sha_ctx);

  /* output the hash value            */
  for (i = 0; i < mac_len; ++i)
    mac[i] = dig[i];
}

/* 'do it all in one go' subroutine     */
__device__ void hmac_sha(enum hmac_hash hash, const unsigned char key[],
                         unsigned long key_len, const unsigned char data[],
                         unsigned long data_len, unsigned char mac[],
                         unsigned long mac_len) {
  hmac_ctx cx[1];

  hmac_sha_begin(cx);
  hmac_sha_key(key, key_len, cx);
  hmac_sha_data(data, data_len, cx);
  hmac_sha_end(mac, mac_len, cx);
}

#if defined(__cplusplus)
}
#endif
