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

This is an implementation of RFC2898, which specifies key derivation from
a password and a salt value.
*/

#include <memory.h>
#include "hmac.h"
#include "sha2.h"

#include <stdio.h>

#define key_len 64
__device__
void derive_key(const unsigned char pwd[],  /* the PASSWORD     */
               unsigned int pwd_len,        /* and its length   */
               const unsigned char salt[],  /* the SALT and its */
               unsigned int salt_len,       /* length           */
               unsigned int iter,   /* the number of iterations */
               unsigned char key[] /* space for the output key */
                )/* and its required length (made exactly 64, sorta) */
{
    unsigned int    i, j, k, n_blk, h_size;
    unsigned char uu[HMAC_MAX_OUTPUT_SIZE], ux[HMAC_MAX_OUTPUT_SIZE];
    hmac_ctx c1[1], c2[1], c3[1];

    /* set HMAC context (c1) for password               */
    hmac_sha_begin(c1);
    h_size = SHA256_DIGEST_SIZE;
    hmac_sha_key(pwd, pwd_len, c1);

    /* set HMAC context (c2) for password and salt      */
    memcpy(c2, c1, sizeof(hmac_ctx));
    hmac_sha_data(salt, salt_len, c2);

    /* find the number of SHA blocks in the key         */
    n_blk = 1 + (key_len - 1) / h_size;
    // == 2

    for(i = 0; i < n_blk; ++i) /* for each block in key */
    {
        /* ux[] holds the running xor value             */
        memset(ux, 0, h_size);

        /* set HMAC context (c3) for password and salt  */
        memcpy(c3, c2, sizeof(hmac_ctx));

        /* enter additional data for 1st block into uu  */
        uu[0] = (unsigned char)((i + 1) >> 24);
        uu[1] = (unsigned char)((i + 1) >> 16);
        uu[2] = (unsigned char)((i + 1) >> 8);
        uu[3] = (unsigned char)(i + 1);

        /* this is the key mixing iteration         */
        for(j = 0, k = 4; j < iter; ++j)
        {
            /* add previous round data to HMAC      */
            hmac_sha_data(uu, k, c3);

            /* obtain HMAC for uu[]                 */
            hmac_sha_end(uu, h_size, c3);

            /* xor into the running xor block       */
            for(k = 0; k < h_size; ++k)
                ux[k] ^= uu[k];

            /* set HMAC context (c3) for password   */
            memcpy(c3, c1, sizeof(hmac_ctx));
        }

        /* compile key blocks into the key output   */
        j = 0; k = i * h_size;
        if (i == 0) {
          for (int j = 0; j < 16; j++) {
            key[j] = ux[j + 16];
          }
        } else {
          for (int j = 0; j < 16; j++) {
            key[j + 16] = ux[j];
          }
        }
    }
}
