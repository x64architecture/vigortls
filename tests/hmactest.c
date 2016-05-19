/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdcompat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/hmac.h>
#include <openssl/md5.h>

static struct test_st {
    uint8_t key[16];
    int key_len;
    uint8_t data[64];
    int data_len;
    uint8_t *digest;
} test[4] = {
      {
        "",
        0,
        "More text test vectors to stuff up EBCDIC machines :-)",
        54,
        (uint8_t *)"e9139d1e6ee064ef8cf514fc7dc83e86",
      },
      {
        {
          0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
          0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        },
        16,
        "Hi There",
        8,
        (uint8_t *)"9294727a3638bb1c13f48ef8158bfc9d",
      },
      {
        "Jefe",
        4,
        "what do ya want for nothing?",
        28,
        (uint8_t *)"750c783e6ab0b503eaa86e310a5db738",
      },
      {
        {
          0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
          0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        },
        16,
        { 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
          0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
          0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
          0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
          0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
          0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
          0xdd, 0xdd },
        50,
        (uint8_t *)"56be34521d144c88dbb8c733f0e8b3f6",
      },
  };

static char *pt(uint8_t *md);
int main(int argc, char *argv[])
{
    int i;
    char *p;
    int err = 0;


    for (i = 0; i < 4; i++) {
        p = pt(HMAC(EVP_md5(),
                    test[i].key, test[i].key_len,
                    test[i].data, test[i].data_len,
                    NULL, NULL));

        if (strcmp(p, (char *)test[i].digest) != 0) {
            printf("error calculating HMAC on %d entry'\n", i);
            printf("got %s instead of %s\n", p, test[i].digest);
            err++;
        } else
            printf("test %d ok\n", i);
    }
    exit(err);
    return (0);
}

static char *pt(uint8_t *md)
{
    int i;
    static char buf[80];

    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
        snprintf(buf + i * 2, sizeof(buf) - i * 2, "%02x", md[i]);
    return (buf);
}
