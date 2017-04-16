/*
* Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the OpenSSL license (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
*/

#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "internal/evp_int.h"
#include <bee2/crypto/bash.h>

static int init256(EVP_MD_CTX *ctx)
{
	bash256Start(EVP_MD_CTX_md_data(ctx));
	return 1;
}

static int update256(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	bash256StepH(data, count, EVP_MD_CTX_md_data(ctx));
	return 1;
}

static int final256(EVP_MD_CTX *ctx, unsigned char *md)
{
	bash256StepG(md, EVP_MD_CTX_md_data(ctx));
	return 1;
}

static const EVP_MD bash_st = {
	NID_hbelt,
	NULL,
	32, /* digest length */
	EVP_MD_FLAG_DIGALGID_ABSENT,
	init256,
	update256,
	final256,
	NULL,
	NULL,
	64,
	sizeof(EVP_MD *) + 392, /* result of bash256_keep() */
};

const EVP_MD *EVP_hbelt(void)
{
	return (&bash_st);
}



