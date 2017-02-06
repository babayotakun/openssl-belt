#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_BELT
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/belt.h>
#include "evp_locl.h"
#include "../../include/openssl/err.h"
#include "../../belt.h"
static int belt_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);

typedef struct
{
	BELT_KEY ks;
} EVP_BELT_KEY;


#define data(ctx) EVP_C_DATA(EVP_BELT_KEY,ctx)
IMPLEMENT_BLOCK_CIPHER(belt_128, ks, Belt, EVP_BELT_KEY,
	NID_belt_128, 16, 16, 16, 128,
	0, belt_init_key, NULL,
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL);
IMPLEMENT_BLOCK_CIPHER(belt_192, ks, Belt, EVP_BELT_KEY,
	NID_indect_192, 16, 24, 16, 128,
	0, belt_init_key, NULL,
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL);
IMPLEMENT_BLOCK_CIPHER(belt_256, ks, Belt, EVP_BELT_KEY,
	NID_indect_256, 16, 40, 16, 128,
	0, belt_init_key, NULL,
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL);
#define IMPLEMENT_INDECT_CFBR(ksize,cbits)
IMPLEMENT_CFBR(indect, Belt, EVP_BELT_KEY, ks, ksize, cbits, 32, 0);
	IMPLEMENT_INDECT_CFBR(128, 1)
	IMPLEMENT_INDECT_CFBR(192, 1)
	IMPLEMENT_INDECT_CFBR(320, 1)
	IMPLEMENT_INDECT_CFBR(128, 8)
	IMPLEMENT_INDECT_CFBR(192, 8)
	IMPLEMENT_INDECT_CFBR(320, 8)
	/* The subkey for Indect is generated. */
	static int belt_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		const unsigned char *iv, int enc)
{
	int ret;
	if ((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CFB_MODE|| (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_OFB_MODE || enc)
		ret = Belt_set_encrypt_key(key, ctx->key_len * 8, ctx ->cipher_data);
	else
		ret = Belt_set_decrypt_key(key, ctx->key_len * 8, ctx ->cipher_data);
	if (ret < 0)
	{
		EVPerr(EVP_F_INDECT_INIT_KEY, EVP_R_INDECT_KEY_SETUP_FAILED);
		return 0;
	}
	return 1;
}
#endif