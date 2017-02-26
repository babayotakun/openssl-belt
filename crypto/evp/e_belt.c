#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_BELT
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/belt.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "internal/evp_int.h"
#include "evp_locl.h"
#include "../../include/openssl/ossl_typ.h"
#include "../../include/openssl/belt.h"
#include "../../include/openssl/evp.h"
static int belt_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);

typedef struct
{
	BELT_KEY ks;
} EVP_BELT_KEY;


#define data(ctx) EVP_C_DATA(EVP_BELT_KEY,ctx)
IMPLEMENT_CBC_BLOCK_CIPHER(belt_128, ks, Belt, EVP_BELT_KEY, \
	NID_belt_128, 16, 16, 16, 128, \
	0, belt_init_key, NULL, \
	EVP_CIPHER_set_asn1_iv, \
	EVP_CIPHER_get_asn1_iv,
	NULL)

	IMPLEMENT_CBC_BLOCK_CIPHER(belt_192, ks, Belt, EVP_BELT_KEY,
	NID_belt_192, 16, 24, 16, 128,
	0, belt_init_key, NULL,
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL)

	IMPLEMENT_CBC_BLOCK_CIPHER(belt_256, ks, Belt, EVP_BELT_KEY,
	NID_belt_256, 16, 40, 16, 128,
	0, belt_init_key, NULL,
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL)

	static int belt_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	int ret;
	if ((ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_CFB_MODE
			 || (ctx->cipher->flags & EVP_CIPH_MODE) == EVP_CIPH_OFB_MODE
			 || enc)
		 ret = Belt_set_encrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
	else
		 ret = Belt_set_decrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
	
	if (ret < 0)
	{
		EVPerr(EVP_F_BELT_KEY, EVP_R_BELT_SETUP_FAILED);
		return 0;
	}
	
	return 1;
}

#endif