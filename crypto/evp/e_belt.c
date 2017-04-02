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
#include "../../include/openssl/obj_mac.h"
#include "../../include/openssl/modes.h"
static int belt_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);

typedef struct
{
	BELT_KEY ks;
	block128_f block;
} EVP_BELT_KEY;


#define data(ctx) EVP_C_DATA(EVP_BELT_KEY,ctx)
#define BLOCK_BELT_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER belt_256_ctr = { \
        NID_belt_256_ctr,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_CTR_MODE,   \
        belt_init_key,              \
        belt_ctr_cipher,       \
        NULL,                           \
        sizeof(EVP_BELT_KEY),       \
        NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_belt_256_ctr(void) \
{ return &belt_256_ctr; }

	static int belt_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	int ret, mode;
	EVP_BELT_KEY *dat = EVP_C_DATA(EVP_BELT_KEY, ctx);
	ret = Belt_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8, &dat->ks);
	if (ret < 0) {
		EVPerr(EVP_F_BELT_KEY, EVP_R_BELT_SETUP_FAILED);
		return 0;
	}
	dat->block = (block128_f)Belt_encrypt;
	return 1;
}

static int belt_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	unsigned int num = EVP_CIPHER_CTX_num(ctx);
	EVP_BELT_KEY *dat = EVP_C_DATA(EVP_BELT_KEY, ctx);
	for (int i = 0; i < len; i++)
	{
		out[i] = in[i];
	}
	printf("Text to encrypt: %s\n", out);
	return 1;
}

BLOCK_BELT_CIPHER_generic(NID_belt_256_ctr, 256, 1, 16, ctr, ctr, CTR, 0)

#endif