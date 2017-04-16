#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_BELT
#include <openssl/evp.h>
#include <string.h>
#include <assert.h>

#include <bee2/crypto/belt.h>
#include "evp_locl.h"
#include <openssl/ossl_typ.h>
#include "../include/internal/evp_int.h"
static int belt_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);

/*
s_server -key C:\build\server.key -cert C:\build\server.crt -accept 8443 -www
s_client -cipher 'TLS-DHE-BIGN-WITH-BELT-CTR-MAC-HBELT' -connect localhost:8443
*/

typedef struct
{
	// 68 bytes
	void* bee2data;
} EVP_BELT_KEY;

#define data(ctx) EVP_C_DATA(EVP_BELT_KEY,ctx)
#define BLOCK_BELT_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags,keysize) \
static const EVP_CIPHER belt_256_ctr = { \
        NID_belt_256_ctr,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_CTR_MODE,   \
        belt_init_key,              \
        belt_ctr_cipher,       \
        NULL,                           \
        keysize,       \
        NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_belt_256_ctr(void) \
{ return &belt_256_ctr; }

	static int belt_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	EVP_BELT_KEY *dat = EVP_C_DATA(EVP_BELT_KEY, ctx);
	beltCTRStart(&dat->bee2data, key, EVP_CIPHER_CTX_key_length(ctx), iv);
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
	printf("IN: %.*s\n", len, in);
	beltCTRStepE(out, len, &dat->bee2data);
	printf("OUT: %.*s\n", len, out);
	return 1;
}

BLOCK_BELT_CIPHER_generic(NID_belt_256_ctr, 256, 1, 16, ctr, ctr, CTR, 0, 68)

#endif