#include <assert.h>

#include <openssl/belt.h>
#include "../../include/openssl/belt.h"

void Belt_cbc_encrypt(const unsigned char *in, unsigned char *out,
	const unsigned long length, const BELT_KEY *key,
	unsigned char *ivec, const int enc) {
	
	for (int i = 0; i < length; i++)
	{
		out[i] = in[i];
	}
	printf("Text to encrypt: %s\n", in);
}