#include <assert.h>

#include <openssl/belt.h>
#include "../../include/openssl/belt.h"

void Indect_cbc_encrypt(const unsigned char *in, unsigned char *out,
	const unsigned long length, const BELT_KEY *key,
	unsigned char *ivec, const int enc) {
	
	out = in;
}