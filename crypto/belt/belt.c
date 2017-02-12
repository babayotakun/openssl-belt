#include <string.h>
#include <stdlib.h>

#include "belt_locl.h"
#include "openssl/belt.h"
#include "../../include/openssl/belt.h"

void Belt_encrypt(const unsigned char *in, unsigned char *out, const BELT_KEY *key)
{
	int i = 0;
	while (in[i] != '\0')
	{
		out[i] = in[i];
		i++;
	}
	printf("Text to encrypt: %s\n", in);
}

void Belt_decrypt(const unsigned char *in, unsigned char *out, const BELT_KEY *key)
{
	int i = 0;
	while (in[i] != '\0')
	{
		out[i] = in[i];
		i++;
	}
	printf("Text to decrypt: %s\n", in);
}

int Belt_set_decrypt_key(const unsigned char *userKey, const int bits, BELT_KEY *key)
{
	printf("User key: %s\n", userKey);
	return 1;
}

int Belt_set_encrypt_key(const unsigned char *userKey, const int bits, BELT_KEY *key)
{
	printf("User key: %s\n", userKey);
	return 1;
}
