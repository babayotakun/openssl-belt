#ifndef HEADER_BELT_H
#define HEADER_BELT_H

#include <openssl/opensslconf.h>

#define BELT_ENCRYPT 1
#define BELT_DECRYPT 0



	struct belt_key_st
	{
		/* belt key structure*/
		void(*enc)(const unsigned char *in, unsigned char *out);
		void(*dec)(const unsigned char *in, unsigned char *out);
	};
	typedef struct belt_key_st BELT_KEY;

	int Belt_set_encrypt_key(const unsigned char *userKey, const int bits, BELT_KEY *key);

	int Belt_set_decrypt_key(const unsigned char *userKey, const int bits, BELT_KEY *key);

	void Belt_encrypt(const unsigned char *in, unsigned char *out, const BELT_KEY *key);

	void Belt_decrypt(const unsigned char *in, unsigned char *out, const BELT_KEY *key);


#endif /* !HEADER_Belt_H */#pragma once
