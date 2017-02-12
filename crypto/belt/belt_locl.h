#ifndef HEADER_INDECT_LOCL_H
#define HEADER_INDECT_LOCL_H

#include "openssl/e_os2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

#ifdef __cplusplus
extern "C" {
#endif
	void update_invalidlc_table(unsigned char chosenlc, unsigned char invalidlc_table[]);
	unsigned char chooselc(unsigned char mappedlc, unsigned char invalidlc_table[]);
	unsigned char parity(unsigned char byte);
	
	void belt_setup(const unsigned char *key, const int bits, unsigned char sbox[][256],
			unsigned char ptab[][2], const int enc);
	
	void Belt_encrypt128(const unsigned char *in, unsigned char *out, const unsigned char
			sbox[][256], const unsigned char ptab[][2]);
	void Belt_decrypt128(const unsigned char *in, unsigned char *out, const unsigned char
		sbox[][256], const unsigned char ptab[][2]);
	void Belt_encrypt192(const unsigned char *in, unsigned char *out, const unsigned char
		sbox[][256], const unsigned char ptab[][2]);
	void Belt_decrypt192(const unsigned char *in, unsigned char *out, const unsigned char
		sbox[][256], const unsigned char ptab[][2]);
	void Belt_encrypt256(const unsigned char *in, unsigned char *out, const unsigned char
		sbox[][256], const unsigned char ptab[][2]);
	void Belt_decrypt256(const unsigned char *in, unsigned char *out, const unsigned char
		sbox[][256], const unsigned char ptab[][2]);
	
#ifdef __cplusplus
		 }
#endif

#endif /* #ifndef HEADER_INDECT_LOCL_H */