#ifndef H_CS1_INCLUDED
#define H_CS1_INCLUDED

#include <limits.h>
#include <stddef.h>

unsigned char *encrypt(unsigned char *dst,
		       const unsigned char *msg, size_t len,
		       const unsigned char *pass, size_t siz);
unsigned char *decrypt(unsigned char *dst,
		       const unsigned char *msg, size_t len,
		       const unsigned char *pass, size_t siz);

#endif
