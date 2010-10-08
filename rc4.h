#ifndef H_RC4_INCLUDED
#define H_RC4_INCLUDED

#include <limits.h>
#include <stddef.h>

#define RC4_IV_SIZE 10

unsigned char *encrypt(unsigned char *dst, size_t N,
      const unsigned char *msg, size_t len,
      const unsigned char *pass, size_t siz);
unsigned char *decrypt(unsigned char *dst, size_t N,
      const unsigned char *msg, size_t len,
      const unsigned char *pass, size_t siz);

#endif
