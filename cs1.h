#ifndef H_CS1_INCLUDED
#define H_CS1_INCLUDED

#include <limits.h>
#include <stddef.h>

void setup(void);
void setkey(const unsigned char *pass, size_t siz, const unsigned char *IV);
unsigned char crypt(unsigned char ch);
unsigned char *encrypt(unsigned char *dst,
      const unsigned char *msg, size_t len,
      const unsigned char *pass, size_t siz);
unsigned char *decrypt(unsigned char *dst,
      const unsigned char *msg, size_t len,
      const unsigned char *pass, size_t siz);

#endif
