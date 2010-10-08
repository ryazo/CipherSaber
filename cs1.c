#include <limits.h>
#include <stdlib.h>
#include "cs1.h"

/* reading and taking notes
** user key is a string
** initialization vector (userkey < 246 bytes (recommended <= 53))
** initialization vector is not secret
** rand() should be good enough provided it's been properly seeded
*/

unsigned char state[256];
unsigned char key[256];		/* not necessarily all used */
unsigned char klen;		/* number of used elements of key */
unsigned char i = 0, j = 0;

static void setup(size_t N)
{
    size_t ndx;

    for (ndx = 0; ndx < 256; ndx++) {
	state[ndx] = ndx;
    }
    while (N--) {
	for (ndx = 0; ndx < 256; ndx++) {
	    unsigned char tmp;
	    unsigned char n;

	    i = ndx;
	    n = i % klen;
	    j += state[i] + key[n];
	    tmp = state[i];
	    state[i] = state[j];
	    state[j] = tmp;
	}
    }
    i = j = 0;
}

/* text from http://ciphersaber.gurus.org/faq.html

 the RC4 algorithm in plain English:

RC4 uses two arrays of eight bit bytes. The "state" array is 256 bytes long
and holds a permutation of the numbers 0 through 255.
The "key" array can be of any length up to 256 bytes.
RC4 also uses two index variables i and j that start off as zero.
All variables are eight bits long and all addition is performed modulo 256.

RC4 has two phases: key setup and ciphering.
The setup phase is only done once per message and starts by initializing
the entire state array so that the first state element is zero,
the second is one, the third is two, and so on.

The state array is then subjected to 256 mixing operations using a loop
that steps i through the values from zero to 255. Each mixing operation
consists of two steps:

 * Add to the variable j the contents of the ith element of the state array
   and the nth element of the key, where n is equal to i modulo the length
   of the key.
 * Swap the ith and jth elements of the state array.

After the entire mixing loop is completed, i and j are set to zero.

During the ciphering operation, the following steps are performed for
each byte of the message:

 * The variable i is incremented by one
 * The contents of the ith element of the state array is then added to j
 * The ith and jth elements of the state array are swapped and their
   contents are added together to form a new value n.
 * The nth element of the state array is then combined with the message
   byte, using a bit by bit exclusive-or operation, to form the output byte.

The same ciphering steps are performed for encryption and for decryption.

Note that in CipherSaber the RC4 key array consists of the user's
CipherSaber key followed by the 10 byte initialization vector (IV).

 * When you are encrypting a file, you generate a new IV randomly
   and write out the 10 bytes before you write out the
   encrypted file bytes.
 * When you are decrypting the file, you read the IV from the first
   10 bytes of the encrypted file.
*/

static void setkey(const unsigned char *pass, size_t siz,
		   const unsigned char *IV)
{
    size_t ndx;

    for (ndx = 0; ndx < siz; ndx++) {
	key[ndx] = *pass++;
    }
    klen = siz + CS_IV_SIZE;
    if (IV == NULL) {
	/* generate 10 random bytes */
	for (ndx = siz; ndx < siz + CS_IV_SIZE; ndx++) {
	    key[ndx] = rand() & 0xFF;
	}
    } else {
	/* use 10 bytes from the IV array */
	for (ndx = siz; ndx < siz + CS_IV_SIZE; ndx++) {
	    key[ndx] = *IV++;
	}
    }
}

static unsigned char crypt(unsigned char ch)
{
    unsigned char tmp;
    unsigned char n;

    i++;
#if CHAR_BIT > 8
    if (i > 255) {
	i = 256 - i;
    }
#endif
    j += state[i];
#if CHAR_BIT > 8
    if (j > 255) {
	j = 256 - j;
    }
#endif
    tmp = state[i];
    state[i] = state[j];
    state[j] = tmp;
    n = state[i] + state[j];
#if CHAR_BIT > 8
    if (n > 255) {
	n = 256 - n;
    }
#endif
    return state[n] ^ ch;
}

unsigned char *encrypt(unsigned char *dst, size_t N,
		       const unsigned char *msg, size_t len,
		       const unsigned char *pass, size_t siz)
{
    unsigned char *saveddst = dst;
    int ndx;

    setkey(pass, siz, NULL);
    for (ndx = 0; ndx < CS_IV_SIZE; ndx++) {
	*dst++ = key[siz + ndx];
    }
    setup(N);
    while (len--) {
	*dst++ = crypt(*msg++);
    }
    return saveddst;
}

unsigned char *decrypt(unsigned char *dst, size_t N,
		       const unsigned char *msg, size_t len,
		       const unsigned char *pass, size_t siz)
{
    unsigned char *saveddst = dst;

    setkey(pass, siz, msg);
    setup(N);
    msg += CS_IV_SIZE;
    len -= CS_IV_SIZE;
    while (len--) {
	*dst++ = crypt(*msg++);
    }
    return saveddst;
}
