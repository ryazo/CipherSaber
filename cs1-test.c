#include <stdio.h>
#include <stdlib.h>
#include "cs1.h"

/* command line parameters
** cs1 e|d filename password
**     e or d ==> encrypt or decrypt
**     filename ==> d'oh
**     password ==> single word, "quoted spaces", 0xDEADBEEF
**                  for a password that starts with 0x (or 0X)
**                  put it in quotes: "0xGoodPass"
**                  Only 0-9 and A-F (any case) are recognized
**                  in '0x' passwords; a remaining odd character
**                  is ignored */
int main(int argc, char **argv)
{
    FILE *h;

    h = fopen("cs2test.cs2", "rb");
    if (h) {
	unsigned char *data, *tmp;
	size_t n;

	data = malloc(10000);
	if (data == NULL) {
	    fclose(h);
	    fprintf(stderr, "error: no memory\n");
	    exit(EXIT_FAILURE);
	}
	n = fread(data, 1, 10000, h);
	tmp = realloc(data, n);
	if (tmp == NULL) {
	    /* failed to realloc down? Strange! Oh well ...
	     ** do nothing: data points to correct values */
	} else {
	    data = tmp;
	}
	if (n > CS_IV_SIZE) {
	    unsigned char *dst;

	    dst = malloc(n - CS_IV_SIZE + 1);
	    if (dst == NULL) {
		free(data);
		fclose(h);
		fprintf(stderr, "error: no memory\n");
		exit(EXIT_FAILURE);
	    }
	    decrypt(dst, 10, data, n, "asdfg", 5);
	    dst[n - CS_IV_SIZE] = 0;
	    printf("dst ==> [%s]\n", dst);
	    free(dst);
	}
	free(data);
	fclose(h);
    }
    return 0;
}
