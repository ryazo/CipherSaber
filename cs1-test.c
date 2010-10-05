#include <stdio.h>
#include <stdlib.h>
#include "cs1.h"

int main(int argc, char **argv)
{
    FILE *h;

    h = fopen("cstest1.cs1", "rb");
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
	    decrypt(dst, data, n, "asdfg", 5);
	    dst[n - CS_IV_SIZE] = 0;
	    printf("dst ==> [%s]\n", dst);
	    free(dst);
	}
	free(data);
	fclose(h);
    }
    return 0;
}
