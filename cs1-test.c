#include <stdio.h>
#include "cs1.h"

int main(void)
{
    FILE *h;

    h = fopen("cstest1.cs1", "rb");
    if (h) {
	char data[1000];
	size_t n = fread(data, 1, 1000, h);
	if (n > CS_IV_SIZE) {
	    unsigned char dst[1000];
	    decrypt(dst, data, n, "asdfg", 5);
	    dst[n - CS_IV_SIZE] = 0;
	    printf("dst ==> [%s]\n", dst);
	}
	fclose(h);
    }
    return 0;
}
