#include <stdio.h>
#include "cs1.h"

int
main (void)
{
  FILE *h;

  h = fopen ("cstest1.cs1", "rb");
  if (h)
    {
      char data[10000];
      size_t n = fread (data, 1, 10000, h);
      if (n)
	{
	  unsigned char dst[1000];
	  setup ();
	  decrypt (dst, data, n, "asdfg", 5);
	}
      fclose (h);
    }
  return 0;
}
