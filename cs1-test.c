#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cs1.h"

static void quit(const char *cmdname, int help, const char *msg)
{
    fprintf(stderr, "usage: %s [options] [input [output]]\n", cmdname);
    if (help) {
	fprintf(stderr, "  -d  decrypt\n");
	fprintf(stderr, "  -e  encrypt (default)\n");
	fprintf(stderr,
		"  -p  password (default is \"password\" with no quotes)\n");
	fprintf(stderr, "  -x  hexpass\n");
	fprintf(stderr,
		"  -n  rounds (default is 1: CipherSaber 1; 20+ advised)\n");
	fprintf(stderr, "  -h  help\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
		"%s -d secret.msg secret.txt -p Hello -x2020 -p World -n 42\n",
		cmdname);
	fprintf(stderr,
		"Decrypt `secret.msg` using 42 initialization rounds and password\n");
	fprintf(stderr,
		"  \"Hello  World\", putting the result in a file named `secret.txt`.\n");
	if (msg)
	    fprintf(stderr, "==> %s <==\n", msg);
	exit(EXIT_FAILURE);
    } else {
	fprintf(stderr, "   try %s -h\n", cmdname);
	if (msg)
	    fprintf(stderr, "==> %s <==\n", msg);
	exit(EXIT_SUCCESS);
    }
}

struct Options {
    int mode;			/* 0: encrypt; 1: decrypt */
    unsigned char key[256];
    unsigned klen;
    long rounds;
    char *ifname;
    FILE *ifh;
    char *ofname;
    FILE *ofh;
};

int main(int argc, char **argv)
{
    int argn = 1;
    int clfiles = 0;
    int initkey = 1;
    struct Options opt = { 0, "password", 8, 1, NULL, NULL, NULL, NULL };
    opt.ifh = stdin;
    opt.ofh = stdout;

    if (argc == 1)
	quit(argv[0], 0, 0);
  /* *INDENT-OFF* */
  while (argn < argc) {
    if (argv[argn][0] != '-') {
      switch (clfiles) {
        default: quit(argv[0], 0, "ONLY TWO FILES CAN BE SPECIFIED"); break;
        case 0: opt.ifname = argv[argn]; break;
        case 1: opt.ofname = argv[argn]; break;
      }
      clfiles++;
    } else {
      char *ptr;
      char *err = NULL;
      switch (argv[argn][1]) {
        default: quit(argv[0], 0, "UNRECOGNIZED OPTION"); break;
        case 'e': opt.mode = 0; break;
        case 'd': opt.mode = 1; break;
        case 'p': if (initkey) {
                    opt.klen = 0;
                    initkey = 0;
                  }
                  if (*(ptr = argv[argn] + 2) == 0) ptr = argv[++argn];
                  while (*ptr) {
                    if (opt.klen == 246) quit(argv[0], 0, "PASSWORD TOO LONG");
                    opt.key[opt.klen++] = *ptr++;
                  }
                  break;
        case 'x': if (initkey) {
                    opt.klen = 0;
                    initkey = 0;
                  }
                  if (*(ptr = argv[argn] + 2) == 0) ptr = argv[++argn];
                  while (*ptr && *(ptr + 1)) {
                    int val = 0;
                    if (isxdigit(*ptr) && isxdigit(*(ptr + 1))) {
                      switch (*ptr) {
                        default: val += *ptr - '0'; break;
                        case 'a': case 'A': val += 10; break;
                        case 'b': case 'B': val += 11; break;
                        case 'c': case 'C': val += 12; break;
                        case 'd': case 'D': val += 13; break;
                        case 'e': case 'E': val += 14; break;
                        case 'f': case 'F': val += 15; break;
                      }
                      val *= 16;
                      switch (*(ptr + 1)) {
                        default: val += *(ptr + 1) - '0'; break;
                        case 'a': case 'A': val += 10; break;
                        case 'b': case 'B': val += 11; break;
                        case 'c': case 'C': val += 12; break;
                        case 'd': case 'D': val += 13; break;
                        case 'e': case 'E': val += 14; break;
                        case 'f': case 'F': val += 15; break;
                      }
                    } else {
                      quit(argv[0], 0, "INVALID HEX DIGIT");
                    }
                    if (opt.klen == 246) quit(argv[0], 0, "PASSWORD TOO LONG");
                    opt.key[opt.klen++] = val;
                    ptr += 2;
                  }
                  if (*ptr) quit(argv[0], 0, "ODD NUMBER OF HEXADECIMAL PASSWORD VALUES");
                  break;
        case 'n': if (*(ptr = argv[argn] + 2) == 0) ptr = argv[++argn];
                  opt.rounds = strtol(ptr, &err, 10);
                  if ((opt.rounds < 1) || (*err != 0)) quit(argv[0], 0, "INVALID NUMBER OF ROUNDS");
                  break;
        case 'h': quit(argv[0], 1, 0); break;
      }
    }
    argn++;
  }
  /* *INDENT-ON* */

    if (opt.ifname) {
	opt.ifh = fopen(opt.ifname, "rb");
	if (!opt.ifh) {
	    fprintf(stderr,
		    "Unable to open input file. Program aborted.\n");
	    exit(EXIT_FAILURE);
	}
    }
    if (opt.ofname) {
	opt.ofh = fopen(opt.ofname, "wb");
	if (!opt.ofh) {
	    fclose(opt.ifh);
	    fprintf(stderr,
		    "Unable to open output file. Program aborted.\n");
	    exit(EXIT_FAILURE);
	}
    }
#if 0
    printf("DBG: mode is %d (0: encrypt; 1: decrypt)\n", opt.mode);
    printf("DBG: key is [%s] (len: %u)\n", opt.key, opt.klen);
    printf("DBG: doing %ld rounds\n", opt.rounds);
    printf("DBG: input filename %s (or handle %d)\n", opt.ifname,
	   fileno(opt.ifh));
    printf("DBG: output filename %s (or handle %d)\n", opt.ofname,
	   fileno(opt.ofh));
#endif

    {				/* work */
	int ch;
	size_t originallen = 0;
	size_t i, len = 0;
	unsigned char *originalmsg = NULL;
	unsigned char *workedmsg;
	unsigned char *tmp;

	/* read opt.ifh into originalmsg */
	while ((ch = fgetc(opt.ifh)) != EOF) {
	    if (len == originallen) {
		originallen = 1 + originallen * 13 / 8;
		tmp = realloc(originalmsg, originallen);
		if (!tmp) {
		    fprintf(stderr, "No memory while reading input\n");
		    exit(EXIT_FAILURE);
		}
		originalmsg = tmp;
	    }
	    originalmsg[len++] = ch;
	}
	/* allocate storage for result */
	if (opt.mode == 0) {
	    workedmsg = malloc(len + 10);
	} else {
	    if (len < 10) {
		fprintf(stderr, "No no! input file is not large enough\n");
		exit(EXIT_FAILURE);
	    }
	    workedmsg = malloc(len - 10);
	}
	if (!workedmsg) {
	    fprintf(stderr, "No memory for output\n");
	    exit(EXIT_FAILURE);
	}
	if (opt.mode == 0) {
	    encrypt(workedmsg, opt.rounds, originalmsg, len, opt.key,
		    opt.klen);
	    len += 10;
	} else {
	    decrypt(workedmsg, opt.rounds, originalmsg, len, opt.key,
		    opt.klen);
	    len -= 10;
	}
	/* write workedmsg into opt.ofh */
	tmp = workedmsg;
	for (i = 0; i < len; i++) {
	    fputc(*tmp++, opt.ofh);
	}
	free(workedmsg);
	free(originalmsg);
    }				/* work */

    if (opt.ifname) {
	fclose(opt.ifh);
    }
    if (opt.ofname) {
	fclose(opt.ofh);
    }

    return 0;
}
