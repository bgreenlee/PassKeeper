#include <limits.h>

/* If the system can handle byte ops, we use those so we don't have to do a
   lot of masking.  Otherwise, we use machine-word-size ops which will be
   faster on RISC machines */

#if UINT_MAX > 0xFFFFL		/* System has 32-bit ints */
  #define USE_LONG_RC4

  typedef unsigned int rc4word;
#else
  typedef unsigned char rc4word;
#endif /* UINT_MAX > 0xFFFFL */

/* The scheduled RC4 key */

typedef struct {
	rc4word state[ 256 ];
	rc4word x, y;
	} RC4KEY ;

void rc4ExpandKey( RC4KEY *rc4, unsigned char const *key, int keylen );
void rc4Crypt( RC4KEY *rc4, unsigned char *data, int len );
