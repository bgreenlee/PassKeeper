/* Optimized RC4 code, from an unknown source ("and they knew not from whence
   it had come...") */

#ifdef _MSC_VER
  #include "rc4.h"
#else
  #include "rc4/rc4.h"
#endif /* _MSC_VER */

void rc4ExpandKey( RC4KEY *rc4, unsigned char const *key, int keylen )
	{
	int x;
	rc4word sx, y = 0;
	unsigned keypos = 0;
	rc4word *state = &rc4->state[ 0 ];

	rc4->x = rc4->y = 0;

	for( x = 0; x < 256; x++ )
		state[ x ] = x;

	for( x = 0; x < 256; x++ )
		{
		sx = state[ x ];
		y += sx + key[ keypos ];
#ifdef USE_LONG_RC4
		y &= 0xFF;
#endif /* USE_LONG_RC4 */
		state[ x ] = state[ y ];
		state[ y ] = sx;

		if( ++keypos == keylen )
			keypos = 0;
		}
	}

void rc4Crypt( RC4KEY *rc4, unsigned char *data, int len )
{
	rc4word x = rc4->x, y = rc4->y;
	rc4word sx, sy;
	rc4word *state = &rc4->state[ 0 ];

	while (len--) {
		x++;
#ifdef USE_LONG_RC4
		x &= 0xFF;
#endif /* USE_LONG_RC4 */
		sx = state[ x ];
		y += sx;
#ifdef USE_LONG_RC4
		y &= 0xFF;
#endif /* USE_LONG_RC4 */
		sy = state[ y ];
		state[ y ] = sx;
		state[ x ] = sy;

#ifdef USE_LONG_RC4
		*data++ ^= state[ ( unsigned char ) ( sx+sy ) ];
#else
		*data++ ^= state[ ( sx+sy ) & 0xFF ];
#endif /* USE_LONG_RC4 */
	}

	rc4->x = x;
	rc4->y = y;
}
