#include <string.h>
#ifdef _MSC_VER
  #include "../crypt.h"
  #include "shs.h"
#else
  #include "crypt.h"
  #include "mdc/shs.h"
#endif /* _MSC_VER */

/* The SHS f()-functions.  The f1 and f3 functions can be optimized to
   save one boolean operation each - thanks to Rich Schroeppel,
   rcs@cs.arizona.edu for discovering this */

/*#define f1(x,y,z)	( ( x & y ) | ( ~x & z ) )			// Rounds  0-19 */
#define f1(x,y,z)	( z ^ ( x & ( y ^ z ) ) )			/* Rounds  0-19 */
#define f2(x,y,z)	( x ^ y ^ z )						/* Rounds 20-39 */
/*#define f3(x,y,z)	( ( x & y ) | ( x & z ) | ( y & z ) )	// Rounds 40-59 */
#define f3(x,y,z)	( ( x & y ) | ( z & ( x | y ) ) )	/* Rounds 40-59 */
#define f4(x,y,z)	( x ^ y ^ z )						/* Rounds 60-79 */

/* The SHS Mysterious Constants */

#define K1	0x5A827999L									/* Rounds  0-19 */
#define K2	0x6ED9EBA1L									/* Rounds 20-39 */
#define K3	0x8F1BBCDCL									/* Rounds 40-59 */
#define K4	0xCA62C1D6L									/* Rounds 60-79 */

/* SHS initial values */

#define h0init	0x67452301L
#define h1init	0xEFCDAB89L
#define h2init	0x98BADCFEL
#define h3init	0x10325476L
#define h4init	0xC3D2E1F0L

/* Note that it may be necessary to add parentheses to these macros if they
   are to be called with expressions as arguments */

/* 32-bit rotate left - kludged with shifts */

#define ROTL(n,X)  ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )

/* The initial expanding function.  The hash function is defined over an
   80-word expanded input array W, where the first 16 are copies of the input
   data, and the remaining 64 are defined by

		W[ i ] = W[ i - 16 ] ^ W[ i - 14 ] ^ W[ i - 8 ] ^ W[ i - 3 ]

   This implementation generates these values on the fly in a circular
   buffer - thanks to Colin Plumb, colin@nyx10.cs.du.edu for this
   optimization.

   The updated SHS changes the expanding function by adding a rotate of 1
   bit.  Thanks to Jim Gillogly, jim@rand.org, and an anonymous contributor
   for this information */

#ifdef NEW_SHS
  #define expand(W,i) ( W[ i & 15 ] = ROTL( 1, ( W[ i & 15 ] ^ W[ i - 14 & 15 ] ^ \
												 W[ i - 8 & 15 ] ^ W[ i - 3 & 15 ] ) ) )
#else
  #define expand(W,i) ( W[ i & 15 ] ^= W[ i - 14 & 15 ] ^ W[ i - 8 & 15 ] ^ W[ i - 3 & 15 ] )
#endif /* NEW_SHS */

/* The prototype SHS sub-round.  The fundamental sub-round is:

		a' = e + ROTL( 5, a ) + f( b, c, d ) + k + data;
		b' = a;
		c' = ROTL( 30, b );
		d' = c;
		e' = d;

   but this is implemented by unrolling the loop 5 times and renaming the
   variables ( e, a, b, c, d ) = ( a', b', c', d', e' ) each iteration.
   This code is then replicated 20 times for each of the 4 functions, using
   the next 20 values from the W[] array each time */

#define subRound(a, b, c, d, e, f, k, data) \
	( e += ROTL( 5, a ) + f( b, c, d ) + k + data, b = ROTL( 30, b ) )

/* Initialize the SHS values */

void shsInit( SHS_INFO *shsInfo )
	{
	/* Set the h-vars to their initial values */
	shsInfo->digest[ 0 ] = h0init;
	shsInfo->digest[ 1 ] = h1init;
	shsInfo->digest[ 2 ] = h2init;
	shsInfo->digest[ 3 ] = h3init;
	shsInfo->digest[ 4 ] = h4init;

	/* Initialise bit count */
	shsInfo->countLo = shsInfo->countHi = 0;
	}

#ifndef ASM_SHS

/* Perform the SHS transformation.  Note that this code, like MD5, seems to
   break some optimizing compilers due to the complexity of the expressions
   and the size of the basic block.  It may be necessary to split it into
   sections, e.g. based on the four subrounds

   Note that this corrupts the shsInfo->data area */

void SHSTransform( LONG *digest, LONG *data )
	{
	LONG A, B, C, D, E;		/* Local vars */
	LONG eData[ 16 ];		/* Expanded data */

	/* Set up first buffer and local data buffer */
	A = digest[ 0 ];
	B = digest[ 1 ];
	C = digest[ 2 ];
	D = digest[ 3 ];
	E = digest[ 4 ];
	memcpy( eData, data, SHS_DATASIZE );

	/* Heavy mangling, in 4 sub-rounds of 20 interations each. */
	subRound( A, B, C, D, E, f1, K1, eData[  0 ] );
	subRound( E, A, B, C, D, f1, K1, eData[  1 ] );
	subRound( D, E, A, B, C, f1, K1, eData[  2 ] );
	subRound( C, D, E, A, B, f1, K1, eData[  3 ] );
	subRound( B, C, D, E, A, f1, K1, eData[  4 ] );
	subRound( A, B, C, D, E, f1, K1, eData[  5 ] );
	subRound( E, A, B, C, D, f1, K1, eData[  6 ] );
	subRound( D, E, A, B, C, f1, K1, eData[  7 ] );
	subRound( C, D, E, A, B, f1, K1, eData[  8 ] );
	subRound( B, C, D, E, A, f1, K1, eData[  9 ] );
	subRound( A, B, C, D, E, f1, K1, eData[ 10 ] );
	subRound( E, A, B, C, D, f1, K1, eData[ 11 ] );
	subRound( D, E, A, B, C, f1, K1, eData[ 12 ] );
	subRound( C, D, E, A, B, f1, K1, eData[ 13 ] );
	subRound( B, C, D, E, A, f1, K1, eData[ 14 ] );
	subRound( A, B, C, D, E, f1, K1, eData[ 15 ] );
	subRound( E, A, B, C, D, f1, K1, expand( eData, 16 ) );
	subRound( D, E, A, B, C, f1, K1, expand( eData, 17 ) );
	subRound( C, D, E, A, B, f1, K1, expand( eData, 18 ) );
	subRound( B, C, D, E, A, f1, K1, expand( eData, 19 ) );

	subRound( A, B, C, D, E, f2, K2, expand( eData, 20 ) );
	subRound( E, A, B, C, D, f2, K2, expand( eData, 21 ) );
	subRound( D, E, A, B, C, f2, K2, expand( eData, 22 ) );
	subRound( C, D, E, A, B, f2, K2, expand( eData, 23 ) );
	subRound( B, C, D, E, A, f2, K2, expand( eData, 24 ) );
	subRound( A, B, C, D, E, f2, K2, expand( eData, 25 ) );
	subRound( E, A, B, C, D, f2, K2, expand( eData, 26 ) );
	subRound( D, E, A, B, C, f2, K2, expand( eData, 27 ) );
	subRound( C, D, E, A, B, f2, K2, expand( eData, 28 ) );
	subRound( B, C, D, E, A, f2, K2, expand( eData, 29 ) );
	subRound( A, B, C, D, E, f2, K2, expand( eData, 30 ) );
	subRound( E, A, B, C, D, f2, K2, expand( eData, 31 ) );
	subRound( D, E, A, B, C, f2, K2, expand( eData, 32 ) );
	subRound( C, D, E, A, B, f2, K2, expand( eData, 33 ) );
	subRound( B, C, D, E, A, f2, K2, expand( eData, 34 ) );
	subRound( A, B, C, D, E, f2, K2, expand( eData, 35 ) );
	subRound( E, A, B, C, D, f2, K2, expand( eData, 36 ) );
	subRound( D, E, A, B, C, f2, K2, expand( eData, 37 ) );
	subRound( C, D, E, A, B, f2, K2, expand( eData, 38 ) );
	subRound( B, C, D, E, A, f2, K2, expand( eData, 39 ) );

	subRound( A, B, C, D, E, f3, K3, expand( eData, 40 ) );
	subRound( E, A, B, C, D, f3, K3, expand( eData, 41 ) );
	subRound( D, E, A, B, C, f3, K3, expand( eData, 42 ) );
	subRound( C, D, E, A, B, f3, K3, expand( eData, 43 ) );
	subRound( B, C, D, E, A, f3, K3, expand( eData, 44 ) );
	subRound( A, B, C, D, E, f3, K3, expand( eData, 45 ) );
	subRound( E, A, B, C, D, f3, K3, expand( eData, 46 ) );
	subRound( D, E, A, B, C, f3, K3, expand( eData, 47 ) );
	subRound( C, D, E, A, B, f3, K3, expand( eData, 48 ) );
	subRound( B, C, D, E, A, f3, K3, expand( eData, 49 ) );
	subRound( A, B, C, D, E, f3, K3, expand( eData, 50 ) );
	subRound( E, A, B, C, D, f3, K3, expand( eData, 51 ) );
	subRound( D, E, A, B, C, f3, K3, expand( eData, 52 ) );
	subRound( C, D, E, A, B, f3, K3, expand( eData, 53 ) );
	subRound( B, C, D, E, A, f3, K3, expand( eData, 54 ) );
	subRound( A, B, C, D, E, f3, K3, expand( eData, 55 ) );
	subRound( E, A, B, C, D, f3, K3, expand( eData, 56 ) );
	subRound( D, E, A, B, C, f3, K3, expand( eData, 57 ) );
	subRound( C, D, E, A, B, f3, K3, expand( eData, 58 ) );
	subRound( B, C, D, E, A, f3, K3, expand( eData, 59 ) );

	subRound( A, B, C, D, E, f4, K4, expand( eData, 60 ) );
	subRound( E, A, B, C, D, f4, K4, expand( eData, 61 ) );
	subRound( D, E, A, B, C, f4, K4, expand( eData, 62 ) );
	subRound( C, D, E, A, B, f4, K4, expand( eData, 63 ) );
	subRound( B, C, D, E, A, f4, K4, expand( eData, 64 ) );
	subRound( A, B, C, D, E, f4, K4, expand( eData, 65 ) );
	subRound( E, A, B, C, D, f4, K4, expand( eData, 66 ) );
	subRound( D, E, A, B, C, f4, K4, expand( eData, 67 ) );
	subRound( C, D, E, A, B, f4, K4, expand( eData, 68 ) );
	subRound( B, C, D, E, A, f4, K4, expand( eData, 69 ) );
	subRound( A, B, C, D, E, f4, K4, expand( eData, 70 ) );
	subRound( E, A, B, C, D, f4, K4, expand( eData, 71 ) );
	subRound( D, E, A, B, C, f4, K4, expand( eData, 72 ) );
	subRound( C, D, E, A, B, f4, K4, expand( eData, 73 ) );
	subRound( B, C, D, E, A, f4, K4, expand( eData, 74 ) );
	subRound( A, B, C, D, E, f4, K4, expand( eData, 75 ) );
	subRound( E, A, B, C, D, f4, K4, expand( eData, 76 ) );
	subRound( D, E, A, B, C, f4, K4, expand( eData, 77 ) );
	subRound( C, D, E, A, B, f4, K4, expand( eData, 78 ) );
	subRound( B, C, D, E, A, f4, K4, expand( eData, 79 ) );

	/* Build message digest */
	digest[ 0 ] += A;
	digest[ 1 ] += B;
	digest[ 2 ] += C;
	digest[ 3 ] += D;
	digest[ 4 ] += E;
	}
#else
  void SHSTransform( LONG *digest, LONG *data );
#endif /* !ASM_SHS */

#ifdef TEST_SHS

/* When run on a little-endian CPU we need to perform byte reversal on an
   array of longwords.  It is possible to make the code endianness-
   independant by fiddling around with data at the byte level, but this
   makes for very slow code, so we rely on the user to sort out endianness
   at compile time */

#if defined( LITTLE_ENDIAN )

void longReverse( LONG *buffer, int byteCount )
	{
	LONG value;

	byteCount /= sizeof( LONG );
	while( byteCount-- )
		{
		value = *buffer;
		value = ( ( value & 0xFF00FF00L ) >> 8  ) | \
				( ( value & 0x00FF00FFL ) << 8 );
		*buffer++ = ( value << 16 ) | ( value >> 16 );
		}
	}
#else
  #define longReverse(buf, count)
#endif /* LITTLE_ENDIAN */

#endif /* TEST_SHS */

/* Update SHS for a block of data */

void shsUpdate( SHS_INFO *shsInfo, BYTE *buffer, int count )
	{
	LONG tmp;
	int dataCount;

	/* Update bitcount */
	tmp = shsInfo->countLo;
	if ( ( shsInfo->countLo = tmp + ( ( LONG ) count << 3 ) ) < tmp )
		shsInfo->countHi++;				/* Carry from low to high */
	shsInfo->countHi += count >> 29;

	/* Get count of bytes already in data */
	dataCount = ( int ) ( tmp >> 3 ) & 0x3F;

	/* Handle any leading odd-sized chunks */
	if( dataCount )
		{
		BYTE *p = ( BYTE * ) shsInfo->data + dataCount;

		dataCount = SHS_DATASIZE - dataCount;
		if( count < dataCount )
			{
			memcpy( p, buffer, count );
			return;
			}
		memcpy( p, buffer, dataCount );
		longReverse( shsInfo->data, SHS_DATASIZE );
		SHSTransform( shsInfo->digest, shsInfo->data );
		buffer += dataCount;
		count -= dataCount;
		}

	/* Process data in SHS_DATASIZE chunks */
	while( count >= SHS_DATASIZE )
		{
		memcpy( shsInfo->data, buffer, SHS_DATASIZE );
		longReverse( shsInfo->data, SHS_DATASIZE );
		SHSTransform( shsInfo->digest, shsInfo->data );
		buffer += SHS_DATASIZE;
		count -= SHS_DATASIZE;
		}

	/* Handle any remaining bytes of data. */
	memcpy( shsInfo->data, buffer, count );
	}

/* Final wrapup - pad to SHS_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

void shsFinal( SHS_INFO *shsInfo )
	{
	int count;
	BYTE *dataPtr;

	/* Compute number of bytes mod 64 */
	count = ( int ) shsInfo->countLo;
	count = ( count >> 3 ) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	dataPtr = ( BYTE * ) shsInfo->data + count;
	*dataPtr++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = SHS_DATASIZE - 1 - count;

	/* Pad out to 56 mod 64 */
	if( count < 8 )
		{
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset( dataPtr, 0, count );
		longReverse( shsInfo->data, SHS_DATASIZE );
		SHSTransform( shsInfo->digest, shsInfo->data );

		/* Now fill the next block with 56 bytes */
		memset( shsInfo->data, 0, SHS_DATASIZE - 8 );
		}
	else
		/* Pad block to 56 bytes */
		memset( dataPtr, 0, count - 8 );

	/* Append length in bits and transform */
	shsInfo->data[ 14 ] = shsInfo->countHi;
	shsInfo->data[ 15 ] = shsInfo->countLo;

	longReverse( shsInfo->data, SHS_DATASIZE - 8 );
	SHSTransform( shsInfo->digest, shsInfo->data );
	}

/****************************************************************************
*																			*
* 								SHS Test Code 								*
*																			*
****************************************************************************/

#ifdef TEST_SHS

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Test the SHS implementation */

#ifdef NEW_SHS

static LONG shsTestResults[][ 5 ] = {
	{ 0xA9993E36L, 0x4706816AL, 0xBA3E2571L, 0x7850C26CL, 0x9CD0D89DL, },
	{ 0x84983E44L, 0x1C3BD26EL, 0xBAAE4AA1L, 0xF95129E5L, 0xE54670F1L, },
	{ 0x34AA973CL, 0xD4C4DAA4L, 0xF61EEB2BL, 0xDBAD2731L, 0x6534016FL, }
	};

#else

static LONG shsTestResults[][ 5 ] = {
	{ 0x0164B8A9L, 0x14CD2A5EL, 0x74C4F7FFL, 0x082C4D97L, 0xF1EDF880L },
	{ 0xD2516EE1L, 0xACFA5BAFL, 0x33DFC1C4L, 0x71E43844L, 0x9EF134C8L },
	{ 0x3232AFFAL, 0x48628A26L, 0x653B5AAAL, 0x44541FD9L, 0x0D690603L }
	};
#endif /* NEW_SHS */

static int compareSHSresults( SHS_INFO *shsInfo, int shsTestLevel )
	{
	int i;

	/* Compare the returned digest and required values */
	for( i = 0; i < 5; i++ )
		if( shsInfo->digest[ i ] != shsTestResults[ shsTestLevel ][ i ] )
			return( ERROR );
	return( OK );
	}

void main( void )
	{
	SHS_INFO shsInfo;
	unsigned int i;
	time_t secondCount;
	BYTE data[ 200 ];

	/* Make sure we've got the endianness set right.  If the machine is
	   big-endian (up to 64 bits) the following value will be signed,
	   otherwise it will be unsigned.  Unfortunately we can't test for odd
	   things like middle-endianness without knowing the size of the data
	   types */
#ifdef LITTLE_ENDIAN
	if( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" < 0 )
		{
		puts( "Error: Comment out the LITTLE_ENDIAN define in SHS.H and recompile" );
		exit( ERROR );
		}
#else
	if( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" >= 0 )
		{
		puts( "Error: Uncomment the LITTLE_ENDIAN define in SHS.H and recompile" );
		exit( ERROR );
		}
#endif /* LITTLE_ENDIAN */

	/* Test SHS against values given in SHS standards document */
	printf( "Running SHS test 1 ... " );
	shsInit( &shsInfo );
	shsUpdate( &shsInfo, ( BYTE * ) "abc", 3 );
	shsFinal( &shsInfo );
	if( compareSHSresults( &shsInfo, 0 ) == ERROR )
		{
		putchar( '\n' );
		puts( "SHS test 1 failed" );
		exit( ERROR );
		}
#ifdef NEW_SHS
	puts( "passed, result= A9993E364706816ABA3E25717850C26C9CD0D89D" );
#else
	puts( "passed, result= 0164B8A914CD2A5E74C4F7FF082C4D97F1EDF880" );
#endif /* NEW_SHS */

	printf( "Running SHS test 2 ... " );
	shsInit( &shsInfo );
	shsUpdate( &shsInfo, ( BYTE * ) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56 );
	shsFinal( &shsInfo );
	if( compareSHSresults( &shsInfo, 1 ) == ERROR )
		{
		putchar( '\n' );
		puts( "SHS test 2 failed" );
		exit( ERROR );
		}
#ifdef NEW_SHS
	puts( "passed, result= 84983E441C3BD26EBAAE4AA1F95129E5E54670F1" );
#else
	puts( "passed, result= D2516EE1ACFA5BAF33DFC1C471E438449EF134C8" );
#endif /* NEW_SHS */

	printf( "Running SHS test 3 ... " );
	shsInit( &shsInfo );
	for( i = 0; i < 15625; i++ )
		shsUpdate( &shsInfo, ( BYTE * ) "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64 );
	shsFinal( &shsInfo );
	if( compareSHSresults( &shsInfo, 2 ) == ERROR )
		{
		putchar( '\n' );
		puts( "SHS test 3 failed" );
		exit( ERROR );
		}
#ifdef NEW_SHS
	puts( "passed, result= 34AA973CD4C4DAA4F61EEB2BDBAD27316534016F" );
#else
	puts( "passed, result= 3232AFFA48628A26653B5AAA44541FD90D690603" );
#endif /* NEW_SHS */

	printf( "\nTesting speed for 10MB data... " );
	shsInit( &shsInfo );
	secondCount = time( NULL );
	for( i = 0; i < 50000U; i++ )
		shsUpdate( &shsInfo, data, 200 );
	secondCount = time( NULL ) - secondCount;
	printf( "done.  Time = %ld seconds, %ld kbytes/second\n", \
			secondCount, 10050L / secondCount );

	puts( "\nAll SHS tests passed" );
	exit( OK );
	}
#endif /* TEST_SHS */
