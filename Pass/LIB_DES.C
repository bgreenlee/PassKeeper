#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define __WINDOWS__
extern "C" {
#include "crypt.h"
#include "des.h"
}

/* The DES key and block size */

#define DES_KEYSIZE				7
#define DES_BLOCKSIZE			8

/* The size of the keyscheduled DES key */

#define DES_EXPANDED_KEYSIZE	sizeof( Key_schedule )

/****************************************************************************
*																			*
*							DES Self-test Routines							*
*																			*
****************************************************************************/

#include "testdes.h"

/* Test the DES implementation against the test vectors given in NBS Special
   Publication 500-20, 1980.  We need to perform the tests at a very low
   level since the encryption library hasn't been intialized yet */

static int desTestLoop( DES_TEST *testData, int iterations, int operation )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	BYTE key[ DES_EXPANDED_KEYSIZE ];
	int i;

	for( i = 0; i < iterations; i++ )
		{
		memcpy( temp, testData[ i ].plaintext, DES_BLOCKSIZE );
		key_sched( ( C_Block * ) testData[ i ].key,
				   *( ( Key_schedule * ) key ) );
		des_ecb_encrypt( ( C_Block * ) temp, ( C_Block * ) temp,
						 *( ( Key_schedule * ) key ), operation );
		if( memcmp( testData[ i ].ciphertext, temp, DES_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

int desSelfTest( void )
	{
	/* Check the DES test vectors */
	if( ( desTestLoop( testIP, sizeof( testIP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testVP, sizeof( testVP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testKP, sizeof( testKP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testRS, sizeof( testRS ) / sizeof( DES_TEST ),
					   DES_DECRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testDP, sizeof( testDP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testSB, sizeof( testSB ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) )
		return( CRYPT_SELFTEST );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int desInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	/* Get rid of unused parameter warnings in a compiler-independant manner */
	if( cryptInfoEx );

	/* Allocate memory for the keyscheduled key */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->key = malloc( DES_EXPANDED_KEYSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( cryptInfo->key, 0, DES_EXPANDED_KEYSIZE );
	cryptInfo->keyLength = DES_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int desInit( CRYPT_INFO *cryptInfo )
	{
	/* Just pass the call through to the extended setup routine */
	return( desInitEx( cryptInfo, NULL ) );
	}

int desEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key, cryptInfo->keyLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int desEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 cryptInfo->key, DES_ENCRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int desDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 cryptInfo->key, DES_DECRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int desEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Encrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 cryptInfo->key, DES_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int desDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, DES_BLOCKSIZE );

		/* Decrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						 cryptInfo->key, DES_DECRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int desEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i + ivCount ];
		memcpy( cryptInfo->currentIV + ivCount, buffer, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
        				 ( C_Block * ) cryptInfo->currentIV,
						 cryptInfo->key, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		memcpy( temp, buffer, bytesToUse );
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i + ivCount ];
		memcpy( cryptInfo->currentIV + ivCount, temp, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
        				 ( C_Block * ) cryptInfo->currentIV,
						 cryptInfo->key, DES_ENCRYPT );

		/* Save the ciphertext */
		memcpy( temp, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int desEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
        				 ( C_Block * ) cryptInfo->currentIV,
						 cryptInfo->key, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
        				 ( C_Block * ) cryptInfo->currentIV,
						 cryptInfo->key, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in PCBC mode */

int desEncryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	/* Encrypt the entire buffer */
	des_pcbc_encrypt( ( C_Block *) buffer, ( C_Block * ) buffer,
					  noBytes, cryptInfo->key,
					  ( C_Block * ) cryptInfo->currentIV, DES_ENCRYPT );

	return( CRYPT_OK );
	}

int desDecryptPCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	/* Decrypt the entire buffer */
	des_pcbc_encrypt( ( C_Block *) buffer, ( C_Block * ) buffer,
					  noBytes, cryptInfo->key,
					  ( C_Block * ) cryptInfo->currentIV, DES_DECRYPT );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DES Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule a DES key */

int desInitKey( CRYPT_INFO *cryptInfo )
	{
	/* Call the libdes key schedule code.  Returns with -1 if the key parity
	   is wrong, -2 if a weak key is used */
	if( key_sched( ( C_Block * ) cryptInfo->userKey,
				   *( ( Key_schedule * ) cryptInfo->key ) ) )
		return( CRYPT_BADPARM );

	return( CRYPT_OK );
	}
