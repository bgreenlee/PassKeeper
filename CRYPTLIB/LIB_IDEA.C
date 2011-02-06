#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "idea/idea.h"

/* The IDEA key and block size */

#define IDEA_KEYSIZE	IDEAKEYSIZE
#define IDEA_BLOCKSIZE	IDEABLOCKSIZE

/* A structure to hold the two expanded IDEA keys */

typedef struct {
	WORD eKey[ IDEAKEYLEN ];		/* The encryption key */
	WORD dKey[ IDEAKEYLEN ];		/* The decryption key */
	} IDEA_KEY;

/* The size of the expanded IDEA keys */

#define IDEA_EXPANDED_KEYSIZE		sizeof( IDEA_KEY )

/****************************************************************************
*																			*
*								IDEA Self-test Routines						*
*																			*
****************************************************************************/

#include "testidea.h"

/* Test the IDEA code against the test vectors from the ETH reference
   implementation */

int ideaSelfTest( void )
	{
	BYTE temp[ IDEA_BLOCKSIZE ];
	WORD key[ IDEAKEYLEN ];
	int i;

	for( i = 0; i < sizeof( testIdea ) / sizeof( IDEA_TEST ); i++ )
		{
		memcpy( temp, testIdea[ i ].plaintext, IDEA_BLOCKSIZE );
		ideaExpandKey( testIdea[ i ].key, key );
		ideaCipher( temp, temp, key );
		if( memcmp( testIdea[ i ].ciphertext, temp, IDEA_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int ideaInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	/* Get rid of unused parameter warnings in a compiler-independant manner */
	if( cryptInfoEx );

	/* Allocate memory for the keyscheduled key */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->key = malloc( IDEA_EXPANDED_KEYSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( cryptInfo->key, 0, IDEA_EXPANDED_KEYSIZE );
	cryptInfo->keyLength = IDEA_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int ideaInit( CRYPT_INFO *cryptInfo )
	{
	/* Just pass the call through to the extended setup routine */
	return( ideaInitEx( cryptInfo, NULL ) );
	}

int ideaEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key, cryptInfo->keyLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							IDEA En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int ideaEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;
	int blockCount = noBytes / IDEA_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % IDEA_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		ideaCipher( buffer, buffer, ideaKey->eKey );

		/* Move on to next block of data */
		buffer += IDEA_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int ideaDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;
	int blockCount = noBytes / IDEA_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % IDEA_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		ideaCipher( buffer, buffer, ideaKey->dKey );

		/* Move on to next block of data */
		buffer += IDEA_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int ideaEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;
	int blockCount = noBytes / IDEA_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % IDEA_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < IDEA_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Encrypt a block of data */
		ideaCipher( buffer, buffer, ideaKey->eKey );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, IDEA_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += IDEA_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int ideaDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;
	BYTE temp[ IDEA_BLOCKSIZE ];
	int blockCount = noBytes / IDEA_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % IDEA_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, IDEA_BLOCKSIZE );

		/* Decrypt a block of data */
		ideaCipher( buffer, buffer, ideaKey->dKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < IDEA_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, IDEA_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += IDEA_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int ideaEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = IDEA_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > IDEA_BLOCKSIZE ) ? IDEA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ideaCipher( cryptInfo->currentIV, cryptInfo->currentIV, ideaKey->eKey );

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
	cryptInfo->ivCount = ( ivCount % IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int ideaDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;
	BYTE temp[ IDEA_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = IDEA_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > IDEA_BLOCKSIZE ) ? IDEA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ideaCipher( cryptInfo->currentIV, cryptInfo->currentIV, ideaKey->eKey );

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
	cryptInfo->ivCount = ( ivCount % IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int ideaEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = IDEA_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > IDEA_BLOCKSIZE ) ? IDEA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ideaCipher( cryptInfo->currentIV, cryptInfo->currentIV, ideaKey->eKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int ideaDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;
	int i, ivCount = cryptInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = IDEA_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > IDEA_BLOCKSIZE ) ? IDEA_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		ideaCipher( cryptInfo->currentIV, cryptInfo->currentIV, ideaKey->eKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ivCount = ( ivCount % IDEA_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							IDEA Key Management Routines					*
*																			*
****************************************************************************/

/* Key schedule an IDEA key */

int ideaInitKey( CRYPT_INFO *cryptInfo )
	{
	IDEA_KEY *ideaKey = ( IDEA_KEY * ) cryptInfo->key;

	/* Generate an expanded IDEA key and its inverse */
	ideaExpandKey( cryptInfo->userKey, ideaKey->eKey );
	ideaInvertKey( ideaKey->eKey, ideaKey->dKey );

	return( CRYPT_OK );
	}
