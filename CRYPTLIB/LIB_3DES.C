#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "libdes/des.h"

/* The DES block size */

#define DES_BLOCKSIZE	8

/* A structure to hold the two keyscheduled DES keys */

typedef struct {
	Key_schedule desKey1;			/* The first DES key */
	Key_schedule desKey2;			/* The second DES key */
	} DES3_KEY;

/* The size of the keyscheduled DES and 3DES keys */

#define DES_KEYSIZE		sizeof( Key_schedule )
#define DES3_KEYSIZE	sizeof( DES3_KEY )

/****************************************************************************
*																			*
*								3DES Self-test Routines						*
*																			*
****************************************************************************/

/* Are there any 3DES test vectors?  Presumably X9F1 will eventually
   publish some... */

int des3SelfTest( void )
	{
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int des3InitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	/* Get rid of unused parameter warnings in a compiler-independant manner */
	if( cryptInfoEx );

	/* Allocate memory for the keyscheduled key */
	if( cryptInfo->key != NULL || cryptInfo->privateData != NULL )
		return( CRYPT_INITED );
	if( ( cryptInfo->key = malloc( DES3_KEYSIZE ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( cryptInfo->key, 0, DES3_KEYSIZE );
	cryptInfo->keyLength = DES3_KEYSIZE;

	return( CRYPT_OK );
	}

int des3Init( CRYPT_INFO *cryptInfo )
	{
	/* Just pass the call through to the extended setup routine */
	return( des3InitEx( cryptInfo, NULL ) );
	}

int des3End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	secureFree( &cryptInfo->key, cryptInfo->keyLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							3DES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int des3EncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		des_3ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2, DES_ENCRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int des3DecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	/* Make sure the data length is a multiple of the block size */
	if( noBytes % DES_BLOCKSIZE )
		return( CRYPT_BADPARM3 );

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		des_3ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2, DES_DECRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int des3EncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_3ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2, DES_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int des3DecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_3ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2, DES_DECRYPT );

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

int des3EncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_3ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
						  ( C_Block * ) cryptInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2, DES_ENCRYPT );

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

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int des3DecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_3ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
						  ( C_Block * ) cryptInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2, DES_ENCRYPT );

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

int des3EncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_3ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
						  ( C_Block * ) cryptInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2, DES_ENCRYPT );

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

/* Decrypt data in OFB mode */

int des3DecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;
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
		des_3ecb_encrypt( ( C_Block * ) cryptInfo->currentIV,
						  ( C_Block * ) cryptInfo->currentIV,
						  des3Key->desKey1, des3Key->desKey2, DES_ENCRYPT );

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

/****************************************************************************
*																			*
*							3DES Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule two DES keys */

int des3InitKey( CRYPT_INFO *cryptInfo )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->key;

	/* Call the libdes key schedule code.  Returns with -1 if the key parity
	   is wrong, -2 if a weak key is used */
	if( key_sched( ( C_Block * ) cryptInfo->userKey, des3Key->desKey1 ) )
		return( CRYPT_BADPARM );
	if( key_sched( ( C_Block * ) ( cryptInfo->userKey + bitsToBytes( 56 ) ),
				   des3Key->desKey2 ) )
		return( CRYPT_BADPARM );

	return( CRYPT_OK );
	}
