#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"

/* The size of the test buffers */

#define TESTBUFFER_SIZE		256

/* Work routines: Set a pair of encrypt/decrypt buffers to a known state,
   and make sure they're still in that known state */

static void initTestBuffers( BYTE *buffer1, BYTE *buffer2 )
	{
	/* Set the buffers to a known state */
	memset( buffer1, '*', TESTBUFFER_SIZE );
	memcpy( buffer1, "12345678", 8 );		/* For endianness check */
	memcpy( buffer2, buffer1, TESTBUFFER_SIZE );
	}

static void checkTestBuffers( BYTE *buffer1, BYTE *buffer2 )
	{
	/* Make sure everything went OK */
	if( memcmp( buffer1, buffer2, TESTBUFFER_SIZE ) )
		{
		puts( "Warning: Decrypted data != original plaintext." );

		/* Try and guess at block chaining problems */
		if( !memcmp( buffer1, "12345678****", 12 ) )
			puts( "\t It looks like there's a problem with block chaining." );
		else
			/* Try and guess at endianness problems - we want "1234" */
			if( !memcmp( buffer1, "4321", 4 ) )
				puts( "\t It looks like the 32-bit word endianness is "
					  "reversed." );
			else
				if( !memcmp( buffer1, "2143", 4 ) )
					puts( "\t It looks like the 16-bit word endianness is "
						  "reversed." );
			else
				if( buffer1[ 0 ] >= '1' && buffer1[ 0 ] <= '9' )
					puts( "\t It looks like there's some sort of endianness "
						  "problem which is\n\t more complex than just a "
						  "reversal." );
				else
					puts( "\t It's probably more than just an endianness "
						  "problem." );
		}
	}

/* Report information on the encryption algorithm */

static void reportAlgorithmInformation( char *algorithmName,
										CRYPT_QUERY_INFO *cryptQueryInfo )
	{
	char speedFactor[ 50 ];

	/* Determine the speed factor relative to a block copy */
	if( cryptQueryInfo->speed == CRYPT_ERROR )
		strcpy( speedFactor, "unknown speed factor" );
	else
		sprintf( speedFactor, "0.%03d times the speed of a block copy",
				 cryptQueryInfo->speed );

	printf( "%s algorithm is available with\n"
				"  name `%s', block size %d bits, %s,\n"
				"  min key size %d bits, recommended key size %d bits, "
					"max key size %d bits,\n"
				"  min IV size %d bits, recommended IV size %d bits, "
					"max IV size %d bits.\n",
				algorithmName, cryptQueryInfo->algoName,
				bytesToBits( cryptQueryInfo->blockSize ), speedFactor,
				bytesToBits( cryptQueryInfo->minKeySize ),
				bytesToBits( cryptQueryInfo->keySize ),
				bytesToBits( cryptQueryInfo->maxKeySize ),
				bytesToBits( cryptQueryInfo->minIVsize ),
				bytesToBits( cryptQueryInfo->ivSize ),
				bytesToBits( cryptQueryInfo->maxIVsize ) );
	}

/* Check the library for an algorithm/mode */

static BOOLEAN checkLibraryInfo( char *name, char *longName,
								 CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	int status;

	status = queryAlgoAvailability( cryptAlgo );
	if( isStatusError( status ) )
		{
		printf( "queryAlgoAvailability() reports %s is not available: "
				"Code %d.\n", name, status );
		return( FALSE );
		}
	status = queryModeAvailability( cryptAlgo, cryptMode );
	if( isStatusError( status ) )
		{
		printf( "queryModeAvailability() reports %s is not available: "
				"Code %d.\n", longName, status );
		return( FALSE );
		}
	status = queryAlgoModeInformation( cryptAlgo, cryptMode, &cryptQueryInfo );
	printf( "queryModeAvailability() reports " );
	if( isStatusOK( status ) )
		reportAlgorithmInformation( longName, &cryptQueryInfo );
	else
		{
		printf( "no information available on %s algorithm: Code %d.\n",
				name, status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load the encryption contexts */

static BOOLEAN loadContexts( CRYPT_INFO *cryptInfo, CRYPT_INFO *decryptInfo,
							 CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode,
							 BYTE *key, int length )
	{
	int status;

	/* Create the encryption context */
	status = initCryptContext( cryptInfo, cryptAlgo, cryptMode );
	if( isStatusError( status ) )
		{
		printf( "initCryptContext(): Failed with error code %d.\n", status );
		return( FALSE );
		}
	status = loadCryptContext( cryptInfo, key, length );
	if( isStatusError( status ) )
		{
		printf( "loadCryptContext(): Failed with error code %d.\n", status );
		return( FALSE );
		}

	/* Create the decryption context */
	status = initCryptContext( decryptInfo, cryptAlgo, cryptMode );
	if( isStatusError( status ) )
		{
		printf( "initCryptContext(): Failed with error code %d.\n", status );
		return( FALSE );
		}
	status = loadCryptContext( decryptInfo, key, length );
	if( isStatusError( status ) )
		{
		printf( "loadCryptContext(): Failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Perform a test en/decryption */

static void testCrypt( CRYPT_INFO *cryptInfo, CRYPT_INFO *decryptInfo,
					   BYTE *buffer )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	BYTE iv[ 100 ];
	int status;

	/* Find out about the algorithm we're using */
	queryContextInformation( cryptInfo, &cryptQueryInfo );
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_CFB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_OFB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_STREAM )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = encryptBuffer( cryptInfo, buffer, 79 );
		if( isStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = encryptBuffer( cryptInfo, buffer + 79, TESTBUFFER_SIZE - 79 );
		if( isStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = encryptBuffer( cryptInfo, buffer + TESTBUFFER_SIZE, 0 );

		/* Copy the IV from the encryption to the decryption context */
		status = retrieveIV( cryptInfo, iv );
		if( isStatusError( status ) )
			printf( "Couldn't retrieve IV after encryption: Code %d.\n",
					status );
		status = loadIV( decryptInfo, iv, cryptQueryInfo.ivSize );
		if( isStatusError( status ) )
			printf( "Couldn't load IV for decryption: Code %d.\n", status );

		/* Decrypt the buffer in different odd-size chunks */
		status = decryptBuffer( decryptInfo, buffer, 125 );
		if( isStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = decryptBuffer( decryptInfo, buffer + 125, TESTBUFFER_SIZE - 125 );
		if( isStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );

		return;
		}
	if( cryptQueryInfo.cryptMode == CRYPT_MODE_ECB ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_CBC ||
		cryptQueryInfo.cryptMode == CRYPT_MODE_PCBC )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = encryptBuffer( cryptInfo, buffer, 80 );
		if( isStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = encryptBuffer( cryptInfo, buffer + 80, TESTBUFFER_SIZE - 80 );
		if( isStatusError( status ) )
			printf( "Couldn't encrypt data: Code %d.\n", status );
		status = encryptBuffer( cryptInfo, buffer + TESTBUFFER_SIZE, 0 );

		/* Copy the IV from the encryption to the decryption context */
		status = retrieveIV( cryptInfo, iv );
		if( isStatusError( status ) )
			printf( "Couldn't retrieve IV after encryption: Code %d.\n",
					status );
		status = loadIV( decryptInfo, iv, cryptQueryInfo.ivSize );
		if( isStatusError( status ) )
			printf( "Couldn't load IV for decryption: Code %d.\n", status );

		/* Decrypt the buffer in different odd-size chunks */
		status = decryptBuffer( decryptInfo, buffer, 128 );
		if( isStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );
		status = decryptBuffer( decryptInfo, buffer + 128, TESTBUFFER_SIZE - 128 );
		if( isStatusError( status ) )
			printf( "Couldn't decrypt data: Code %d.\n", status );

		return;
		}

	puts( "Unknown encryption mode found in test code." );
	}

/* Destroy the encryption contexts */

static void destroyContexts( CRYPT_INFO *cryptInfo, CRYPT_INFO *decryptInfo )
	{
	int status;

	status = destroyCryptContext( cryptInfo );
	if( isStatusError( status ) )
		printf( "destroyCryptContext(): Failed with error code %d.\n", status );
	status = destroyCryptContext( decryptInfo );
	if( isStatusError( status ) )
		printf( "destroyCryptContext(): Failed with error code %d.\n", status );
	}

/* Sample code to test an algorithm/mode implementation */

static int testLibrary( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode,
						char *name, char *longName )
	{
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	CRYPT_INFO cryptInfo, decryptInfo;
	CRYPT_INFO_MDCSHS cryptInfoEx;
	int status;

	/* Initialise the test buffers */
	initTestBuffers( buffer, testBuffer );

	/* Check the capabilities of the library */
	putchar( '\n' );
	if( !checkLibraryInfo( name, longName, cryptAlgo, cryptMode ) )
		return( FALSE );

	/* Set up an encryption context, load a user key into it, and perform a
	   key setup */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_MDCSHS:
			/* We use an extended setup with reduced iteration count for
			   people who have to run this thing 2000 times while debugging */
			cryptInfoEx.keySetupIterations = 10;
			status = initCryptContextEx( &cryptInfo, cryptAlgo, cryptMode,
										 &cryptInfoEx );
			if( isStatusError( status ) )
				{
				printf( "initCryptContext(): Failed with error code %d.\n",
						status );
				return( FALSE );
				}
			status = loadCryptContext( &cryptInfo, "Test key", 8 );
			if( isStatusError( status ) )
				{
				printf( "loadCryptContext(): Failed with error code %d.\n",
						status );
				return( FALSE );
				}

			/* Create another crypt context for decryption.  The error
			   checking here is a bit less picky to save space */
			cryptInfoEx.keySetupIterations = 10;
			initCryptContextEx( &decryptInfo, cryptAlgo, cryptMode,
								&cryptInfoEx );
			status = loadCryptContext( &decryptInfo, "Test key", 8 );
			if( isStatusError( status ) )
				{
				printf( "loadCryptContext(): Failed with error code %d.\n",
						status );
				return( FALSE );
				}
			break;

		case CRYPT_ALGO_DES:
			if( !loadContexts( &cryptInfo, &decryptInfo, cryptAlgo, cryptMode,
							   ( BYTE * ) "1234567", 7 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_3DES:
			if( !loadContexts( &cryptInfo, &decryptInfo, cryptAlgo, cryptMode,
							   ( BYTE * ) "12345677654321", 14 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_IDEA:
			if( !loadContexts( &cryptInfo, &decryptInfo, cryptAlgo, cryptMode,
							   ( BYTE * ) "1234567887654321", 16 ) )
				return( FALSE );
			break;

		case CRYPT_ALGO_RC4:
			if( !loadContexts( &cryptInfo, &decryptInfo, cryptAlgo, cryptMode,
							   ( BYTE * ) "12345678900987654321", 20 ) )
				return( FALSE );
			break;

		default:
			printf( "Unknown encryption algorithm = ID %d, cannot perform "
					"encryption test\n", cryptAlgo );
			return( FALSE );
		}

	/* Perform a test en/decryption */
	testCrypt( &cryptInfo, &decryptInfo, buffer );

	/* Make sure everything went OK */
	checkTestBuffers( buffer, testBuffer );

	/* Destroy the encryption contexts */
	destroyContexts( &cryptInfo, &decryptInfo );

	return( TRUE );
	}

/* Exercise various aspects of the encryption library */

void main( void )
	{
	int status, bigEndian;

	/* Make sure we've got the endianness set right.  If the machine is
	   big-endian (up to 64 bits) the following value will be signed,
	   otherwise it will be unsigned.  Unfortunately we can't test for
	   things like middle-endianness without knowing the size of the data
	   types */
	bigEndian = ( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" < 0 );
#ifdef LITTLE_ENDIAN
	if( bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nbig-endian, not little-endian.  Edit "
			  "the file and rebuild the library." );
		exit( EXIT_FAILURE );
		}
#else
	if( !bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nlittle-endian, not big-endian.  Edit "
			  "the file and rebuild the library." );
		exit( EXIT_FAILURE );
		}
#endif /* LITTLE_ENDIAN */

	/* Initialise the library */
	status = initLibrary();
	if( isStatusError( status ) )
		{
		printf( "Couldn't init library, code %d.\n", status );
		exit( EXIT_FAILURE );
		}

	/* Test the encryption routines contained in the library */
	if( !testLibrary( CRYPT_ALGO_MDCSHS, CRYPT_MODE_CFB, "MDC/SHS",
					  "MDC/SHS-CFB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_DES, CRYPT_MODE_ECB, "DES", "DES-ECB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_DES, CRYPT_MODE_CBC, "DES", "DES-CBC" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_DES, CRYPT_MODE_CFB, "DES", "DES-CFB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_DES, CRYPT_MODE_OFB, "DES", "DES-OFB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_DES, CRYPT_MODE_PCBC, "DES", "DES-PCBC" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_3DES, CRYPT_MODE_ECB, "3DES", "3DES-ECB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_3DES, CRYPT_MODE_CBC, "3DES", "3DES-CBC" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_3DES, CRYPT_MODE_CFB, "3DES", "3DES-CFB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_3DES, CRYPT_MODE_OFB, "3DES", "3DES-OFB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, "IDEA", "IDEA-ECB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, "IDEA", "IDEA-CBC" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_IDEA, CRYPT_MODE_CFB, "IDEA", "IDEA-CFB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_IDEA, CRYPT_MODE_OFB, "IDEA", "IDEA-OFB" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}
	if( !testLibrary( CRYPT_ALGO_RC4, CRYPT_MODE_STREAM, "RC4", "RC4" ) )
		{
		puts( "Tests aborted due to encryption library error." );
		exit( EXIT_FAILURE );
		}

	/* Shut down the library */
	status = endLibrary();
	if( isStatusError( status ) )
		{
		printf( "endLibrary(): Failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}
	}
