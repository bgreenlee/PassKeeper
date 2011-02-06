#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define __WINDOWS__
extern "C" {
#include "crypt.h"
}

/****************************************************************************
*																			*
*								General Work Routines						*
*																			*
****************************************************************************/

/* Get an IV value.  It doesn't matter much what it is, as long as it's
   completely different for each call.  We use the first built-in encrypt
   capability we find (actually we just assume it's there to save some time) */

static void getIV( void *iv, int ivLength )
	{
	static BOOLEAN initialised = FALSE;
	static BYTE ivBuffer[ CRYPT_MAX_IVSIZE ];
	CRYPT_INFO cryptInfo;
	CRYPT_INFO_MDCSHS cryptInfoEx;

	if( !initialised )
		{
		/* Seed the data with a value which is guaranteed to be different
		   each time (unless the entire program is rerun more than twice a
		   second, which is doubtful) */
		memset( ivBuffer, 0, CRYPT_MAX_IVSIZE );
		time( ( time_t * ) ivBuffer );
		initialised = TRUE;
		}

	/* Use an extended setup call to only perform 2 setup iterations for
	   speed, since we're not concerned about security */
	cryptInfoEx.keySetupIterations = 2;

	/* Shuffle the bits and return them to the user.  Since the encryption
	   will force a call to getIV() again, we cheat a bit by poking around
	   the cryptInfo internals to fool encryptBuffer() into thinking the IV
	   is already set */
	initCryptContextEx( &cryptInfo, CRYPT_ALGO_MDCSHS, CRYPT_MODE_CFB,
						&cryptInfoEx );
	loadCryptContext( &cryptInfo, ivBuffer, CRYPT_MAX_IVSIZE );
	cryptInfo.ivSet = TRUE;		/* Nasty hack to stop recursion */
	encryptBuffer( &cryptInfo, ivBuffer, CRYPT_MAX_IVSIZE );
	destroyCryptContext( &cryptInfo );
	memcpy( iv, ivBuffer, ivLength );
	}

/* Byte-reverse an array of 16- and 32-bit words to account for processor
   endianness.  These routines assume the given count is a multiple of
   16 or 32 bits */

void longReverse( LONG *buffer, unsigned count )
	{
	LONG value;

	count /= sizeof( LONG );
	while( count-- )
		{
		value = *buffer;
		value = ( ( value & 0xFF00FF00L ) >> 8  ) | \
				( ( value & 0x00FF00FFL ) << 8 );
		*buffer++ = ( value << 16 ) | ( value >> 16 );
		}
	}

void wordReverse( WORD *buffer, unsigned count )
	{
	WORD value;

	count /= sizeof( WORD );
	while( count-- )
		{
		value = *buffer;
		*buffer++ = ( value << 8 ) | ( value >> 8 );
		}
	}

/* A safe free function which scrubs memory and zeroes the pointer */

void secureFree( void **pointer, int count )
	{
	if( *pointer != NULL )
		{
		/* Scrub the memory, free it, and zero the pointer */
		memset( *pointer, 0, count );
		free( *pointer );
		*pointer = NULL;
		}
	}

/****************************************************************************
*																			*
*						Capability Management Functions						*
*																			*
****************************************************************************/

/* The parameters of most encryption algorithms are traditionally specified
	 in bytes, so we define a shorter form of the bitsToBytes() macro to allow
	 the capability information to be specified in bits */

#define bits(x)	bitsToBytes(x)

/* The functions used to implement the null encryption routines */
/*
int nullSelfTest( void );
int nullInit( CRYPT_INFO *cryptInfo );
int nullInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx );
int nullEnd( CRYPT_INFO *cryptInfo );
int nullInitKey( CRYPT_INFO *cryptInfo );
int nullInitIV( CRYPT_INFO *cryptInfo );
int nullEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int nullDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
*/
/* The functions used to implement the MDC/SHS encryption routines */

/*
int mdcshsSelfTest( void );
int mdcshsInit( CRYPT_INFO *cryptInfo );
int mdcshsInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx );
int mdcshsEnd( CRYPT_INFO *cryptInfo );
int mdcshsInitKey( CRYPT_INFO *cryptInfo );
int mdcshsInitIV( CRYPT_INFO *cryptInfo );
int mdcshsEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int mdcshsDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
*/

/* The functions used to implement the DES encryption routines */
/*
int desSelfTest( void );
int desInit( CRYPT_INFO *cryptInfo );
int desInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx );
int desEnd( CRYPT_INFO *cryptInfo );
int desInitKey( CRYPT_INFO *cryptInfo );
int desEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptPCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
*/
/* The functions used to implement the two-key triple DES encryption
   routines */

int des3SelfTest( void );
int des3Init( CRYPT_INFO *cryptInfo );
int des3InitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx );
int des3End( CRYPT_INFO *cryptInfo );
int des3InitKey( CRYPT_INFO *cryptInfo );
int des3EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the IDEA encryption routines */
/*
int ideaSelfTest( void );
int ideaInit( CRYPT_INFO *cryptInfo );
int ideaInitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx );
int ideaEnd( CRYPT_INFO *cryptInfo );
int ideaInitKey( CRYPT_INFO *cryptInfo );
int ideaEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
*/
/* The functions used to implement the RC4 encryption routines */
/*
int rc4SelfTest( void );
int rc4Init( CRYPT_INFO *cryptInfo );
int rc4InitEx( CRYPT_INFO *cryptInfo, void *cryptInfoEx );
int rc4End( CRYPT_INFO *cryptInfo );
int rc4InitKey( CRYPT_INFO *cryptInfo );
int rc4Encrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc4Decrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
*/
/* The encryption library intrinsic capability list */

static CAPABILITY_INFO intrinsicCapabilities[] = {
	/* The no-encryption capability */
/*
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, 0, "None", CRYPT_MAX_SPEED,
		0, 0, 0,
		0, 0, 0,
		nullSelfTest, nullInit, nullInitEx, nullEnd, nullInitKey, nullInitIV,
		nullEncrypt, nullDecrypt, CRYPT_ERROR, NULL },
*/
	/* The MDC/SHS capabilities */
/*
	{ CRYPT_ALGO_MDCSHS, CRYPT_MODE_CFB, bits( 8 ), "MDC/SHS", CRYPT_ERROR,
		bits( 40 ), bits( 512 ), bits( 2048 ),
		bits( 32 ), bits( 64 ), bits( 160 ),
		mdcshsSelfTest, mdcshsInit, mdcshsInitEx, mdcshsEnd,
		mdcshsInitKey, mdcshsInitIV, mdcshsEncrypt, mdcshsDecrypt,
		CRYPT_ERROR, NULL },
*/
	/* The DES capabilities */
/*
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB, bits( 64 ), "DES-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desEncryptECB, desDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC, bits( 64 ), "DES-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desEncryptCBC, desDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB, bits( 8 ), "DES-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desEncryptCFB, desDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB, bits( 8 ), "DES-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desEncryptOFB, desDecryptOFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_DES, CRYPT_MODE_PCBC, bits( 64 ), "DES-PCBC", CRYPT_ERROR,
		bits( 40 ), bits( 56 ), bits( 56 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		desSelfTest, desInit, desInitEx, desEnd, desInitKey, NULL,
		desEncryptPCBC, desDecryptPCBC, CRYPT_ERROR, NULL },
*/
	/* The two-key triple DES capabilities */

	{ CRYPT_ALGO_3DES, CRYPT_MODE_ECB, bits( 64 ), "3DES-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 112 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3EncryptECB, des3DecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC, bits( 64 ), "3DES-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 112 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3EncryptCBC, des3DecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CFB, bits( 64 ), "3DES-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 112 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3EncryptCFB, des3DecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_OFB, bits( 64 ), "3DES-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 112 ), bits( 112 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		des3SelfTest, des3Init, des3InitEx, des3End, des3InitKey, NULL,
		des3EncryptOFB, des3DecryptOFB, CRYPT_ERROR, NULL },

	/* The IDEA capabilities */
/*
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, bits( 64 ), "IDEA-ECB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		ideaEncryptECB, ideaDecryptECB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, bits( 64 ), "IDEA-CBC", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		ideaEncryptCBC, ideaDecryptCBC, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB, bits( 8 ), "IDEA-CFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		ideaEncryptCFB, ideaDecryptCFB, CRYPT_ERROR, NULL },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB, bits( 8 ), "IDEA-OFB", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 16 ), bits( 32 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaInitEx, ideaEnd, ideaInitKey, NULL,
		ideaEncryptOFB, ideaDecryptOFB, CRYPT_ERROR, NULL },
*/
	/* The RC4 capabilities */
/*
	{ CRYPT_ALGO_RC4, CRYPT_MODE_STREAM, bits( 8 ), "RC4", CRYPT_ERROR,
		bits( 40 ), bits( 128 ), bits( 256 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc4SelfTest, rc4Init, rc4InitEx, rc4End, rc4InitKey, NULL,
		rc4Encrypt, rc4Decrypt, CRYPT_ERROR, NULL },
*/
	/* The end-of-list marker */
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, CRYPT_ERROR, "", 0,
		0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, CRYPT_ERROR, NULL }
	};

/* The list of crypt library capability records.  Even if initCapabilities()
   is never called we still have a minimum non-encryption method available */

static CAPABILITY_INFO *capabilityListHead = intrinsicCapabilities;
static CAPABILITY_INFO *capabilityListTail = intrinsicCapabilities;
static CAPABILITY_INFO *intrinsicCapabilityListEnd = NULL;

/* Free the capability list */

static void freeCapabilityList( void )
	{
	CAPABILITY_INFO *capabilityListPtr = intrinsicCapabilityListEnd;
	void *capabilityToFree;

	/* Mark the list as being empty */
	intrinsicCapabilityListEnd = NULL;

	/* Free the capability record list list */
	while( capabilityListPtr != NULL )
		{
		capabilityToFree = capabilityListPtr;
		capabilityListPtr = capabilityListPtr->next;
		secureFree( &capabilityToFree, sizeof( CAPABILITY_INFO ) );
		}
	}

/* Initialise the intrinsic encryption library capability list */

static int initCapabilities( void )
	{
	CAPABILITY_INFO *capabilityInfoPtr;
	int i;

	/* Add the built-in encryption capabilities */
	for( i = 0; intrinsicCapabilities[ i + 1 ].blockSize != CRYPT_ERROR; i++ )
		intrinsicCapabilities[ i ].next = &intrinsicCapabilities[ i + 1 ];

	/* Perform the self-test for each encryption algorithm */
	for( capabilityInfoPtr = capabilityListHead;
		 capabilityInfoPtr != NULL;
		 capabilityInfoPtr = capabilityInfoPtr->next )
		{
		CAPABILITY_INFO *capabilitySelfTestPtr;
		int status;

		/* If the self-test for this algorithm has already been performed,
		   don't do it again */
		if( capabilityInfoPtr->selfTestStatus != CRYPT_ERROR )
			continue;

		/* Perform the self-test for this algorithm type */
		status = capabilityInfoPtr->selfTestFunction();

		/* Set the test status for each capability using this algorithm */
		for( capabilitySelfTestPtr = capabilityInfoPtr;
			 capabilitySelfTestPtr != NULL;
			 capabilitySelfTestPtr = capabilitySelfTestPtr->next )
			if( capabilitySelfTestPtr->cryptAlgo == capabilityInfoPtr->cryptAlgo )
				capabilitySelfTestPtr->selfTestStatus = status;
		}

	return( CRYPT_OK );
	}

/* Add a capability record to the library */

static int addCapability( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode, \
						  int blockSize, char *name, int speed, \
						  int minKeySize, int keySize, int maxKeySize )
	{
	CAPABILITY_INFO *newElement;

	/* Check the passed-in parameters */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode > CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );
	if( blockSize < 0 )
		return( CRYPT_BADPARM3 );
	if( name == NULL )
		return( CRYPT_BADPARM4 );
	if( ( speed != CRYPT_ERROR && speed < 0 ) || speed > CRYPT_MAX_SPEED )
		return( CRYPT_BADPARM5 );
	if( minKeySize < 0 )
		return( CRYPT_BADPARM6 );
	if( keySize < minKeySize )
		return( CRYPT_BADPARM7 );
	if( maxKeySize < keySize )
		return( CRYPT_BADPARM8 );

	/* Allocate memory for the new capability and its associated message */
	if( ( newElement = ( CAPABILITY_INFO * ) malloc( sizeof( CAPABILITY_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );
	memset( newElement, 0, sizeof( CAPABILITY_INFO ) );
	if( ( newElement->name = ( char * ) malloc( strlen( name ) + 1 ) ) == NULL )
		{
		free( newElement );
		return( CRYPT_NOMEM );
		}

	/* Copy the information across */
	newElement->cryptAlgo = cryptAlgo;
	newElement->cryptMode = cryptMode;
	newElement->blockSize = blockSize;
	strcpy( newElement->name, name );
	newElement->minKeySize = minKeySize;
	newElement->keySize = keySize;
	newElement->maxKeySize = maxKeySize;
	newElement->next = NULL;

	/* Link it into the list */
	if( capabilityListHead == NULL )
		capabilityListHead = newElement;
	else
		capabilityListTail->next = newElement;
	capabilityListTail = newElement;

	return( CRYPT_OK );
	}

/* Find the capability record for a given encryption algorithm */

static CAPABILITY_INFO *findCapabilityInfo( CRYPT_ALGO cryptAlgo, \
											CRYPT_MODE cryptMode )
	{
	CAPABILITY_INFO *capabilityInfoPtr;

	/* Try and find information on the required algorithm */
	for( capabilityInfoPtr = capabilityListHead;
		 capabilityInfoPtr != NULL;
		 capabilityInfoPtr = capabilityInfoPtr->next )
		if( capabilityInfoPtr->cryptAlgo == cryptAlgo &&
			( capabilityInfoPtr->cryptMode == cryptMode ||
			  cryptMode == CRYPT_MODE_NONE ) )
			return( capabilityInfoPtr );

	/* Nothing available */
	return( NULL );
	}

/****************************************************************************
*																			*
*							Capability Query Functions						*
*																			*
****************************************************************************/

/* Determine whether a given encryption mode is available */

CRET queryModeAvailability( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode )
	{
	/* Perform basic error checking */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode > CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );

	/* Make sure the library has been initalised */
	if( capabilityListHead == NULL )
		return( CRYPT_NOTINITED );

	/* See if we have any information on this encryption algo/mode */
	if( findCapabilityInfo( cryptAlgo, cryptMode ) == NULL )
		return( ( findCapabilityInfo( cryptAlgo, CRYPT_MODE_NONE ) == NULL ) ? \
				CRYPT_NOALGO : CRYPT_NOMODE );

	return( CRYPT_OK );
	}

CRET queryAlgoAvailability( CRYPT_ALGO cryptAlgo )
	{
	return( queryModeAvailability( cryptAlgo, CRYPT_MODE_NONE ) );
	}

/* Get information on a given encrytion algorithm */

CRET queryAlgoModeInformation( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode, \
							   CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	CAPABILITY_INFO *capabilityInfo;

	/* Perform basic error checking */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode > CRYPT_MODE_LAST )
		return( CRYPT_BADPARM2 );
	if( cryptQueryInfo == NULL )
		return( CRYPT_BADPARM3 );

	/* Make sure the library has been initalised */
	if( capabilityListHead == NULL )
		return( CRYPT_NOTINITED );

	/* Clear the fields in the query structure */
	memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );

	/* Find the information record on this algorithm */
	if( ( capabilityInfo = findCapabilityInfo( cryptAlgo, cryptMode ) ) == NULL )
		{
		cryptQueryInfo->algoName = "";
		cryptQueryInfo->blockSize = CRYPT_ERROR;
		cryptQueryInfo->minKeySize = CRYPT_ERROR;
		cryptQueryInfo->keySize = CRYPT_ERROR;
		cryptQueryInfo->maxKeySize = CRYPT_ERROR;
		cryptQueryInfo->minIVsize = CRYPT_ERROR;
		cryptQueryInfo->ivSize = CRYPT_ERROR;
		cryptQueryInfo->maxIVsize = CRYPT_ERROR;
		cryptQueryInfo->speed = CRYPT_ERROR;
		return( ( findCapabilityInfo( cryptAlgo, CRYPT_MODE_NONE ) == NULL ) ? \
				CRYPT_NOALGO : CRYPT_NOMODE );
		}

	/* Return the appropriate information */
	cryptQueryInfo->cryptAlgo = cryptAlgo;
	cryptQueryInfo->cryptMode = cryptMode;
	cryptQueryInfo->algoName = capabilityInfo->name;
	cryptQueryInfo->blockSize = capabilityInfo->blockSize;
	cryptQueryInfo->minKeySize = capabilityInfo->minKeySize;
	cryptQueryInfo->keySize = capabilityInfo->keySize;
	cryptQueryInfo->maxKeySize = capabilityInfo->maxKeySize;
	cryptQueryInfo->minIVsize = capabilityInfo->minIVsize;
	cryptQueryInfo->ivSize = capabilityInfo->ivSize;
	cryptQueryInfo->maxIVsize = capabilityInfo->maxIVsize;
	cryptQueryInfo->speed = capabilityInfo->speed;
	return( CRYPT_OK );
	}

/* Get information on the algorithm used by a given encryption context */

CRET queryContextInformation( CRYPT_INFO CPTR cryptInfo,
							  CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptInfo->capabilityInfo == NULL )
		return( CRYPT_NOTINITED );

	return( queryAlgoModeInformation( cryptInfo->capabilityInfo->cryptAlgo,
			cryptInfo->capabilityInfo->cryptMode, cryptQueryInfo ) );
	}

/* Initialise and shut down the encryption library */

CRET initLibrary( void )
	{
	return( initCapabilities() );
	}

CRET endLibrary( void )
	{
	freeCapabilityList();
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Encryption Context Management Functions					*
*																			*
****************************************************************************/

/* A magic value to detect whether an encryption context has been
   initialised yet */

#define CRYPT_MAGIC		0xC0EDBABEL

/* Initialise and perform an extended initialisation of an encryption
   context */

CRET initCryptContext( CRYPT_INFO CPTR cryptInfo, CRYPT_ALGO cryptAlgo, \
					   CRYPT_MODE cryptMode )
	{
	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM2 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode > CRYPT_MODE_LAST )
		return( CRYPT_BADPARM3 );

	/* Set all fields to zero */
	memset( cryptInfo, 0, sizeof( CRYPT_INFO ) );

	/* Set up the pointer to the capability information */
	if( ( cryptInfo->capabilityInfo = findCapabilityInfo( cryptAlgo, cryptMode ) ) == NULL )
		return( ( queryAlgoAvailability( cryptAlgo ) ) ? \
				CRYPT_NOMODE : CRYPT_NOALGO );

	/* Make sure the algorithm self-test went OK */
	if( cryptInfo->capabilityInfo->selfTestStatus != CRYPT_OK )
		return( CRYPT_SELFTEST );

	/* Perform any algorithm-specific initialization */
	if( cryptInfo->capabilityInfo->initFunction != NULL )
		{
		int status;

		status = cryptInfo->capabilityInfo->initFunction( cryptInfo );
		if( isStatusError( status ) )
			return( status );
		}

	/* Set up the IV information to the default values.  This can be
	   overridden later if required */
	cryptInfo->ivLength = cryptInfo->capabilityInfo->ivSize;

	/* Set the check value.  Note that we set it after the capability info
	   has been set, so that a check on this value will also tell us whether
	   the capability info is present */
	cryptInfo->checkValue = CRYPT_MAGIC;

	return( CRYPT_OK );
	}

CRET initCryptContextEx( CRYPT_INFO CPTR cryptInfo, CRYPT_ALGO cryptAlgo, \
						 CRYPT_MODE cryptMode, void *cryptInfoEx )
	{
	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM2 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode > CRYPT_MODE_LAST )
		return( CRYPT_BADPARM3 );
	if( cryptInfoEx == NULL )
		return( CRYPT_BADPARM4 );

	/* Set all fields to zero */
	memset( cryptInfo, 0, sizeof( CRYPT_INFO ) );

	/* Set up the pointer to the capability information */
	if( ( cryptInfo->capabilityInfo = findCapabilityInfo( cryptAlgo, cryptMode ) ) == NULL )
		return( ( queryAlgoAvailability( cryptAlgo ) ) ? \
				CRYPT_NOMODE : CRYPT_NOALGO );

	/* Make sure the algorithm self-test went OK */
	if( cryptInfo->capabilityInfo->selfTestStatus != CRYPT_OK )
		return( CRYPT_SELFTEST );

	/* Perform any algorithm-specific initialization */
	if( cryptInfo->capabilityInfo->initExFunction != NULL )
		{
		int status;

		status = cryptInfo->capabilityInfo->initExFunction( cryptInfo, cryptInfoEx );
		if( isStatusError( status ) )
			return( status );
		}

	/* Set up the IV information to the default values.  This can be
	   overridden later if required */
	cryptInfo->ivLength = cryptInfo->capabilityInfo->ivSize;

	/* Set the check value.  Note that we set it after the capability info
	   has been set, so that a check on this value will also tell us whether
	   the capability info is present */
	cryptInfo->checkValue = CRYPT_MAGIC;

	return( CRYPT_OK );
	}

/* Destroy an encryption context */

CRET destroyCryptContext( CRYPT_INFO CPTR cryptInfo )
	{
	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptInfo->checkValue != CRYPT_MAGIC ||
		cryptInfo->capabilityInfo == NULL )
		return( CRYPT_NOTINITED );

	/* Perform any algorithm-specific shutdown */
	if( cryptInfo->capabilityInfo->endFunction != NULL )
		{
		int status;

		status = cryptInfo->capabilityInfo->endFunction( cryptInfo );
		if( isStatusError( status ) )
			return( status );
		}

	/* Clear all data in the encryption context */
	memset( cryptInfo, 0, sizeof( CRYPT_INFO ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Keying Functions							*
*																			*
****************************************************************************/

/* Load a user key into an encryption context */

CRET loadCryptContext( CRYPT_INFO CPTR cryptInfo, void CPTR userKey,
					   int userKeyLength )
	{
	int status;

	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( userKey == NULL )
		return( CRYPT_BADPARM2 );
	if( cryptInfo->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( userKeyLength < cryptInfo->capabilityInfo->minKeySize ||
		userKeyLength > cryptInfo->capabilityInfo->maxKeySize )
		return( CRYPT_BADPARM3 );
	if( cryptInfo->capabilityInfo->initKeyFunction == NULL )
		return( CRYPT_NOALGO );

	/* Load the user encryption key into the crypt context */
	memcpy( cryptInfo->userKey, userKey, userKeyLength );
	cryptInfo->userKeyLength = userKeyLength;

	/* Remember that we need to set an IV before we encrypt anything */
	cryptInfo->ivSet = FALSE;

	/* Call the encryption routine for this algorithm/mode */
	if( ( status = cryptInfo->capabilityInfo->initKeyFunction( cryptInfo ) ) != CRYPT_OK )
		return( status );

	/* Record the fact that the key has been initialized */
	cryptInfo->keySet = TRUE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							IV Handling Functions							*
*																			*
****************************************************************************/

/* Load an IV key into an encryption context */

CRET loadIV( CRYPT_INFO CPTR cryptInfo, void CPTR iv, int ivLength )
	{
	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( cryptInfo->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( ivLength < cryptInfo->capabilityInfo->minIVsize ||
		ivLength > cryptInfo->capabilityInfo->maxIVsize )
		return( CRYPT_BADPARM3 );

	/* Set the IV length and check whether we'll be using a user-supplied
	   IV */
	cryptInfo->ivLength = ivLength;
	cryptInfo->ivCount = 0;
	if( iv != NULL )
		{
		/* Load the IV of the required length.  If the required IV size is
		   less than the maximum possible IV size, we pad it with zeroes */
		memset( cryptInfo->iv, 0, CRYPT_MAX_IVSIZE );
		memcpy( cryptInfo->iv, iv, cryptInfo->ivLength );
		memcpy( cryptInfo->currentIV, cryptInfo->iv, CRYPT_MAX_IVSIZE );
		cryptInfo->ivSet = TRUE;
		}
	if( cryptInfo->capabilityInfo->initIVFunction != NULL )
		{
		int status;

		status = cryptInfo->capabilityInfo->initIVFunction( cryptInfo );
		if( isStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Retrieve an IV from an encryption context */

CRET retrieveIV( CRYPT_INFO CPTR cryptInfo, void CPTR iv )
	{
	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( iv == NULL )
		return( CRYPT_BADPARM2 );
	if( cryptInfo->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );

	/* Make sure the IV has been set */
	if( cryptInfo->ivSet == FALSE )
		return( CRYPT_NOIV );

	/* Copy the IV data of the required length to the output buffer */
	memcpy( iv, cryptInfo->iv, cryptInfo->ivLength );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Encrypt/Decrypt Routines						*
*																			*
****************************************************************************/

/* Encrypt a block of memory */

CRET encryptBuffer( CRYPT_INFO CPTR cryptInfo, void CPTR buffer, int length )
	{
	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( buffer == NULL )
		return( CRYPT_BADPARM2 );
	if( length < 0 )
		return( CRYPT_BADPARM3 );
	if( !cryptInfo->keySet )
		return( CRYPT_NOKEY );
	if( cryptInfo->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( cryptInfo->capabilityInfo->encryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* If there's no IV set, generate one ourselves */
	if( !cryptInfo->ivSet )
		{
		BYTE iv[ CRYPT_MAX_IVSIZE ];
		int status;

		getIV( iv, cryptInfo->ivLength );
		status = loadIV( cryptInfo, iv, cryptInfo->ivLength );
		if( isStatusError( status ) )
			return( CRYPT_ERROR );
		}

	/* Call the encryption routine for this algorithm/mode */
	return( cryptInfo->capabilityInfo->encryptFunction( cryptInfo, buffer, length ) );
	}

/* Decrypt a block of memory */

CRET decryptBuffer( CRYPT_INFO CPTR cryptInfo, void CPTR buffer, int length )
	{
	/* Perform basic error checking */
	if( cryptInfo == NULL )
		return( CRYPT_BADPARM1 );
	if( buffer == NULL )
		return( CRYPT_BADPARM2 );
	if( length < 0 )
		return( CRYPT_BADPARM3 );
	if( !cryptInfo->keySet )
		return( CRYPT_NOKEY );
	if( cryptInfo->checkValue != CRYPT_MAGIC )
		return( CRYPT_NOTINITED );
	if( cryptInfo->capabilityInfo->decryptFunction == NULL )
		return( CRYPT_NOALGO );

	/* Make sure the IV has been set */
	if( cryptInfo->ivSet == FALSE )
		return( CRYPT_NOIV );

	/* Call the decryption routine for this algorithm/mode */
	return( cryptInfo->capabilityInfo->decryptFunction( cryptInfo, buffer, length ) );
	}

/****************************************************************************
*																			*
*						Dynamic Library Update Support						*
*																			*
****************************************************************************/

/* Add a new encryption capability to the library.  This routine is quite
   powerful, but what a kludge! */

CRET addCryptCapability( CRYPT_ALGO cryptAlgo, CRYPT_MODE cryptMode, \
						 int blockSize, char *name, int speed, \
						 int minKeySize, int keySize, int maxKeySize )
	{
	int status;

	/* Add the basic capability information */
	status = addCapability( cryptAlgo, cryptMode, blockSize, name,
							speed, minKeySize, keySize, maxKeySize );
	if( isStatusError( status ) )
		return( status );

	/* Add the handlers */
/* Not implemented yet */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						OS-Specific Support Routines						*
*																			*
****************************************************************************/

#if defined( __WINDOWS__ ) && !defined( WIN32 )

/* Whether LibMain() has been called before */

static BOOLEAN libMainCalled = FALSE;
static HWND hInst;

/* The main function for the DLL */

int CALLBACK LibMain( HINSTANCE hInstance, WORD wDataSeg, WORD wHeapSize, \
					  LPSTR lpszCmdLine )
	{
	/* Rot bilong kargo */
	if( wHeapSize > 0 )
		UnlockData( 0 );	/* Allow heap to move */

	/* If we've been called before, return with an error message */
	if( libMainCalled )
		return( FALSE );
	libMainCalled = TRUE;

	/* Initialise the library */
	if( initLibrary() != CRYPT_OK )
		return( FALSE );

	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

/* Shut down the DLL */

int CALLBACK WEP( int nSystemExit )
	{
	switch( nSystemExit )
		{
		case WEP_SYSTEM_EXIT:
			/* System is shutting down */
			break;

		case WEP_FREE_DLL:
			/* DLL reference count = 0, DLL-only shutdown */
			break;
		}

	/* Shut down the encryption library if necessary */
	endLibrary();
	
	return( TRUE );
	}

#elif defined( __WINDOWS__ ) && defined( WIN32 )

/* Whether LibMain() has been called before */

static BOOLEAN libMainCalled = FALSE;
static HWND hInst;

int LibMain( HANDLE hInstance, ULONG ulReasonCalled, LPVOID lpReserved )
	{
	/* If we've been called before, return with an error message */
	if( libMainCalled )
		return( FALSE );
	libMainCalled = TRUE;

	/* Initialise the library */
	if( initLibrary() != CRYPT_OK )
		return( FALSE );

	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

int CALLBACK WEP( int nSystemExit )
	{
	/* Shut down the encryption library if necessary */
	endLibrary();
	
	return( TRUE );
	}
#endif /* __WINDOWS__ */
