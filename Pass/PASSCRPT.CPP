#include "passcrpt.hpp"
#include <strstrea.h>
#include "pass.hpp"

#define __WINDOWS__  // for crypt.h
extern "C" {
#include "crypt.h"
}

TCrypt::TCrypt() {}

int
TCrypt::encrypt(unsigned char *data,unsigned int size, unsigned char *password)
{
	int status;
	strstream msg1, msg2;
	unsigned char buffer[MAX_CRYPT_SIZE], newpass[CRYPT_KEY_SIZE], uubuffer[MAX_CRYPT_SIZE];

	memset(buffer,0,sizeof(buffer));
	memset(newpass,0,CRYPT_KEY_SIZE);
	memcpy(buffer,data,sizeof(buffer));
	memcpy(newpass,password,CRYPT_KEY_SIZE);
	memset(uubuffer,0,sizeof(uubuffer));

	initLibrary();
	CRYPT_INFO cryptInfo;
	initCryptContext(&cryptInfo,CRYPT_ALGO_3DES,CRYPT_MODE_CBC);

	status = loadCryptContext(&cryptInfo,newpass,CRYPT_KEY_SIZE);
	if (isStatusError(status))
	{
//		msg1 << "Couldn't load crypt context. Error code: " << status << '\0';
//		MessageBox(msg1.str());
		return status;
	}

	int paddedSize = sizeof(buffer);
	if (paddedSize % CRYPT_BLOCK_SIZE != 0) {
		paddedSize = ((int)(sizeof(buffer) / CRYPT_BLOCK_SIZE) + 1) * CRYPT_BLOCK_SIZE;
	}

	status = encryptBuffer(&cryptInfo,(unsigned char *)buffer,paddedSize);
	if (isStatusError(status))
	{
//		msg2 << "Couldn't encrypt. Error code: " << status << '\0';
//		MessageBox(msg2.str());
		return status;
	}

	unsigned char iv[IV_SIZE];
	memset(iv,0,sizeof(iv));
	retrieveIV(&cryptInfo,iv);

	memcpy(data,iv,sizeof(iv));

	destroyCryptContext(&cryptInfo);
	endLibrary();

	memcpy(data+IV_SIZE,buffer,size-IV_SIZE);

	return 0;
}


int
TCrypt::decrypt(unsigned char *data,unsigned int size,unsigned char *password)
{
	int status;
	strstream msg1, msg2;
	unsigned char buffer[MAX_CRYPT_SIZE+IV_SIZE], newpass[CRYPT_KEY_SIZE];
	unsigned char iv[IV_SIZE];

	memcpy(iv,data,IV_SIZE);

	memset(buffer,0,sizeof(buffer));
	memset(newpass,0,CRYPT_KEY_SIZE);
	memcpy(buffer,data+IV_SIZE,sizeof(buffer)-IV_SIZE);
	memcpy(newpass,password,CRYPT_KEY_SIZE);

	initLibrary();
	CRYPT_INFO cryptInfo;
	initCryptContext(&cryptInfo,CRYPT_ALGO_3DES,CRYPT_MODE_CBC);

	status = loadCryptContext(&cryptInfo,newpass,CRYPT_KEY_SIZE);
	if (isStatusError(status))
	{
//		msg1 << "Couldn't load crypt context. Error code: " << status << '\0';
//		MessageBox(msg1.str());
		return status;
	}

	// create and load Initialization Vector
	loadIV(&cryptInfo,iv,sizeof(iv));

	int paddedSize = sizeof(buffer);
	if (paddedSize % CRYPT_BLOCK_SIZE != 0) {
		paddedSize = ((int)(sizeof(buffer) / CRYPT_BLOCK_SIZE) + 1) * CRYPT_BLOCK_SIZE;
	}

	status = decryptBuffer(&cryptInfo,(unsigned char *)buffer,paddedSize);
	if (isStatusError(status))
	{
//		msg2 << "Couldn't decrypt. Error code: " << status << '\0';
//		MessageBox(msg2.str());
		return status;
	}
	destroyCryptContext(&cryptInfo);
	endLibrary();

	memset(data,0,size);
	memcpy(data,buffer,size);

  return 0;
}

