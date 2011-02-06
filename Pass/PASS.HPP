#ifndef PASS_HPP
#define PASS_HPP

//
//	 Global defines and variables
//

const unsigned int MAX_ENTRY_SIZE = 32;
const unsigned int MAX_NOTES_SIZE = 256;
const unsigned int MAX_ENTRIES = 128;
const unsigned int ADD = 0;
const unsigned int EDIT = 1;
const unsigned int CRYPT_KEY_SIZE = 7;
const unsigned int CRYPT_BLOCK_SIZE = 8;
const unsigned int IV_SIZE = 4;
const unsigned int MAX_CRYPT_SIZE = MAX_NOTES_SIZE + IV_SIZE +
	(MAX_ENTRY_SIZE + IV_SIZE)*3;

typedef struct {
		char account[MAX_ENTRY_SIZE];
		char username[MAX_ENTRY_SIZE];
		char password[MAX_ENTRY_SIZE];
		char notes[MAX_NOTES_SIZE];
	} TEntry;

typedef struct {
		unsigned char account[MAX_ENTRY_SIZE];
		unsigned char username[MAX_ENTRY_SIZE];
		unsigned char encryptedPassword[MAX_ENTRY_SIZE+IV_SIZE];
		unsigned char notes[MAX_NOTES_SIZE];
	} TEncryptedEntry;


class TAddEditDialog;

#endif
