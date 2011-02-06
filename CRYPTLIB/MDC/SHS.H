#ifndef _SHS_DEFINED

#define _SHS_DEFINED

/* Define the following to compile the SHS test code */

/*#define TEST_SHS			/**/

/* Define the following to use the updated SHS implementation */

/*#define NEW_SHS			/**/

/* The SHS block size and message digest sizes, in bytes */

#define SHS_DATASIZE	64
#define SHS_DIGESTSIZE	20

/* The structure for storing SHS info */

typedef struct {
			   LONG digest[ 5 ];			/* Message digest */
			   LONG countLo, countHi;		/* 64-bit bit count */
			   LONG data[ 16 ];				/* SHS data buffer */
			   } SHS_INFO;

/* Message digest functions */

void shsInit( SHS_INFO *shsInfo );
void shsUpdate( SHS_INFO *shsInfo, BYTE *buffer, int count );
void shsFinal( SHS_INFO *shsInfo );

#endif /* _SHS_DEFINED */
