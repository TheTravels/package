#include <stdlib.h>
#include <time.h>

#ifdef MSDOS
	#include <sys\types.h>
#endif

#include "rsa_incl.h"
#include "r_random.h"

#define RANDOM_BYTES_RQ 256

	/* We use more seed data for an internally created object */
#define RANDOM_BYTES_RQINT 512

#define MIX_CNT 16

static UINT4 subrand PROTO_LIST((long));

/* Set up, random object ready for seeding. */

int R_RandomInit(random)
R_RANDOM_STRUCT *random;        /* new random structure */
{
			/* clear and setup object for seeding */
	R_memset((POINTER)random->state, 0, sizeof(random->state));
	random->outputAvailable = 0;
	random->bytesNeeded = RANDOM_BYTES_RQ;

	return(ID_OK);
}



int R_RandomUpdate(random, block, len)
R_RANDOM_STRUCT *random;        /* random structure */
unsigned char *block;           /* block of values to mix in */
unsigned int len;               /* length of block */
{
	MD5_CTX context;
	BYTE digest[16];
    unsigned short int i, j;

	MD5Init(&context);
	MD5Update(&context, block, len);
	MD5Final(digest, &context);

	/* add digest to state */

	for(j = 0, i = 16; i > 0; i--) {
		j += random->state[i-1] + digest[i-1];
		random->state[i-1] = (BYTE)j;
		j >>= 8;
	}

	if(random->bytesNeeded < len)
		random->bytesNeeded = 0;
	else
		random->bytesNeeded -= len;

	/* Clear sensitive information. */

	R_memset((POINTER)digest, 0, sizeof (digest));
	j = 0;

	return(ID_OK);
}

/* Get the number of seed byte still required by the object */

int R_GetRandomBytesNeeded(bytesNeeded, random)
unsigned int *bytesNeeded;      /* number of mix-in bytes needed */
R_RANDOM_STRUCT *random;        /* random structure */
{
	*bytesNeeded = random->bytesNeeded;

	return(ID_OK);
}

int R_GenerateBytes(block, len, random)
unsigned char *block;                             /* block */
unsigned int len;                                 /* length of block */
R_RANDOM_STRUCT *random;                          /* random structure */
{
	MD5_CTX context;
	unsigned int avail, i;

	if(random->bytesNeeded)
		return(RE_NEED_RANDOM);

	avail = random->outputAvailable;

	while(avail < len) {
		R_memcpy((POINTER)block, (POINTER)&random->output[16-avail], avail);
		len -= avail;
		block += avail;

		/* generate new output */

		MD5Init(&context);
		MD5Update(&context, random->state, 16);
		MD5Final(random->output, &context);
		avail = 16;

		/* increment state */
		for(i = 16; i > 0; i--)
			if(random->state[i-1]++)
				break;
	}

	R_memcpy((POINTER)block, (POINTER)&random->output[16-avail], len);
	random->outputAvailable = avail - len;

	return(ID_OK);
}

/* Clear Random object when finished. */

void R_RandomFinal(random)
R_RANDOM_STRUCT *random;        /* random structure */
{
	R_memset((POINTER)random, 0, sizeof(R_RANDOM_STRUCT));
}

/*  Create Random object, seed ready for use.
    Requires ANSI Standard time routines to provide seed data.
*/

void R_RandomCreate(random)
R_RANDOM_STRUCT *random;                                /* random structure */
{
	clock_t cnow;
	time_t t;
	struct tm *gmt;
    UINT4 temp;

			/* clear and setup object for seeding */
	R_memset((POINTER)random->state, 0, sizeof(random->state));
	random->outputAvailable = 0;
	random->bytesNeeded = RANDOM_BYTES_RQINT;  /* using internal value */

		/* Add data to random object */
	while(random->bytesNeeded) {
		t = time(NULL);                 /* use for seed data */
		gmt = gmtime(&t);
		cnow = clock();
        temp = subrand(t);              /* use special routine to produce seed */

        R_RandomUpdate(random, (POINTER)&temp, sizeof(UINT4));
		R_RandomUpdate(random, (POINTER)gmt, sizeof(struct tm));
        R_RandomUpdate(random, (POINTER)&cnow, sizeof(clock_t));
	}

    /* Clean Up time related data */
	R_memset((POINTER)gmt, 0, sizeof(struct tm));
	cnow = 0;
	t = 0;
    temp = 0;
}

/*  Mix up state of the current random structure.
    Again requires both clock functions this just adds something
    extra to the state, then refreshes the output.
*/

void R_RandomMix(random)
R_RANDOM_STRUCT *random;
{
	unsigned int i;
	MD5_CTX context;

    for(i = 0; i < MIX_CNT; i++) {
        random->state[i] ^= (unsigned char) clock();
        random->state[15-i] ^= (unsigned char) time(NULL);
	}

	/* Clear any old state with new data */

	MD5Init(&context);
	MD5Update(&context, random->state, 16);
	MD5Final(random->output, &context);

	/* tell R_GenerateBytes there is new output */

	random->outputAvailable = 16;

}

/*
    This routine is based on an idea outlined in the book "Numerical Recipes
    in C" using a form of reduced DES like function.
*/

#define NITER 4

static UINT4 subrand(long idum) {

    UINT4 irword, lword;
    static long idums = 0.0;
    UINT4 i, ia, ib, iswap, itmph=0, itmpl=0;

    static UINT4 c1[NITER] = { 0xbaa96887L, 0x1e17d32cL, 0x03dcbc3cL, 0xf033d1b2L };
    static UINT4 c2[NITER] = { 0x4bf03b58L, 0xe8740fc3L, 0x69aac5a6L, 0x55a7ca46L };

    if (idum < 0) {
        idums = -(idum);
        idum = 1;
    }

    irword = idum;
    lword = idums;

    for(i=0; i < NITER; i++) {
        ia=(iswap=irword) ^ c1[i];
        itmpl = ia & 0xffff;
        itmph = ia >> 16;
        ib = itmpl*itmpl+~(itmph*itmph);
        irword=lword ^ (((ia = (ib >> 16) | ((ib & 0xffff) << 16)) ^ c2[i])+itmpl*itmph);
        lword=iswap;
    }
    return irword;
}

