#include "rsa_incl.h"
#include "r_random.h"
#include "rsa.h"
#include "nn.h"
#include "stdio.h"

static int rsapublicfunc PROTO_LIST((unsigned char *, unsigned int *, unsigned char *, unsigned int, R_RSA_PUBLIC_KEY *));
static int rsaprivatefunc PROTO_LIST((unsigned char *, unsigned int *, unsigned char *, unsigned int, R_RSA_PRIVATE_KEY *));


#if 0
int mainrsa()
{
 	int status;
 	R_RSA_PUBLIC_KEY publicKey;    /* new RSA public key */
 	R_RSA_PRIVATE_KEY privateKey;  /* new RSA private key */
	R_RSA_PROTO_KEY protoKey;      /* RSA prototype key */
	R_RANDOM_STRUCT randomStruct;  /* random structure */

	R_RSA_PUBLIC_KEY publicKey1;    /* new RSA public key */
	R_RSA_PRIVATE_KEY privateKey1;  /* new RSA private key */

//	unsigned char output[128];
	unsigned int outputLen;        /* length of output block */
//	unsigned char input[130];           /* input block */
	unsigned int inputLen=117;          /* length of input block */

	FILE * infile;
	FILE * outfile;

//	DWORD start,end;
	char filename[100];

	R_RandomCreate(&randomStruct);

	protoKey.bits=1024;
	protoKey.useFermat4=1;
 
	strcpy(filename,"PEMKeys");
 	status=R_GeneratePEMKeys(&publicKey, &privateKey, &protoKey, &randomStruct);
 	SaveKeys1(filename,publicKey,privateKey);
	return 0;
//	LodeKeys(filename,&publicKey1,&privateKey1);

/////////////////////////////////////////////////////////////////
/*
	infile=fopen("input.txt","rb");
	outfile=fopen("output.txt","wb");
	fseek(infile, 0L, SEEK_END);
	inputLen=ftell(infile);
	fseek(infile,0L,SEEK_SET);

	FilePrivateEncrypt (outfile, &outputLen, infile, inputLen,&privateKey1);

	fclose(infile);
	fclose(outfile);

	infile=fopen("output.txt","rb");
	outfile=fopen("output2.txt","wb");
	fseek(infile, 0L, SEEK_END);
	inputLen=ftell(infile);
	fseek(infile,0L,SEEK_SET);

	FilePublicDecrypt (outfile, &outputLen, infile, inputLen,&publicKey1);

	fclose(infile);
	fclose(outfile);
*/
	infile=fopen("input.txt","rb");
	outfile=fopen("output.txt","wb");
	fseek(infile, 0L, SEEK_END);
	inputLen=ftell(infile);
	fseek(infile,0L,SEEK_SET);

	FilePublicEncrypt (outfile, &outputLen, infile, inputLen,&publicKey1);

	fclose(infile);
	fclose(outfile);

	infile=fopen("output.txt","rb");
	outfile=fopen("output2.txt","wb");
	fseek(infile, 0L, SEEK_END);
	inputLen=ftell(infile);
	fseek(infile,0L,SEEK_SET);

	FilePrivateDecrypt (outfile, &outputLen, infile, inputLen,&privateKey1);

	fclose(infile);
	fclose(outfile);



//////////////////////////////////////////////////////////////////////////////
/*
	R_memcpy(input,"ScanDisk checked drive C for problems, with the following results: Directory structure Scan Disk did not perform any.\0",inputLen+1);
	inputLen=117;          
	printf("%s\n",input);

	start = timeGetTime();
	status=RSAPublicEncrypt(output, &outputLen, input, inputLen, &publicKey1);
	end = timeGetTime();
	output[outputLen]=0;
	printf("%s--%d\n",output,outputLen);
	printf("PublicEncrypt time:%u\n" , end-start );

	R_memcpy(input,output,outputLen);
	inputLen=outputLen;


	start = timeGetTime();
	status=RSAPrivateDecrypt(output, &outputLen, input, inputLen, &privateKey1);
	end = timeGetTime();
	output[outputLen]=0;
	printf("%s--%d\n",output,outputLen);
	printf("PrivateDecrypt time:%u\n" , end-start );

	R_memcpy(input,output,outputLen);
	inputLen=outputLen;

	start = timeGetTime();
	status=RSAPrivateEncrypt(output, &outputLen, input, inputLen, &privateKey1);
	end = timeGetTime();
	output[outputLen]=0;
	printf("%s--%d\n",output,outputLen);
	printf("PrivateEncrypt time:%u\n" , end-start );

	R_memcpy(input,output,outputLen);
	inputLen=outputLen;

	start = timeGetTime();
	status=RSAPublicDecrypt(output, &outputLen, input, inputLen, &publicKey1);
	end = timeGetTime();
	output[outputLen]=0;
	printf("%s--%d\n",output,outputLen);
	printf("PublicDecrypt time:%u\n" , end-start );
*/

	return 0;
}

int SaveKeys1(char* filename,R_RSA_PUBLIC_KEY publicKey,R_RSA_PRIVATE_KEY privateKey)
{
	FILE* KeyFile;
	char *  pbuf;
	int i;
	KeyFile=fopen(filename,"w");
	if( KeyFile== NULL )
		return 0;

    pbuf=(char*)&publicKey;
	fprintf(KeyFile,"---PUBLIC KEY----\n");
	fprintf(KeyFile,"R_RSA_PUBLIC_KEY publickey={\n");
	for(  i=0;i<sizeof(R_RSA_PUBLIC_KEY);i++)
	{

		if(i%16==2)
		{
			fprintf(KeyFile,"\n");
		}
		fprintf(KeyFile,"0x%02x",pbuf[i]&0xff);

		if(i%128 ==1)
		{
			if(i==1){
				fprintf(KeyFile,",\n{");
			}
			else{
				fprintf(KeyFile,"}");
				if(i!=sizeof(R_RSA_PUBLIC_KEY)-1)
				{
					fprintf(KeyFile,",\n{");
				}
				else{
					fprintf(KeyFile,"};");
				}
			}
		}
		else{
			fprintf(KeyFile,",");
		}
	 
		
	}
	fprintf(KeyFile,"\n\n---PRIVATE KEY---\n");
	fprintf(KeyFile,"R_RSA_PRIVATE_KEY privatekey ={\n");
	pbuf=&privateKey;
	for(i=0;i<sizeof(R_RSA_PRIVATE_KEY);i++)
	{
		if(i%16==2)
		{
			fprintf(KeyFile,"\n");
		}
		fprintf(KeyFile,"0x%02x",pbuf[i]&0xff);

		if(i%128 ==1)
		{
			if(i==1){
				fprintf(KeyFile,",\n{");
			}
			else{
				fprintf(KeyFile,"}");
				if(i!=sizeof(R_RSA_PRIVATE_KEY)-1)
				{
					fprintf(KeyFile,",\n{");
				}
				else{
					fprintf(KeyFile,"};");
				}
			}
		}
		else if(i==sizeof(R_RSA_PRIVATE_KEY)-1){
			fprintf(KeyFile,"}};");
		}
		else{
			fprintf(KeyFile,",");
		}
		
	}

	//fwrite(&publicKey,sizeof(R_RSA_PUBLIC_KEY),1,KeyFile);
	//fwrite(&privateKey,sizeof(R_RSA_PRIVATE_KEY),1,KeyFile);

	fclose(KeyFile);
	return 1;
}


int SaveKeys(char* filename,R_RSA_PUBLIC_KEY publicKey,R_RSA_PRIVATE_KEY privateKey)
{
	FILE* KeyFile;
	char *  pbuf;
	int i;
	KeyFile=fopen(filename,"w");
	if( KeyFile== NULL )
		return 0;

    pbuf=(char*)&publicKey;
	fprintf(KeyFile,"---PUBLIC KEY----\n");
	for(  i=0;i<sizeof(R_RSA_PUBLIC_KEY);i++)
	{
		if(i%16==0)
		{
			fprintf(KeyFile,"\n");
		}
		fprintf(KeyFile,"0x%02x",pbuf[i]&0xff);
		if(i!=sizeof(R_RSA_PUBLIC_KEY)-1)
		{
			fprintf(KeyFile,",");
		}
		
	}
	fprintf(KeyFile,"\n---PRIVATE KEY---\n");
	pbuf=&privateKey;
	for(i=0;i<sizeof(R_RSA_PRIVATE_KEY);i++)
	{
		if(i%16==0)
		{
			fprintf(KeyFile,"\n");
		}
		fprintf(KeyFile,"0x%02x",pbuf[i]&0xff);
		if(i!=sizeof(R_RSA_PRIVATE_KEY)-1)
		{
			fprintf(KeyFile,",");
		}
		
	}

	//fwrite(&publicKey,sizeof(R_RSA_PUBLIC_KEY),1,KeyFile);
	//fwrite(&privateKey,sizeof(R_RSA_PRIVATE_KEY),1,KeyFile);

	fclose(KeyFile);
	return 1;
}


int LodeKeys(char* filename,R_RSA_PUBLIC_KEY * publicKey,R_RSA_PRIVATE_KEY * privateKey)
{
	FILE* KeyFile;

	KeyFile=fopen(filename,"rb");
	if( KeyFile== NULL )
		return 0;

	fread(publicKey,sizeof(R_RSA_PUBLIC_KEY),1,KeyFile);
	fread(privateKey,sizeof(R_RSA_PRIVATE_KEY),1,KeyFile);

	fclose(KeyFile);
	return 1;
}


int FilePublicEncrypt (FILE * output, unsigned int * outputLen, FILE * input, unsigned int inputLen,
    R_RSA_PUBLIC_KEY * publicKey)
{
	int ilen=inputLen;
	int outlen,olen=0;
	int inlen,ibufsize,obufsize;
	unsigned char ibuf[MAX_RSA_MODULUS_LEN];
	unsigned char obuf[MAX_RSA_MODULUS_LEN];

	ibufsize=(publicKey->bits + 7) / 8-11;

	while(ilen > 0)
	{
		inlen = fread(ibuf, sizeof(unsigned char),ibufsize, input);
		ilen -=inlen;

		RSAPublicEncrypt(obuf, &outlen, ibuf, inlen,publicKey);

		obufsize = fwrite(obuf, sizeof(unsigned char), outlen, output);
		olen+=obufsize;
	}

	*outputLen=olen;

	return 1;
}
int FilePrivateEncrypt (FILE * output, unsigned int * outputLen, FILE * input, unsigned int inputLen,
    R_RSA_PRIVATE_KEY * privateKey)
{
	int ilen=inputLen;
	int outlen,olen=0;
	int inlen,ibufsize,obufsize;
	unsigned char ibuf[MAX_RSA_MODULUS_LEN];
	unsigned char obuf[MAX_RSA_MODULUS_LEN];

	ibufsize=(privateKey->bits + 7) / 8-11;

	while(ilen > 0)
	{
		inlen = fread(ibuf, sizeof(unsigned char),ibufsize, input);
		ilen -=inlen;

		RSAPrivateEncrypt(obuf, &outlen, ibuf, inlen,privateKey);

		obufsize = fwrite(obuf, sizeof(unsigned char), outlen, output);
		olen+=obufsize;
	}

	*outputLen=olen;

	return 1;
}

int FilePublicDecrypt (FILE * output, unsigned int * outputLen, FILE * input, unsigned int inputLen,
    R_RSA_PUBLIC_KEY * publicKey)
{
	int ilen=inputLen;
	int outlen,olen=0;
	int inlen,ibufsize,obufsize;
	unsigned char ibuf[MAX_RSA_MODULUS_LEN];
	unsigned char obuf[MAX_RSA_MODULUS_LEN];

	ibufsize=(publicKey->bits + 7) / 8;

	while(ilen > 0)
	{
		inlen = fread(ibuf, sizeof(unsigned char),ibufsize, input);
		ilen -=inlen;

		RSAPublicDecrypt(obuf, &outlen, ibuf, inlen,publicKey);

		obufsize = fwrite(obuf, sizeof(unsigned char), outlen, output);
		olen+=obufsize;
	}

	*outputLen=olen;

	return 1;
}

int FilePrivateDecrypt (FILE * output, unsigned int * outputLen, FILE * input, unsigned int inputLen,
    R_RSA_PRIVATE_KEY * privateKey)
{
	int ilen=inputLen;
	int outlen,olen=0;
	int inlen,ibufsize,obufsize;
	unsigned char ibuf[MAX_RSA_MODULUS_LEN];
	unsigned char obuf[MAX_RSA_MODULUS_LEN];

	ibufsize=(privateKey->bits + 7) / 8;

	while(ilen > 0)
	{
		inlen = fread(ibuf, sizeof(unsigned char),ibufsize, input);
		ilen -=inlen;

		RSAPrivateDecrypt(obuf, &outlen, ibuf, inlen,privateKey);

		obufsize = fwrite(obuf, sizeof(unsigned char), outlen, output);
		olen+=obufsize;
	}

	*outputLen=olen;

	return 1;
}
#endif
/* RSA encryption, according to RSADSI's PKCS #1. */

//int RSAPublicEncrypt(output, outputLen, input, inputLen, publicKey, randomStruct)
int RSAPublicEncrypt(output, outputLen, input, inputLen, publicKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PUBLIC_KEY *publicKey;    /* RSA public key */
//R_RANDOM_STRUCT *randomStruct;  /* random structure */
{
	int status;
	unsigned char byte, pkcsBlock[MAX_RSA_MODULUS_LEN];
	unsigned int i, modulusLen;

	modulusLen = (publicKey->bits + 7) / 8;

	if(inputLen + 11 > modulusLen)
        return(RE_LEN);
/*
    R_GetRandomBytesNeeded(&i, randomStruct);
    if(i != 0)
        return(RE_NEED_RANDOM);

	*pkcsBlock = 0;                 // PKCS Block Makeup 

		// block type 2 
	*(pkcsBlock+1) = 2;

	for(i = 2; i < modulusLen - inputLen - 1; i++) {
		// Find nonzero random byte. 
		do {    // random bytes used to pad the PKCS Block 
			R_GenerateBytes(&byte, 1, randomStruct);
		}while(byte == 0);
		*(pkcsBlock+i) = byte;
	}

	// separator 
	pkcsBlock[i++] = 0;

	R_memcpy((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);
*/

	i=0;

	*pkcsBlock = 0;                 // PKCS Block Makeup 

		// block type 2 
	*(pkcsBlock+1) = 2;

	for(i = 2; i < modulusLen - inputLen - 1; i++) 
		*(pkcsBlock+i) = 0xff;
	
	// separator 
	pkcsBlock[i++] = 0;

	R_memcpy((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);

	status = rsapublicfunc(output, outputLen, pkcsBlock, modulusLen, publicKey);

	/* Clear sensitive information. */

	byte = 0;
	R_memset((POINTER)pkcsBlock, 0, sizeof(pkcsBlock));

	return(status);
}

/* RSA decryption, according to RSADSI's PKCS #1. */

int RSAPublicDecrypt(output, outputLen, input, inputLen, publicKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PUBLIC_KEY *publicKey;    /* RSA public key */
{
	static int status;
	static unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
	static unsigned int i, modulusLen, pkcsBlockLen;

	modulusLen = (publicKey->bits + 7) / 8;

	if(inputLen > modulusLen)
		return(RE_LEN);

	status = rsapublicfunc(pkcsBlock, &pkcsBlockLen, input, inputLen, publicKey);
	if(status)
		return(status);

	if(pkcsBlockLen != modulusLen)
		return(RE_LEN);

	/* Require block type 1. */

	if((pkcsBlock[0] != 0) || (pkcsBlock[1] != 1))
	 return(RE_DATA);

	for(i = 2; i < modulusLen-1; i++)
		if(*(pkcsBlock+i) != 0xff)
			break;

	/* separator check */

	if(pkcsBlock[i++] != 0)
		return(RE_DATA);

	*outputLen = modulusLen - i;

	if(*outputLen + 11 > modulusLen)
		return(RE_DATA);

	R_memcpy((POINTER)output, (POINTER)&pkcsBlock[i], *outputLen);

	/* Clear sensitive information. */

	R_memset((POINTER)pkcsBlock, 0, sizeof(pkcsBlock));

	return(ID_OK);
}

/* RSA encryption, according to RSADSI's PKCS #1. */

int RSAPrivateEncrypt(output, outputLen, input, inputLen, privateKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PRIVATE_KEY *privateKey;  /* RSA private key */
{
	int status;
	unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
	unsigned int i, modulusLen;

	modulusLen = (privateKey->bits + 7) / 8;

	if(inputLen + 11 > modulusLen)
		return (RE_LEN);

	*pkcsBlock = 0;
	/* block type 1 */
	*(pkcsBlock+1) = 1;

	for (i = 2; i < modulusLen - inputLen - 1; i++)
		*(pkcsBlock+i) = 0xff;

	/* separator */
	pkcsBlock[i++] = 0;

	R_memcpy((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);

	status = rsaprivatefunc(output, outputLen, pkcsBlock, modulusLen, privateKey);

	/* Clear sensitive information. */

	R_memset((POINTER)pkcsBlock, 0, sizeof(pkcsBlock));

	return(status);
}

/* RSA decryption, according to RSADSI's PKCS #1. */

int RSAPrivateDecrypt(output, outputLen, input, inputLen, privateKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PRIVATE_KEY *privateKey;  /* RSA private key */
{
	int status;
	unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
	unsigned int i, modulusLen, pkcsBlockLen;

	modulusLen = (privateKey->bits + 7) / 8;

	if(inputLen > modulusLen)
		return (RE_LEN);

	status = rsaprivatefunc(pkcsBlock, &pkcsBlockLen, input, inputLen, privateKey);
	if(status)
		return (status);

	if(pkcsBlockLen != modulusLen)
		return (RE_LEN);

	/* We require block type 2. */

	if((*pkcsBlock != 0) || (*(pkcsBlock+1) != 2))
	 return (RE_DATA);

	for(i = 2; i < modulusLen-1; i++)
		/* separator */
		if (*(pkcsBlock+i) == 0)
			break;

	i++;
	if(i >= modulusLen)
		return(RE_DATA);

	*outputLen = modulusLen - i;

	if(*outputLen + 11 > modulusLen)
		return(RE_DATA);

	R_memcpy((POINTER)output, (POINTER)&pkcsBlock[i], *outputLen);

	/* Clear sensitive information. */
	R_memset((POINTER)pkcsBlock, 0, sizeof(pkcsBlock));

	return(ID_OK);
}

/* Raw RSA public-key operation. Output has same length as modulus.

	 Requires input < modulus.
*/
static int rsapublicfunc(output, outputLen, input, inputLen, publicKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PUBLIC_KEY *publicKey;    /* RSA public key */
{
	static NN_DIGIT c[MAX_NN_DIGITS], e[MAX_NN_DIGITS], m[MAX_NN_DIGITS],
		n[MAX_NN_DIGITS];
	static unsigned int eDigits, nDigits;


		/* decode the required RSA function input data */
	NN_Decode(m, MAX_NN_DIGITS, input, inputLen);
	NN_Decode(n, MAX_NN_DIGITS, publicKey->modulus, MAX_RSA_MODULUS_LEN);
	NN_Decode(e, MAX_NN_DIGITS, publicKey->exponent, MAX_RSA_MODULUS_LEN);

	nDigits = NN_Digits(n, MAX_NN_DIGITS);
	eDigits = NN_Digits(e, MAX_NN_DIGITS);

	if(NN_Cmp(m, n, nDigits) >= 0)
		return(RE_DATA);

	*outputLen = (publicKey->bits + 7) / 8;

	/* Compute c = m^e mod n.  To perform actual RSA calc.*/

	NN_ModExp (c, m, e, eDigits, n, nDigits);

	/* encode output to standard form */
	NN_Encode (output, *outputLen, c, nDigits);

	/* Clear sensitive information. */

	R_memset((POINTER)c, 0, sizeof(c));
	R_memset((POINTER)m, 0, sizeof(m));

	return(ID_OK);
}

/* Raw RSA private-key operation. Output has same length as modulus.

	 Requires input < modulus.
*/

static int rsaprivatefunc(output, outputLen, input, inputLen, privateKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PRIVATE_KEY *privateKey;  /* RSA private key */
{
/*
	NN_DIGIT c[MAX_NN_DIGITS], d[MAX_NN_DIGITS], m[MAX_NN_DIGITS],
		n[MAX_NN_DIGITS];
	unsigned int dDigits, nDigits;


		// decode the required RSA function input data 
	NN_Decode(c, MAX_NN_DIGITS, input, inputLen);
	NN_Decode(n, MAX_NN_DIGITS, privateKey->modulus, MAX_RSA_MODULUS_LEN);
	NN_Decode(d, MAX_NN_DIGITS, privateKey->exponent, MAX_RSA_MODULUS_LEN);

	nDigits = NN_Digits(n, MAX_NN_DIGITS);
	dDigits = NN_Digits(d, MAX_NN_DIGITS);

	if(NN_Cmp(c, n, nDigits) >= 0)
		return(RE_DATA);

	*outputLen = (privateKey->bits + 7) / 8;

	// Compute m = c^d mod n.  To perform actual RSA calc.

	NN_ModExp (m, c, d, dDigits, n, nDigits);

	// encode output to standard form 
	NN_Encode (output, *outputLen, m, nDigits);

	// Clear sensitive information. 

	R_memset((POINTER)c, 0, sizeof(c));
	R_memset((POINTER)m, 0, sizeof(m));

	return(ID_OK);

*/	
	
	
	static NN_DIGIT c[MAX_NN_DIGITS], cP[MAX_NN_DIGITS], cQ[MAX_NN_DIGITS],
		dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS], mP[MAX_NN_DIGITS],
		mQ[MAX_NN_DIGITS], n[MAX_NN_DIGITS], p[MAX_NN_DIGITS], q[MAX_NN_DIGITS],
		qInv[MAX_NN_DIGITS], t[MAX_NN_DIGITS];
	unsigned int cDigits, nDigits, pDigits;

	// decode required input data from standard form 
	NN_Decode(c, MAX_NN_DIGITS, input, inputLen);           // input 

					// private key data 
	NN_Decode(p, MAX_NN_DIGITS, privateKey->prime[0], MAX_RSA_PRIME_LEN);
	NN_Decode(q, MAX_NN_DIGITS, privateKey->prime[1], MAX_RSA_PRIME_LEN);
	NN_Decode(dP, MAX_NN_DIGITS, privateKey->primeExponent[0], MAX_RSA_PRIME_LEN);
	NN_Decode(dQ, MAX_NN_DIGITS, privateKey->primeExponent[1], MAX_RSA_PRIME_LEN);
	NN_Decode(n, MAX_NN_DIGITS, privateKey->modulus, MAX_RSA_MODULUS_LEN);
	NN_Decode(qInv, MAX_NN_DIGITS, privateKey->coefficient, MAX_RSA_PRIME_LEN);
		// work out lengths of input components 

    cDigits = NN_Digits(c, MAX_NN_DIGITS);
    pDigits = NN_Digits(p, MAX_NN_DIGITS);
	nDigits = NN_Digits(n, MAX_NN_DIGITS);


	if(NN_Cmp(c, n, nDigits) >= 0)
		return(RE_DATA);

	*outputLen = (privateKey->bits + 7) / 8;

	// Compute mP = cP^dP mod p  and  mQ = cQ^dQ mod q. (Assumes q has
	//	 length at most pDigits, i.e., p > q.)
	

	NN_Mod(cP, c, cDigits, p, pDigits);
	NN_Mod(cQ, c, cDigits, q, pDigits);

	NN_AssignZero(mP, nDigits);
	NN_ModExp(mP, cP, dP, pDigits, p, pDigits);

	NN_AssignZero(mQ, nDigits);
	NN_ModExp(mQ, cQ, dQ, pDigits, q, pDigits);

	// Chinese Remainder Theorem:
	//		m = ((((mP - mQ) mod p) * qInv) mod p) * q + mQ.
	
	if(NN_Cmp(mP, mQ, pDigits) >= 0) {
		NN_Sub(t, mP, mQ, pDigits);
	}else{
		NN_Sub(t, mQ, mP, pDigits);
		NN_Sub(t, p, t, pDigits);
	}

	NN_ModMult(t, t, qInv, p, pDigits);
	NN_Mult(t, t, q, pDigits);
	NN_Add(t, t, mQ, nDigits);

	// encode output to standard form 
	NN_Encode (output, *outputLen, t, nDigits);

	// Clear sensitive information. 
	R_memset((POINTER)c, 0, sizeof(c));
	R_memset((POINTER)cP, 0, sizeof(cP));
	R_memset((POINTER)cQ, 0, sizeof(cQ));
	R_memset((POINTER)dP, 0, sizeof(dP));
	R_memset((POINTER)dQ, 0, sizeof(dQ));
	R_memset((POINTER)mP, 0, sizeof(mP));
	R_memset((POINTER)mQ, 0, sizeof(mQ));
	R_memset((POINTER)p, 0, sizeof(p));
	R_memset((POINTER)q, 0, sizeof(q));
	R_memset((POINTER)qInv, 0, sizeof(qInv));
	R_memset((POINTER)t, 0, sizeof(t));
	return(ID_OK);

}