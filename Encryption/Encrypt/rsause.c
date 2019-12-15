#include <stdio.h>
#include <windows.h>
#include <mmsystem.h>

#include "rsa_incl.h"

int SaveKeys(char* filename,R_RSA_PUBLIC_KEY publicKey,R_RSA_PRIVATE_KEY privateKey);
int LodeKeys(char* filename,R_RSA_PUBLIC_KEY * publicKey,R_RSA_PRIVATE_KEY * privateKey);

int FilePublicEncrypt (FILE * output, unsigned int * outputLen, FILE * input, unsigned int inputLen,
    R_RSA_PUBLIC_KEY *);
int FilePrivateEncrypt (FILE * output, unsigned int * outputLen, FILE * input, unsigned int inputLen,
    R_RSA_PRIVATE_KEY *);
int FilePublicDecrypt (FILE * output, unsigned int * outputLen, FILE * input, unsigned int inputLen,
    R_RSA_PUBLIC_KEY *);
int FilePrivateDecrypt (FILE * output, unsigned int * outputLen, FILE * input, unsigned int inputLen,
    R_RSA_PRIVATE_KEY *);


int mainrsa()
{
//	int status;
//	R_RSA_PUBLIC_KEY publicKey;    /* new RSA public key */
//	R_RSA_PRIVATE_KEY privateKey;  /* new RSA private key */
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
//	status=R_GeneratePEMKeys(&publicKey, &privateKey, &protoKey, &randomStruct);
//	SaveKeys(filename,publicKey,privateKey);
	LodeKeys(filename,&publicKey1,&privateKey1);

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

int SaveKeys(char* filename,R_RSA_PUBLIC_KEY publicKey,R_RSA_PRIVATE_KEY privateKey)
{
	FILE* KeyFile;

	KeyFile=fopen(filename,"wb");
	if( KeyFile== NULL )
		return 0;
	
	fwrite(&publicKey,sizeof(R_RSA_PUBLIC_KEY),1,KeyFile);
	fwrite(&privateKey,sizeof(R_RSA_PRIVATE_KEY),1,KeyFile);

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

