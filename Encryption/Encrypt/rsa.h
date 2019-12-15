//int RSAPublicEncrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
//    R_RSA_PUBLIC_KEY *, R_RANDOM_STRUCT *));
int RSAPublicEncrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PUBLIC_KEY *));
int RSAPrivateEncrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PRIVATE_KEY *));
int RSAPublicDecrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PUBLIC_KEY *));
int RSAPrivateDecrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PRIVATE_KEY *));

#if 0
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
#endif
