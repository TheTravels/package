/**/
#include <stdio.h>
#include <string.h>
 

#ifdef __cplusplus
extern "C" {
#endif
 
	char DecryptData(char *inbuf,char *outbuf,long len);
     char EncryptData(char *inbuf,char *outbuf,long len);
  
  char VerifyLicence(char *id,char *sn,char *licence,int len);
  
  
#ifdef __cplusplus
}
#endif