#ifndef __SSL_HMAC_H__
#define __SSL_HMAC_H__

#include <openssl/hmac.h>

#define HMAC_MD4 0
#define HMAC_MD5 1
#define HMAC_SHA1 2
#define HMAC_SHA224 3
#define HMAC_SHA256 4
#define HMAC_SHA384 5
#define HMAC_SHA512 6
#define HMAC_SHA512_256 7 
#define HMAC_BLAKE_2B_256 8
#define HMAC_MD5_SHA1 9

int hmac(const uint8_t *data,const void *key,uint8_t **out,unsigned int *out_len,int mode);


#endif
