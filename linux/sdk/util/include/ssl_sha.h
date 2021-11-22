#ifndef __SSL_SHA_H__
#define __SSL_SHA_H__

#include <openssl/sha.h>
#include <openssl/crypto.h>

#define SHA_1 0
#define SHA_224 1
#define SHA_256 2
#define SHA_384 3
#define SHA_512 4
#define SHA_512_256 5

int sha1(const char *in,unsigned char **out);

int sha224(const char *in,unsigned char **out);

int sha256(const char *in,unsigned char **out);

int sha384(const char *in,unsigned char **out);

int sha512(const char *in,unsigned char **out);

int sha512_256(const char *in,unsigned char **out);

int sha(const char *in ,unsigned char **out,int mode);

#endif
