#ifndef __SSL_MD_H__
#define __SSL_MD_H__

#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/crypto.h>

#define MD_4 0
#define MD_5 1

int md4(const char *in,unsigned char **out);

int md5(const char *in,unsigned char **out);

int md(const char *in ,unsigned char **out,int mode);

#endif
