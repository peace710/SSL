#ifndef __SSL_BASE_64_H__
#define __SSL_BASE_64_H__

#include <openssl/base64.h>


int base64_encode(const char *in,unsigned char **out);

int base64_decode(const char *in,unsigned char **out);

#endif
