#ifndef __SSL_RSA_H__
#define __SSL_RSA_H__

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define RSA_BITS_1024 1024
#define RSA_BITS_2048 2048

#define PUB_EXPONENT "65537"

#define PKCS1_PADDING 0 
#define NO_PADDING 1

#define ERROR -1



RSA *rsa_bits(int bits);

RSA *rsa_with_modulus(const char *modulus);

RSA *rsa_with_all(const char *modulus,const char *exponent);

int rsa_pub_encrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding);

int rsa_pri_encrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding);

int rsa_pub_decrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding);

int rsa_pri_decrypt(RSA *rsa,unsigned char *in,int data_len,unsigned char **out,int padding);

void free_rsa(RSA *rsa);

#endif
